#!/usr/bin/env python3
"""
Measures what two computers running SIP Inspector can do: how many calls a second they set up and end, and how
many calls with G.711 audio both ways they carry at the same time, each within the limits of a gate (ASR, response
time, RTP loss, MOS). Both computers run SIP Inspector as an API service; this script drives them over HTTP, so it
needs no SIP Inspector files of its own and can run on either computer or a third one.

On each computer (the program folder needs pcap/test.pcap and the licence; nothing else):
  SIPInspDlxCLI -api 8080 -apiHost 0.0.0.0 -apiToken <token> -lip <its address> -lp 5060 -lrtp 10000 -np
  (or: java -Xmx2g -jar SIPInspDlx.jar ... with the same options)

Then, from anywhere that reaches both:
  test/capacity.py --a http://10.0.0.5:8080 --b http://10.0.0.9:8080 --token <token>

Tests (--test):
  cps   calls a second: short calls without media (Perf_cps_*), the rate raised step by step (--cps-steps), each
        step --cps-seconds long, until a step fails its gate (--cps-gate)
  rtp   concurrent calls with audio: calls with G.711 both ways (Perf_rtp_*), the number of calls at the same time
        raised step by step (--rtp-steps), until a step fails its gate (--rtp-gate)
Roles (--roles): ab = A calls B, ba = B calls A, both (default). A machine is measured best as the caller and as the
answerer; the weaker one limits each run, and the CPU load of both is recorded to show which one it was.

A step passes when the runs on both computers pass their gates. Each step is run --repeat times (all must pass);
after the first failing step the limit is narrowed down between the last passing and the first failing value
(--refine times). Results go to --out: results.json (everything), steps.csv and summary.md (the tables for the
documentation). Python 3.6+, standard library only.
"""

import argparse
import csv
import datetime
import json
import math
import os
import sys
import threading
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCEN_DIR = os.path.join(ROOT, "scenarios")

# What the limits of a gate mean, for the summary
METRIC_TEXT = {
    "asr": "answer-seizure ratio: answered calls / call attempts, in %",
    "p95": "95th percentile of the SIP response times (request to its response), in ms",
    "loss": "RTP packets lost / RTP packets expected, in %",
    "mos": "estimated MOS (1 to 4.5) of the received audio, from loss and jitter (E-model)",
    "jitter": "average RTP interarrival jitter, in ms",
    "unfinished": "calls that did not reach the end of the scenario",
}


# --------------------------------------------------------------------------- the API of one computer

class Api(object):
    def __init__(self, label, url, token):
        self.label, self.url, self.token = label, url.rstrip("/"), token

    def call(self, method, path, body=None, raw=None, timeout=30):
        data, headers = None, {"Authorization": "Bearer " + self.token}
        if raw is not None:
            data, headers["Content-Type"] = raw, "text/plain; charset=utf-8"
        elif body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode("utf-8"), "application/json"
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, json.loads(r.read().decode("utf-8") or "null")
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(text)
            except ValueError:
                return e.code, {"error": text}
        except (urllib.error.URLError, OSError) as e:
            raise SystemExit("%s (%s) does not answer: %s" % (self.label, self.url, e))

    def get(self, path):
        code, data = self.call("GET", path)
        if code != 200:
            raise SystemExit("%s: GET %s: %s" % (self.label, path, data.get("error", code) if isinstance(data, dict) else code))
        return data

    def upload(self, name, text):
        code, data = self.call("POST", "/scenarios?name=" + urllib.request.quote(name), raw=text.encode("utf-8"))
        if code != 201:
            raise SystemExit("%s: the scenario %s cannot be sent: %s" % (self.label, name, data.get("error")))
        return data["path"]

    def start(self, run):
        code, data = self.call("POST", "/run", run)
        if code != 202:
            raise SystemExit("%s: the run cannot be started: %s\n%s" % (self.label, data.get("error"), json.dumps(run)))
        return data["run"]

    def wait_idle(self, seconds=120):
        deadline = time.time() + seconds
        while time.time() < deadline:
            st = self.get("/status")
            if st.get("state") == "idle":
                return st
            time.sleep(0.5)
        raise SystemExit("%s: a run is still going on after %d s" % (self.label, seconds))

    def wait_run(self, run, seconds):
        """Waits for the end of the run and returns its summary (GET /runs/N)."""
        deadline = time.time() + seconds
        while time.time() < deadline:
            code, r = self.call("GET", "/runs/%d" % run)
            if code == 200 and r.get("state") in ("finished", "failed"):
                return r
            time.sleep(1)
        self.call("POST", "/stop")
        return self.wait_run(run, 60)

    def report(self, run):
        return self.get("/report?format=json&run=%d" % run)


class Monitor(threading.Thread):
    """Samples the CPU load of both computers and the calls going on, every --sample seconds while a step runs."""

    def __init__(self, apis, caller, period):
        threading.Thread.__init__(self, daemon=True)
        self.apis, self.caller, self.period = apis, caller, period
        self.samples = {a.label: [] for a in apis}
        self.active, self.cps = [], []
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.is_set():
            for a in self.apis:
                try:
                    code, s = a.call("GET", "/system", timeout=5)
                    if code == 200 and s.get("cpuLoad", -1) >= 0:
                        self.samples[a.label].append((s["cpuLoad"], s.get("processCpuLoad", -1), s.get("usedHeapMB", 0)))
                except SystemExit:
                    pass
            try:
                code, st = self.caller.call("GET", "/status", timeout=5)
                if code == 200:
                    self.active.append(st.get("callsActive") or 0)
                    if st.get("measuredCallsPerSecond") is not None:
                        self.cps.append(st["measuredCallsPerSecond"])
            except SystemExit:
                pass
            self.stopped.wait(self.period)

    def summary(self, label):
        s = self.samples[label]
        if not s:
            return {}
        cpu = [x[0] * 100 for x in s]
        proc = [x[1] * 100 for x in s if x[1] >= 0]
        return {"cpuAvg": round(sum(cpu) / len(cpu), 1), "cpuMax": round(max(cpu), 1),
                "procCpuAvg": round(sum(proc) / len(proc), 1) if proc else None, "heapMaxMB": max(x[2] for x in s)}


# --------------------------------------------------------------------------- one step

def scenario_text(name, hold_ms):
    with open(os.path.join(SCEN_DIR, name), encoding="utf-8") as f:
        text = f.read()
    if name == "Perf_cps_client.txt":
        text = text.replace("cmd_Pause=1000", "cmd_Pause=%d" % hold_ms)
    elif name == "Perf_rtp_client.txt":
        text = text.replace(";duration=60000", ";duration=%d" % hold_ms)
    return text


def metrics_of(rep):
    m = rep.get("metrics", {})
    num = lambda k: (None if m.get(k) in ("", None, -1) else m.get(k))
    return {"result": rep.get("result"), "reasons": rep.get("reasons", []), "attempts": num("calls.attempted"), "answered": num("calls.answered"),
            "asr": num("calls.asrPercent"), "p95": num("responseTime.p95Ms"), "rtpCalls": num("rtp.calls"), "packets": num("rtp.packets"),
            "loss": num("rtp.lossPercent"), "jitter": num("rtp.jitterAvgMs"), "mos": num("rtp.mosAvg"), "mosMin": num("rtp.mosMin")}


def run_step(args, caller, answerer, kind, value):
    """One step: the answerer waits for calls, the caller makes them, both are judged by their gates."""
    if kind == "cps":
        cps, hold_ms = float(value), args.cps_hold_ms
        total = int(math.ceil(cps * args.cps_seconds))
        max_conc = int(cps * hold_ms / 1000.0 * 3) + 50
        caller_gate, answerer_gate = args.cps_gate, args.cps_answer_gate
        expected_s = args.cps_seconds + hold_ms / 1000.0
    else:
        cps, total = args.rtp_cps, int(value)
        ramp_s = total / cps
        hold_ms = int((ramp_s + args.rtp_measure_seconds) * 1000)  # every call is up while the last ones start, then for the measuring time
        max_conc = total
        caller_gate, answerer_gate = args.rtp_gate, args.rtp_answer_gate
        expected_s = ramp_s + hold_ms / 1000.0
    timeout = int(expected_s * 1.5 + 60)
    client, server = "Perf_%s_client.txt" % kind, "Perf_%s_server.txt" % kind
    client_path = caller.upload(client, scenario_text(client, hold_ms))
    server_path = answerer.upload(server, scenario_text(server, hold_ms))
    ans_sys = answerer.get("/system")
    remote = args.sip.get(answerer.label) or "%s:%s" % (ans_sys["sipAddress"], ans_sys["sipPort"])
    host, port = remote.rsplit(":", 1)
    caller.wait_idle()
    answerer.wait_idle()

    mon = Monitor([caller, answerer], caller, args.sample)
    started = time.time()
    a_run = answerer.start({"scenario": server_path, "gate": answerer_gate, "timeout": timeout + 120, "noChecks": args.no_checks})
    time.sleep(1.0)
    mon.start()
    c_run = caller.start({"scenario": client_path, "remote": host.strip("[]"), "remotePort": int(port), "totalCalls": total, "cps": cps,
                          "maxConcurrent": max_conc, "timeout": timeout, "gate": caller_gate, "noChecks": args.no_checks})
    caller.wait_run(c_run, timeout + 120)
    time.sleep(args.grace)                 # the last BYEs and their answers
    answerer.call("POST", "/stop")         # an answering run has no end of its own
    answerer.wait_run(a_run, 120)
    mon.stopped.set()
    mon.join(10)
    c, a = metrics_of(caller.report(c_run)), metrics_of(answerer.report(a_run))
    step = {"test": kind, "caller": caller.label, "answerer": answerer.label, "value": value, "cps": cps, "totalCalls": total,
            "holdMs": hold_ms, "seconds": round(time.time() - started, 1), "pass": c["result"] == "PASS" and a["result"] == "PASS",
            "callerResult": c, "answererResult": a, "callerLoad": mon.summary(caller.label), "answererLoad": mon.summary(answerer.label),
            "maxActive": max(mon.active) if mon.active else None, "measuredCps": round(max(mon.cps), 1) if mon.cps else None}
    if kind == "cps" and step["measuredCps"] is not None and step["measuredCps"] < 0.95 * cps:
        # every call answered but made slower than asked: the step did not show the rate
        step["pass"] = False
        c["reasons"] = (c["reasons"] or []) + ["the caller made %s calls/s of the %s asked for" % (step["measuredCps"], cps)]
    print("  %-4s %s->%s %8s  %s  ASR %s%%  p95 %s ms  loss %s%%  MOS %s  active %s  CPU %s%%/%s%%  (%.0f s)%s" % (
        kind, caller.label, answerer.label, value, "PASS" if step["pass"] else "FAIL", c["asr"], c["p95"],
        c["loss"] if kind == "rtp" else "-", c["mos"] if kind == "rtp" else "-", step["maxActive"],
        step["callerLoad"].get("cpuMax", "?"), step["answererLoad"].get("cpuMax", "?"), step["seconds"],
        "" if step["pass"] else "\n       " + "; ".join((c["reasons"] or []) + (a["reasons"] or []))[:400]), flush=True)
    return step


def warm_up(args, caller, answerer):
    """A short run of each test that is not counted: Java compiles the busy code in the first seconds, so the first step measured
    would otherwise get a CPU load (and response times) the program does not have later."""
    keep = (args.cps_seconds, args.rtp_measure_seconds)
    args.cps_seconds, args.rtp_measure_seconds = 10, 10
    print("  warming up ...", flush=True)
    try:
        run_step(args, caller, answerer, "cps", 20)
        run_step(args, caller, answerer, "rtp", 20)
    finally:
        args.cps_seconds, args.rtp_measure_seconds = keep


def find_limit(args, caller, answerer, kind, steps, log):
    """Raises the load step by step until a step fails, then narrows the limit down. Returns (best passing step, first failing value)."""
    best, fail_value = None, None
    integer = kind == "rtp" or all(float(s).is_integer() for s in steps)

    def attempt(value):
        results = [run_step(args, caller, answerer, kind, value) for _ in range(args.repeat)]
        log.extend(results)
        ok = all(r["pass"] for r in results)
        return ok, results[-1]

    for value in steps:
        ok, step = attempt(value)
        if not ok:
            fail_value = value
            break
        best = step
    if fail_value is not None and best is not None:
        low, high = best["value"], fail_value
        for _ in range(args.refine):
            mid = (low + high) / 2.0
            if integer:
                mid = int(round(mid))
            if mid in (low, high):
                break
            ok, step = attempt(mid)
            if ok:
                low, best = mid, step
            else:
                high = mid
        fail_value = high
    return best, fail_value


# --------------------------------------------------------------------------- the summary

def write_summary(path, machines, config, results, steps):
    L = []
    L.append("# SIP Inspector capacity, %s" % config["date"])
    L.append("")
    L.append("## The computers")
    L.append("")
    L.append("| | Computer | CPU | Cores | Memory | OS | Java | Max heap |")
    L.append("|---|---|---|---|---|---|---|---|")
    for label, s in machines.items():
        L.append("| %s | %s | %s | %s | %.1f GB | %s %s | %s | %d MB |" % (label, s.get("host"), s.get("cpu"), s.get("cores"), s.get("memoryMB", 0) / 1024.0,
                                                                   s.get("os"), s.get("arch"), s.get("java"), s.get("maxHeapMB", 0)))
    L.append("")
    hosts = set(s.get("host") for s in machines.values())
    if len(machines) > 1 and len(hosts) == 1:
        L.append("Both services ran on the same computer (loopback): every number is for that one computer carrying both sides, "
                 "and the CPU load of both columns is the load of that computer.")
    else:
        L.append("Network: %s." % config["network"])
    L.append("Transport: %s. Codec: G.711 PCMU, 20 ms packets, both ways." % config["transport"])
    L.append("")
    L.append("## Results")
    L.append("")
    L.append("| Test | Caller -> answerer | Limit reached | First failing step | ASR | p95 | Loss | MOS | CPU caller avg / max | CPU answerer avg / max |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    for r in results:
        b = r["best"]
        name = "Calls per second" if r["test"] == "cps" else "Concurrent calls with G.711 both ways"
        if b is None:
            L.append("| %s | %s -> %s | below the first step | %s | | | | | | |" % (name, r["caller"], r["answerer"], r["firstFail"]))
            continue
        c = b["callerResult"]
        limit = ("%s calls/s" % b["value"]) if r["test"] == "cps" else ("%s calls (%s RTP streams each way)" % (b["value"], b["value"]))
        cl, al = b["callerLoad"], b["answererLoad"]
        L.append("| %s | %s -> %s | %s | %s | %s %% | %s ms | %s | %s | %s / %s %% | %s / %s %% |" % (
            name, r["caller"], r["answerer"], limit, r["firstFail"] if r["firstFail"] is not None else "none (last step passed)", c["asr"], c["p95"],
            ("%s %%" % c["loss"]) if r["test"] == "rtp" else "-", c["mos"] if r["test"] == "rtp" else "-",
            cl.get("cpuAvg", "?"), cl.get("cpuMax", "?"), al.get("cpuAvg", "?"), al.get("cpuMax", "?")))
    L.append("")
    L.append("## The limits a step must keep (the gate)")
    L.append("")
    L.append("- Calls per second: caller `%s`, answerer `%s`; each step %d s of calls held %d ms." % (config["cpsGate"], config["cpsAnswerGate"],
                                                                                                config["cpsSeconds"], config["cpsHoldMs"]))
    L.append("- Concurrent calls: caller `%s`, answerer `%s`; calls start at %s a second, then all of them stay up for %d s." % (
        config["rtpGate"], config["rtpAnswerGate"], config["rtpCps"], config["rtpMeasureSeconds"]))
    for k, v in METRIC_TEXT.items():
        L.append("- `%s`: %s" % (k, v))
    L.append("")
    L.append("A step passes when the runs on both computers keep their limits; it was run %d time(s). Every step is in steps.csv." % config["repeat"])
    L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def write_csv(path, steps):
    cols = ["test", "caller", "answerer", "value", "pass", "cps", "totalCalls", "holdMs", "seconds", "maxActive", "measuredCps"]
    met = ["result", "attempts", "answered", "asr", "p95", "packets", "loss", "jitter", "mos", "mosMin"]
    load = ["cpuAvg", "cpuMax", "procCpuAvg", "heapMaxMB"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols + ["caller_" + m for m in met] + ["answerer_" + m for m in met] + ["caller_" + l for l in load] + ["answerer_" + l for l in load])
        for s in steps:
            w.writerow([s[c] for c in cols] + [s["callerResult"].get(m) for m in met] + [s["answererResult"].get(m) for m in met]
                       + [s["callerLoad"].get(l) for l in load] + [s["answererLoad"].get(l) for l in load])


# --------------------------------------------------------------------------- main

def numbers(text):
    return [float(x) if "." in x else int(x) for x in text.split(",") if x.strip()]


def main():
    ap = argparse.ArgumentParser(description="Capacity test of SIP Inspector between two computers (see the top of this file).",
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--a", required=True, metavar="URL", help="API of computer A, e.g. http://10.0.0.5:8080")
    ap.add_argument("--b", required=True, metavar="URL", help="API of computer B")
    ap.add_argument("--token", required=True, help="the -apiToken of both services (or --a-token / --b-token)")
    ap.add_argument("--a-token"), ap.add_argument("--b-token")
    ap.add_argument("--a-name", default="A", help="name of computer A in the results (default A)")
    ap.add_argument("--b-name", default="B")
    ap.add_argument("--a-sip", help="SIP address:port the other computer calls A at (default: what A's service was started with)")
    ap.add_argument("--b-sip")
    ap.add_argument("--test", choices=("cps", "rtp", "both"), default="both")
    ap.add_argument("--roles", choices=("ab", "ba", "both"), default="both", help="ab: A calls B; ba: B calls A; both (default)")
    ap.add_argument("--cps-steps", default="10,20,50,100,150,200,300,400,500,700,1000", help="call rates to try, calls a second")
    ap.add_argument("--cps-seconds", type=int, default=60, help="how long each call rate step makes calls (default 60)")
    ap.add_argument("--cps-hold-ms", type=int, default=1000, help="how long a call of the call rate test lasts (default 1000 ms)")
    ap.add_argument("--cps-gate", default="asr>=99.5,p95<=500")
    ap.add_argument("--cps-answer-gate", default="asr>=99.5")
    ap.add_argument("--rtp-steps", default="25,50,100,200,300,400,600,800,1000,1500,2000", help="numbers of calls at the same time to try")
    ap.add_argument("--rtp-cps", type=float, default=20, help="rate the calls of an RTP step start at (default 20 a second)")
    ap.add_argument("--rtp-measure-seconds", type=int, default=60, help="how long all calls of an RTP step are up together (default 60)")
    ap.add_argument("--rtp-gate", default="asr>=99,loss<=0.5,mos>=4.0")
    ap.add_argument("--rtp-answer-gate", default="asr>=99,loss<=0.5,mos>=4.0")
    ap.add_argument("--repeat", type=int, default=1, help="runs of each step; all must pass (default 1; 3 for the published numbers)")
    ap.add_argument("--refine", type=int, default=3, help="steps that narrow the limit down after the first failure (default 3)")
    ap.add_argument("--no-checks", action="store_true", help="do not check the SIP/SDP of every message (-noChecks), as in a pure load test")
    ap.add_argument("--no-warmup", action="store_true", help="do not make the short uncounted warm-up runs first")
    ap.add_argument("--grace", type=float, default=5, help="seconds after the caller ended before the answerer is stopped (default 5)")
    ap.add_argument("--sample", type=float, default=2, help="seconds between CPU samples (default 2)")
    ap.add_argument("--network", default="1 Gbit/s Ethernet", help="the network, for the summary")
    ap.add_argument("--out", help="folder for the results (default capacity_<date>)")
    args = ap.parse_args()

    a = Api(args.a_name, args.a, args.a_token or args.token)
    b = Api(args.b_name, args.b, args.b_token or args.token)
    args.sip = {a.label: args.a_sip, b.label: args.b_sip}
    machines = {a.label: a.get("/system"), b.label: b.get("/system")}
    for label, s in machines.items():
        print("%s: %s, %s, %s cores, %.1f GB, %s, SIP %s:%s" % (label, s.get("host"), s.get("cpu"), s.get("cores"), s.get("memoryMB", 0) / 1024.0,
                                                              s.get("os"), s.get("sipAddress"), s.get("sipPort")))
    out = args.out or "capacity_" + datetime.datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(out, exist_ok=True)
    config = {"date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "network": args.network, "transport": machines[a.label].get("transport"),
              "cpsGate": args.cps_gate, "cpsAnswerGate": args.cps_answer_gate, "cpsSeconds": args.cps_seconds, "cpsHoldMs": args.cps_hold_ms,
              "rtpGate": args.rtp_gate, "rtpAnswerGate": args.rtp_answer_gate, "rtpCps": args.rtp_cps, "rtpMeasureSeconds": args.rtp_measure_seconds,
              "repeat": args.repeat, "refine": args.refine, "noChecks": args.no_checks}
    pairs = {"ab": [(a, b)], "ba": [(b, a)], "both": [(a, b), (b, a)]}[args.roles]
    tests = ["cps", "rtp"] if args.test == "both" else [args.test]
    steps, results = [], []

    def save():
        with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as f:
            json.dump({"config": config, "machines": machines, "results": results, "steps": steps}, f, indent=2)
        write_csv(os.path.join(out, "steps.csv"), steps)
        write_summary(os.path.join(out, "summary.md"), machines, config, results, steps)

    if not args.no_warmup:
        for caller, answerer in pairs:
            warm_up(args, caller, answerer)
    for kind in tests:
        for caller, answerer in pairs:
            print("\n%s: %s calls %s" % ("Calls per second" if kind == "cps" else "Concurrent calls with G.711 both ways", caller.label, answerer.label))
            best, fail_value = find_limit(args, caller, answerer, kind, numbers(args.cps_steps if kind == "cps" else args.rtp_steps), steps)
            results.append({"test": kind, "caller": caller.label, "answerer": answerer.label, "best": best, "firstFail": fail_value})
            print("  => %s" % ("below the first step" if best is None else "%s %s" % (best["value"], "calls/s" if kind == "cps" else "calls at the same time")))
            save()
    save()
    print("\nResults: %s" % os.path.abspath(out))
    with open(os.path.join(out, "summary.md"), encoding="utf-8") as f:
        print(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
