#!/usr/bin/env python3
"""
Measures what two computers running SIP Inspector can do: how many calls a second they set up and end, and how
many calls with G.711 audio both ways they carry at the same time, each within the limits of a gate (ASR, response
time, RTP loss, MOS). Both computers run SIP Inspector as an API service; this script drives them over HTTP, so it
needs no SIP Inspector files of its own and can run on either computer or a third one.

On each computer (the program folder needs pcap/test.pcap and the license; nothing else):
  ./SIPInspDlx -api 8080 -apiHost 0.0.0.0 -apiToken <token> -lip <its address> -lp 5060 -lrtp 10000 -np -d ERROR
  (on Windows SIPInspDlxCLI.exe with the same options)
  -d ERROR: without it a service logs at the level the GUI saved last, and VERBOSE writes lines for every SIP message
  (GET /system gives logLevel; the script warns when it is above ERROR)

Then, from anywhere that reaches both:
  test/capacity.py --a http://10.0.0.5:8080 --b http://10.0.0.9:8080 --token <token>

Both services on one computer, each in its own copy of the program folder:
  ./SIPInspDlx -api 8080 -apiToken <token> -lip 127.0.0.1 -lp 5060 -lrtp 10000 -np -d ERROR
  ./SIPInspDlx -api 8081 -apiToken <token> -lip 127.0.0.2 -lp 5070 -lrtp 10000 -np -d ERROR
  test/capacity.py --a http://127.0.0.1:8080 --b http://127.0.0.1:8081 --token <token> --roles ab
(on Windows SIPInspDlxCLI.exe with the same options). macOS answers on 127.0.0.1 only: before B starts run
"sudo ifconfig lo0 alias 127.0.0.2 up" (again after every restart of the Mac), and start B again if it was started
without it, as its SIP port could not be opened then ("lsof -nP -iUDP:5070" shows java on 127.0.0.2:5070 when it listens).
On one address instead, the media ports must be far enough apart (-lrtp 10000 and -lrtp 20000). Every call
of a step takes the next RTP port, 2 apart, counted up from -lrtp; on one address the ports of the two sides must not
meet, or one side gets the RTP of the other and the numbers are wrong. The script checks that before every step and
stops with the -lrtp to use. A media port that another program holds is reported by the service (rtp.portErrors) and
stops the test too: media ports below 32768 keep out of the ports the system gives to other programs.

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

# --------------------------------------------------------------------------- the limits: change them here
# (each one is also an option on the command line, which wins over the value here)

CPS_STEPS = "10,20,50,100,200,300,500,700,1000,1500,2000,3000,5000,7000,10000,15000,20000"  # calls a second to try
RTP_STEPS = "25,50,100,200,500,1000,2000,3000,5000,7000,10000,15000,20000"  # calls with audio at the same time to try
RTP_START_CPS = 100        # calls a second the calls of an RTP step start at: 20000 calls take 200 s to start
RTP_MEASURE_SECONDS = 60   # how long all calls of an RTP step are up together
RTP_RAMP_MARGIN = 1.5      # a call is held this many times the planned start-up time (plus the measuring time), so the
                           # first calls are still up with their RTP when the last ones start, even when the caller starts
                           # them slower than RTP_START_CPS
RTP_PACKETS_PER_SECOND = 50  # pcap/test.pcap: G.711 in 20 ms packets, a stream each way per call
RTP_MIN_PACKETS = 0.95     # an RTP step fails when a side got less than this share of the RTP its calls should have sent it
RTP_START_SECONDS = 2      # RTP of a call starts after its INVITE, 200 and ACK: left out of the packets a call is expected to get
RTP_MIN_ACTIVE = 0.99      # an RTP step fails when fewer than this share of its calls were seen up at the same time
MEDIA_PORT_MARGIN = 10     # calls a run may take RTP ports for beyond the calls of its step, for the port check

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
# the Perf_* scenarios: those of the source tree (test/../scenarios), those next to the script (the capacityTester
# folder on GitHub has them), or those of the program folder the script is started in
SCEN_DIRS = [os.path.join(ROOT, "scenarios"), os.path.join(HERE, "scenarios"), os.path.join(os.getcwd(), "scenarios")]
SCEN_DIR = next((d for d in SCEN_DIRS if os.path.isfile(os.path.join(d, "Perf_cps_client.txt"))), SCEN_DIRS[0])

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
            hint = ""
            if "Errno 99" in str(e) or "Cannot assign requested address" in str(e):
                # no free source port for the request: net.ipv4.ip_local_reserved_ports covers all of net.ipv4.ip_local_port_range
                hint = ("\n  This computer has no free port for an outgoing connection: the reserved ports (net.ipv4.ip_local_reserved_ports) cover "
                        "the range it takes them from. Undo the reservation and move the range above the media ports instead:\n"
                        "    sudo sysctl -w net.ipv4.ip_local_reserved_ports=\n    sudo sysctl -w net.ipv4.ip_local_port_range=\"61000 65535\"")
            raise SystemExit("%s (%s) does not answer: %s%s" % (self.label, self.url, e, hint))

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
        self.tester = {a.label: [] for a in apis}   # (busiest RTP reader %, SIP queue) from /status: the load of SIP Inspector itself
        self.active, self.cps = [], []
        self.stopped = threading.Event()

    def run(self):
        while not self.stopped.is_set():
            for a in self.apis:
                try:
                    code, s = a.call("GET", "/system", timeout=5)
                    if code == 200 and s.get("cpuLoad", -1) >= 0:
                        self.samples[a.label].append((s["cpuLoad"], s.get("processCpuLoad", -1), s.get("usedHeapMB", 0)))
                    if a is not self.caller:
                        code, st = a.call("GET", "/status", timeout=5)
                        if code == 200:
                            self.tester_sample(a.label, st)
                except SystemExit:
                    pass
            try:
                code, st = self.caller.call("GET", "/status", timeout=5)
                if code == 200:
                    self.tester_sample(self.caller.label, st)
                    self.active.append(st.get("callsActive") or 0)
                    if st.get("measuredCallsPerSecond") is not None:
                        self.cps.append(st["measuredCallsPerSecond"])
            except SystemExit:
                pass
            self.stopped.wait(self.period)

    def tester_sample(self, label, st):
        t = st.get("tester") or {}
        if t.get("rtpBusiestPercent") is not None or t.get("sipQueue") is not None:
            # the longest queue of one SIP thread (sipQueue alone with programs that have one SIP thread)
            # the RTP packets a second all its readers got since the previous sample: the streams that were really flowing at that moment
            pps = sum((rd.get("packetsPerSecond") or 0) for rd in (t.get("rtpReaders") or {}).values())
            self.tester[label].append((t.get("rtpBusiestPercent") or 0, t.get("sipQueueLongest") or t.get("sipQueue") or 0, pps))

    def summary(self, label):
        s = self.samples[label]
        if not s:
            return {}
        cpu = [x[0] * 100 for x in s]
        proc = [x[1] * 100 for x in s if x[1] >= 0]
        t = self.tester[label]
        return {"cpuAvg": round(sum(cpu) / len(cpu), 1), "cpuMax": round(max(cpu), 1),
                "procCpuAvg": round(sum(proc) / len(proc), 1) if proc else None, "heapMaxMB": max(x[2] for x in s),
                "rtpReaderMax": max(x[0] for x in t) if t else None, "sipQueueMax": max(x[1] for x in t) if t else None,
                "rtpPpsMax": max(x[2] for x in t) if t else None}


# --------------------------------------------------------------------------- the media ports

class PortProblem(Exception):
    """A step does not measure the computers: the RTP ports of the two sides meet, or a side could not open some of them."""

    def __init__(self, text, step=None):
        Exception.__init__(self, text)
        self.step = step


WILDCARD = ("0.0.0.0", "::", "0:0:0:0:0:0:0:0")


def same_address(sa, sb):
    """Whether the media sockets of both services bind the same address (they bind the -lip address of their service)."""
    a, b = sa.get("sipAddress"), sb.get("sipAddress")
    return a == b or (sa.get("host") == sb.get("host") and (a in WILDCARD or b in WILDCARD))


def media_ports(s, calls):
    """The RTP ports a run of `calls` calls takes: one a call, 2 apart, counted up from -lrtp (each run starts again there)"""
    base = int(s.get("mediaPort") or 0)
    return base, min(65535, base + 2 * (calls + MEDIA_PORT_MARGIN))


def ephemeral_range():
    """The ports this computer gives to outgoing connections (Linux net.ipv4.ip_local_port_range; 32768-60999 by default)."""
    try:
        with open("/proc/sys/net/ipv4/ip_local_port_range") as f:
            lo, hi = f.read().split()[:2]
            return int(lo), int(hi)
    except (OSError, ValueError):
        return 32768, 60999


EPHEMERAL = ephemeral_range()


def port_room(machines, calls):
    """Why a side cannot give a media port to each of `calls` calls (one a call, 2 apart, from its -lrtp up to 65535), or None."""
    short = []
    for label, s in machines.items():
        base = int(s.get("mediaPort") or 0)
        room = (65535 - base) // 2
        if room < calls + MEDIA_PORT_MARGIN:
            fit = 65535 - 2 * (calls + MEDIA_PORT_MARGIN)
            advice = ("start it with -lrtp %d or lower" % fit) if fit >= 1024 else "no -lrtp gives that many ports: split the calls over two instances"
            short.append("%s has %d media ports from -lrtp %d, %d calls need %d: %s" % (label, room, base, calls, calls + MEDIA_PORT_MARGIN, advice))
    return "; ".join(short) or None


def port_clash(machines, la, lb, calls):
    """Why the RTP ports of the two sides would meet in a step of `calls` calls with audio, or None."""
    sa, sb = machines[la], machines[lb]
    if not same_address(sa, sb):
        return None
    ranges = {la: media_ports(sa, calls), lb: media_ports(sb, calls)}
    problems = []
    (a_lo, a_hi), (b_lo, b_hi) = ranges[la], ranges[lb]
    if a_lo <= b_hi and b_lo <= a_hi:
        problems.append("the RTP ports of %s (%d-%d) and %s (%d-%d) meet" % (la, a_lo, a_hi, lb, b_lo, b_hi))
    for label, (lo, hi) in ranges.items():
        for other, s in ((la, sa), (lb, sb)):
            sip = int(s.get("sipPort") or 0)
            if lo <= sip <= hi:
                problems.append("the RTP ports of %s (%d-%d) take the SIP port %d of %s" % (label, lo, hi, sip, other))
    return "; ".join(problems) or None


def port_advice(machines, la, lb, calls):
    """The -lrtp (or -lip) that keeps the RTP ports of the two sides apart for `calls` calls."""
    low, high = sorted((la, lb), key=lambda l: int(machines[l].get("mediaPort") or 0))
    start = int(math.ceil((media_ports(machines[low], calls)[1] + 2) / 1000.0)) * 1000
    if media_ports({"mediaPort": start}, calls)[1] >= 32768:
        # side by side they reach the ports the system gives to other programs, or past 65535
        return "start %s with another address (for example -lip 127.0.0.2): %d calls do not fit side by side below port 32768" % (high, calls)
    return "start %s with -lrtp %d, or with another address (for example -lip 127.0.0.2)" % (high, start)


def calls_apart(machines, la, lb):
    """The most calls a step can have before the RTP ports of the two sides meet; None when they cannot meet."""
    if not same_address(machines[la], machines[lb]):
        return None
    lo, hi = 0, 32768
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if port_clash(machines, la, lb, mid):
            hi = mid - 1
        else:
            lo = mid
    return lo


# --------------------------------------------------------------------------- one step

def scenario_text(name, hold_ms):
    path = os.path.join(SCEN_DIR, name)
    if not os.path.isfile(path):
        raise SystemExit("The scenario %s is not in %s: start the script in the program folder of SIP Inspector, or keep the "
                         "scenarios folder next to it" % (name, " or ".join(SCEN_DIRS)))
    with open(path, encoding="utf-8") as f:
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
            "loss": num("rtp.lossPercent"), "jitter": num("rtp.jitterAvgMs"), "mos": num("rtp.mosAvg"), "mosMin": num("rtp.mosMin"),
            "portErrors": num("rtp.portErrors"), "portErrorPorts": str(m.get("rtp.portErrorPorts") or ""),  # one port comes as a number
            "noFreePort": num("rtp.noFreePort"),
            "sipDrops": num("local.sipDrops"), "rtpDrops": num("local.rtpDrops"),
            # messages sent again (;retrans) and copies answered: a step can pass only because lost SIP was sent again
            "retransmitted": num("sip.retransmitted"), "repeats": num("sip.repeatsReceived")}


# an RTP reader of SIP Inspector this busy (in %) means it, not the server under test, was the limit of the step
TESTER_BUSY_PERCENT = 95


def tester_overloaded(label, r, load):
    """Why SIP Inspector on this computer was the limit of a step (its own packet drops, an RTP reader at full load), or None."""
    why = []
    if r.get("sipDrops"):
        why.append("%s SIP messages lost" % r["sipDrops"])
    if r.get("rtpDrops"):
        why.append("%s RTP packets lost" % r["rtpDrops"])
    if (load.get("rtpReaderMax") or 0) >= TESTER_BUSY_PERCENT:
        why.append("an RTP reader at %s%%" % load["rtpReaderMax"])
    return "%s (%s)" % (label, ", ".join(why)) if why else None


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
        # Every call is held through the start of all the others (with a margin for a caller slower than asked), then for the
        # measuring time: the RTP of the first calls goes on while the last ones are made
        hold_ms = int((ramp_s * args.rtp_ramp_margin + args.rtp_measure_seconds) * 1000)
        max_conc = total
        caller_gate, answerer_gate = args.rtp_gate, args.rtp_answer_gate
        expected_s = ramp_s + hold_ms / 1000.0
    if kind == "rtp":
        room = port_room({caller.label: args.machines[caller.label], answerer.label: args.machines[answerer.label]}, total)
        if room:
            # a call without a port fails, and before it went on without audio, unseen by loss and MOS
            raise PortProblem("a step of %d calls with audio does not fit the media ports: %s" % (total, room))
        clash = port_clash(args.machines, caller.label, answerer.label, total)
        if clash:
            raise PortProblem("a step of %d calls with audio: %s, so one side would get the RTP of the other; %s"
                              % (total, clash, port_advice(args.machines, caller.label, answerer.label, total)))
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
    extra = {k: v for k, v in (("rtpThreads", args.rtp_threads), ("sipThreads", args.sip_threads)) if v}
    a_run = answerer.start(dict({"scenario": server_path, "gate": answerer_gate, "timeout": timeout + 120, "noChecks": args.no_checks}, **extra))
    time.sleep(1.0)
    mon.start()
    c_run = caller.start({"scenario": client_path, "remote": host.strip("[]"), "remotePort": int(port), "totalCalls": total, "cps": cps,
                          "maxConcurrent": max_conc, "timeout": timeout, "gate": caller_gate, "noChecks": args.no_checks, **extra})
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
    if kind == "rtp":
        # the calls were up together (maxActive below); here: their RTP really flowed. Calls up without audio (no media port, a stream that never
        # started) are not seen by loss and MOS, which count only the streams that came
        want_pps = total * RTP_PACKETS_PER_SECOND
        want_packets = total * max(0.0, hold_ms / 1000.0 - RTP_START_SECONDS) * RTP_PACKETS_PER_SECOND
        streams = {}
        for api, r, load in ((caller, c, step["callerLoad"]), (answerer, a, step["answererLoad"])):
            why = []
            if r.get("rtpCalls") is not None and r["rtpCalls"] < args.rtp_min_active * total:
                why.append("only %s of the %d calls received RTP" % (r["rtpCalls"], total))
            if r.get("packets") is not None and r["packets"] < RTP_MIN_PACKETS * want_packets:
                why.append("%s RTP packets came of about %d (%d calls x %.0f s x %d a second)"
                           % (r["packets"], want_packets, total, hold_ms / 1000.0 - RTP_START_SECONDS, RTP_PACKETS_PER_SECOND))
            pps = load.get("rtpPpsMax")
            if pps is not None:
                streams[api.label] = int(round(pps / float(RTP_PACKETS_PER_SECOND)))
                if pps < RTP_MIN_PACKETS * want_pps:
                    why.append("at most %d RTP packets a second came, %d streams at the same time of %d" % (pps, streams[api.label], total))
            if why:
                step["pass"] = False
                r["reasons"] = (r["reasons"] or []) + why
        step["rtpStreamsPeak"] = streams or None
    if kind == "rtp" and step["maxActive"] is not None and step["maxActive"] < args.rtp_min_active * total:
        # the first calls ended before the last ones started: the step never had its calls up together
        step["pass"] = False
        c["reasons"] = (c["reasons"] or []) + ["only %s of the %s calls were up at the same time" % (step["maxActive"], total)]
    over = [w for w in (tester_overloaded(caller.label, c, step["callerLoad"]), tester_overloaded(answerer.label, a, step["answererLoad"])) if w]
    # the step measured SIP Inspector, not the other computer: its failure is the limit of the tester
    step["testerOverloaded"] = "; ".join(over) if over else None
    for api, r in ((caller, c), (answerer, a)):
        if r.get("noFreePort"):
            # calls failed for want of a media port: the step measured the -lrtp, not the computers
            step["pass"] = False
            r["reasons"] = (r["reasons"] or []) + ["%s calls found no free media port (-lrtp %s)" % (r["noFreePort"], args.machines[api.label].get("mediaPort"))]
    held = [(api.label, r["portErrorPorts"]) for api, r in ((caller, c), (answerer, a)) if r.get("portErrors")]
    if held:
        # a call without its RTP port: the loss and MOS are not those of the computers
        step["pass"] = False
        step["portErrors"] = dict(held)
        for api, r in ((caller, c), (answerer, a)):
            if r.get("portErrors"):
                r["reasons"] = (r["reasons"] or []) + ["RTP ports in use by another program: %s" % r["portErrorPorts"]]
    tail = ("  streams %s" % "/".join(str(v) for v in step["rtpStreamsPeak"].values())) if step.get("rtpStreamsPeak") else ""
    tail += ("\n       tester overloaded: " + step["testerOverloaded"]) if step["testerOverloaded"] else ""
    if not step["pass"]:
        tail += "\n       " + "; ".join((c["reasons"] or []) + (a["reasons"] or []))[:400]
    print("  %-4s %s->%s %8s  %s  ASR %s%%  p95 %s ms  loss %s%%  MOS %s  active %s  CPU %s%%/%s%%  (%.0f s)%s" % (
        kind, caller.label, answerer.label, value, "PASS" if step["pass"] else "FAIL", c["asr"], c["p95"],
        c["loss"] if kind == "rtp" else "-", c["mos"] if kind == "rtp" else "-", step["maxActive"],
        step["callerLoad"].get("cpuMax", "?"), step["answererLoad"].get("cpuMax", "?"), step["seconds"], tail), flush=True)
    if held:
        several = len(held) > 1 or " " in held[0][1]
        raise PortProblem("; ".join("%s could not open the RTP %s %s" % (label, "ports" if several else "port", ports) for label, ports in held)
                          + ": another program holds %s, so the step does not measure the computers. Stop that program, or start "
                          "the service with another -lrtp (below 32768 keeps out of the ports the system gives to other programs)"
                          % ("them" if several else "it"), step)
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
        peak = b.get("rtpStreamsPeak") or {}
        streams = ("%d RTP streams each way at the peak, measured" % min(peak.values())) if peak else ("%s RTP streams each way" % b["value"])
        limit = ("%s calls/s" % b["value"]) if r["test"] == "cps" else ("%s calls (%s)" % (b["value"], streams))
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
    L.append("- Concurrent calls: caller `%s`, answerer `%s`; calls start at %s a second and each is held %s x the start-up time "
             "of the step, so all of them stay up together for at least %d s." % (
        config["rtpGate"], config["rtpAnswerGate"], config["rtpCps"], config["rtpRampMargin"], config["rtpMeasureSeconds"]))
    for k, v in METRIC_TEXT.items():
        L.append("- `%s`: %s" % (k, v))
    L.append("")
    L.append("A step passes when the runs on both computers keep their limits; it was run %d time(s). Every step is in steps.csv." % config["repeat"])
    L.append("")
    over = [s for s in steps if s.get("testerOverloaded")]
    if over:
        L.append("## Steps where SIP Inspector itself was the limit")
        L.append("")
        L.append("In these steps SIP Inspector lost packets on its own sockets or an RTP reader thread was at %d %% or more, so they measured "
                 "the tester, not the computer it called (more `--rtp-threads`, larger UDP buffers or a second instance raise it):" % TESTER_BUSY_PERCENT)
        L.append("")
        for s in over:
            L.append("- %s %s -> %s, %s: %s" % (s["test"], s["caller"], s["answerer"], s["value"], s["testerOverloaded"]))
        L.append("")
    if config.get("stopped"):
        L.append("**The test stopped before its end:** %s" % config["stopped"])
        L.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def write_csv(path, steps):
    cols = ["test", "caller", "answerer", "value", "pass", "cps", "totalCalls", "holdMs", "seconds", "maxActive", "measuredCps", "rtpStreamsPeak", "testerOverloaded"]
    met = ["result", "attempts", "answered", "asr", "p95", "packets", "loss", "jitter", "mos", "mosMin", "rtpCalls", "portErrors", "noFreePort", "sipDrops", "rtpDrops", "retransmitted", "repeats"]
    load = ["cpuAvg", "cpuMax", "procCpuAvg", "heapMaxMB", "rtpReaderMax", "sipQueueMax", "rtpPpsMax"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(cols + ["caller_" + m for m in met] + ["answerer_" + m for m in met] + ["caller_" + l for l in load] + ["answerer_" + l for l in load])
        for s in steps:
            w.writerow([s.get(c) for c in cols] + [s["callerResult"].get(m) for m in met] + [s["answererResult"].get(m) for m in met]
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
    ap.add_argument("--cps-steps", default=CPS_STEPS, help="call rates to try, calls a second (default CPS_STEPS at the top of this file)")
    ap.add_argument("--cps-seconds", type=int, default=60, help="how long each call rate step makes calls (default 60)")
    ap.add_argument("--cps-hold-ms", type=int, default=1000, help="how long a call of the call rate test lasts (default 1000 ms)")
    ap.add_argument("--cps-gate", default="asr>=99.5,p95<=500")
    ap.add_argument("--cps-answer-gate", default="asr>=99.5")
    ap.add_argument("--rtp-steps", default=RTP_STEPS, help="numbers of calls at the same time to try (default RTP_STEPS)")
    ap.add_argument("--rtp-cps", type=float, default=RTP_START_CPS, help="rate the calls of an RTP step start at (default %(default)s a second)")
    ap.add_argument("--rtp-measure-seconds", type=int, default=RTP_MEASURE_SECONDS,
                    help="how long all calls of an RTP step are up together (default %(default)s)")
    ap.add_argument("--rtp-ramp-margin", type=float, default=RTP_RAMP_MARGIN,
                    help="hold of a call = this x the start-up time of the step + the measuring time (default %(default)s)")
    ap.add_argument("--rtp-min-active", type=float, default=RTP_MIN_ACTIVE,
                    help="share of the calls of an RTP step that must be up at the same time (default %(default)s)")
    ap.add_argument("--rtp-gate", default="asr>=99,loss<=0.5,mos>=4.0")
    ap.add_argument("--rtp-answer-gate", default="asr>=99,loss<=0.5,mos>=4.0")
    ap.add_argument("--repeat", type=int, default=1, help="runs of each step; all must pass (default 1; 3 for the published numbers)")
    ap.add_argument("--refine", type=int, default=3, help="steps that narrow the limit down after the first failure (default 3)")
    ap.add_argument("--sip-threads", type=int, help="threads that handle SIP in both services (-sipThreads; default: a quarter of the cores of each)")
    ap.add_argument("--rtp-threads", type=int, help="threads that read RTP in both services (-rtpThreads; default: half the cores of each)")
    ap.add_argument("--checks", action="store_true",
                    help="check the SIP/SDP of every message as the program does by default; off here (-noChecks), so a step measures the computers, not the checker")
    ap.add_argument("--no-checks", action="store_true", help="the default: the SIP/SDP of the messages is not checked (-noChecks)")
    ap.add_argument("--no-warmup", action="store_true", help="do not make the short uncounted warm-up runs first")
    ap.add_argument("--grace", type=float, default=5, help="seconds after the caller ended before the answerer is stopped (default 5)")
    ap.add_argument("--sample", type=float, default=2, help="seconds between CPU samples (default 2)")
    ap.add_argument("--network", default="1 Gbit/s Ethernet", help="the network, for the summary")
    ap.add_argument("--out", help="folder for the results (default capacity_<date>)")
    args = ap.parse_args()
    # a load test does not check every message (the checks were a large part of the work of each SIP message)
    args.no_checks = not args.checks

    a = Api(args.a_name, args.a, args.a_token or args.token)
    b = Api(args.b_name, args.b, args.b_token or args.token)
    args.sip = {a.label: args.a_sip, b.label: args.b_sip}
    machines = {a.label: a.get("/system"), b.label: b.get("/system")}
    for label, s in machines.items():
        print("%s: %s, %s, %s cores, %.1f GB, %s, SIP %s:%s" % (label, s.get("host"), s.get("cpu"), s.get("cores"), s.get("memoryMB", 0) / 1024.0,
                                                              s.get("os"), s.get("sipAddress"), s.get("sipPort")))
    args.machines = machines
    # a log above ERROR writes lines for every SIP message (VERBOSE about 27 a call): the step then measures the log as well
    for label, s in machines.items():
        level = s.get("logLevel")
        if level is None:
            print("Warning: %s does not report its log level (an older SIP Inspector): start it with -d ERROR" % label)
        elif level not in ("ERROR", "OFF"):
            print("Warning: %s logs at %s, so writing SIPInspector.log takes part of every call and the limits come out lower. "
                  "Start the service with -d ERROR (without -d it takes the level the GUI saved last)" % (label, level))
    tests = ["cps", "rtp"] if args.test == "both" else [args.test]
    if "rtp" in tests:
        # before any step: a clash at the first RTP step would otherwise show only after the whole call rate test
        first = min(numbers(args.rtp_steps) + ([] if args.no_warmup else [20]))
        clash = port_clash(machines, a.label, b.label, first)
        if clash:
            print("\nNot started: %s, so one side would get the RTP of the other; %s" % (clash, port_advice(machines, a.label, b.label, first)))
            return 2
        apart = calls_apart(machines, a.label, b.label)
        if apart is not None:
            print("%s and %s use the same address %s: their RTP ports stay apart up to %d calls with audio a step"
                  % (a.label, b.label, machines[a.label].get("sipAddress"), apart))
    for label, s in machines.items():
        lo, hi = media_ports(s, max(numbers(args.rtp_steps)) if "rtp" in tests else 0)
        if "rtp" in tests and lo <= EPHEMERAL[1] and hi >= EPHEMERAL[0]:
            # another program may hold one of them at any time, which stops the test (rtp.portErrors)
            # moving the system's range above the media ports keeps them free; reserving them instead leaves outgoing connections (this script's
            # requests to the API) without a source port when the reservation covers the whole range
            print("%s: its media ports (%d-%d for the largest step) reach the ports the system gives to outgoing connections (%d-%d); start the "
                  "service with a lower -lrtp, or move that range above them for the test with:\n"
                  "    sudo sysctl -w net.ipv4.ip_local_port_range=\"%d 65535\"" % (label, lo, hi, EPHEMERAL[0], EPHEMERAL[1], min(hi + 2, 65000)))
    out = args.out or "capacity_" + datetime.datetime.now().strftime("%Y%m%d_%H%M")
    os.makedirs(out, exist_ok=True)
    config = {"date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), "network": args.network, "transport": machines[a.label].get("transport"),
              "cpsGate": args.cps_gate, "cpsAnswerGate": args.cps_answer_gate, "cpsSeconds": args.cps_seconds, "cpsHoldMs": args.cps_hold_ms,
              "rtpGate": args.rtp_gate, "rtpAnswerGate": args.rtp_answer_gate, "rtpCps": args.rtp_cps, "rtpMeasureSeconds": args.rtp_measure_seconds, "rtpRampMargin": args.rtp_ramp_margin,
              "repeat": args.repeat, "refine": args.refine, "noChecks": args.no_checks, "rtpThreads": args.rtp_threads, "sipThreads": args.sip_threads}
    pairs = {"ab": [(a, b)], "ba": [(b, a)], "both": [(a, b), (b, a)]}[args.roles]
    steps, results = [], []

    def save():
        with open(os.path.join(out, "results.json"), "w", encoding="utf-8") as f:
            json.dump({"config": config, "machines": machines, "results": results, "steps": steps}, f, indent=2)
        write_csv(os.path.join(out, "steps.csv"), steps)
        write_summary(os.path.join(out, "summary.md"), machines, config, results, steps)

    try:
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
    except PortProblem as e:
        if e.step is not None:
            steps.append(e.step)
        config["stopped"] = str(e)
        save()
        print("\nStopped: %s\nResults so far: %s" % (e, os.path.abspath(out)))
        return 2
    save()
    print("\nResults: %s" % os.path.abspath(out))
    with open(os.path.join(out, "summary.md"), encoding="utf-8") as f:
        print(f.read())
    return 0


if __name__ == "__main__":
    sys.exit(main())
