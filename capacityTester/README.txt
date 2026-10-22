Tests
=====

This directory has three scripts and the Java code behind one of them:

  run.sh               unit tests of the program code (a few seconds to a minute)
  scenario_test.py     runs scenario files against each other (a minute to hours,
                       depending on how many calls you ask for)
  capacity.py          measures what two computers can do: calls a second and calls with
                       audio at the same time (see 3. below)
  sipinspector/        the Java test classes that run.sh compiles and runs

Run both from the root of the repository (the directory that has src/, lib/ and scenarios/).
You need a JDK (javac and java on the PATH, or JAVA_HOME set). scenario_test.py also needs
Python 3.6 or newer; it uses only the standard library.


1. run.sh - unit tests
----------------------

    test/run.sh            run all the unit tests
    test/run.sh bench      run only the replaceKeyWords benchmark

It compiles src/ and test/ into a temporary directory (nothing is left behind, and
SIPInspector.log is not written into the source tree), then runs the tests one after the
other. Every check prints PASS or FAIL, each test ends with ALL CHECKS PASSED or the number
of failed checks, and the exit code is not 0 if anything failed.

The tests (all in test/sipinspector/):

  MultiClientRtpTest        Sending RTP to several remote clients: each client's SSRC and
                            ports, clients on hold, one client failing without stopping the
                            others, DTMF to its own call only, port allocation, and outgoing SRTP
                            checked against an independent implementation of RFC 3711; received
                            SRTP speech played decrypted, and dropped if it fails its check.

  LiveSpeechTest            Live speech, with a fake microphone and no network: the RTP
                            timestamps around a DTMF digit, whole PCMU and G.729 packets one
                            every 20 ms, no old speech reaching the next call after a time with
                            no call, the G.729 input buffer with blocks that arrive in parts,
                            calls with different codecs at the same time (each gets its own
                            codec, also after a codec change), and opening the sound lines
                            without throwing.

  AudioPlaybackTest         Playing received speech, with a fake speaker that blocks like a
                            real one: the network thread never waits, one call is played at a
                            time and the next once it has gone quiet, the speaker at most
                            100 ms ahead, no DTMF or comfort noise, repeated and late packets,
                            header extensions and padding, G.729 packets of any length and
                            with a silence frame, and a codec change.

  DialDigitsTest            Dialling digits (cmd_DialDigits, RFC 4733): the packets of a key
                            press, digits going to their own call only over a pcap, live speech
                            or the digits-only thread, the header and payload type of a DTMF
                            packet in place of a pcap packet, the digit senders ending, the
                            check of the entry when a scenario is loaded, and which thread
                            sends the digits of a call.

  CallDBMediaTest           The call an incoming RTP packet belongs to, found by its source
                            address: each call its own RTP, an ended call and a reused port,
                            media moved by a re-INVITE, and 250,000 lookups among 5000 calls
                            in well under a second (it was a search of all calls per packet).

  SipThreadsTest            SIP handled by several threads (-sipThreads): the messages of a
                            call go to one thread in the order they came, also under a further
                            Call-ID of the call; the calls are spread over the threads; one
                            thread without the Call-ID check.

  MediaPortErrorTest        A media port that another program holds: reported once a run
                            (rtp.portErrors and its ports in the run report, a reason of the
                            result), not tried again for every packet, tried again when the port
                            is free for a new call, and the channels that failed are closed.

  MediaReadersTest          The RTP of the calls read by several threads apart from SIP
                            (-rtpThreads): each media port goes to one reader, every packet is
                            read, the load of each reader; the rows of /proc/net/udp, and the
                            packets SIP Inspector loses on its own sockets counted
                            (local.sipDrops) with a result that says the tester was overloaded.

  RetransmissionTest        ;retrans on a message: read and written on both arrows, the
                            ;ReTxCnt=N of the earlier format read as ;retrans (dropped where
                            RFC 3261 never sends the message again), the timers A, E and G
                            with T1 and T2 (when a copy is due, what stops it, when it gives
                            up), copies of received messages answered as before, and the
                            validator on a ;retrans that has no effect.

  NoFreePortTest            More calls than media ports from -lrtp: the call that finds none
                            fails with that reason instead of offering port -1 in its SDP,
                            rtp.noFreePort counts it and the run fails with it.

  PauseTimingTest           A pause lasts as long as the scenario says also when a pass of the
                            pause thread over the calls is long (many calls up): it counts the
                            time that passed, not only its sleep.

  ReplaceKeyWordsTest       The current SIPCall.replaceKeyWords gives exactly the same result
                            as the original implementation, on hand-written cases and about
                            600,000 random messages (both IPv4 and IPv6 settings).

  ScenarioCommentsTest      Every file in scenarios/ is loaded, saved and loaded again the way
                            the GUI does it, and no "//" comment line may be lost or moved.
                            Also tests editing an entry and deleting the first entry.

  H264VideoTest             The H.264 video support, without a window, a network or a camera:
                            the RFC 6184 depacketizer (single NAL units, STAP-A, FU-A; lost,
                            reordered and repeated packets, sequence number wrap, a stream that
                            starts again, a stray packet from another source), the JCodec decoder
                            (the pictures are compared with the originals), the receiving thread,
                            the SDP (fmtp with a '/' in it), the keyword [video_port] in a call,
                            the waitVideo entry, the Video pane, and the pcap file of the test
                            video. Video from an MP4 file: the file is read (frames, timing,
                            SPS/PPS, the SDP parameters), files that are not a video, cut off,
                            empty or missing are refused, and the sender thread is run with two
                            clients (own SSRC and numbering for each, the payload type of the
                            client's SDP, the clip going round, a client on hold). The test
                            video is made by SyntheticVideo.java, VideoPcapGenerator.java and
                            VideoMp4Generator.java (see "Test video" below).

  SerialNumberValidatorTest The serial number calculation gives the serial that the SISNGen
                            mobile app makes for the same Machine-ID, and the 7.x magic cookie
                            in CustomMessages decodes to the right text.

  MachineIDStabilityTest    The Machine-ID calculation keeps its original fingerprint when a
                            previously recorded adapter remains, regardless of adapter order;
                            learns new adapters, rebinds when all old adapters disappear, and
                            preserves the saved binding when no usable NIC values are available.

  SecurityToolsTest         Security key input validation and PEM output, rejection of a
                            mismatched certificate/private key, valid truststore import, and
                            preservation of a corrupt existing truststore. Uses keytool to
                            create a temporary certificate fixture.

  TraceConvertTest          Tools / Trace to Scenario. Synthetic captures (pcap in both byte orders, with
                            microsecond and nanosecond time stamps, pcapng in both byte orders; Ethernet,
                            VLAN, IPv4, IPv6, UDP, TCP in pieces that arrive out of order or twice, retransmitted
                            messages) are read, the endpoint is chosen by MAC address, and the scenario is
                            checked: send or receive, the keywords instead of addresses, ports, tags, Call-ID,
                            branch, CSeq and media port, authentication, CANCEL, new dialogs, pauses (exact timing, a threshold, none, and
                            a decision for each message), the RTP
                            pcap file (read back with the program's own pcap reader). Finally the scenario is
                            run through the real keyword engine of the program and the messages it gives must be
                            the captured ones. Also: the order of the messages (by dialog, as captured), a NOTIFY
                            before or after the response to its SUBSCRIBE, CSeq, and the command line conversion
                            (-pcap2scen: the options, the files it writes, the exit codes, and the real program
                            started as a subprocess), the last ones with the real program playing the scenarios
                            against itself.

  SdpParserTest             An SDP with a media section that is not audio or video (text, application) still
                            gives the audio destination.

  CommandTabTest            The Command tab (headless): Pause, Wait RTP, Wait video and Set variable add the right
                            entries, only the fields of the selected command can be edited, wrong input is refused,
                            the tab is not bigger than the others; and a play pcap entry keeps video=true when it
                            is saved and read again (duration=N before it used to hide it).

  AssertMetricsTest         Assertions (status, responseTime, header, body, rtp): what is accepted and refused,
                            and what passes and fails on real messages; the RTP quality numbers (loss with the
                            16-bit wrap, an SSRC change and a pcap that loops, jitter, MOS); ASR, ACD and final
                            responses; the JUnit, CSV, HTML and console reports. No network.

  AssertReportE2ETest       The real program calls itself (Reg_call_client with assertions against
                            Reg_call_server, RTP both ways) and writes the three reports: once with assertions
                            that hold (exit 0, RTP counted), once with one that cannot (exit 1, the failure in
                            the reports), and with a CI gate: one that holds although an assertion fails (exit 0),
                            one that does not (exit 1) and one with a typing mistake (exit 2).

  ApiE2ETest                The control API (-api) on a real run (Reg_client against Reg_server, no end of its
                            own): no token or a wrong one is refused, the status and the numbers are live, a new
                            rate holds from then on (0 makes no calls), the reports in every format, POST /stop
                            ends the run with its reports, -apiKeep keeps the result readable; with a gate a
                            stopped run passes on its numbers; a wrong API option is exit code 2.

  ApiServiceE2ETest         The service (-api without -fs): two instances wait, one to answer and one to call, and
                            every run is started with POST /run. Wrong runs are refused (no scenario, a file outside
                            the program folder, an unknown name, a value that is not a number), one run at a time,
                            each run has its own result and reports (GET /runs, ?run=N), the next run starts from
                            the command line settings again, POST /stop ends a run, a scenario that cannot be loaded
                            fails that run only, POST /shutdown ends the program with exit code 0. The control
                            page: GET /ui, /ui.js and /ui.css come without a token and with their security
                            headers, HEAD works, POST is refused, a path next to them still needs the token.
                            The scenario files: GET /scenarios lists the scenarios folder only, POST /scenarios
                            keeps a sent file in scenarios/uploads and refuses a name with a folder, a file that
                            is not .txt, empty or binary, and a request without the token; a run of the sent
                            file passes.

  MessageChecksTest         The SIP/SDP checks of the messages: SIP (start line, required headers, tags, branch,
                            CSeq, Content-Length, Contact), SDP (v o s t c m lines, the order, a=rtpmap, SRTP keys)
                            and offer/answer (a codec the offer did not have, the number of m= lines, directions, a
                            late offer answered in the ACK); a run counts a problem by kind; -noChecks. The call
                            flow of a dialog (columns, text, HTML ladder, the first problem kept, at most 200
                            lines) and the masking of the diagnostics bundle.

  DiagnosticsE2ETest        A server answers with a codec the client did not offer: the checks find it (console,
                            JSON, HTML), a gate problems==0 fails the run, the reports have the call flow, -diag
                            writes the bundle with the password masked, -noChecks turns the checks off, -diag alone
                            and GET /diag of the API give a bundle too.

  NamedColumnsTest          Values files with named columns ([field:user]): a #columns: line, the first line of a
                            .csv file (commas, quoted values with commas, quotes and line breaks, counting values),
                            the columns attribute of XML; a misspelt name of the scenario is found before the calls;
                            the keyword engine of a call gives the values.

  RunGateTest               The CI gate (-gate): what it accepts and refuses, its limits against the numbers of a
                            run (a number that was not measured fails), and the result in the console, JUnit, CSV,
                            HTML and JSON reports with and without a gate.

  ReplaceKeyWordsBenchmark  (only with "bench") speed of the original replaceKeyWords
                            against the current one on five typical messages. Prints
                            nanoseconds per call and the speed-up. KeywordSupport.java holds
                            the copy of the original method: do not change it, it is the
                            baseline for both the benchmark and ReplaceKeyWordsTest.


Test video
----------

pcap/video_h264.pcap is a synthetic test video: a moving white square on a gradient, with a
strip of bars that counts the frames in binary, 320x240, 10 frames per second, 8 seconds, an
IDR frame every 2 seconds and P frames in between (Baseline profile, level 4.0). It is
encoded with the JCodec H.264 encoder and cut into RTP packets as RFC 6184 describes (payload
type 96, SPS and PPS in a STAP-A packet before every IDR frame, FU-A fragments of 1200 bytes).
No camera, FFmpeg or other tool is needed to make it again:

    test/make_video_pcap.sh                              the file as it is in pcap/
    test/make_video_pcap.sh FILE [W H FPS SECONDS KEY]   another file or another video

The file has the same content every time. Scenarios play it with
cmd_PlayPcap=./pcap/video_h264.pcap;video=true (see Call_video_server / Call_video_client).

pcap/video_h264.mp4 is the same picture as an MP4 file (H.264, 320x240, 10 fps, 8 seconds), made
with the MP4 writer of JCodec:

    test/make_video_mp4.sh                          the file as it is in pcap/
    test/make_video_mp4.sh FILE [W H FPS SECONDS]   another file or another video

The picture is the same every time; the header of an MP4 file holds the time it was made, so a
new file differs from the old one in a few bytes.

To send a video of your own, put an MP4 (or MOV) file with H.264 video in pcap/ and run

    test/mp4_info.sh pcap/clip.mp4

It says what the program will send (size, frames per second, length, key frames) and prints the
video lines for the SDP of the scenario, with the profile-level-id and sprop-parameter-sets of
that file. Files with another video codec, without a key frame, cut off, or bigger than 200 MB
are refused. The audio track of the file is ignored.
It tests the program's own sending and receiving of H.264, it is not a recording of a
real camera: a real stream (High profile, 720p and bigger, many reference frames) may decode
slower or not at all with the Java decoder.


2. scenario_test.py - scenario files against each other
-------------------------------------------------------

A scenario file is one side of a SIP conversation. This script takes a server scenario and
the client scenario that talks to it (a "pair"), starts SIP Inspector in CLI mode once as
the server and once or more as clients, lets the clients make calls, and reports PASS or
FAIL for each pair. Everything runs on the loopback interface of one machine.

The pairs are listed in test/pairs.txt (see test/scenarios.txt for what each pair
does and which scenario files have no partner).

Basic use:

    test/scenario_test.py --list                      list the pairs
    test/scenario_test.py                             run every pair, 1 call each
    test/scenario_test.py Reg PRACK                   only pairs whose name contains Reg or PRACK
    test/scenario_test.py --help                      all options

Choosing how many times a pair runs:

    test/scenario_test.py -n 1000 -c 50               every pair: 1000 calls, 50 at a time
    test/scenario_test.py Reg=1000 PRACK=50           a different number for each pair
    test/scenario_test.py Reg=1000:50 PRACK=50:5      ... and how many run at the same time
    test/scenario_test.py --clients 2 -n 1000         two client instances, 1000 calls each

Calls are per client, from 1 to 10000. PAIR=N needs the exact pair name from --list. The
number for a pair is taken from, in this order: PAIR=N on the command line, -n / -c, the
"calls:N" / "concurrent:N" notes of the pair in test/pairs.txt, and finally 1.

Making big runs finish in reasonable time:

    --cps N         calls started per second, per client (default 10, so 1000 calls take at
                    least 100 seconds - raise it for big runs)
    --pause-ms N    cap every cmd_Pause and every cmd_PlayPcap duration to N milliseconds.
                    This is done in temporary copies; the scenario files are not changed.
                    Without it a call lasts as long as the scenario says (some pause 15 s).
    --allow-unexpected N
                    accept up to N unexpected messages per instance. With heavy load an
                    occasional repeated UDP response is normal; the default is 0.

A typical big run:

    test/scenario_test.py --clients 2 -n 1000 -c 50 --cps 200 --pause-ms 100 --allow-unexpected 5

Other options:

    --with-audio    also run pairs marked "audio" (they need a sound device)
    --transport     UDP (default), TCP, TLS, WS or WSS. With TLS and WSS the run first
                    makes a self-signed certificate for the server with SIP Inspector
                    itself (-genCrt) and imports it into the clients' truststore
                    (-addTCA); every instance gets a copy (security/ in its working
                    directory)
    --mtls          with --transport TLS or WSS: the clients get a certificate too, the
                    server imports it and checks it (-cTLS)
    --ipv6          run over IPv6: the server and every client on ::1, with -ip v6. The
                    clients share ::1 (on their own ports) and are kept apart by their
                    Call-ID prefix, so --clients works too
    --sip-log       also write each instance's SIP message log
    --keep          keep the working directories even when everything passed
    --workdir DIR   put the working directories in DIR instead of a temporary directory
    -v              show every problem found, not just the first four per pair
    --timeout N     seconds a pair may take (default: estimated from the scenario and the
                    numbers above; a pair that is stuck is stopped and reported as a failure)
    --classes DIR   use already compiled classes instead of compiling src/ (saves ~10 s)
    --jar FILE      use a SIP Inspector jar instead of compiling (lib/*.jar is added)
    --port-base N   add N to every port, to run two copies of this script at the same time
    --startup N     seconds the server gets before the clients start (default 3); over
                    TCP, TLS, WS and WSS the clients also wait until it listens
    --shared-prefs  use the preferences the GUI saved instead of isolated ones (see below)

What happens for each pair:

  1. A working directory is made with a copy of both scenarios (and links to pcap/ and
     values), one directory for the server and one for each client.
  2. The server starts (127.0.0.1, SIP port 5070 + --port-base). Each client then starts on
     its own loopback address (127.0.0.1, 127.0.0.2, ...) so that two clients never use the
     same address (with --ipv6 all of them are on ::1). The program identifies a call by
     the part of the Call-ID before the "@" and numbers its calls the same way in every
     instance, so the Call-IDs the scenarios make from [call_number] get a prefix: s- in
     the server (a dialog the server starts must not take the Call-ID of a call of a
     client) and, when there is more than one client, c1-, c2- in the clients. A Call-ID
     copied from the other side ([$cid]) is left as it is.
  3. The clients make their calls (-tc, -mc and -cps of the program).
  4. When all clients have finished, the script waits a little (longer when the server
     scenario has pauses of its own), then stops the server with SIGTERM. The program then
     prints its summary and writes its scenario results file.
  5. Both sides are judged from what they report:

       client   ends with SUCCESS; no unexpected messages; every mandatory entry of the
                scenario reached at least once per call (entries on branches that
                were not taken are ignored when the scenario has conditions or gotos,
                and then only the end result counts)
       server   no unexpected messages; every mandatory entry reached at least once

Reading the result:

    running Reg          40 call(s),  10 at a time ... PASS  (6.8s)
    running Reg_auth_call_advanced ...   FAIL
          - [client1] client ended with TERMINATED
          - server entry '<--- BYE' reached 0 time(s), expected at least 1

  PASS     the pair works
  FAIL     the lines below it say why. TERMINATED means a client did not finish in time;
           "reached 0 time(s)" shows where a call got stuck; "unexpected" shows a message
           that arrived when the scenario did not expect it.
  XFAIL    a known problem listed in pairs.txt (xfail:reason). It does not count as a
           failure. When it starts to work the result is XPASS, and the note can be removed.
  SKIP     the pair needs a sound device (use --with-audio)

At the end there is a table with the number of calls and the seconds per pair, then
"N passed, N failed ...". The exit code is 1 if any pair failed, otherwise 0.

When something fails, the script prints the path of the working directory (or use --keep).
In it, for each of server, client1, client2:

    stdout.txt          what the program printed
    Logs/<scenario>_*.log   the scenario results file (entries, how often each was
                        reached, unexpected messages) - this is what the verdict is made of
    SIPInspector.log    the program's own log
    Logs/*.log          with --sip-log, the SIP messages

Adding a pair or changing one: edit test/pairs.txt. One line per pair:

    name   server-scenario-file   client-scenario-file   [notes]

Notes are separated by commas: audio, xfail:some_reason_with_underscores, calls:N,
concurrent:N. Lines starting with # are comments.

Things to know:

  - Linux. Each extra client needs its own loopback address (127.0.0.2, 127.0.0.3, ...);
    Linux has the whole 127.0.0.0/8 range, macOS does not by default. One client works
    everywhere that has a shell.
  - The program needs a license. The script runs it with isolated preferences, so it takes
    your .licence file from the repository root (or the current directory, or your home
    directory) and copies it into each working directory. If the program reports that it is
    not registered, put your .licence file in the repository root, or use --shared-prefs.
  - Ports used: 5070 (server), 5100 and up (clients), RTP from 7000 (server) and 8000 and
    up (clients), all plus --port-base. Nothing else may be using them.
  - A pair that needs RTP speech, dialled digits or a sound device is marked "audio".
    Without a sound device such a call can hang.
  - Run it again after changing the code: it compiles src/ every time (unless --classes or
    --jar is given), so it always tests the current source.


3. capacity.py - what two computers can do
------------------------------------------

Measures, between two computers that both run SIP Inspector:

  - calls a second: short calls without media (scenarios Perf_cps_client/server), the rate
    raised step by step until a step fails its limits
  - calls with audio at the same time: calls with G.711 (PCMU, 20 ms) both ways from
    pcap/test.pcap (Perf_rtp_client/server), the number of calls raised step by step until a
    step fails its limits. Each call is two RTP streams, one each way.

Both computers run SIP Inspector as an API service; the script drives them over HTTP, so a
computer needs no source code, only the program, its license and pcap/test.pcap. The
script sends the scenarios itself (POST /scenarios). It runs on either computer or a third
one and needs only Python 3.6+.

Without the source: the folder capacityTester of https://github.com/zcoklin/SIPInspector
has capacity.py, this README and the Perf scenarios. Keep the scenarios folder next to
capacity.py, or start the script in the program folder of SIP Inspector, whose
scenarios folder has them too. The commands below call it test/capacity.py: give the path
where you keep it.

1. On each computer, in the program folder, start the service. It keeps running until you
   press Ctrl+C.

   Linux and macOS (the program folder of the Linux/other OS package):

       ./SIPInspDlx -api 8080 -apiHost 0.0.0.0 -apiToken <token> -lip <its address> \
                    -lp 5060 -lrtp 10000 -np -d ERROR

   Windows (Command Prompt, in the program folder; all on one line):

       SIPInspDlxCLI.exe -api 8080 -apiHost 0.0.0.0 -apiToken <token> -lip <its address> -lp 5060 -lrtp 10000 -np -d ERROR

   -apiHost 0.0.0.0 opens the API to the network: use a long token, and a firewall that
   lets the other computer reach port 8080 (API), 5060 (SIP) and 10000 and up (RTP). On
   Windows allow Java (or SIPInspDlxCLI.exe) through Windows Defender Firewall when it asks,
   for private networks.

   -d ERROR keeps the log out of the measurement. Without -d a service takes the debugging
   level the GUI saved last (every copy of the program folder shares it), and at VERBOSE it
   writes about 27 lines of SIPInspector.log for every call, so the limits come out lower.
   GET /system gives the level a service runs at (logLevel), capacity.py warns when it is
   above ERROR, and the first line of SIPInspector.log says it too (log level=...).

2. Then, on any computer that reaches both services:

   Linux and macOS:

       python3 test/capacity.py --a http://<A>:8080 --b http://<B>:8080 --token <token> \
                                --a-name Laptop --b-name Workstation --repeat 3

   Windows (Command Prompt, all on one line; py is the Python launcher, python works too):

       py test\capacity.py --a http://<A>:8080 --b http://<B>:8080 --token <token> --a-name Laptop --b-name Workstation --repeat 3

   In PowerShell the line is the same; to split a long line end it with ` (backtick) in
   PowerShell or ^ in the Command Prompt, where Linux uses \.

   A calls B and B calls A (--roles), first the call rate test, then the RTP test (--test).
   GET /system of each service gives the computer (CPU, cores, memory, OS, Java) and its CPU
   load, which is sampled every two seconds of every step.

   On a single computer
   - - - - - - - - - - -

   A and B can be two services on the same computer, to try the script out or to see what
   one computer does when it is both caller and answerer. They talk over the loopback, so no
   firewall and no network are involved. Each service needs its own SIP address, its own API
   port and its own copy of the program folder (each writes SIPInspector.log and
   scenarios/uploads/ in the folder it runs in). A takes SIP 127.0.0.1:5060 and API 8080,
   B takes SIP 127.0.0.2:5070 and API 8081; with an address each, both use -lrtp 10000 and
   their RTP ports never meet:

   Linux and macOS, two terminals:

       cp -r SIPInspector SIPInspector_B                (once: the second program folder)

       cd SIPInspector
       ./SIPInspDlx -api 8080 -apiToken <token> -lip 127.0.0.1 -lp 5060 -lrtp 10000 -np -d ERROR

       cd SIPInspector_B
       ./SIPInspDlx -api 8081 -apiToken <token> -lip 127.0.0.2 -lp 5070 -lrtp 10000 -np -d ERROR

   and a third one (both APIs are on 127.0.0.1, whatever -lip says):

       python3 test/capacity.py --a http://127.0.0.1:8080 --b http://127.0.0.1:8081 \
                                --token <token> --a-name A --b-name B --roles ab

   Windows, two Command Prompt windows:

       xcopy /e /i SIPInspector SIPInspector_B          (once: the second program folder)

       cd SIPInspector
       SIPInspDlxCLI.exe -api 8080 -apiToken <token> -lip 127.0.0.1 -lp 5060 -lrtp 10000 -np -d ERROR

       cd SIPInspector_B
       SIPInspDlxCLI.exe -api 8081 -apiToken <token> -lip 127.0.0.2 -lp 5070 -lrtp 10000 -np -d ERROR

   and a third one:

       py test\capacity.py --a http://127.0.0.1:8080 --b http://127.0.0.1:8081 --token <token> --a-name A --b-name B --roles ab

   The script calls each side at the SIP address and port its service was started with
   (-lip and -lp, from GET /system), so A calls 127.0.0.2:5070 and B calls 127.0.0.1:5060.
   Without -apiHost the API listens on 127.0.0.1 only, which is all a single computer needs.
   Linux and Windows answer on every 127.x.x.x address.

   macOS: its loopback has only 127.0.0.1. Add 127.0.0.2 before B starts, and check it:

       sudo ifconfig lo0 alias 127.0.0.2 up
       ifconfig lo0                     (lists inet 127.0.0.2)

   The address is gone after every restart of the Mac: add it again then. A service started
   before the address was there could not open its SIP port on it, and the INVITEs of A
   reach nothing: start B again. When B listens, lsof -nP -iUDP:5070 shows java on
   127.0.0.2:5070.

   Both on one address (-lip 127.0.0.1 for both, B on -lp 5070) works too, but then the RTP
   ports must be far apart: a call takes two ports from -lrtp up, so A on -lrtp 10000 and B
   on -lrtp 20000 stay apart up to about 5000 calls with audio a step. The script checks
   that before every step and stops, with the -lrtp to use, when they would meet: then one
   side gets the RTP of the other and the loss and MOS are wrong (the same -lrtp for both
   makes every step wrong). Keep the RTP ports below 32768: from there up (49152 on
   Windows and macOS) the system gives ports to other programs, and a media port another
   program holds is counted by the service (rtp.portErrors in the report) and stops the
   test too.

   --roles ab is enough: on one computer B calling A measures the same thing again. Both
   services share the CPU, so the limits are lower than between two computers, and the CPU
   columns show the load of the one computer twice. For a quick try
   make the steps fewer and shorter, for example:

       --test cps --cps-steps 10,50,100 --cps-seconds 10 --no-warmup

3. The results are in capacity_<date>/:
       summary.md     the computers, the limit reached in each test and role, and the
                      limits used: the tables for the documentation
       steps.csv      every step: rates, calls at a time, ASR, p95, loss, jitter, MOS and
                      the CPU load of both computers
       results.json   all of it, with the full reports

What the limits (the gate) mean:

  asr>=99.5      answer-seizure ratio: of the calls attempted, at least 99.5 % answered
  p95<=500       95 % of the SIP requests got their response within 500 ms
  loss<=0.5      at most 0.5 % of the RTP packets expected did not arrive
  mos>=4.0       the estimated voice quality (MOS, 1 to 4.5, from loss and jitter) is at
                 least 4.0; G.711 without loss is 4.4

A step passes when the runs on both computers keep their limits (the caller checks the
answers and the audio it gets, the answerer the audio it gets). Change them with
--cps-gate, --cps-answer-gate, --rtp-gate and --rtp-answer-gate; the steps with
--cps-steps and --rtp-steps; --help lists the rest.

The default steps, up to 20000 calls a second and 20000 calls with audio at a time, and
the rate the RTP calls start at are at the top of capacity.py (CPS_STEPS, RTP_STEPS,
RTP_START_CPS, RTP_MEASURE_SECONDS, RTP_RAMP_MARGIN, RTP_MIN_ACTIVE): change them there.
In an RTP step every call is held through the start of all the others and then for the
measuring time, so the audio of the first calls goes on while the last ones are made; a
step where fewer than 99 % of its calls were up together fails. Thousands of calls need
many open files: on Linux raise them first, in the terminal that starts the service
(ulimit -n 200000); each call is one RTP socket, and 20000 calls send and receive 1 million
packets a second on each side. Each service may take up to a quarter of the memory of the
computer, which was enough for every measurement in the manual.

For numbers to publish use --repeat 3 and close other programs on both computers. The
weaker computer limits every run: the CPU columns show which one ran out.
