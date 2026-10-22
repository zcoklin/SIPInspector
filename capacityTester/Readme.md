# SIP Inspector capacity tester

`capacity.py` measures what computers running SIP Inspector 7.02 or later can carry: calls a second, and calls with
G.711 audio both ways at the same time. Both computers run SIP Inspector as an API service; the script drives them
over HTTP. It needs Python 3.6 or later and nothing else. Keep the `scenarios` folder next to `capacity.py`.

On each computer, in the program folder of SIP Inspector (Linux and macOS):

    ./SIPInspDlx -api 8080 -apiHost 0.0.0.0 -apiToken <token> -lip <its address> -lp 5060 -lrtp 10000 -np -d ERROR

Then, on any computer that reaches both:

    python3 capacity.py --a http://<A>:8080 --b http://<B>:8080 --token <token> --repeat 3

On Windows the service is `SIPInspDlxCLI.exe` with the same options, and the script `py capacity.py ...`.

Both services on one computer: A on `-lip 127.0.0.1 -lp 5060`, B on `-lip 127.0.0.2 -lp 5070` (its own copy of the
program folder, `-api 8081`), then `python3 capacity.py --a http://127.0.0.1:8080 --b http://127.0.0.1:8081
--token <token> --roles ab`. On macOS first `sudo ifconfig lo0 alias 127.0.0.2 up`.

README.txt (section 3) has the details, and the manual the chapter Performance and capacity:
https://www.sipinspector.com/docs/performance-and-capacity
