#!/usr/bin/env python3
"""Replay captured files using the real EAlert and parser, without ESend."""
import argparse
import configparser
import importlib.util
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import sys
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, required=True)
parser.add_argument("--module", required=True)
parser.add_argument("--logs", type=Path, required=True)
parser.add_argument("--logfile", required=True)
parser.add_argument("--payloads", type=Path, required=True)
parser.add_argument("--state", type=Path, required=True)
parser.add_argument("--expect-no-alerts", action="store_true")
args = parser.parse_args()
for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
    os.environ.pop(name, None)
os.environ["no_proxy"] = "127.0.0.1,localhost"
os.environ["TZ"] = "UTC"
if hasattr(time, "tzset"):
    time.tzset()
repo = args.repo.resolve()
logs = args.logs.resolve()
payloads = args.payloads.resolve()
state = args.state.resolve()
state.mkdir(parents=True, exist_ok=True)
(state / "spool").mkdir(exist_ok=True)
payloads.mkdir(parents=True, exist_ok=True)
config = configparser.ConfigParser()
config["MAIN"] = {"logdir": str(state)}
config[args.module.upper()] = {
    args.module: "true",
    "nodeid": "example-sensor",
    "logfile": str(logs / args.logfile),
    "logdir": str(logs),
    "malwaredir": str(payloads),
    "payloaddir": str(payloads),
    "uploaddir": str(payloads),
}
with (state / "ews.cfg").open("w") as handle:
    config.write(handle)


class Sink(BaseHTTPRequestHandler):
    received = 0

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).received += 1
        path = state / "spool" / f"{type(self).received:04d}.ews"
        path.write_bytes(body)
        answer = b"<StatusCode>OK</StatusCode>"
        self.send_response(200)
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, format, *args):
        pass


server = HTTPServer(("127.0.0.1", 0), Sink)
thread = threading.Thread(target=server.serve_forever)
thread.start()
sink_url = "http://127.0.0.1:" + str(server.server_port)
ecfg = {
    "cfgfile": str(state / "ews.cfg"),
    "homedir": str(state),
    "indexdir": str(state),
    "spooldir": str(state / "spool"),
    "logdir": str(state),
    "username": "example",
    "token": "not-a-real-token",
    "hostname": "example-sensor",
    "uuid": "00000000-0000-4000-8000-000000000001",
    "ip_ext": "192.0.2.10",
    "ip_int": "192.0.2.20",
    "send_malware": True,
    "del_malware_after_send": False,
    "sendlimit": 5000,
    "ews": True,
    "hpfeed": False,
    "influxdb": False,
    "json": True,
    "jsondir": str(state / "alerts.jsonl"),
    "name": "Offline example replay",
    "version": "1",
    "rhost_first": sink_url,
    "rhost_second": sink_url,
    "proxy": False,
    "a.jsondir": "",
    "a.verbose": False,
    "a.debug": False,
    "a.ignorecert": False,
    "a.ewsonly": False,
}
sys.path.insert(0, str(repo))
sys.argv = [sys.argv[0], "-c", str(state)]
os.chdir(state)
try:
    spec = importlib.util.spec_from_file_location(
        "captured_honeypot", repo / "honeypots" / (args.module + ".py")
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    getattr(module, args.module)(ecfg)
finally:
    server.shutdown()
    thread.join()
    server.server_close()
if args.expect_no_alerts:
    assert Sink.received == 0, "A repeated pass posted duplicate alerts"
print("Local-only replay complete. XML messages:", Sink.received)
