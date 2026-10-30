#!/usr/bin/env python3
import argparse
import base64
import csv
import http.client
import json
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument("service", choices=["h0neytr4p", "heralding"])
args = parser.parse_args()
capture = Path("/home/lima.guest/ews-captures")
smoke = (capture / (args.service + "-smoke.log")).read_text()
artifact = Path(smoke.split("Artifacts kept at: ")[-1].splitlines()[0])
compose = ["docker", "compose", "-f", str(artifact / "docker-compose.yml")]
subprocess.run(compose + ["up", "-d", "--no-build"], check=True)
try:
    port = int(subprocess.check_output(
        compose + ["port", args.service, "80"], text=True
    ).strip().rsplit(":", 1)[1])
    deadline = time.monotonic() + 30
    while True:
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    if args.service == "h0neytr4p":
        boundary = "ews-example-boundary"
        body = (
            "--" + boundary + "\r\n"
            'Content-Disposition: form-data; name="file"; filename="example.txt"\r\n'
            "Content-Type: text/plain\r\n\r\n"
            "Harmless ewsposter example upload.\n"
            "\r\n--" + boundary + "--\r\n"
        ).encode()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/upload", body,
                     {"Content-Type": "multipart/form-data; boundary=" + boundary})
        conn.getresponse().read()
        conn.close()
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/.env", b"ews-example=harmless-test-body\n",
                     {"Content-Type": "application/x-www-form-urlencoded",
                      "User-Agent": "ews-example-client"})
        conn.getresponse().read()
        conn.close()
    else:
        for username, password in [
            ("user,with,commas", 'pass"with"quotes'),
            ("timestamp", "timestamp"),
            ("user\nsecond-line", "not-a-real-password"),
        ]:
            token = base64.b64encode((username + ":" + password).encode()).decode()
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/", headers={"Authorization": "Basic " + token})
            conn.getresponse().read()
            conn.close()
    time.sleep(1)
finally:
    subprocess.run(compose + ["down", "--remove-orphans"], check=True)
if args.service == "h0neytr4p":
    events = [json.loads(line) for line in (artifact / "log/log.json").read_text().splitlines()]
    assert any(event.get("payload_filename") for event in events), "no stored POST payload"
else:
    with (artifact / "log/auth.csv").open(newline="") as handle:
        rows = list(csv.DictReader(handle))
    for wanted in ["user,with,commas", "timestamp", "user\nsecond-line"]:
        assert any(row.get("username") == wanted for row in rows), wanted
print("Supplemental real HTTP log fields captured:", args.service)
