#!/usr/bin/env python3
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

if "--stub" in sys.argv:
    class Ollama(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            body = json.dumps({
                "model": "openchat", "done": True,
                "message": {"role": "assistant", "content": "example-response"},
                "response": "example-response",
            }).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            print("local-llm-request", flush=True)

        def log_message(self, format, *args):
            pass

    server = HTTPServer(("127.0.0.1", 9), Ollama)
    print("ready", flush=True)
    server.serve_forever()
    raise SystemExit

capture = Path("/home/lima.guest/ews-captures")
smoke = (capture / "beelzebub-smoke.log").read_text()
artifact = Path(smoke.split("Artifacts kept at: ")[-1].splitlines()[0])
compose = ["docker", "compose", "-f", str(artifact / "docker-compose.yml")]
subprocess.run(compose + ["up", "-d", "--no-build"], check=True)
stub = None
try:
    container = subprocess.check_output(compose + ["ps", "-q", "beelzebub"], text=True).strip()
    info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
    pid = info["State"]["Pid"]
    address = next(iter(info["NetworkSettings"]["Networks"].values()))["IPAddress"]
    stub = subprocess.Popen(
        ["nsenter", "-t", str(pid), "-n", sys.executable, __file__, "--stub"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    assert stub.stdout.readline().strip() == "ready", "local LLM stub did not start"
    deadline = time.monotonic() + 30
    while True:
        try:
            sock = socket.create_connection((address, 8080), timeout=2)
            sock.close()
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    for port in [80, 8081, 8888, 8000]:
        conn = http.client.HTTPConnection(address, port, timeout=5)
        if port == 8000:
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                               "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                                          "clientInfo": {"name": "ews-example-client", "version": "1"}}})
            conn.request("POST", "/mcp", body, {"Content-Type": "application/json",
                                              "Accept": "application/json, text/event-stream"})
        else:
            conn.request("GET", "/ews-example", headers={"User-Agent": "ews-example-client"})
        response = conn.getresponse()
        response.read(4096)
        conn.close()
    for port in [389, 445, 1433, 1883, 3389, 5432, 5900, 6379, 11211]:
        with socket.create_connection((address, port), timeout=5) as sock:
            sock.settimeout(1)
            sock.sendall(b"PING\r\n")
            try:
                sock.recv(4096)
            except socket.timeout:
                print("No immediate reply (recorded connection):", port)
    with socket.create_connection((address, 23), timeout=5) as sock:
        sock.settimeout(1)
        for data in [b"root\r\n", b"123456\r\n", b"whoami\r\n", b"exit\r\n"]:
            time.sleep(0.2)
            sock.sendall(data)
            try:
                sock.recv(4096)
            except socket.timeout:
                print("Telnet response timeout; connection remains a real recorded attempt")
    environment = dict(os.environ, SSH_ASKPASS=str(artifact / "askpass.sh"),
                       SSH_ASKPASS_REQUIRE="force", DISPLAY=":0")
    subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
         "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR", "-p", "22",
         "root@" + address, "whoami"],
        stdin=subprocess.DEVNULL, env=environment, timeout=25, check=True,
    )
    time.sleep(1)
finally:
    if stub is not None:
        stub.terminate()
        out, err = stub.communicate(timeout=10)
        print(out, end="")
        if err:
            print(err, file=sys.stderr)
    subprocess.run(compose + ["down", "--remove-orphans"], check=True)
events = [json.loads(row) for row in (artifact / "log/beelzebub.json").read_text().splitlines()]
protocols = {str(event.get("protocol")).lower() for event in events}
assert {"ssh", "telnet", "tcp", "http"} <= protocols, protocols
assert "local-llm-request" in out, "no actual request reached the local LLM stub"
print("Supplemental real service protocols:", sorted(str(value) for value in protocols))
