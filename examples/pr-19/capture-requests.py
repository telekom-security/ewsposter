#!/usr/bin/env python3
import json
from pathlib import Path
import socket
import subprocess
import time

capture = Path("/home/lima.guest/ews-captures")
smoke = (capture / "redishoneypot-smoke.log").read_text()
artifact = Path(smoke.split("Artifacts kept at: ")[-1].splitlines()[0])
compose = ["docker", "compose", "-f", str(artifact / "docker-compose.yml")]
sockets = []
subprocess.run(compose + ["up", "-d", "--no-build"], check=True)
try:
    port = subprocess.check_output(
        compose + ["port", "redishoneypot", "6379"], text=True
    ).strip().rsplit(":", 1)[1]
    deadline = time.monotonic() + 30
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", int(port)), timeout=3)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.2)
    with sock:
        value = b"x" * 8300
        sock.sendall(b"*3\r\n$3\r\nSET\r\n$11\r\news-example\r\n$8300\r\n" + value + b"\r\n")
        assert sock.recv(256).startswith(b"+OK"), "harmless SET failed"
    time.sleep(0.5)
    for number in range(17):
        sock = socket.create_connection(("127.0.0.1", int(port)), timeout=3)
        sockets.append(sock)
        sock.sendall(b"*1\r\n$4\r\nPING\r\n")
        answer = sock.recv(256)
        if number < 16:
            assert answer.startswith(b"+PONG"), (number, answer)
        else:
            assert not answer.startswith(b"+PONG"), "17th connection unexpectedly accepted"
    time.sleep(0.5)
finally:
    for sock in sockets:
        sock.close()
    subprocess.run(compose + ["down", "--remove-orphans"], check=True)
events = [json.loads(line) for line in (artifact / "log/redishoneypot.log").read_text().splitlines()]
assert any(event.get("event") == "refused" for event in events), "no refused event"
assert any(any(key.endswith("_truncated") and value for key, value in event.items()) for event in events), "no truncation event"
print("Real refused connection and truncated harmless SET value captured.")
