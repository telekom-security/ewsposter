#!/usr/bin/env python3
"""Offline reproduction using the actual PR implementation and supplied data."""
import argparse
import base64
import configparser
import hashlib
import json
import linecache
import os
from pathlib import Path
import shutil
import sys
import tempfile
from unittest import mock

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
args = parser.parse_args()
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(args.repo.resolve()))
temporary = tempfile.TemporaryDirectory(prefix="ews-pr-example-")
state = Path(temporary.name)
(state / "ews.cfg").write_text("[MAIN]\nlogdir = " + str(state) + "\n")
sys.argv = [sys.argv[0], "-c", str(state)]
from modules.ealert import EAlert
ecfg = {"username": "example", "token": "not-a-real-token", "homedir": str(state)}
def alert():
    return EAlert("example", ecfg)

events = [json.loads(row) for row in (HERE / "logs/log.json").read_bytes().splitlines()]
event = next(row for row in events if row.get("payload_hash_md5"))
checksum = event["payload_hash_md5"]
original = HERE / "payloads" / Path(event["payload_filename"]).name
assert hashlib.md5(original.read_bytes()).hexdigest() == checksum
available = state / "available"
available.mkdir()
reader = alert()
assert reader.malwarecheck(str(available), checksum, False, checksum) == (False, None)
index = state / "malware.md5"
assert not index.exists() or checksum not in index.read_text().splitlines()
assert checksum not in reader.malwareindex
shutil.copyfile(original, available / checksum)
ok, encoded = reader.malwarecheck(str(available), checksum, False, checksum)
assert ok is True
assert base64.b64decode(encoded) == original.read_bytes()
assert index.read_text().splitlines() == [checksum]
assert reader.malwarecheck(str(available), checksum, False, checksum) == (False, None)
assert index.read_text().splitlines() == [checksum]
print("PASS: absent real upload not marked; later available upload read once with matching MD5.")
