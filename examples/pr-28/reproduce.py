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

from modules.eindex import setupIndexDir
home = state / "home"
index = state / "persistent-index"
home.mkdir()
(home / "ews.idx").write_text("[EXAMPLE]\nindex = 1\n")
session = json.loads((HERE / "logs/rdphoneypot.json").read_bytes().splitlines()[0])["session"]
(home / "rdphoneypot.session").write_text(session + "\n")
checksum = hashlib.md5((HERE / "logs/rdphoneypot.json").read_bytes()).hexdigest()
(home / "malware.md5").write_text(checksum + "\n")
assert set(setupIndexDir(str(home), str(index))) == {"ews.idx", "rdphoneypot.session", "malware.md5"}
assert setupIndexDir(str(home), str(index)) == []
ecfg.update(homedir=str(home), indexdir=str(index))
live = state / "live.json"
initial = (HERE / "states/initial.json").read_bytes()
replacement = (HERE / "states/replacement.json").read_bytes()
def consume():
    current = alert()
    result = []
    while (value := current.lineREAD(str(live), "json")):
        result.append(value)
    return result
def decoded(data):
    return [json.loads(row) for row in data.splitlines()]
live.write_bytes(initial)
assert consume() == decoded(initial)
assert consume() == []
live.rename(state / "rotated.json")
live.write_bytes(replacement)
assert consume() == decoded(replacement)
assert consume() == []
with live.open("wb") as handle:
    handle.write(initial)
assert consume() == decoded(initial)
assert consume() == []
assert (index / "rdphoneypot.session").read_text() == session + "\n"
assert (index / "malware.md5").read_text() == checksum + "\n"
print("PASS: index migration, restart, rename rotation, copytruncate, session and hash persistence.")
