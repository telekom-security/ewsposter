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

reader = alert()
missing = state / "absent.log"
assert reader.lineREAD(str(missing), "simple") == ()
live = state / "live.json"
shutil.copyfile(HERE / "states/empty.json", live)
assert reader.lineREAD(str(live), "simple") == ()
assert reader.lineREAD(str(live), "json") == ()
assert reader.alertCount("EXAMPLE", "get_counter") == "1"
first = (HERE / "logs/rdphoneypot.json").read_bytes().splitlines(keepends=True)[0]
with live.open("ab") as handle:
    handle.write(first)
assert reader.lineREAD(str(live), "json") == json.loads(first)
assert reader.alertCount("EXAMPLE", "get_counter") == "2"
assert reader.lineREAD(str(live), "json") == ()
print("PASS: missing/empty logs do not advance the counter; first actual event read once.")
