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
live = state / "live.json"
shutil.copyfile(HERE / "states/partial.json", live)
assert reader.lineREAD(str(live), "json") == ()
assert reader.alertCount("EXAMPLE", "get_counter") == "1"
assert reader.jsonfailcounter == 0
with live.open("ab") as handle:
    handle.write((HERE / "states/remainder.fragment").read_bytes())
expected = json.loads((HERE / "states/complete.json").read_bytes())
assert reader.lineREAD(str(live), "json") == expected
assert reader.alertCount("EXAMPLE", "get_counter") == "2"
assert reader.lineREAD(str(live), "json") == ()
assert reader.jsonfailcounter == 0
print("PASS: incomplete final line deferred; completed actual event read exactly once.")
