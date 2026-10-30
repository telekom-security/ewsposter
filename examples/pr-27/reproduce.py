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

from modules import etoolbox
inputs = json.loads((HERE / "inputs/sources.json").read_text())
config = {"path": str(state), "ip_int": "None", "ip_ext": "None"}
class Answer:
    def __init__(self, text):
        self.text = text
    def raise_for_status(self):
        return None
with mock.patch.dict(os.environ, {}, clear=True):
    with mock.patch.object(etoolbox.requests, "get", side_effect=AssertionError("unexpected external lookup")):
        config["ip_ext"] = inputs["config"]
        assert etoolbox.getIP("EINIT", config)["connect_ip_ext"] == ""
        config["ip_ext"] = "None"
        os.environ["MY_EXTIP"] = inputs["environment"]
        assert etoolbox.getIP("EINIT", config)["env_ip_ext"] == inputs["environment"]
        del os.environ["MY_EXTIP"]
        shutil.copyfile(HERE / "inputs/ews.ip", state / "ews.ip")
        assert etoolbox.getIP("EINIT", config)["file_ip_ext"] == inputs["file"]
        (state / "ews.ip").unlink()
    with mock.patch.object(etoolbox.requests, "get", return_value=Answer(inputs["lookup"] + "\n")) as lookup:
        assert etoolbox.getIP("EINIT", config)["connect_ip_ext"] == inputs["lookup"]
        assert lookup.call_count == 1
    with mock.patch.object(etoolbox.requests, "get", return_value=Answer("<html>not an address</html>")):
        assert etoolbox.getIP("EINIT", config)["connect_ip_ext"] == ""
    with mock.patch.object(etoolbox.requests, "get", side_effect=etoolbox.requests.exceptions.ConnectionError("controlled offline failure")):
        assert etoolbox.getIP("EINIT", config)["connect_ip_ext"] == ""
print("PASS: configured sources suppress lookup; fallback validates responses and tolerates lookup failure.")
