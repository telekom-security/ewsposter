#!/usr/bin/env python3
"""Replay these supplied files against the actual checkout and compare XML alerts."""
import argparse
import difflib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
parser.add_argument("--record", action="store_true", help=argparse.SUPPRESS)
args = parser.parse_args()
here = Path(__file__).resolve().parent
cases = json.loads((here / "cases.json").read_text())
actual = {}
for case in cases:
    with tempfile.TemporaryDirectory(prefix="ews-capture-replay-") as directory:
        command = [
            sys.executable, str(here / "replay.py"), "--repo", str(args.repo.resolve()),
            "--module", case["module"], "--logs", str(here / case["logs"]),
            "--logfile", case["logfile"], "--payloads", str(here / "payloads"),
            "--state", directory,
        ]
        subprocess.run(command, check=True, timeout=30)
        def summarize():
            result = []
            for path in sorted((Path(directory) / "spool").glob("*.ews")):
                for alert in ET.parse(path).getroot().findall("Alert"):
                    source = alert.find("Source")
                    target = alert.find("Target")
                    result.append({
                        "timestamp": alert.findtext("CreateTime"),
                        "timezone": alert.find("CreateTime").get("tz"),
                        "source": dict(address=source.text, **source.attrib),
                        "target": dict(address=target.text, **target.attrib),
                        "requests": {r.get("type"): r.text for r in alert.findall("Request")},
                        "metadata": {r.get("meaning"): r.text for r in alert.findall("AdditionalData")},
                    })
            return sorted(result, key=lambda row: json.dumps(row, sort_keys=True))
        first = summarize()
        subprocess.run(command + ["--expect-no-alerts"], check=True, timeout=30)
        assert summarize() == first, "A second pass unexpectedly produced different/additional alerts"
        actual[case["name"]] = first
if args.record:
    (here / "expected.json").write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n")
else:
    expected = json.loads((here / "expected.json").read_text())
    if actual != expected:
        difference = difflib.unified_diff(
            json.dumps(expected, indent=2, sort_keys=True).splitlines(keepends=True),
            json.dumps(actual, indent=2, sort_keys=True).splitlines(keepends=True),
            fromfile="expected.json", tofile="actual XML summary",
        )
        sys.stderr.write("".join(difference))
    assert actual == expected, "Captured-file replay differs from expected.json"
print("PASS:", {name: len(alerts) for name, alerts in actual.items()})
