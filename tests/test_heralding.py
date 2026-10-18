import csv
import importlib.util
import io
import os
import sys
import types
import unittest
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "honeypots", "heralding.py")
HEADER = ["timestamp", "auth_id", "session_id", "source_ip", "source_port", "destination_ip",
          "destination_port", "protocol", "username", "password", "password_hash"]


def load_heralding():
    """ load honeypots/heralding.py with a stand-in for modules.ealert, sys.modules stays as it was """
    modules = types.ModuleType("modules")
    ealert = types.ModuleType("modules.ealert")
    ealert.EAlert = object
    with mock.patch.dict(sys.modules, {"modules": modules, "modules.ealert": ealert}):
        spec = importlib.util.spec_from_file_location("heralding_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


heralding_module = load_heralding()


def csv_text(*rows, header=True):
    """ auth.csv as Heralding writes it (csv.DictWriter, lineterminator \\n) """
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    if header:
        writer.writerow(HEADER)
    for row in rows:
        writer.writerow(row)
    return out.getvalue()


def row(n, username="root", password="toor", password_hash="", protocol="ftp"):
    return [f"2026-10-17 10:43:{n:02d}.529480", f"a{n}", f"s{n}", f"198.51.100.{n}", str(40000 + n),
            "172.20.0.5", "21", protocol, username, password, password_hash]


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, msg, handles=""):
        self.warnings.append(msg)


class FakeEAlert:
    """ reads the given text line by line like EAlert.lineREAD and keeps the counter like alertCount """

    text = ""

    def __init__(self, MODUL, ECFG):
        self.MODUL = MODUL.upper()
        self.lines = self.text.splitlines(keepends=True)
        self.counter = 1
        self.alerts = []
        self.current = {"data": {}, "request": {}, "adata": {}}
        self.logger = FakeLogger()
        FakeEAlert.last = self

    def readCFG(self, items, cfgfile):
        return {"heralding": "true", "nodeid": "heralding-test", "logfile": "auth.csv"}

    def alertCount(self, section, counting, item="index", setto=1):
        if counting == "get_counter":
            return str(self.counter)
        if counting == "set_counter":
            self.counter = setto
        return ()

    def lineREAD(self, filename, format="json"):
        if self.counter > len(self.lines):
            return ()
        line = self.lines[self.counter - 1]
        self.counter += 1
        return line

    def data(self, key, value):
        self.current["data"][key] = value

    def request(self, key, value):
        self.current["request"][key] = value

    def adata(self, key, value):
        self.current["adata"][key] = value

    def buildAlert(self):
        self.alerts.append(self.current)
        self.current = {"data": {}, "request": {}, "adata": {}}
        return True

    def finAlert(self):
        pass


ECFG = {"cfgfile": "ews.cfg", "hostname": "sensor", "ip_ext": "203.0.113.10", "ip_int": "10.0.0.5", "uuid": "u"}


def run(text):
    FakeEAlert.text = text
    with mock.patch.object(heralding_module, "EAlert", FakeEAlert):
        heralding_module.heralding(ECFG)
    return FakeEAlert.last


class HeraldingCsvTest(unittest.TestCase):
    def test_plain_records_and_header(self):
        alert = run(csv_text(row(1), row(2, protocol="vnc", username="", password="", password_hash="$vnc$*00*FF")))
        self.assertEqual(len(alert.alerts), 2)
        first, second = alert.alerts
        self.assertEqual(first["data"]["timestamp"], "2026-10-17 10:43:01")
        self.assertEqual(first["data"]["source_address"], "198.51.100.1")
        self.assertEqual(first["data"]["source_port"], "40001")
        self.assertEqual(first["data"]["target_port"], "21")
        self.assertEqual(first["adata"]["username"], "root")
        self.assertEqual(first["adata"]["password"], "toor")
        self.assertNotIn("username", second["adata"])
        self.assertEqual(second["adata"]["password_hash"], "$vnc$*00*FF")

    def test_quoted_commas_and_quotes(self):
        alert = run(csv_text(row(1, username="user,with,commas", password='pa"ss')))
        self.assertEqual(alert.alerts[0]["adata"]["username"], "user,with,commas")
        self.assertEqual(alert.alerts[0]["adata"]["password"], 'pa"ss')
        self.assertEqual(alert.alerts[0]["data"]["target_port"], "21")

    def test_timestamp_as_username_or_password(self):
        alert = run(csv_text(row(1, username="timestamp"), row(2, password="timestamp")))
        self.assertEqual([a["adata"]["username"] for a in alert.alerts], ["timestamp", "root"])
        self.assertEqual(alert.alerts[1]["adata"]["password"], "timestamp")

    def test_record_over_several_lines(self):
        alert = run(csv_text(row(1, username="line1\nline2\nline3"), row(2)))
        self.assertEqual(len(alert.alerts), 2)
        self.assertEqual(alert.alerts[0]["adata"]["username"], "line1\nline2\nline3")
        self.assertEqual(alert.alerts[1]["data"]["source_address"], "198.51.100.2")

    def test_short_or_broken_records_are_skipped(self):
        text = csv_text(row(1)) + "2026-10-17 10:43:02.1,a2,s2,198.51.100.2\nnot,an,address,x,1,y,2,ftp,u,p,\n"
        alert = run(text + csv_text(row(3), header=False))
        self.assertEqual([a["data"]["source_address"] for a in alert.alerts], ["198.51.100.1", "198.51.100.3"])
        self.assertEqual(len(alert.logger.warnings), 2)

    def test_unfinished_record_is_read_again(self):
        complete = csv_text(row(1), row(2, password="first\nsecond"))
        cut = complete[:complete.index("second")]
        alert = run(cut)
        self.assertEqual(len(alert.alerts), 1)
        self.assertEqual(alert.counter, 3)

    def test_header_after_truncation(self):
        alert = run(csv_text(row(1)) + csv_text(row(2)))
        self.assertEqual(len(alert.alerts), 2)
        self.assertEqual(alert.logger.warnings, [])


if __name__ == "__main__":
    unittest.main()
