import base64
import configparser
import importlib.util
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock
from datetime import UTC, datetime


stub_ealert = types.ModuleType("modules.ealert")
stub_ealert.EAlert = object
sys.modules["modules.ealert"] = stub_ealert

MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "honeypots", "miniprint.py")
SPEC = importlib.util.spec_from_file_location("miniprint_under_test", MODULE_PATH)
miniprint_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(miniprint_module)


class FakeEAlert:
    instances = []
    counters = {}
    indexes = {}

    def __init__(self, modul, ECFG):
        self.MODUL = modul.upper()
        self.ECFG = ECFG
        self.DATA = {}
        self.REQUEST = {}
        self.ADATA = {}
        self.alerts = []
        self.line_index = FakeEAlert.counters.get(modul.upper(), 1) - 1
        self.lines = None
        self.malware_seen = set()
        self.fin_called = False
        FakeEAlert.instances.append(self)

    def readCFG(self, items, file):
        config = configparser.ConfigParser()
        config.read(file)
        return {item: config.get(self.MODUL, item) for item in items if config.has_option(self.MODUL, item)}

    def lineREAD(self, filename, format="json", linenumber=None, item="index", debugoutput=False):
        del format, linenumber, item, debugoutput
        if self.lines is None:
            with open(filename, encoding="utf-8") as handle:
                self.lines = handle.readlines()
        if self.line_index >= len(self.lines):
            return ()
        line = self.lines[self.line_index]
        self.line_index += 1
        FakeEAlert.counters[self.MODUL] = self.line_index + 1
        return json.loads(line)

    def alertCount(self, section, counting, item="index", setto=1):
        if counting == "get_counter":
            return FakeEAlert.counters.get(section, 1)
        if counting == "set_counter":
            FakeEAlert.counters[section] = setto

    def fileIndex(self, filename, action, content=None):
        index = FakeEAlert.indexes.setdefault(filename, [])
        if action == "read":
            return list(index)
        if action == "write":
            index.append(content)

    def data(self, key, value):
        self.DATA[key] = value
        return True

    def request(self, key, value):
        self.REQUEST[key] = value
        return True

    def adata(self, key, value):
        self.ADATA[key] = value
        return True

    def buildAlert(self):
        self.alerts.append(
            {
                "data": dict(self.DATA),
                "request": dict(self.REQUEST),
                "adata": dict(self.ADATA),
            }
        )
        self.DATA.clear()
        self.REQUEST.clear()
        self.ADATA.clear()
        return True

    def finAlert(self):
        self.fin_called = True

    def malwarecheck(self, malwaredir, malwarefile, localremove, md5filechecksum=None):
        if md5filechecksum in self.malware_seen:
            return (False, None)
        self.malware_seen.add(md5filechecksum)
        path = os.path.join(malwaredir, malwarefile)
        if not os.path.isfile(path):
            return (False, None)
        with open(path, "rb") as handle:
            payload = handle.read()
        if localremove:
            os.remove(path)
        return (True, base64.b64encode(payload))


class MiniprintTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = self.tmpdir.name
        self.logfile = os.path.join(self.root, "miniprint.json")
        self.uploads = os.path.join(self.root, "uploads")
        os.mkdir(self.uploads)
        FakeEAlert.instances = []
        FakeEAlert.counters = {}
        FakeEAlert.indexes = {}
        self.patch = mock.patch.object(miniprint_module, "EAlert", FakeEAlert)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self.tmpdir.cleanup()

    def write_config(self, upload_option="malwaredir"):
        cfgfile = os.path.join(self.root, "ews.cfg")
        with open(cfgfile, "w", encoding="utf-8") as handle:
            handle.write(
                "[MINIPRINT]\n"
                "miniprint = true\n"
                "nodeid = miniprint-test\n"
                f"logfile = {self.logfile}\n"
                f"{upload_option} = {self.uploads}\n"
            )
        return cfgfile

    def run_miniprint(self, records, upload_option="malwaredir"):
        with open(self.logfile, "w", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")
        ECFG = {
            "cfgfile": self.write_config(upload_option),
            "del_malware_after_send": False,
            "send_malware": True,
            "hostname": "sensor-1",
            "ip_ext": "198.51.100.20",
            "ip_int": "10.0.0.5",
            "uuid": "sensor-uuid",
        }
        miniprint_module.miniprint(ECFG)
        return FakeEAlert.instances[-1].alerts

    def recent(self, sid, **fields):
        return {
            "session_id": sid,
            "timestamp": datetime.now(UTC).isoformat(),
            "src_ip": "203.0.113.1",
            "src_port": 1234,
            "dest_ip": "198.51.100.2",
            "dest_port": 80,
            **fields,
        }

    def test_open_session_rewinds_and_closed_session_is_not_resent(self):
        records = [
            self.recent("open", event="connection"),
            self.recent("closed", event="connection_closed", session_end="done"),
        ]
        alerts = self.run_miniprint(records)
        self.assertEqual([a["adata"]["session_id"] for a in alerts], ["closed"])
        self.assertEqual(FakeEAlert.counters["MINIPRINT"], 1)
        records.append(self.recent("open", event="http_connection_closed", session_end="done"))
        alerts = self.run_miniprint(records)
        self.assertEqual([a["adata"]["session_id"] for a in alerts], ["open"])
        self.assertEqual(self.run_miniprint(records), [])

    def test_request_text_is_xml_compatible(self):
        records = [
            self.recent(
                "binary-probe",
                event="unknown_command",
                command="\x1bPJL\x00",
                payload_preview="probe\x00\x1b\uffff\ud800\t\ntext",
            ),
            self.recent("binary-probe", event="connection_closed", session_end="done"),
        ]
        alert = self.run_miniprint(records)[0]
        self.assertEqual(alert["request"]["request"], "PJL")
        self.assertEqual(alert["request"]["payload"], "probe\t\ntext")

    def test_empty_connections_are_skipped_by_default(self):
        alerts = self.run_miniprint([self.recent("empty", event="empty_connection", session_end="done")])
        self.assertEqual(alerts, [])

    def test_http_requests_secret_union_and_schema_fields(self):
        records = [
            self.recent(
                "s",
                event="serial_leak_probe",
                request="GET",
                url="/etc/mnt_info.csv",
                persona="brother",
                secret_supplied=False,
                cve_hint="CVE-2024-51977",
            ),
            self.recent(
                "s",
                event="default_password_success",
                request="POST",
                url="/login",
                secret_supplied=True,
                cve_hint="CVE-2024-51978,CVE-2024-51977",
            ),
            self.recent("s", event="fsquery", virtual_path="/x"),
            self.recent("s", event="http_connection_closed", session_end="done"),
        ]
        alert = self.run_miniprint(records)[0]
        self.assertEqual(alert["request"]["request"], "GET /etc/mnt_info.csv\nPOST /login")
        self.assertTrue(alert["adata"]["secret_supplied"])
        self.assertEqual(alert["adata"]["cve_hint"], "CVE-2024-51977,CVE-2024-51978")
        self.assertEqual(alert["adata"]["virtual_path"], "/x")
        self.assertEqual(alert["adata"]["persona"], "brother")

    def test_best_artifact_is_selected_and_all_are_summarized(self):
        for name, payload in [("raw.prn", b"raw"), ("job.ps", b"print"), ("firmware.bin", b"firmware")]:
            with open(os.path.join(self.uploads, name), "wb") as handle:
                handle.write(payload)
        records = [
            self.recent("s", event="fsappend", file_name="/virtual", size=17),
            self.recent(
                "s", event="save_print_job", file_name="raw.prn", artifact_type="raw", payload_sha256="r", size=3
            ),
            self.recent(
                "s",
                event="save_print_job",
                file_name="job.ps",
                artifact_type="ps",
                language="POSTSCRIPT",
                payload_sha256="p",
                size=5,
            ),
            self.recent(
                "s",
                event="save_firmware",
                file_name="firmware.bin",
                artifact_type="firmware",
                payload_sha256="f",
                size=8,
            ),
            self.recent("s", event="request_too_large", size=9000, limit=8000),
            self.recent("s", event="connection_closed", session_end="done"),
        ]
        alert = self.run_miniprint(records)[0]
        self.assertEqual(alert["request"]["binary"], base64.b64encode(b"firmware").decode())
        self.assertEqual(alert["adata"]["artifact_size"], 8)
        self.assertEqual(alert["adata"]["request_too_large_size"], 9000)
        self.assertIn("job.ps:p", alert["adata"]["artifacts"])
        self.assertNotIn("/virtual", alert["adata"]["file_name"])

    def test_sendlimit_rewinds_only_remaining_sessions(self):
        records = [
            self.recent("s", event="connection_closed", session_end="done"),
            self.recent("t", event="connection_closed", session_end="done"),
        ]
        original = FakeEAlert.buildAlert

        def limited(instance):
            original(instance)
            return "sendlimit"

        with mock.patch.object(FakeEAlert, "buildAlert", limited):
            alerts = self.run_miniprint(records)
        self.assertEqual([a["adata"]["session_id"] for a in alerts], ["s"])
        self.assertEqual(FakeEAlert.counters["MINIPRINT"], 2)
        alerts = self.run_miniprint(records)
        self.assertEqual([a["adata"]["session_id"] for a in alerts], ["t"])

    def test_empty_connections_can_be_enabled(self):
        cfgfile = self.write_config()
        with open(cfgfile, "a") as handle:
            handle.write("send_empty_connections = true\n")
        with mock.patch.object(self, "write_config", return_value=cfgfile):
            alerts = self.run_miniprint([self.recent("empty", event="empty_connection", session_end="done")])
        self.assertEqual(len(alerts), 1)

    def test_abandoned_session_times_out_after_ten_minutes(self):
        record = self.recent("abandoned", event="connection")
        record["timestamp"] = "2020-01-01T00:00:00Z"
        self.assertEqual(len(self.run_miniprint([record])), 1)

    def test_larger_artifact_wins_within_same_priority(self):
        records = []
        for name, size in [("small.ps", 2), ("big.pdf", 7)]:
            with open(os.path.join(self.uploads, name), "wb") as handle:
                handle.write(b"x" * size)
            records.append(
                self.recent(
                    "s",
                    event="save_print_job",
                    file_name=name,
                    size=size,
                    payload_sha256=name,
                    artifact_type=name.split(".")[-1],
                )
            )
        records.append(self.recent("s", event="connection_closed", session_end="done"))
        self.assertEqual(self.run_miniprint(records)[0]["request"]["binary"], base64.b64encode(b"x" * 7).decode())

    def test_http_ssrf_session_builds_one_alert(self):
        session = "fa054f81-040f-41a1-a01f-2572ca7c7f83"
        records = [
            {
                "timestamp": "2026-06-16T15:28:47.734303Z",
                "info": "HTTP request received",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 55456,
                "dest_ip": "172.22.0.2",
                "dest_port": 8080,
                "session_start": "2026-06-16T15:28:47.734127Z",
                "protocol": "http",
                "action": "request",
                "event": "ssrf_probe",
                "request": "GET",
                "url": "/network/config?url=http://169.254.169.254/probe",
                "user_agent": "miniprint-smoke/probe",
                "cve_hint": "CVE-2024-51980,CVE-2024-51981,CVE-2025-9269",
            },
            {
                "timestamp": "2026-06-16T15:28:47.734453Z",
                "info": "HTTP access",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 55456,
                "dest_ip": "172.22.0.2",
                "dest_port": 8080,
                "session_start": "2026-06-16T15:28:47.734127Z",
                "protocol": "http",
                "action": "access",
                "event": "http_access",
                "request_line": '"GET /network/config?url=http://169.254.169.254/probe HTTP/1.1" 401 -',
            },
            {
                "timestamp": "2026-06-16T15:28:47.734571Z",
                "info": "HTTP request completed",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 55456,
                "dest_ip": "172.22.0.2",
                "dest_port": 8080,
                "session_start": "2026-06-16T15:28:47.734127Z",
                "protocol": "http",
                "action": "close_conn",
                "event": "http_connection_closed",
                "session_end": "2026-06-16T15:28:47.734556Z",
                "session_duration": 0.000429,
            },
        ]

        alerts = self.run_miniprint(records)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["data"]["source_port"], "55456")
        self.assertEqual(alert["request"]["url"], "/network/config?url=http://169.254.169.254/probe")
        self.assertEqual(alert["request"]["request"], "GET /network/config?url=http://169.254.169.254/probe")
        self.assertEqual(alert["adata"]["session_id"], session)
        self.assertEqual(alert["adata"]["protocol"], "http")
        self.assertIn("ssrf_probe", alert["adata"]["event"])
        self.assertIn("CVE-2025-9269", alert["adata"]["cve_hint"])
        self.assertEqual(alert["adata"]["user_agent"], "miniprint-smoke/probe")

    def test_pjl_command_session_keeps_command_and_payload_metadata(self):
        session = "7d847994-3190-48c1-8bb4-304d85275847"
        records = [
            {
                "timestamp": "2026-06-16T15:28:47.735757Z",
                "info": "Connection opened",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47284,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.735069Z",
                "protocol": "pjl",
                "action": "open_conn",
                "event": "connection",
            },
            {
                "timestamp": "2026-06-16T15:28:47.735909Z",
                "info": "PJL command received",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47284,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.735069Z",
                "protocol": "pjl",
                "action": "request",
                "event": "command_received",
                "command": "ECHO",
                "payload_sha256": "c83c7e6add2b724039cef279c1636174ce4df4cea6759852c9e8bc32e42bd654",
                "payload_preview": "@PJL ECHO SMOKE\\r\\n",
            },
            {
                "timestamp": "2026-06-16T15:28:47.736094Z",
                "info": "Connection closed",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47284,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.735069Z",
                "protocol": "pjl",
                "action": "close_conn",
                "event": "connection_closed",
                "session_end": "2026-06-16T15:28:47.736084Z",
                "session_duration": 0.001015,
            },
        ]

        alerts = self.run_miniprint(records)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["data"]["source_port"], "47284")
        self.assertEqual(alert["request"]["request"], "ECHO")
        self.assertEqual(alert["request"]["payload"], "@PJL ECHO SMOKE\\r\\n")
        self.assertEqual(alert["adata"]["command"], "ECHO")
        self.assertIn("c83c7e6add2b724039", alert["adata"]["payload_sha256"])
        self.assertEqual(alert["adata"]["session_duration"], 0.001015)

    def test_raw_print_artifact_is_loaded_from_malwaredir_and_appends_are_summarized(self):
        session = "e0ac80fc-db5b-4026-9e4b-afb7cf73aadd"
        file_name = "2026-06-16_15-28-47-738451_1f8745f0d2d1387e.txt"
        with open(os.path.join(self.uploads, file_name), "wb") as handle:
            handle.write(b"hello print")
        records = [
            {
                "timestamp": "2026-06-16T15:28:47.737168Z",
                "info": "Connection opened",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "action": "open_conn",
                "event": "connection",
            },
            {
                "timestamp": "2026-06-16T15:28:47.737316Z",
                "info": "Appending raw print job",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "payload_sha256": "a2e659dacb4691e887ac0139f8893d04764ee197d70fb73d3190d56113d18e3e",
                "payload_preview": "xxxxxxxx",
                "action": "append",
                "event": "append_raw_print_job",
                "size": 4096,
            },
            {
                "timestamp": "2026-06-16T15:28:47.737426Z",
                "info": "Appending raw print job",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "payload_sha256": "a2e659dacb4691e887ac0139f8893d04764ee197d70fb73d3190d56113d18e3e",
                "payload_preview": "xxxxxxxx",
                "action": "append",
                "event": "append_raw_print_job",
                "size": 4096,
            },
            {
                "timestamp": "2026-06-16T15:28:47.738606Z",
                "info": "Saved print artifact",
                "session_id": session,
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "action": "saving",
                "event": "save_raw_print_job",
                "file_name": file_name,
                "payload_sha256": "1f8745f0d2d1387ec1af2211a3cf417b2e9e885e853472649c1d979d0e9370e3",
                "size": 65536,
            },
        ]

        alerts = self.run_miniprint(records)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["request"]["binary"], base64.b64encode(b"hello print").decode("utf-8"))
        self.assertEqual(alert["adata"]["append_raw_print_job_count"], 2)
        self.assertEqual(alert["adata"]["append_raw_print_job_bytes"], 8192)
        self.assertEqual(alert["adata"]["file_name"], file_name)
        self.assertEqual(alert["adata"]["artifact_size"], 65536)

    def test_missing_artifact_does_not_drop_session_alert(self):
        records = [
            {
                "timestamp": "2026-06-16T15:28:47.738606Z",
                "info": "Saved print artifact",
                "session_id": "missing-artifact",
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "action": "saving",
                "event": "save_raw_print_job",
                "file_name": "missing.txt",
                "payload_sha256": "missing-sha",
                "size": 1024,
            }
        ]

        alerts = self.run_miniprint(records)

        self.assertEqual(len(alerts), 1)
        self.assertNotIn("binary", alerts[0]["request"])
        self.assertNotIn("largepayload", alerts[0]["request"])
        self.assertEqual(alerts[0]["adata"]["file_name"], "missing.txt")

    def test_legacy_uploaddir_is_still_accepted(self):
        file_name = "legacy.txt"
        with open(os.path.join(self.uploads, file_name), "wb") as handle:
            handle.write(b"legacy upload")
        records = [
            {
                "timestamp": "2026-06-16T15:28:47.738606Z",
                "info": "Saved print artifact",
                "session_id": "legacy-upload",
                "src_ip": "172.22.0.1",
                "src_port": 47300,
                "dest_ip": "172.22.0.2",
                "dest_port": 9100,
                "session_start": "2026-06-16T15:28:47.736463Z",
                "protocol": "pjl",
                "action": "saving",
                "event": "save_raw_print_job",
                "file_name": file_name,
                "payload_sha256": "legacy-sha",
                "size": 13,
            }
        ]

        alerts = self.run_miniprint(records, upload_option="uploaddir")

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["request"]["binary"], base64.b64encode(b"legacy upload").decode("utf-8"))


if __name__ == "__main__":
    unittest.main()
