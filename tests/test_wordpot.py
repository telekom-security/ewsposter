import base64
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "wordpot_module",
    ROOT / "honeypots" / "wordpot.py",
)
wordpot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wordpot)


ECFG = {
    "hostname": "ews-host",
    "ip_ext": "198.51.100.10",
    "ip_int": "10.0.0.10",
    "uuid": "test-uuid",
    "send_malware": False,
    "del_malware_after_send": False,
}

HONEYPOT = {
    "nodeid": "wordpot-node",
    "malwaredir": "/tmp/wordpot/log/payloads",
}

PAYLOAD_SHA = "ab" + "0" * 62
PAYLOAD_REF = f"ab/{PAYLOAD_SHA}.bin"


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message, handles=''):
        self.warnings.append((message, handles))


class FakeAlert:
    def __init__(self, submitted=None):
        self.logger = FakeLogger()
        self.requests = []
        self.submitted = set(submitted or ())

    def md5malware(self, checksum):
        if checksum in self.submitted:
            return(False)
        self.submitted.add(checksum)
        return(True)

    def request(self, key, value):
        self.requests.append((key, value))
        return(True)


def _line(**fields):
    line = {
        "timestamp": "2026-06-15T16:18:25.123456+00:00",
        "request_id": "req-1",
        "profile_id": "wp-6.5",
        "src_ip": "203.0.113.7",
        "src_port": 54321,
        "dest_ip": "8.8.8.8",
        "dest_port": 31337,
        "user_agent": "curl/8.0",
        "browser_family": "curl",
        "browser_version": "8.0",
        "os_family": "Other",
        "device_family": "Other",
        "url": "http://8.8.8.8:31337/wp-login.php?redirect_to=x",
        "method": "POST",
        "path": "/wp-login.php",
        "query": "redirect_to=%2Fwp-admin%2F&reauth=1",
        "headers_subset": {"Host": "8.8.8.8:31337", "Cookie": "secret"},
        "component_type": "core",
        "technique": "credential_attempt",
        "payload_sha256": PAYLOAD_SHA,
        "payload_excerpt": "log=admin&pwd=secret",
        "payload_size": 20,
        "payload_stored": True,
        "payload_ref": PAYLOAD_REF,
        "payload_path": f"/opt/wordpot/logs/payloads/{PAYLOAD_REF}",
        "username": "admin",
        "password": "secret",
        "credentials_observed": {"log": "admin", "pwd": "secret"},
        "response_status": 200,
        "details": {"login_result": "failed", "remember": False},
    }
    line.update(fields)
    return(line)


def _legacy_line(**fields):
    line = {
        "timestamp": "2024-03-01T12:34:56.789000",
        "src_ip": "203.0.113.8",
        "src_port": "40000",
        "dest_ip": "172.17.0.2",
        "dest_port": "8080",
        "browser_family": "Firefox",
        "browser_version": "123.0",
        "os_family": "Linux",
        "os_version": "",
        "device_family": "Other",
        "user_agent": "Mozilla/5.0",
        "url": "http://example.test/wp-content/plugins/revslider/readme.txt",
        "username": "",
        "password": "",
        "plugin": "revslider",
        "filename": "readme.txt",
        "author": "",
        "info": "",
    }
    line.update(fields)
    return(line)


class WordpotEventTests(unittest.TestCase):
    def test_new_format_credential_attempt_is_mapped(self):
        event = wordpot._build_event(_line(), HONEYPOT, ECFG)
        data, request, adata = event["data"], event["request"], event["adata"]

        self.assertEqual(data, {
            "timestamp": "2026-06-15 16:18:25",
            "timezone": "+0000",
            "source_address": "203.0.113.7",
            "target_address": "198.51.100.10",
            "source_port": "54321",
            "target_port": "31337",
            "source_protocol": "tcp",
            "target_protocol": "tcp",
            "analyzer_id": "wordpot-node",
        })
        self.assertEqual(request["description"], "Wordpot Honeypot")
        self.assertEqual(request["url"], "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1")
        self.assertEqual(adata["technique"], "credential_attempt")
        self.assertEqual(adata["component_type"], "core")
        self.assertEqual(adata["method"], "POST")
        self.assertEqual(adata["username"], "admin")
        self.assertEqual(adata["password"], "secret")
        self.assertEqual(adata["response_status"], 200)
        self.assertEqual(adata["payload_size"], 20)
        self.assertEqual(adata["payload_sha256"], PAYLOAD_SHA)
        self.assertEqual(adata["details"], '{"login_result":"failed","remember":false}')
        self.assertEqual(adata["hostname"], "ews-host")
        self.assertEqual(adata["externalIP"], "198.51.100.10")
        self.assertEqual(adata["internalIP"], "10.0.0.10")
        self.assertEqual(adata["uuid"], "test-uuid")

    def test_excluded_fields_are_not_forwarded(self):
        adata = wordpot._build_event(_line(), HONEYPOT, ECFG)["adata"]

        for key in ("headers_subset", "payload_excerpt", "payload_path", "payload_ref", "payload_stored",
                    "credentials_observed", "dest_ip", "url", "query", "path", "timestamp", "src_ip"):
            self.assertNotIn(key, adata)
        self.assertNotIn("8.8.8.8", repr(adata))

    def test_dest_ip_is_never_used_as_target(self):
        for dest_ip in ("8.8.8.8", "::ffff:8.8.8.8", "not-an-ip", None):
            with self.subTest(dest_ip=dest_ip):
                event = wordpot._build_event(_line(dest_ip=dest_ip), HONEYPOT, ECFG)

                self.assertEqual(event["data"]["target_address"], "198.51.100.10")
                self.assertNotIn("8.8.8.8", repr(event))

    def test_invalid_ports_fall_back_to_defaults(self):
        for value in ("abc", 0, 70000, -1, None, True, ""):
            with self.subTest(port=value):
                event = wordpot._build_event(_line(src_port=value, dest_port=value), HONEYPOT, ECFG)

                self.assertEqual(event["data"]["source_port"], "0")
                self.assertEqual(event["data"]["target_port"], "80")

    def test_missing_dest_port_defaults_to_80(self):
        line = _line()
        del line["dest_port"]

        self.assertEqual(wordpot._build_event(line, HONEYPOT, ECFG)["data"]["target_port"], "80")

    def test_legacy_master_line_is_mapped(self):
        event = wordpot._build_event(_legacy_line(), HONEYPOT, ECFG)

        self.assertEqual(event["data"]["timestamp"], "2024-03-01 12:34:56")
        self.assertEqual(event["data"]["timezone"], wordpot.time.strftime('%z'))
        self.assertEqual(event["data"]["source_address"], "203.0.113.8")
        self.assertEqual(event["data"]["source_port"], "40000")
        self.assertEqual(event["data"]["target_address"], "198.51.100.10")
        self.assertEqual(event["data"]["target_port"], "8080")
        self.assertEqual(event["request"]["url"], "/wp-content/plugins/revslider/readme.txt")
        self.assertEqual(event["adata"]["plugin"], "revslider")
        self.assertEqual(event["adata"]["browser_family"], "Firefox")
        for key in ("url", "username", "password", "os_version", "filename", "author", "info", "dest_ip"):
            self.assertNotIn(key, event["adata"])

    def test_timezone_offset_of_the_event_is_kept(self):
        event = wordpot._build_event(_line(timestamp="2026-06-15T18:18:25+02:00"), HONEYPOT, ECFG)

        self.assertEqual(event["data"]["timestamp"], "2026-06-15 18:18:25")
        self.assertEqual(event["data"]["timezone"], "+0200")

    def test_zulu_timestamp_is_parsed(self):
        event = wordpot._build_event(_line(timestamp="2026-06-15T16:18:25Z"), HONEYPOT, ECFG)

        self.assertEqual(event["data"]["timestamp"], "2026-06-15 16:18:25")
        self.assertEqual(event["data"]["timezone"], "+0000")

    def test_ipv4_mapped_source_is_normalized(self):
        event = wordpot._build_event(_line(src_ip="::ffff:203.0.113.7"), HONEYPOT, ECFG)

        self.assertEqual(event["data"]["source_address"], "203.0.113.7")

    def test_invalid_or_missing_source_is_skipped(self):
        for src_ip in ("not-an-ip", "", None, "203.0.113.300"):
            with self.subTest(src_ip=src_ip):
                self.assertIsNone(wordpot._build_event(_line(src_ip=src_ip), HONEYPOT, ECFG))

    def test_invalid_or_missing_timestamp_is_skipped(self):
        for timestamp in ("yesterday", "2026-13-45T99:00:00", "", None):
            with self.subTest(timestamp=timestamp):
                self.assertIsNone(wordpot._build_event(_line(timestamp=timestamp), HONEYPOT, ECFG))

    def test_non_object_lines_are_skipped(self):
        for line in (["a"], "text", 42):
            with self.subTest(line=line):
                self.assertIsNone(wordpot._build_event(line, HONEYPOT, ECFG))

    def test_url_is_built_from_path_and_query(self):
        event = wordpot._build_event(_line(path="/xmlrpc.php", query=None), HONEYPOT, ECFG)
        self.assertEqual(event["request"]["url"], "/xmlrpc.php")

        event = wordpot._build_event(_line(path="/wp-json/wp/v2/users", query="per_page=100"), HONEYPOT, ECFG)
        self.assertEqual(event["request"]["url"], "/wp-json/wp/v2/users?per_page=100")
        self.assertNotIn("url", event["adata"])

    def test_url_is_quoted_and_non_ascii_dropped(self):
        event = wordpot._build_event(_line(path="/a b/<x>ä", query="q=1 2"), HONEYPOT, ECFG)

        self.assertEqual(event["request"]["url"], "/a%20b/%3Cx%3E?q=1%202")

    def test_no_url_without_path_or_url(self):
        line = _line()
        del line["path"], line["url"]

        self.assertNotIn("url", wordpot._build_event(line, HONEYPOT, ECFG)["request"])


class WordpotPayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.malwaredir = Path(self.tmpdir.name) / "payloads"
        self.payload = self.malwaredir / PAYLOAD_REF
        self.payload.parent.mkdir(parents=True)
        self.payload.write_bytes(b"lure-payload-sample")
        self.outside = Path(self.tmpdir.name) / "outside.bin"
        self.outside.write_bytes(b"outside")
        self.hcfg = {"malwaredir": str(self.malwaredir)}
        self.ecfg = dict(ECFG, send_malware=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _upload_line(self, **fields):
        line = _line(technique="upload_lure_payload", component_type="upload",
                     path="/wp-content/uploads/shell.php", query=None)
        line.update(fields)
        return(line)

    def test_nothing_is_sent_when_send_malware_is_false(self):
        alert = FakeAlert()

        self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, ECFG))

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_login_bodies_are_not_sent(self):
        for technique in ("credential_attempt", "xmlrpc_login"):
            with self.subTest(technique=technique):
                alert = FakeAlert()

                self.assertFalse(wordpot._attach_event_payload(alert, _line(technique=technique), self.hcfg, self.ecfg))
                self.assertEqual(alert.requests, [])
                self.assertEqual(alert.submitted, set())

    def test_non_exploit_techniques_are_not_sent(self):
        for technique in ("plugin_probe", "request_too_large", "rest_user_enumeration", "catchall_probe"):
            with self.subTest(technique=technique):
                alert = FakeAlert()
                line = _line(technique=technique, component_type="plugin")

                self.assertFalse(wordpot._attach_event_payload(alert, line, self.hcfg, self.ecfg))
                self.assertEqual(alert.requests, [])

    def test_unstored_payload_is_not_sent(self):
        alert = FakeAlert()

        self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(payload_stored=False), self.hcfg, self.ecfg))
        self.assertEqual(alert.requests, [])

    def test_upload_lure_payload_is_sent_as_binary(self):
        alert = FakeAlert()

        self.assertTrue(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg))

        self.assertEqual(alert.requests, [("binary", base64.b64encode(self.payload.read_bytes()).decode("utf-8"))])
        self.assertEqual(alert.submitted, {PAYLOAD_SHA})

    def test_exploit_techniques_are_sent(self):
        for technique in wordpot.EXPLOIT_TECHNIQUES + ("plugin_lure_payload", "theme_lure_payload"):
            with self.subTest(technique=technique):
                alert = FakeAlert()
                line = _line(technique=technique, component_type="core")

                self.assertTrue(wordpot._attach_event_payload(alert, line, self.hcfg, self.ecfg))
                self.assertEqual(alert.requests[0][0], "binary")

    def test_upload_component_is_sent(self):
        alert = FakeAlert()

        self.assertTrue(wordpot._attach_event_payload(alert, self._upload_line(technique="uploads_probe"), self.hcfg, self.ecfg))
        self.assertEqual(len(alert.requests), 1)

    def test_large_payload_uses_largepayload(self):
        self.payload.write_bytes(b"x" * wordpot.SMALL_PAYLOAD_SIZE)
        alert = FakeAlert()

        wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg)

        self.assertEqual(alert.requests[0][0], "largepayload")

    def test_payload_bigger_than_limit_is_not_sent(self):
        with open(self.payload, "wb") as payload:
            payload.truncate(wordpot.MAX_PAYLOAD_SIZE + 1)
        alert = FakeAlert()

        self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg))
        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_payload_ref_must_stay_inside_malwaredir(self):
        link = self.malwaredir / "ab" / "link.bin"
        os.symlink(self.outside, link)

        for payload_ref in ("../outside.bin", str(self.outside), str(self.payload), "ab/link.bin"):
            with self.subTest(payload_ref=payload_ref):
                alert = FakeAlert()

                self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(payload_ref=payload_ref), self.hcfg, self.ecfg))
                self.assertEqual(alert.requests, [])
                self.assertEqual(alert.submitted, set())
                self.assertEqual(len(alert.logger.warnings), 1)

    def test_payload_path_is_not_used_as_fallback(self):
        line = self._upload_line(payload_path=str(self.payload))
        del line["payload_ref"]
        alert = FakeAlert()

        self.assertFalse(wordpot._attach_event_payload(alert, line, self.hcfg, self.ecfg))
        self.assertEqual(alert.requests, [])

    def test_same_payload_is_sent_once(self):
        alert = FakeAlert()

        self.assertTrue(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg))
        self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg))

        self.assertEqual(len(alert.requests), 1)

    def test_missing_sha256_is_not_sent(self):
        for checksum in (None, ""):
            with self.subTest(checksum=checksum):
                alert = FakeAlert()

                self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(payload_sha256=checksum), self.hcfg, self.ecfg))
                self.assertEqual(alert.requests, [])

    def test_missing_payload_file_is_skipped(self):
        self.payload.unlink()
        alert = FakeAlert()

        self.assertFalse(wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, self.ecfg))
        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_payload_is_removed_after_send_when_configured(self):
        alert = FakeAlert()
        ecfg = dict(self.ecfg, del_malware_after_send=True)

        wordpot._attach_event_payload(alert, self._upload_line(), self.hcfg, ecfg)

        self.assertEqual(len(alert.requests), 1)
        self.assertFalse(self.payload.exists())


if __name__ == "__main__":
    unittest.main()
