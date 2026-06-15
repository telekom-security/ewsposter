import base64
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "mailoney_module",
    ROOT / "honeypots" / "mailoney.py",
)
mailoney = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mailoney)


ECFG = {
    "hostname": "ews-host",
    "ip_ext": "198.51.100.10",
    "ip_int": "10.0.0.10",
    "uuid": "test-uuid",
    "send_malware": False,
    "del_malware_after_send": False,
}

HONEYPOT = {
    "nodeid": "mailoney-node",
    "malwaredir": "/tmp/mailoney/log/mails",
}


class FakeLogger:
    def __init__(self):
        self.warnings = []

    def warning(self, message, handles=''):
        self.warnings.append((message, handles))


class FakeAlert:
    def __init__(self):
        self.logger = FakeLogger()
        self.requests = []
        self.submitted = set()

    def md5malware(self, checksum):
        if checksum in self.submitted:
            return(False)
        self.submitted.add(checksum)
        return(True)

    def request(self, key, value):
        self.requests.append((key, value))
        return(True)


class MailoneyEventTests(unittest.TestCase):
    def test_rate_limit_events_are_skipped(self):
        line = {
            "event.type": "rate_limit_block",
            "timestamp": "2026-06-15T16:18:25.123Z",
            "src_ip": "203.0.113.7",
        }

        self.assertIsNone(mailoney._build_event(line, HONEYPOT, ECFG))

    def test_mail_auth_and_session_events_are_mapped(self):
        for event_type in ("mail", "auth", "session"):
            with self.subTest(event_type=event_type):
                line = {
                    "event.type": event_type,
                    "timestamp": "2026-06-15T16:18:25.123Z",
                    "src_ip": "203.0.113.7",
                    "src_port": 54321,
                    "dest_ip": "198.51.100.20",
                    "listener.port": 587,
                    "mail.envelope_to": ["bob@example.test"],
                    "tls.used": False,
                    "attachment.count": 0,
                    "nested": {"a": 1},
                }

                event = mailoney._build_event(line, HONEYPOT, ECFG)

                self.assertEqual(event["data"]["analyzer_id"], "mailoney-node")
                self.assertEqual(event["data"]["timestamp"], "2026-06-15 16:18:25")
                self.assertEqual(event["data"]["timezone"], "+0000")
                self.assertEqual(event["data"]["source_address"], "203.0.113.7")
                self.assertEqual(event["data"]["source_port"], "54321")
                self.assertEqual(event["data"]["target_address"], "198.51.100.20")
                self.assertEqual(event["data"]["target_port"], "587")
                self.assertEqual(event["request"]["description"], f"Mail Honeypot mailoney ({event_type})")
                self.assertEqual(event["adata"]["mail.envelope_to"], '["bob@example.test"]')
                self.assertEqual(event["adata"]["nested"], '{"a":1}')
                self.assertIs(event["adata"]["tls.used"], False)
                self.assertEqual(event["adata"]["attachment.count"], 0)

    def test_dest_port_overrides_listener_port_and_missing_dest_ip_uses_external_ip(self):
        line = {
            "event.type": "mail",
            "timestamp": "2026-06-15T16:18:25Z",
            "src_ip": "203.0.113.7",
            "src_port": 54321,
            "dest_port": 2525,
            "listener.port": 587,
        }

        event = mailoney._build_event(line, HONEYPOT, ECFG)

        self.assertEqual(event["data"]["target_address"], "198.51.100.10")
        self.assertEqual(event["data"]["target_port"], "2525")

    def test_payload_files_are_not_read_when_send_malware_is_false(self):
        alert = FakeAlert()
        line = {
            "mail.eml_file": "2026-06-15/203.0.113.7/session/message.eml",
            "attachment.files": ["2026-06-15/203.0.113.7/session/attachments/a.bin"],
            "attachment.sha256": ["attachment-sha"],
        }

        mailoney._attach_event_payloads(alert, line, HONEYPOT, ECFG)

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_payload_files_are_attached_from_malwaredir_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            malwaredir = Path(tmpdir) / "mails"
            eml = malwaredir / "2026-06-15" / "203.0.113.7" / "session" / "message.eml"
            attachment = eml.parent / "attachments" / "a.bin"
            eml.parent.mkdir(parents=True)
            attachment.parent.mkdir(parents=True)
            eml.write_bytes(b"Subject: hello\r\n\r\nBody")
            attachment.write_bytes(b"sample")

            alert = FakeAlert()
            hcfg = {"malwaredir": str(malwaredir)}
            ecfg = dict(ECFG, send_malware=True)
            line = {
                "mail.eml_file": "2026-06-15/203.0.113.7/session/message.eml",
                "attachment.files": ["2026-06-15/203.0.113.7/session/attachments/a.bin"],
                "attachment.sha256": ["attachment-sha"],
            }

            mailoney._attach_event_payloads(alert, line, hcfg, ecfg)

            self.assertEqual(len(alert.requests), 2)
            self.assertEqual(alert.requests[0][0], "binary")
            self.assertEqual(alert.requests[0][1], base64.b64encode(eml.read_bytes()).decode("utf-8"))
            self.assertEqual(alert.requests[1][0], "binary")
            self.assertEqual(alert.requests[1][1], base64.b64encode(attachment.read_bytes()).decode("utf-8"))
            self.assertEqual(
                alert.submitted,
                {
                    "mailoney:eml:2026-06-15/203.0.113.7/session/message.eml",
                    "mailoney:attachment:attachment-sha",
                },
            )

    def test_payload_path_must_stay_inside_malwaredir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            alert = FakeAlert()
            hcfg = {"malwaredir": str(Path(tmpdir) / "mails")}
            ecfg = dict(ECFG, send_malware=True)
            line = {"mail.eml_file": "../outside.eml"}

            mailoney._attach_event_payloads(alert, line, hcfg, ecfg)

            self.assertEqual(alert.requests, [])
            self.assertEqual(len(alert.logger.warnings), 1)


if __name__ == "__main__":
    unittest.main()
