import base64
import hashlib
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

EML_FILE = "2026-06-15/203.0.113.7/session/message.eml"
ATTACHMENT_FILE = "2026-06-15/203.0.113.7/session/attachments/a.bin"


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


def _base_line(event_type, **fields):
    line = {
        "event.type": event_type,
        "timestamp": "2026-06-15T16:18:25.123Z",
        "session_id": "session-1",
        "session_start": "2026-06-15T16:18:20.000Z",
        "session_end": "2026-06-15T16:18:25.123Z",
        "session_duration": 5.123,
        "session_outcome": "ok",
        "session_last_response_code": 221,
        "src_ip": "203.0.113.7",
        "src_port": 54321,
        "dest_ip": "198.51.100.20",
        "dest_port": 587,
        "server_name": "mail01.localdomain",
        "listener.name": "submission",
        "listener.port": 587,
        "listener.tls_mode": "starttls",
        "smtp_input": "EHLO client\nQUIT",
        "smtp_input_count": 2,
        "smtp_input_truncated": False,
        "tls.used": False,
    }
    line.update(fields)
    return(line)


def _mail_line(**fields):
    line = _base_line(
        "mail",
        **{
            "mail.timestamp": "2026-06-15T16:18:23.000Z",
            "mail.message_id": "message-1",
            "mail.envelope_from": "alice@example.test",
            "mail.envelope_to": ["bob@example.test"],
            "mail.subject": "Hello",
            "mail.eml_file": EML_FILE,
            "mail.eml_size": 24,
            "mail.truncated": False,
            "attachment.count": 1,
            "attachment.files": [ATTACHMENT_FILE],
            "attachment.filenames": ["a.bin"],
            "attachment.sha256": ["attachment-sha"],
        },
    )
    line.update(fields)
    return(line)


class MailoneyEventTests(unittest.TestCase):
    def test_unsupported_events_are_skipped(self):
        for line in (
            {"event.type": "rate_limit_block", "timestamp": "2026-06-15T16:18:25.123Z", "src_ip": "203.0.113.7"},
            {"timestamp": "2026-06-15T16:18:25.123Z", "src_ip": "203.0.113.7", "data": {"EHLO User": "x"}},
            {"event.type": "unknown", "timestamp": "2026-06-15T16:18:25.123Z", "src_ip": "203.0.113.7"},
        ):
            with self.subTest(line=line):
                self.assertIsNone(mailoney._build_event(line, HONEYPOT, ECFG))

    def test_mail_auth_and_session_events_are_mapped(self):
        for event_type in ("mail", "auth", "session"):
            with self.subTest(event_type=event_type):
                event = mailoney._build_event(_base_line(event_type), HONEYPOT, ECFG)

                self.assertEqual(event["data"]["analyzer_id"], "mailoney-node")
                self.assertEqual(event["data"]["timezone"], "+0000")
                self.assertEqual(event["data"]["source_address"], "203.0.113.7")
                self.assertEqual(event["data"]["source_port"], "54321")
                self.assertEqual(event["data"]["target_address"], "198.51.100.20")
                self.assertEqual(event["data"]["target_port"], "587")
                self.assertEqual(event["request"]["description"], f"Mail Honeypot mailoney ({event_type})")
                self.assertEqual(event["adata"]["listener.name"], "submission")
                self.assertEqual(event["adata"]["tls.used"], "false")
                self.assertEqual(event["adata"]["hostname"], "ews-host")

    def test_session_result_fields_are_forwarded(self):
        line = _base_line(
            "session",
            session_outcome="timeout",
            session_last_response_code=421,
            smtp_input_count=1001,
            smtp_input_truncated=True,
            errors=["connection timed out after 30s"],
        )
        line["auth.count"] = 0

        adata = mailoney._build_event(line, HONEYPOT, ECFG)["adata"]

        self.assertEqual(adata["session_id"], "session-1")
        self.assertEqual(adata["session_outcome"], "timeout")
        self.assertEqual(adata["session_last_response_code"], 421)
        self.assertEqual(adata["smtp_input_count"], 1001)
        self.assertEqual(adata["smtp_input_truncated"], "true")
        self.assertEqual(adata["smtp_input"], "EHLO client\nQUIT")
        self.assertEqual(adata["errors"], '["connection timed out after 30s"]')
        self.assertEqual(adata["auth.count"], 0)

    def test_auth_fields_are_forwarded(self):
        line = _base_line(
            "auth",
            **{
                "auth.timestamp": "2026-06-15T16:18:21.000Z",
                "auth.method": "login",
                "auth.raw": "dXNlcg==:cGFzcw==",
                "auth.username": "user",
                "auth.password": "pass",
            },
        )

        event = mailoney._build_event(line, HONEYPOT, ECFG)

        self.assertEqual(event["data"]["timestamp"], "2026-06-15 16:18:21")
        self.assertEqual(event["adata"]["auth.method"], "login")
        self.assertEqual(event["adata"]["auth.username"], "user")
        self.assertEqual(event["adata"]["auth.password"], "pass")
        self.assertNotIn("mail.subject", event["adata"])

    def test_mail_fields_are_forwarded_without_local_paths(self):
        event = mailoney._build_event(_mail_line(**{"tls.cert_file": "/opt/mailoney/log/tls/server.crt"}), HONEYPOT, ECFG)
        adata = event["adata"]

        self.assertEqual(event["data"]["timestamp"], "2026-06-15 16:18:23")
        self.assertEqual(adata["mail.envelope_to"], '["bob@example.test"]')
        self.assertEqual(adata["mail.subject"], "Hello")
        self.assertEqual(adata["mail.truncated"], "false")
        self.assertEqual(adata["attachment.count"], 1)
        self.assertEqual(adata["attachment.sha256"], '["attachment-sha"]')
        for key in ("mail.eml_file", "attachment.files", "tls.cert_file", "server_name",
                    "timestamp", "src_ip", "dest_port", "listener.port", "session_start", "auth.count"):
            self.assertNotIn(key, adata)

    def test_session_start_is_used_without_event_timestamp(self):
        event = mailoney._build_event(_base_line("session"), HONEYPOT, ECFG)

        self.assertEqual(event["data"]["timestamp"], "2026-06-15 16:18:20")

    def test_ipv4_mapped_addresses_are_normalized(self):
        line = _base_line("session", src_ip="::ffff:203.0.113.7", dest_ip="::ffff:198.51.100.20")

        event = mailoney._build_event(line, HONEYPOT, ECFG)

        self.assertEqual(event["data"]["source_address"], "203.0.113.7")
        self.assertEqual(event["data"]["target_address"], "198.51.100.20")

    def test_dest_port_overrides_listener_port_and_missing_dest_ip_uses_external_ip(self):
        line = _base_line("mail", dest_port=2525)
        del line["dest_ip"]

        event = mailoney._build_event(line, HONEYPOT, ECFG)

        self.assertEqual(event["data"]["target_address"], "198.51.100.10")
        self.assertEqual(event["data"]["target_port"], "2525")


class MailoneyPayloadTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.malwaredir = Path(self.tmpdir.name) / "mails"
        self.eml = self.malwaredir / EML_FILE
        self.attachment = self.malwaredir / ATTACHMENT_FILE
        self.attachment.parent.mkdir(parents=True)
        self.eml.write_bytes(b"Subject: hello\r\n\r\nBody")
        self.attachment.write_bytes(b"sample")
        self.hcfg = {"malwaredir": str(self.malwaredir)}
        self.ecfg = dict(ECFG, send_malware=True)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_payload_files_are_not_read_when_send_malware_is_false(self):
        alert = FakeAlert()

        mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, ECFG)

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_only_mail_events_carry_payloads(self):
        alert = FakeAlert()

        mailoney._attach_event_payloads(alert, _mail_line(**{"event.type": "session"}), self.hcfg, self.ecfg)

        self.assertEqual(alert.requests, [])

    def test_first_attachment_is_the_single_payload(self):
        alert = FakeAlert()

        self.assertTrue(mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, self.ecfg))

        self.assertEqual(alert.requests, [("binary", base64.b64encode(b"sample").decode("utf-8"))])
        self.assertEqual(alert.submitted, {"attachment-sha"})

    def test_next_new_attachment_is_used_when_first_was_submitted(self):
        second = self.attachment.parent / "b.bin"
        second.write_bytes(b"second")
        line = _mail_line(**{
            "attachment.files": [ATTACHMENT_FILE, ATTACHMENT_FILE.replace("a.bin", "b.bin")],
            "attachment.sha256": ["attachment-sha", "second-sha"],
        })
        alert = FakeAlert(submitted={"attachment-sha"})

        mailoney._attach_event_payloads(alert, line, self.hcfg, self.ecfg)

        self.assertEqual(alert.requests, [("binary", base64.b64encode(b"second").decode("utf-8"))])

    def test_known_attachment_does_not_fall_back_to_eml(self):
        alert = FakeAlert(submitted={"attachment-sha"})

        self.assertFalse(mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, self.ecfg))

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, {"attachment-sha"})

    def test_eml_is_sent_for_mail_without_attachments(self):
        line = _mail_line(**{"attachment.count": 0, "attachment.files": [], "attachment.sha256": []})
        alert = FakeAlert()

        self.assertTrue(mailoney._attach_event_payloads(alert, line, self.hcfg, self.ecfg))

        self.assertEqual(alert.requests, [("binary", base64.b64encode(self.eml.read_bytes()).decode("utf-8"))])
        self.assertEqual(alert.submitted, {hashlib.sha256(self.eml.read_bytes()).hexdigest()})

        """ the same content is not submitted twice """
        mailoney._attach_event_payloads(alert, line, self.hcfg, self.ecfg)
        self.assertEqual(len(alert.requests), 1)

    def test_large_payload_uses_largepayload(self):
        self.attachment.write_bytes(b"x" * (mailoney.SMALL_PAYLOAD_SIZE + 1))
        alert = FakeAlert()

        mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, self.ecfg)

        self.assertEqual(alert.requests[0][0], "largepayload")

    def test_payload_path_must_stay_inside_malwaredir(self):
        line = _mail_line(**{"attachment.files": ["../outside.bin"], "attachment.sha256": ["outside-sha"]})
        alert = FakeAlert()

        mailoney._attach_event_payloads(alert, line, self.hcfg, self.ecfg)

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())
        self.assertEqual(len(alert.logger.warnings), 1)

    def test_missing_attachment_file_is_skipped(self):
        self.attachment.unlink()
        alert = FakeAlert()

        mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, self.ecfg)

        self.assertEqual(alert.requests, [])
        self.assertEqual(alert.submitted, set())

    def test_payload_is_removed_after_send_when_configured(self):
        alert = FakeAlert()
        ecfg = dict(self.ecfg, del_malware_after_send=True)

        mailoney._attach_event_payloads(alert, _mail_line(), self.hcfg, ecfg)

        self.assertEqual(len(alert.requests), 1)
        self.assertFalse(self.attachment.exists())


if __name__ == "__main__":
    unittest.main()
