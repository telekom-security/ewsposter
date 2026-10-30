import base64
import importlib
import json
import sys
import types
import unittest
from unittest.mock import Mock, patch

with patch.dict(sys.modules, {"modules.ealert": types.SimpleNamespace(EAlert=Mock())}):
    parser = importlib.import_module("honeypots.glutton")


class GluttonTest(unittest.TestCase):
    def session(self, **changes):
        event = {"event_kind": "session", "timestamp": "2026-10-29T12:34:56.123456789Z",
                 "transport": "udp", "srcHost": "192.0.2.1", "srcPort": "12345",
                 "dstPort": 5060, "handler": "sip", "payload": "AP+A",
                 "handlers": ["udp", "sip"], "scanner": "example", "tls": {"ja4": "fingerprint"},
                 "endReason": "handler_close", "frameCount": 2, "durationMs": 25,
                 "decoded": [{"command": "OPTIONS"}]}
        event.update(changes)
        return event

    def legacy(self, **changes):
        event = {"ts": 0, "level": "info", "src_ip": "192.0.2.1", "src_port": "23456",
                 "dest_port": "80", "handler": "http", "payload_hex": "00ff80"}
        event.update(changes)
        return event

    def test_structured_session(self):
        event = parser._event(self.session())
        self.assertEqual(event["source_protocol"], "udp")
        self.assertEqual(event["target_protocol"], "udp")
        self.assertEqual(base64.b64decode(event["binary"]), b"\x00\xff\x80")
        self.assertEqual(event["timestamp"], "2026-10-29 12:34:56")
        self.assertEqual(event["timezone"], "+0000")
        metadata = json.loads(event["metadata"])
        for key in ("handlers", "scanner", "tls", "endReason", "decoded", "durationMs", "frameCount"):
            self.assertEqual(metadata[key], self.session()[key])

    def test_upstream_envelope_without_tpot_marker(self):
        event = self.session(transport="tcp")
        del event["event_kind"]
        self.assertEqual(parser._event(event)["source_protocol"], "tcp")

    def test_legacy_unix_hex_and_tcp(self):
        event = parser._event(self.legacy())
        self.assertEqual(event["timestamp"], "1970-01-01 00:00:00")
        self.assertEqual(event["source_protocol"], "tcp")
        self.assertEqual(base64.b64decode(event["binary"]), b"\x00\xff\x80")

    def test_slog_time_and_offset(self):
        event = parser._event(self.legacy(time="2026-10-29T14:34:56.123+02:00", level="INFO"))
        self.assertEqual(event["timestamp"], "2026-10-29 12:34:56")
        self.assertEqual(event["timezone"], "+0000")

    def test_udp_and_application_protocol_are_distinct(self):
        for changes in ({"msg": "SIP UDP packet received", "handler": "sip"},
                        {"protocol": "udp"}, {"handler": "dtls", "protocol": "dtls"}):
            with self.subTest(changes=changes):
                self.assertEqual(parser._event(self.legacy(**changes))["source_protocol"], "udp")
        self.assertEqual(parser._event(self.legacy(protocol="http"))["source_protocol"], "tcp")

    def test_diagnostics_are_not_attacks(self):
        for level in ("ERROR", "error", "WARN", "warning", "DEBUG"):
            self.assertIsNone(parser._event(self.legacy(level=level)))
        self.assertIsNone(parser._event({"level": "INFO", "msg": "All done"}))
        self.assertIsNone(parser._event(self.session(event_kind="diagnostic")))
        self.assertIsNone(parser._event([]))

    def test_invalid_input_is_rejected(self):
        for changes in ({"timestamp": "bad"}, {"timestamp": "2026-10-29T12:34:56"},
                        {"srcHost": "bad"}, {"srcPort": True}, {"dstPort": 65536},
                        {"transport": "sip"}, {"transport": None}, {"payload": "bad!"}):
            with self.subTest(changes=changes), self.assertRaises((ValueError, TypeError)):
                parser._event(self.session(**changes))
        for value in (None, True, float("nan"), float("inf")):
            with self.subTest(ts=value), self.assertRaises((ValueError, OverflowError)):
                parser._event(self.legacy(ts=value))
        with self.assertRaises(ValueError):
            parser._event(self.legacy(payload_hex="z0"))

    def test_loop_reports_invalid_line_and_finishes(self):
        alert = Mock()
        alert.readCFG.return_value = {"glutton": "true", "nodeid": "glutton-1", "logfile": "/log"}
        alert.lineREAD.side_effect = ["jsonfail", self.session(payload="bad!"), self.session(), ""]
        alert.buildAlert.return_value = True
        config = {"cfgfile": "cfg", "ip_ext": "203.0.113.1", "hostname": "sensor", "ip_int": "192.0.2.10", "uuid": "uuid"}
        with patch.object(parser, "EAlert", return_value=alert):
            parser.glutton(config)
        alert.logger.warning.assert_called_once()
        alert.buildAlert.assert_called_once()
        alert.data.assert_any_call("source_protocol", "udp")
        alert.request.assert_any_call("binary", "AP+A")
        alert.finAlert.assert_called_once()

    def test_sendlimit_and_disabled_module(self):
        alert = Mock()
        alert.readCFG.return_value = {"glutton": "true", "nodeid": "g", "logfile": "/log"}
        alert.lineREAD.side_effect = [self.session()]
        alert.buildAlert.return_value = "sendlimit"
        config = {"cfgfile": "cfg", "ip_ext": "203.0.113.1", "hostname": "sensor", "ip_int": "192.0.2.10", "uuid": "uuid"}
        with patch.object(parser, "EAlert", return_value=alert):
            parser.glutton(config)
        alert.finAlert.assert_called_once()
        alert.reset_mock()
        alert.readCFG.return_value = {"glutton": "false"}
        with patch.object(parser, "EAlert", return_value=alert):
            parser.glutton(config)
        alert.lineREAD.assert_not_called()

    def test_loop_finishes_at_empty_tuple_eof(self):
        alert = Mock()
        alert.readCFG.return_value = {"glutton": "true", "nodeid": "g", "logfile": "/log"}
        alert.lineREAD.side_effect = [self.session(), ()]
        alert.buildAlert.return_value = True
        config = {"cfgfile": "cfg", "ip_ext": "203.0.113.1", "hostname": "sensor", "ip_int": "192.0.2.10", "uuid": "uuid"}
        with patch.object(parser, "EAlert", return_value=alert):
            parser.glutton(config)
        alert.buildAlert.assert_called_once()
        alert.finAlert.assert_called_once()

    def test_loop_skips_non_record_json_values(self):
        alert = Mock()
        alert.readCFG.return_value = {"glutton": "true", "nodeid": "g", "logfile": "/log"}
        alert.lineREAD.side_effect = [[], False, 0, self.session(), ""]
        alert.buildAlert.return_value = True
        config = {"cfgfile": "cfg", "ip_ext": "203.0.113.1", "hostname": "sensor", "ip_int": "192.0.2.10", "uuid": "uuid"}
        with patch.object(parser, "EAlert", return_value=alert):
            parser.glutton(config)
        alert.buildAlert.assert_called_once()
        alert.finAlert.assert_called_once()


if __name__ == "__main__":
    unittest.main()
