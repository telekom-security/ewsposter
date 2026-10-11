"""Ciscoasa legacy/v2 event compatibility; stdlib only, no live EWS server."""
import importlib.util
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

class Alert:
    def __init__(self, records):
        self.records = list(records) + [{}]
        self.sent = []
        self.current = {}
    def readCFG(self, *_):
        return {'ciscoasa': 'true', 'nodeid': 'test', 'logfile': 'unused'}
    def lineREAD(self, *_):
        return self.records.pop(0)
    def data(self, key, value):
        self.current[key] = value
    def request(self, key, value):
        self.current[key] = value
    def adata(self, *_):
        pass
    def buildAlert(self):
        self.sent.append(self.current)
        self.current = {}
    def finAlert(self):
        pass

class CiscoasaTest(unittest.TestCase):
    def parse(self, records):
        alert = Alert(records)
        stub = types.ModuleType('modules.ealert')
        stub.EAlert = lambda *_: alert
        with patch.dict(sys.modules, {'modules.ealert': stub}):
            spec = importlib.util.spec_from_file_location('ciscoasa_test_parser', ROOT / 'honeypots/ciscoasa.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.ciscoasa({'cfgfile': 'unused', 'ip_ext': '198.51.100.1',
                             'hostname': 'test', 'ip_int': '192.0.2.1', 'uuid': 'test'})
        return alert.sent

    def test_v2_http(self):
        event = self.parse([{'timestamp': '2026-10-11T10:00:00Z', 'src_ip': '192.0.2.2',
                            'src_port': 12345, 'dest_port': 8443, 'protocol': 'tcp', 'payload': 'inert'}])[0]
        self.assertEqual(event['source_port'], '12345')
        self.assertEqual(event['target_port'], '8443')
        self.assertEqual(event['source_protocol'], 'tcp')
        self.assertEqual(event['payload'], 'inert')
        self.assertEqual(event['timestamp'], '2026-10-11 10:00:00')

    def test_v2_ike_both_ports(self):
        for port in (500, 4500):
            event = self.parse([{'src_ip': '192.0.2.2', 'src_port': 500, 'dest_port': port,
                                'protocol': 'udp', 'payload': 'IKE'}])[0]
            self.assertEqual(event['target_port'], str(port))
            self.assertEqual(event['source_protocol'], 'udp')
            self.assertEqual(event['target_protocol'], 'udp')

    def test_legacy_payload_without_gate_key(self):
        event = self.parse([{'src_ip': '192.0.2.2', 'payload_printable': 'legacy'}])[0]
        self.assertEqual(event['payload'], 'legacy')
        self.assertEqual(event['source_port'], '0')
        self.assertEqual(event['target_port'], '8443')
        self.assertEqual(event['target_protocol'], 'tcp')

    def test_new_payload_preferred_and_missing_optional_fields(self):
        events = self.parse([{'payload': 'new', 'payload_printable': 'old'}, {'src_ip': '192.0.2.2'}])
        self.assertEqual(events[0]['payload'], 'new')
        self.assertNotIn('payload', events[1])

    def test_bad_optional_ports_and_protocol_use_legacy_defaults(self):
        event = self.parse([{'src_port': 'invalid', 'dest_port': -1, 'protocol': 'bad'}])[0]
        self.assertEqual(event['source_port'], '0')
        self.assertEqual(event['target_port'], '8443')
        self.assertEqual(event['source_protocol'], 'tcp')

    def test_status_version_and_invalid_json_are_skipped(self):
        self.assertEqual(self.parse(['jsonfail', {'Status': 'ready'}, {'Version': 'old'}]), [])

if __name__ == '__main__':
    unittest.main()
