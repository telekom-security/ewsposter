import importlib.util
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "honeypots", "beelzebub.py")


def load_beelzebub():
    """ load honeypots/beelzebub.py with a stand-in for modules.ealert, sys.modules stays as it was """
    modules = types.ModuleType("modules")
    ealert = types.ModuleType("modules.ealert")
    ealert.EAlert = object
    with mock.patch.dict(sys.modules, {"modules": modules, "modules.ealert": ealert}):
        spec = importlib.util.spec_from_file_location("beelzebub_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


beelzebub_module = load_beelzebub()


class FakeEAlert:
    """ records the alerts beelzebub() builds from the given log lines; the session index lives in `index` """

    lines = []
    index = []

    def __init__(self, MODUL, ECFG):
        self.queue = list(self.lines)
        self.alerts = []
        self.current = {"data": {}, "request": {}, "adata": {}}
        FakeEAlert.last = self

    def readCFG(self, items, cfgfile):
        return {"beelzebub": "true", "nodeid": "beelzebub-test", "logfile": "beelzebub.json"}

    def fileIndex(self, name, action, session=None):
        if action == "write":
            FakeEAlert.index.append(session)
        return list(FakeEAlert.index)

    def alertCount(self, section, counting, item="index"):
        return ()

    def lineREAD(self, filename, format="json"):
        return self.queue.pop(0) if self.queue else ()

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
NOW = datetime.now(timezone.utc)


def ts(seconds_ago=0):
    return (NOW - timedelta(seconds=seconds_ago)).strftime("%Y-%m-%dT%H:%M:%S.123456789Z")


def line(message, status, session, protocol, **fields):
    """ one line of the flat T-Pot log of Beelzebub (docker/beelzebub/dist/tpot) """
    entry = {"level": "info", "timestamp": fields.pop("timestamp", ts()), "message": message, "msg": message,
             "status": status, "protocol": protocol, "session": session}
    entry.update(fields)
    return entry


def run(lines, index=()):
    FakeEAlert.lines = lines
    FakeEAlert.index = list(index)
    with mock.patch.object(beelzebub_module, "EAlert", FakeEAlert):
        beelzebub_module.beelzebub(ECFG)
    return FakeEAlert.last.alerts


class BeelzebubServicesTest(unittest.TestCase):
    def test_http_request(self):
        alerts = run([line("HTTP New request", "Stateless", "h1", "HTTP", src_ip="198.51.100.1", src_port="40001",
                           dest_port="80", service="Wordpress 6.0", request_method="GET",
                           request_uri="/wp-login.php?x=a b", userAgent="curl/8.0", hostname="192.0.2.1",
                           body="", request_cookies="")])
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert["data"]["source_address"], "198.51.100.1")
        self.assertEqual(alert["data"]["target_address"], "203.0.113.10")
        self.assertEqual(alert["data"]["target_port"], "80")
        self.assertEqual(alert["data"]["timezone"], "+0000")
        self.assertEqual(alert["request"]["url"], "/wp-login.php?x=a%20b")
        self.assertEqual(alert["adata"]["protocol"], "HTTP")
        self.assertEqual(alert["adata"]["httpmethod"], "GET")
        self.assertEqual(alert["adata"]["user_agent"], "curl/8.0")
        self.assertEqual(alert["adata"]["http_host"], "192.0.2.1")
        self.assertEqual(alert["adata"]["service"], "Wordpress 6.0")
        self.assertNotIn("body", alert["adata"])

    def test_tcp_session_until_end(self):
        lines = [
            line("New TCP Session", "Start", "t1", "TCP", src_ip="198.51.100.2", src_port="40002", dest_port="6379",
                 service="Redis 7.0.12"),
            line("TCP Session Interaction", "Interaction", "t1", "TCP", src_ip="198.51.100.2", src_port="40002",
                 dest_port="6379", command="PING", input_duration="0.10s"),
            line("TCP Session Interaction", "Interaction", "t1", "TCP", src_ip="198.51.100.2", src_port="40002",
                 dest_port="6379", command="INFO"),
        ]
        self.assertEqual(run(lines), [])
        lines.append(line("End TCP Session", "End", "t1", "TCP", src_ip="198.51.100.2", src_port="40002",
                          dest_port="6379", session_duration="1.00s"))
        alerts = run(lines)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["adata"]["input"], "PING;INFO")
        self.assertEqual(alerts[0]["adata"]["type"], "End TCP Session")
        self.assertIn("logouttime", alerts[0]["adata"])
        self.assertEqual(run(lines, index=FakeEAlert.index), [])

    def test_tcp_attempt_telnet_login_and_mcp(self):
        alerts = run([
            line("New TCP attempt", "Stateless", "a1", "TCP", src_ip="198.51.100.3", src_port="40003",
                 dest_port="445", command="probe"),
            line("New TELNET Login Attempt", "Stateless", "a2", "TELNET", src_ip="198.51.100.4", src_port="40004",
                 dest_port="23", username="admin", password="admin"),
            line("New MCP tool invocation", "Stateless", "a3", "MCP", src_ip="198.51.100.5", src_port="40005",
                 dest_port="8000", input="tool.list|{}"),
        ])
        self.assertEqual([a["adata"]["protocol"] for a in alerts], ["TCP", "TELNET", "MCP"])
        self.assertEqual(alerts[0]["adata"]["input"], "probe")
        self.assertEqual(alerts[1]["adata"]["username"], "admin")
        self.assertEqual(alerts[1]["adata"]["password"], "admin")
        self.assertEqual(alerts[2]["adata"]["input"], "tool.list|{}")

    def test_ssh_session_and_inline_command(self):
        alerts = run([
            line("New SSH attempt", "Stateless", "s0", "SSH", src_ip="198.51.100.6", src_port="40006",
                 dest_port="22", username="root", password="1234", client="SSH-2.0-Go"),
            line("New SSH Session", "Start", "s1", "SSH", src_ip="198.51.100.6", src_port="40006", dest_port="22",
                 username="root", input="", client_version="SSH-2.0-Go"),
            line("New SSH Terminal Session", "Interaction", "s1", "SSH", src_ip="198.51.100.6", src_port="40006",
                 dest_port="22", input="uname -a"),
            line("End SSH Session", "End", "s1", "SSH", src_ip="198.51.100.6", src_port="40006", dest_port="22"),
            line("New SSH Inline Session", "Start", "s2", "SSH", src_ip="198.51.100.7", src_port="40007",
                 dest_port="22", input="id"),
            line("End SSH Inline Session", "End", "s2", "SSH", src_ip="198.51.100.7", src_port="40007",
                 dest_port="22", session_duration="0.00s"),
        ])
        self.assertEqual(len(alerts), 3)
        self.assertEqual(alerts[0]["adata"]["client"], "SSH-2.0-Go")
        self.assertEqual(alerts[1]["adata"]["input"], "uname -a")
        self.assertEqual(alerts[1]["adata"]["client_version"], "SSH-2.0-Go")
        self.assertEqual(alerts[2]["adata"]["input"], "id")

    def test_session_without_end_after_ttl(self):
        lines = [line("New TELNET Terminal Session", "Start", "x1", "TELNET", timestamp=ts(3 * 3600),
                      src_ip="198.51.100.8", src_port="40008", dest_port="23", username="root"),
                 line("New TELNET Terminal Session", "Start", "x2", "TELNET", timestamp=ts(60),
                      src_ip="198.51.100.9", src_port="40009", dest_port="23", username="root")]
        alerts = run(lines)
        self.assertEqual([a["adata"]["sessionid"] for a in alerts], ["x1"])

    def test_lines_without_session_or_json(self):
        self.assertEqual(run(["jsonfail", {"message": "no session"}, ["list"]]), [])


if __name__ == "__main__":
    unittest.main()
