import importlib.util
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

import requests


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "etoolbox.py")


class FakeLog:
    """ records the messages of ELog instead of writing ews.log (ELog needs an ews.cfg) """

    def __init__(self, modul):
        self.messages = []

    def __getattr__(self, level):
        if level in ("debug", "info", "warning", "error"):
            return lambda msg, handles="": self.messages.append((level, msg, handles))
        raise AttributeError(level)


def load_etoolbox():
    modules = types.ModuleType("modules")
    modules.__path__ = []
    elog = types.ModuleType("modules.elog")
    elog.ELog = FakeLog
    with mock.patch.dict(sys.modules, {"modules": modules, "modules.elog": elog}):
        spec = importlib.util.spec_from_file_location("etoolbox_under_test", MODULE_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


etoolbox = load_etoolbox()


class FakeSocket:
    def __init__(self, *args):
        pass

    def connect(self, address):
        pass

    def getsockname(self):
        return ("10.0.0.5", 40000)

    def close(self):
        pass


class Answer:
    def __init__(self, text, status=200):
        self.text = text
        self.status = status

    def raise_for_status(self):
        if self.status >= 400:
            raise requests.exceptions.HTTPError(f"{self.status}")


class GetIPTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.ecfg = {"path": self.tmpdir.name, "ip_int": "None", "ip_ext": "None"}
        patches = [
            mock.patch.object(etoolbox.socket, "socket", FakeSocket),
            mock.patch.dict(os.environ, {}, clear=False),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        os.environ.pop("MY_INTIP", None)
        os.environ.pop("MY_EXTIP", None)
        etoolbox.logger.messages.clear()

    def tearDown(self):
        self.tmpdir.cleanup()

    def write_ews_ip(self, ip_ext):
        with open(os.path.join(self.tmpdir.name, "ews.ip"), "w") as handle:
            handle.write(f"[EWSIP]\nip_int = 10.0.0.5\nip_ext = {ip_ext}\n")

    def run_getip(self, answer=None, error=None):
        def fake_get(url, timeout):
            fake_get.calls.append(url)
            if error is not None:
                raise error
            return answer
        fake_get.calls = []
        with mock.patch.object(etoolbox.requests, "get", fake_get):
            result = etoolbox.getIP("EINIT", self.ecfg)
        return result, fake_get.calls

    def test_no_lookup_when_the_config_names_the_external_ip(self):
        self.ecfg["ip_ext"] = "203.0.113.10"
        result, calls = self.run_getip(Answer("198.51.100.1"))
        self.assertEqual(calls, [])
        self.assertEqual(result["connect_ip_ext"], "")

    def test_no_lookup_when_the_environment_names_the_external_ip(self):
        os.environ["MY_EXTIP"] = "203.0.113.11"
        result, calls = self.run_getip(Answer("198.51.100.1"))
        self.assertEqual(calls, [])
        self.assertEqual(result["env_ip_ext"], "203.0.113.11")

    def test_no_lookup_when_ews_ip_names_the_external_ip(self):
        self.write_ews_ip("203.0.113.12")
        result, calls = self.run_getip(Answer("198.51.100.1"))
        self.assertEqual(calls, [])
        self.assertEqual(result["file_ip_ext"], "203.0.113.12")

    def test_lookup_when_no_source_names_the_external_ip(self):
        for value in ("None", "none", "", None):
            with self.subTest(value=value):
                self.ecfg["ip_ext"] = value
                result, calls = self.run_getip(Answer("198.51.100.1\n"))
                self.assertEqual(len(calls), 1)
                self.assertEqual(result["connect_ip_ext"], "198.51.100.1")

    def test_failed_lookup_is_a_warning(self):
        for error in (requests.exceptions.ConnectionError("unreachable"), requests.exceptions.Timeout("slow"),
                      requests.exceptions.TooManyRedirects("loop")):
            with self.subTest(error=type(error).__name__):
                result, calls = self.run_getip(error=error)
                self.assertEqual(result["connect_ip_ext"], "")
        self.assertTrue(all(level == "warning" for level, msg, handles in etoolbox.logger.messages))
        self.assertTrue(all("E" not in handles for level, msg, handles in etoolbox.logger.messages))

    def test_error_page_or_text_is_no_ip(self):
        for answer in (Answer("busy", 503), Answer("<html>busy</html>")):
            with self.subTest(text=answer.text):
                result, calls = self.run_getip(answer)
                self.assertEqual(result["connect_ip_ext"], "")


if __name__ == "__main__":
    unittest.main()
