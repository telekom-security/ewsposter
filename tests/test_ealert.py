import importlib.util
import linecache
import os
import tempfile
import unittest


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "modules", "ealert.py")
SPEC = importlib.util.spec_from_file_location("ealert_under_test", MODULE_PATH)
ealert_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ealert_module)


class LineReadTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.counter = 1
        self.alert = ealert_module.EAlert.__new__(ealert_module.EAlert)
        self.alert.MODUL = "TEST"
        self.alert.jsonfailcounter = 0
        self.alert.alertCount = self.fake_alert_count
        linecache.clearcache()

    def tearDown(self):
        linecache.clearcache()
        self.tmpdir.cleanup()

    def fake_alert_count(self, section, counting, item="index"):
        if counting == "get_counter":
            return str(self.counter)
        if counting == "add_counter":
            self.counter += 1
        return ()

    def write(self, content):
        path = os.path.join(self.tmpdir.name, "test.log")
        with open(path, "w") as handle:
            handle.write(content)
        return path

    def test_empty_file_simple(self):
        path = self.write("")
        self.assertEqual(self.alert.lineREAD(path, "simple"), ())
        self.assertEqual(self.counter, 1)

    def test_empty_file_json(self):
        path = self.write("")
        self.assertEqual(self.alert.lineREAD(path, "json"), ())
        self.assertEqual(self.counter, 1)
        self.assertEqual(self.alert.jsonfailcounter, 0)

    def test_missing_file(self):
        path = os.path.join(self.tmpdir.name, "missing.log")
        self.assertEqual(self.alert.lineREAD(path, "simple"), ())
        self.assertEqual(self.counter, 1)

    def test_first_line_after_file_was_empty(self):
        path = self.write("")
        self.assertEqual(self.alert.lineREAD(path, "json"), ())
        self.write('{"src_ip": "192.0.2.1"}\n')
        self.assertEqual(self.alert.lineREAD(path, "json"), {"src_ip": "192.0.2.1"})
        self.assertEqual(self.counter, 2)
        self.assertEqual(self.alert.lineREAD(path, "json"), ())
        self.assertEqual(self.counter, 2)


if __name__ == "__main__":
    unittest.main()
