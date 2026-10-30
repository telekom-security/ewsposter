import importlib.util
import linecache
import os
import tempfile
import unittest


MODULE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules", "ealert.py")
SPEC = importlib.util.spec_from_file_location("ealert_partial_under_test", MODULE_PATH)
ealert_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ealert_module)


class PartialLineTest(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmpdir.name, "test.log")
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

    def append(self, content):
        with open(self.path, "a") as handle:
            handle.write(content)

    def read_all(self, format="json"):
        lines = []
        while (line := self.alert.lineREAD(self.path, format)):
            lines.append(line)
        return lines

    def test_last_line_without_newline_waits(self):
        self.append('{"n": 1}\n{"n": 2')
        self.assertEqual(self.read_all(), [{"n": 1}])
        self.assertEqual(self.counter, 2)
        self.assertEqual(self.alert.jsonfailcounter, 0)

        self.append(', "more": true}\n{"n": 3}\n')
        self.assertEqual(self.read_all(), [{"n": 2, "more": True}, {"n": 3}])
        self.assertEqual(self.counter, 4)

    def test_simple_format_waits_too(self):
        self.append("a,b,c\nd,e")
        self.assertEqual(self.read_all("simple"), ["a,b,c\n"])
        self.append(",f\n")
        self.assertEqual(self.read_all("simple"), ["d,e,f\n"])

    def test_complete_last_line_is_read(self):
        self.append('{"n": 1}\n{"n": 2}\n')
        self.assertEqual(self.read_all(), [{"n": 1}, {"n": 2}])
        self.assertEqual(self.counter, 3)

    def test_crlf_lines(self):
        with open(self.path, "wb") as handle:
            handle.write(b'{"n": 1}\r\n{"n": 2}\r\n')
        self.assertEqual(self.read_all(), [{"n": 1}, {"n": 2}])

    def test_empty_and_missing_file(self):
        self.assertEqual(self.alert.lineREAD(self.path, "simple"), ())
        self.append("")
        self.assertEqual(self.alert.lineREAD(self.path, "simple"), ())
        self.assertEqual(self.counter, 1)

    def test_explicit_line_number_of_a_partial_line(self):
        self.append("first\nsecond")
        self.assertEqual(self.alert.lineREAD(self.path, "simple", 1), "first\n")
        self.assertEqual(self.alert.lineREAD(self.path, "simple", 2), ())
        self.assertEqual(self.counter, 1)


if __name__ == "__main__":
    unittest.main()
