import configparser
import importlib.util
import linecache
import os
import shutil
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from modules import eindex  # noqa: E402  (standard library only)

SPEC = importlib.util.spec_from_file_location("ealert_index_under_test", os.path.join(ROOT, "modules", "ealert.py"))
ealert_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ealert_module)


class FakeLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg, handles=""):
        self.messages.append(msg)

    warning = info


class IndexTestCase(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.home = os.path.join(self.tmpdir.name, "home")
        self.index = os.path.join(self.tmpdir.name, "data", "ews", "index")
        self.logs = os.path.join(self.tmpdir.name, "logs")
        for folder in (self.home, self.logs):
            os.makedirs(folder)
        self.logfile = os.path.join(self.logs, "test.json")
        linecache.clearcache()

    def tearDown(self):
        linecache.clearcache()
        self.tmpdir.cleanup()

    def alert(self, indexdir=True):
        """ an EAlert of one run (each run of ews.py builds new ones) """
        alert = ealert_module.EAlert.__new__(ealert_module.EAlert)
        alert.MODUL = "TEST"
        alert.jsonfailcounter = 0
        alert.malwareindex = []
        alert.logger = FakeLogger()
        alert.ECFG = {"homedir": self.home, "indexdir": self.index if indexdir else None}
        os.makedirs(self.index, exist_ok=True)
        return alert

    def write(self, *lines, mode="a"):
        with open(self.logfile, mode) as handle:
            for line in lines:
                handle.write(line + "\n")

    def read_run(self, alert):
        lines = []
        while (line := alert.lineREAD(self.logfile, "json")):
            lines.append(line["n"])
        return lines

    def counter(self):
        count = configparser.ConfigParser()
        count.read(os.path.join(self.index, "ews.idx"))
        return count.get("TEST", "index")


class SetupIndexDirTest(IndexTestCase):
    def test_empty_indexdir_gets_the_files_of_homedir(self):
        for name in ("ews.idx", "cowrie.session", "malware.md5", "ews.cfg", "other.txt"):
            with open(os.path.join(self.home, name), "w") as handle:
                handle.write(name)
        copied = eindex.setupIndexDir(self.home, self.index)
        self.assertEqual(copied, ["cowrie.session", "ews.idx", "malware.md5"])
        self.assertEqual(sorted(os.listdir(self.index)), ["cowrie.session", "ews.idx", "malware.md5"])
        self.assertTrue(os.path.isfile(os.path.join(self.home, "ews.idx")))

    def test_indexdir_with_files_is_left_alone(self):
        os.makedirs(self.index)
        with open(os.path.join(self.index, "ews.idx"), "w") as handle:
            handle.write("[TEST]\nindex = 7\n")
        with open(os.path.join(self.home, "ews.idx"), "w") as handle:
            handle.write("[TEST]\nindex = 3\n")
        self.assertEqual(eindex.setupIndexDir(self.home, self.index), [])
        self.assertEqual(self.counter(), "7")

    def test_indexdir_same_as_homedir(self):
        with open(os.path.join(self.home, "ews.idx"), "w") as handle:
            handle.write("")
        self.assertEqual(eindex.setupIndexDir(self.home, self.home + os.sep), [])


class FileIdentityTest(IndexTestCase):
    def test_identity(self):
        self.assertIsNone(eindex.fileIdentity(self.logfile))
        self.write('{"n": 1}')
        inode, size, digest = eindex.fileIdentity(self.logfile).split(":")
        self.assertEqual(inode, str(os.stat(self.logfile).st_ino))
        self.assertEqual(size, "9")
        self.assertEqual(len(digest), 40)

    def test_first_line_without_newline_has_no_hash(self):
        with open(self.logfile, "w") as handle:
            handle.write('{"n": 1')
        self.assertTrue(eindex.fileIdentity(self.logfile).endswith(":"))

    def test_same_file(self):
        self.assertTrue(eindex.sameFile("1:10:aa", "1:20:aa"))
        self.assertTrue(eindex.sameFile("1:10:", "1:20:bb"))
        self.assertFalse(eindex.sameFile("1:10:aa", "2:20:aa"))
        self.assertFalse(eindex.sameFile("1:10:aa", "1:5:aa"))
        self.assertFalse(eindex.sameFile("1:10:aa", "1:20:bb"))
        self.assertTrue(eindex.sameFile("broken", "1:20:bb"))


class CounterTest(IndexTestCase):
    def test_grown_file_goes_on(self):
        self.write('{"n": 1}', '{"n": 2}')
        self.assertEqual(self.read_run(self.alert()), [1, 2])
        self.write('{"n": 3}')
        self.assertEqual(self.read_run(self.alert()), [3])
        self.assertEqual(self.counter(), "4")
        self.assertFalse(os.path.exists(os.path.join(self.home, "ews.idx")))

    def test_rotated_file_starts_at_line_one(self):
        self.write('{"n": 1}', '{"n": 2}', '{"n": 3}')
        self.assertEqual(self.read_run(self.alert()), [1, 2, 3])
        os.rename(self.logfile, self.logfile + ".1")
        self.write('{"n": 4}', '{"n": 5}', '{"n": 6}', '{"n": 7}')
        alert = self.alert()
        self.assertEqual(self.read_run(alert), [4, 5, 6, 7])
        self.assertEqual(len(alert.logger.messages), 1)

    def test_truncated_file_starts_at_line_one(self):
        self.write('{"n": 1}', '{"n": 2}', '{"n": 3}')
        self.assertEqual(self.read_run(self.alert()), [1, 2, 3])
        with open(self.logfile, "r+") as handle:
            handle.truncate(0)
        self.write('{"n": 4}')
        self.assertEqual(self.read_run(self.alert()), [4])

    def test_truncated_and_grown_file_starts_at_line_one(self):
        self.write('{"n": 1}', '{"n": 2}')
        self.assertEqual(self.read_run(self.alert()), [1, 2])
        with open(self.logfile, "r+") as handle:
            handle.truncate(0)
        self.write('{"n": 3, "x": "longer"}', '{"n": 4}', '{"n": 5}')
        self.assertEqual(self.read_run(self.alert()), [3, 4, 5])

    def test_counter_of_an_earlier_version_is_kept(self):
        self.write('{"n": 1}', '{"n": 2}', '{"n": 3}')
        os.makedirs(self.index)
        with open(os.path.join(self.index, "ews.idx"), "w") as handle:
            handle.write("[TEST]\nindex = 3\n")
        self.assertEqual(self.read_run(self.alert()), [3])

    def test_explicit_line_number_is_not_checked(self):
        self.write('{"n": 1}')
        alert = self.alert()
        self.assertEqual(alert.lineREAD(self.logfile, "json", 1), {"n": 1})
        self.assertFalse(os.path.exists(os.path.join(self.index, "ews.idx")))


class IndexFilesTest(IndexTestCase):
    def test_session_index_and_md5_in_indexdir(self):
        alert = self.alert()
        alert.fileIndex("cowrie.session", "write", "abc")
        self.assertEqual(alert.fileIndex("cowrie.session", "read"), ["abc"])
        self.assertTrue(alert.md5malware("d41d8cd98f00b204e9800998ecf8427e"))
        self.assertFalse(alert.md5malware("d41d8cd98f00b204e9800998ecf8427e"))
        alert.alertCount("TEST", "add_counter")
        self.assertEqual(sorted(os.listdir(self.index)), ["cowrie.session", "ews.idx", "malware.md5"])
        self.assertEqual(os.listdir(self.home), [])

    def test_homedir_without_indexdir(self):
        alert = self.alert(indexdir=False)
        alert.fileIndex("cowrie.session", "write", "abc")
        alert.alertCount("TEST", "add_counter")
        self.assertEqual(sorted(os.listdir(self.home)), ["cowrie.session", "ews.idx"])


if __name__ == "__main__":
    unittest.main()
