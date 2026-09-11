"""The read-only ratchet — and proof that it LOOKS, and that it FAILS.

A guard nobody has watched fail is a guard nobody should trust; neither is one
nobody has watched look. So this file does three things: runs the ratchet over
the real package, asserts what it covered, and feeds it one small program per
rule and watches each one go red.
"""

from __future__ import annotations

import ast
import unittest

from _support import PACKAGE

from forensics_workshop import blocker, ratchet


def _modules_on_disk() -> set:
    out = set()
    for path in PACKAGE.rglob("*.py"):
        parts = [p for p in path.relative_to(PACKAGE).with_suffix("").parts
                 if p != "__init__"]
        out.add(".".join(parts) or "__init__")
    return out


class ThePackage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = ratchet.scan_package(PACKAGE, blocker.WRITERS)

    def test_no_write_outside_a_listed_writer(self):
        self.assertEqual(self.report.violations, [])

    def test_it_scanned_every_module(self):
        self.assertEqual(set(self.report.files), _modules_on_disk())
        for must in ("case", "custody", "ingest", "extract", "artefacts.browser",
                     "blocker", "caseindex", "index", "image", "ntfs", "carve",
                     "diskimage", "partitions", "usn"):
            self.assertIn(must, self.report.files)

    def test_it_actually_found_the_writes_that_exist(self):
        """If this count drops to zero the ratchet has gone blind, not clean."""
        allowed = [s for s in self.report.sites if s.allowed]
        self.assertGreaterEqual(len(allowed), 15)
        self.assertGreater(self.report.functions, 100)
        self.assertGreater(self.report.opens_inspected, 10)
        kinds = {s.what.split("(")[0] for s in allowed}
        for expected in ("sqlite3.connect", "os.open", "open", ".mkdir",
                         "os.replace", "winreg.SetValueEx"):
            self.assertTrue(any(k.startswith(expected) for k in kinds),
                            f"no {expected} site seen: {sorted(kinds)}")

    def test_every_listed_writer_exists(self):
        self.assertEqual(self.report.stale_writers, set())
        self.assertEqual(self.report.writers_seen, set(blocker.WRITERS))

    def test_only_one_probe_and_it_is_the_one_in_blocker(self):
        probes = [k for k, v in blocker.WRITERS.items() if v == "probe"]
        self.assertEqual(probes, ["blocker:verify_write_refused"])

    def test_the_evidence_door_opens_read_only(self):
        """Scanned with NO writers allowed: `open_evidence` must raise nothing
        while `verify_write_refused`, in the same file, must — which proves
        the os.open calls in this module were actually inspected rather than
        skipped. (The first version of this test scanned the function on its
        own, without `import os`, and passed because it saw nothing at all.)"""
        source = (PACKAGE / "blocker.py").read_text(encoding="utf-8")
        report = ratchet.scan_source(source, "blocker", {})
        flagged = {s.qualname for s in report.sites}
        self.assertNotIn("blocker:open_evidence", flagged)
        self.assertIn("blocker:verify_write_refused", flagged)
        tree = ast.parse(source)
        fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "open_evidence")
        os_opens = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                    and getattr(n.func, "attr", "") == "open"
                    and getattr(n.func.value, "id", "") == "os"]
        self.assertEqual(len(os_opens), 2, "the NOATIME try and the fallback")


class WatchItFail(unittest.TestCase):
    """One program per rule. Each must produce a violation."""

    def assertViolates(self, source, needle=""):
        report = ratchet.scan_source(source, "m")
        self.assertTrue(report.violations, f"not caught:\n{source}")
        if needle:
            self.assertTrue(any(needle in v for v in report.violations),
                            report.violations)

    def test_open_for_update(self):
        self.assertViolates("def f(p):\n    return open(p, 'r+b')\n", "r+b")

    def test_open_write_by_keyword(self):
        self.assertViolates("def f(p):\n    return open(p, mode='wb')\n")

    def test_append_and_exclusive(self):
        self.assertViolates("def f(p):\n    open(p, 'a')\n")
        self.assertViolates("def f(p):\n    open(p, 'x')\n")

    def test_a_mode_nobody_can_read(self):
        self.assertViolates("def f(p, m):\n    open(p, m)\n", "not a literal")

    def test_path_open_for_writing(self):
        self.assertViolates("from pathlib import Path\n"
                            "def f(p):\n    Path(p).open('wb')\n")

    def test_os_open_write_flags(self):
        self.assertViolates("import os\ndef f(p):\n"
                            "    os.open(p, os.O_RDWR)\n", "O_RDWR")

    def test_os_open_flags_through_a_constant(self):
        self.assertViolates("import os\nFLAGS = os.O_WRONLY | os.O_CREAT\n"
                            "def f(p):\n    os.open(p, FLAGS)\n", "O_WRONLY")

    def test_os_open_unidentified_flags(self):
        self.assertViolates("import os\ndef f(p, flags):\n"
                            "    os.open(p, flags)\n", "unidentified")

    def test_mutators(self):
        for call in ("os.remove(p)", "os.utime(p)", "shutil.copy2(p, q)",
                     "shutil.rmtree(p)", "os.replace(p, q)",
                     "sqlite3.connect(p)", "tempfile.mkstemp()"):
            self.assertViolates(f"import os, shutil, sqlite3, tempfile\n"
                                f"def f(p, q):\n    {call}\n")

    def test_from_imports_are_resolved(self):
        self.assertViolates("from shutil import copyfile as cp\n"
                            "def f(p, q):\n    cp(p, q)\n")

    def test_path_methods(self):
        for call in ("p.write_bytes(b'x')", "p.write_text('x')", "p.unlink()",
                     "p.touch()", "p.replace(q)", "p.rename(q)"):
            self.assertViolates(f"def f(p, q):\n    {call}\n")

    def test_win32_writers(self):
        self.assertViolates("import ctypes\ndef f():\n"
                            "    ctypes.windll.kernel32.SetFileTime(1, 0, 0, 0)\n")

    def test_writes_at_module_level(self):
        self.assertViolates("open('x', 'w')\n", "<module>")

    def test_a_case_writer_that_never_asserts(self):
        report = ratchet.scan_source("def w(p):\n    open(p, 'wb')\n", "m",
                                     {"m:w": "case"})
        self.assertTrue(any("assert_case_path" in v for v in report.violations))

    def test_a_probe_with_a_default(self):
        src = ("import os\ndef probe(p, *, confirm_not_evidence=True):\n"
               "    os.remove(p)\n")
        report = ratchet.scan_source(src, "m", {"m:probe": "probe"})
        self.assertTrue(any("keyword-only" in v for v in report.violations))


class DoNotCryWolf(unittest.TestCase):
    """What must NOT be a violation — the four needles ATK broke in one day."""

    def assertClean(self, source):
        report = ratchet.scan_source(source, "m")
        self.assertEqual(report.violations, [], source)

    def test_a_docstring_that_names_the_forbidden_call(self):
        self.assertClean('def f(p):\n    """Never open(p, "w") here."""\n'
                         '    # os.remove(p) would be wrong\n'
                         '    return open(p, "rb").read()\n')

    def test_str_replace_is_not_path_replace(self):
        self.assertClean("def f(s):\n    return s.replace('a', 'b')\n")

    def test_datetime_replace_with_keywords(self):
        self.assertClean("def f(d):\n    return d.replace(microsecond=0)\n")

    def test_zip_entry_open(self):
        self.assertClean("def f(zf, name):\n    return zf.open(name)\n")

    def test_read_only_os_open(self):
        self.assertClean("import os\nR = os.O_RDONLY | getattr(os, 'O_BINARY', 0)\n"
                         "def f(p):\n    return os.open(p, R)\n")

    def test_read_only_mmap(self):
        self.assertClean("import mmap\ndef f(fd):\n"
                         "    return mmap.mmap(fd, 0, access=mmap.ACCESS_READ)\n")

    def test_nested_function_inside_a_writer(self):
        src = ("from forensics_workshop import blocker\n"
               "def w(root, p):\n    blocker.assert_case_path(root, p)\n"
               "    def inner():\n        open(p, 'ab')\n    inner()\n")
        report = ratchet.scan_source(src, "m", {"m:w": "case"})
        self.assertEqual(report.violations, [])


if __name__ == "__main__":
    unittest.main()
