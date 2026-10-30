"""What may run, and who said so: the owner-exception mechanism (empty since
SAM Audio was removed), and the writers the ratchet allows (FORENSICS_PLAN
§1.1, §12). Every guard here is also watched failing."""

from __future__ import annotations

import ast
import unittest
from unittest import mock

from _support import PACKAGE

from forensics_workshop import blocker, capabilities, ratchet
from forensics_workshop.errors import CasePathError


class OwnerException(unittest.TestCase):
    """The mechanism stays; the one exception it held (SAM Audio) went with
    SAM on 2026-10-29."""

    SAM = "LicenseRef-SAM-License"

    def rows(self):
        return {c.id: c for c in capabilities.capabilities()}

    def test_there_are_no_exceptions_and_no_sam_rows(self):
        self.assertEqual(capabilities.OWNER_EXCEPTIONS, {})
        rows = self.rows()
        self.assertNotIn("sam-audio", rows)
        self.assertNotIn("audiocpp", rows)
        for row in rows.values():
            self.assertEqual(row.exception, "", row.id)

    def test_the_rule_itself_is_not_loosened(self):
        self.assertFalse(capabilities.licence_permits(self.SAM))
        self.assertNotIn(self.SAM, capabilities.PERMITTED_LICENCES)

    def test_an_exception_still_binds_one_row_and_one_licence(self):
        granted = capabilities.OwnerException(
            capability="x-model", licence=self.SAM, granted_by="Bill",
            granted_on="2026-01-01", reason="test", removal_trigger="test",
            sentence="owner exception — test")
        rows = (("x-model", "X", 3, "third-party", "", "", self.SAM,
                 "planned", "Excepted."),
                ("rider", "Rider", 3, "third-party", "", "", self.SAM,
                 "planned", "Same licence, different component."),
                ("x-model-2", "X under GPL", 3, "third-party", "", "",
                 "GPL-3.0-only", "planned", ""))
        with mock.patch.object(capabilities, "_TABLE", rows), \
                mock.patch.object(capabilities, "OWNER_EXCEPTIONS",
                                  {"x-model": granted}):
            got = {c.id: c for c in capabilities.capabilities()}
        self.assertEqual(got["x-model"].exception, "owner exception — test")
        self.assertNotEqual(got["x-model"].status, "excluded")
        self.assertEqual(got["rider"].status, "excluded")
        self.assertEqual(got["x-model-2"].status, "excluded")
        self.assertIn("Fails the licence rule", got["rider"].note)

    def test_the_written_table_admits_only_permitted_licences(self):
        for cid, _l, _p, _h, _m, package, licence, status, _n in \
                capabilities._TABLE:
            if (package or licence) and status != "excluded":
                self.assertTrue(capabilities.licence_permits(licence), cid)


class WritersAndIsolation(unittest.TestCase):
    MEDIA_WRITERS = {"media.lab:_case_log": "case",
                     "media.lab:_harness_dirs": "harness",
                     "media.lab:_harness_log": "harness",
                     "media.lab:_harness_json": "harness",
                     "media.proc:run_process": "spawn",
                     "media.proc:probe_version": "spawn"}

    def test_the_media_writers_are_listed_and_the_package_is_clean(self):
        for name, kind in self.MEDIA_WRITERS.items():
            self.assertEqual(blocker.WRITERS.get(name), kind, name)
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        self.assertEqual(report.violations, [])
        for module in ("media.lab", "media.proc", "media.wav",
                       "media.recipe", "media.restore", "media.voiceprint"):
            self.assertIn(module, report.files)
        self.assertTrue(set(self.MEDIA_WRITERS) <= report.writers_seen)

    def test_sam_is_gone_from_the_package(self):
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        for module in ("media.sam_audio", "media.separator",
                       "media.weights", "media.disagreement"):
            self.assertNotIn(module, report.files)
        self.assertFalse([k for k in blocker.WRITERS
                          if "sam_audio" in k or "weights" in k])

    def test_unlisting_a_media_writer_turns_the_ratchet_red(self):
        writers = {k: v for k, v in blocker.WRITERS.items()
                   if k != "media.lab:_case_log"}
        report = ratchet.scan_package(PACKAGE, writers)
        self.assertTrue(any("media.lab:_case_log" in v
                            for v in report.violations))

    def test_starting_a_child_process_is_a_write_site(self):
        for call in ("subprocess.run(['x'])", "subprocess.Popen(['x'])",
                     "os.system('x')"):
            report = ratchet.scan_source(
                f"import os, subprocess\ndef f():\n    {call}\n", "m")
            self.assertTrue(report.violations, call)
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        spawns = [s for s in report.sites if s.what.startswith("subprocess.")]
        self.assertTrue(spawns and all(s.allowed for s in spawns))
        self.assertTrue({"media.proc:run_process", "media.proc:probe_version"}
                        <= {s.qualname for s in spawns})

    def test_a_child_with_targets_needs_a_guard(self):
        with self.assertRaises(CasePathError):
            blocker.assert_child_writes(None, ["x"])
        self.assertEqual(blocker.assert_child_writes(None, ()), [])

    def test_harness_and_spawn_writers_must_call_their_guards(self):
        for kind, guard in (("harness", "assert_harness_path"),
                            ("spawn", "assert_child_writes")):
            report = ratchet.scan_source("def w(p):\n    open(p, 'xb')\n",
                                         "m", {"m:w": kind})
            self.assertTrue(any(guard in v for v in report.violations), kind)
            ok = ratchet.scan_source(
                f"def w(r, p):\n    {guard}(r, p)\n    open(p, 'xb')\n",
                "m", {"m:w": kind})
            self.assertEqual(ok.violations, [], kind)

    def test_numpy_is_reached_in_one_place_and_never_imported(self):
        hits = []
        for path in (PACKAGE / "media").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names] + [
                        getattr(node, "module", "") or ""]
                    self.assertFalse(any(n.split(".")[0] == "numpy"
                                         for n in names), path.name)
                if isinstance(node, ast.Call) and getattr(
                        node.func, "attr", "") == "import_module":
                    hits.append((path.name, ast.unparse(node.args[0])))
        self.assertEqual(hits, [], "numpy is never imported here since "
                         "seed disagreement went with SAM")

    def test_the_media_init_imports_nothing(self):
        tree = ast.parse((PACKAGE / "media" / "__init__.py").read_text(
            encoding="utf-8"))
        self.assertFalse([n for n in ast.walk(tree)
                          if isinstance(n, (ast.Import, ast.ImportFrom))])

    def test_the_notices_name_every_licence(self):
        text = (PACKAGE / "media" / "NOTICES.md").read_text(encoding="utf-8")
        for needle in ("removed on 2026-10-29", "SpeechBrain", "FFmpeg"):
            self.assertIn(needle, text)
        for gone in ("ShugoAI", "LICENSE-T5"):
            self.assertNotIn(gone, text)


if __name__ == "__main__":
    unittest.main()
