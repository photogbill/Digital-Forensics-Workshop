"""The command line, end to end: the engine standing alone."""

from __future__ import annotations

import contextlib
import io
import json
import unittest

from _support import EXAMINER, TempDirCase
import synth

from forensics_workshop import cli


def run(*argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as exc:            # argparse errors
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class EndToEnd(TempDirCase):
    def test_a_whole_case_from_the_command_line(self):
        ev = self.tmp / "evidence"
        synth.build_corpus(ev)
        case = str(self.tmp / "case")
        ex = ("--examiner", EXAMINER)

        code, out, _ = run("case", "new", case, "--id", "CLI-1", *ex)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["case_id"], "CLI-1")

        code, out, err = run("add", case, str(ev), *ex, "--label", "profile")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["id"], "E001")
        self.assertIn("hardware write blocker", err)

        code, out, _ = run("ingest", case, "E001", *ex)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["state"], "completed")

        code, out, _ = run("verify", case, "E001", *ex)
        self.assertEqual(code, 0, out)

        code, out, _ = run("files", case, "E001", *ex, "--filter", "mismatch")
        self.assertIn("Pictures/vacation.jpg", out)

        code, out, _ = run("dupes", case, *ex)
        self.assertEqual(len(json.loads(out)), 1)

        code, out, _ = run("extract", case, "E001", "Documents/report.pdf", *ex,
                           "--reason", "for the report")
        self.assertTrue(json.loads(out)["matches_manifest"])

        code, out, _ = run("browser", case, "E001", *ex)
        self.assertEqual(code, 0)
        code, out, _ = run("artefacts", case, "E001", *ex, "--kind", "visit")
        self.assertIn("https://late.example/", out)
        self.assertIn("wal", out)

        code, out, _ = run("custody", case, *ex, "--tail", "5")
        self.assertEqual(code, 0)
        self.assertIn("chain intact", out)

        code, out, _ = run("case", "show", case, *ex)
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["integrity"], [])

    def test_refusals_exit_3_with_the_reason(self):
        code, _, err = run("case", "new", str(self.tmp / "c"), "--id", "../x",
                           "--examiner", EXAMINER)
        self.assertEqual(code, 3)
        self.assertIn("refused", err)

    def test_the_probe_needs_its_flag(self):
        code, _, err = run("probe-write", str(self.tmp))
        self.assertEqual(code, 3)
        self.assertIn("test device", err)
        code, out, _ = run("probe-write", str(self.tmp),
                           "--i-confirm-this-is-not-evidence")
        self.assertEqual(code, 1, "a writable folder is NOT protected")
        self.assertFalse(json.loads(out)["refused"])

    def test_examiner_is_required(self):
        code, _, _ = run("ingest", str(self.tmp), "E001")
        self.assertEqual(code, 2)

    def test_capabilities_and_volume_and_policy(self):
        code, out, _ = run("capabilities")
        self.assertEqual(code, 0)
        self.assertIn("available", out)
        self.assertIn("planned", out)
        self.assertIn("excluded", out)
        self.assertIn("licence: LGPL-3.0-or-later", out)
        code, out, _ = run("volume", str(self.tmp))
        self.assertIn("read_only", json.loads(out))
        code, out, _ = run("usb-policy", "status")
        self.assertIn("supported", json.loads(out))


if __name__ == "__main__":
    unittest.main()
