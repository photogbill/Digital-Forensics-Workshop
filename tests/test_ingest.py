"""Logical ingest: the evidence is unchanged, every file is accounted for."""

from __future__ import annotations

import os
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import synth
from _support import CorpusCase, EXAMINER

from forensics_workshop import ingest, manifest
from forensics_workshop.case import Case
from forensics_workshop.errors import CaseLayoutError, EvidenceError


class Ingest(CorpusCase):
    def test_every_file_is_hashed_and_the_evidence_is_untouched(self):
        before = synth.snapshot(self.evidence)
        summary = ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(summary.state, "completed")
        self.assertEqual(summary.errors, 0)
        self.assertEqual(summary.files, len(before))
        self.assertEqual(synth.snapshot(self.evidence), before,
                         "size, mtime or content of a source file changed")
        rows, total = manifest.list_files(self.case, self.item.id,
                                          filter="files", limit=10_000)
        by_path = {r["relpath"]: r for r in rows}
        for rel, (size, _mtime, sha) in before.items():
            self.assertEqual(by_path[rel]["sha256"], sha, rel)
            self.assertEqual(by_path[rel]["size"], size, rel)

    def test_nothing_is_written_inside_the_evidence(self):
        names = {p.relative_to(self.evidence) for p in self.evidence.rglob("*")}
        ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(names, {p.relative_to(self.evidence)
                                 for p in self.evidence.rglob("*")})

    def test_the_custody_log_brackets_the_run_with_the_manifest_digest(self):
        summary = ingest.ingest_folder(self.case, self.item.id)
        started = self.case.custody.last("ingest.started", self.item.id)
        done = self.case.custody.last("ingest.completed", self.item.id)
        self.assertEqual(started["detail"]["run_id"], summary.run_id)
        self.assertEqual(done["hashes"]["manifest"], summary.manifest_sha256)
        self.assertEqual(ingest.manifest_digest(self.case, self.item.id),
                         summary.manifest_sha256)
        self.assertTrue(self.case.custody.verify().ok)

    def test_findings_of_interest_are_counted(self):
        ingest.ingest_folder(self.case, self.item.id)
        counts = manifest.counts(self.case, self.item.id)
        self.assertEqual(counts["mismatch"], 1)          # vacation.jpg
        self.assertEqual(counts["duplicates"], 2)        # two holiday jpegs
        self.assertGreaterEqual(counts["hidden"], 1)     # .hidden_config
        self.assertEqual(counts["high-entropy"], 1)      # random.bin
        rows, _ = manifest.list_files(self.case, self.item.id,
                                      filter="mismatch")
        self.assertEqual([r["relpath"] for r in rows], ["Pictures/vacation.jpg"])

    def test_links_are_recorded_and_not_followed(self):
        if not self.corpus["link_made"]:
            self.skipTest("cannot create symlinks here")
        ingest.ingest_folder(self.case, self.item.id)
        link = manifest.lookup(self.case, self.item.id, "docs-link")
        self.assertEqual(link["kind"], "link")
        self.assertTrue(link["link_target"])
        rows, _ = manifest.list_files(self.case, self.item.id, search="docs-link/")
        self.assertEqual(rows, [], "a link was descended")

    def test_a_second_run_resumes_and_a_changed_file_is_re_read(self):
        first = ingest.ingest_folder(self.case, self.item.id)
        again = ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(again.resumed, first.files)
        target = self.evidence / "Documents" / "notes.txt"
        target.write_text("changed after ingest\n", encoding="utf-8")
        os.utime(target, ns=(target.stat().st_atime_ns,
                             target.stat().st_mtime_ns + 5_000_000_000))
        third = ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(third.resumed, first.files - 1)
        self.assertNotEqual(third.manifest_sha256, first.manifest_sha256)

    def test_cancel_keeps_what_was_done_and_says_so(self):
        calls = {"n": 0}

        def cancel_after_some():
            calls["n"] += 1
            return calls["n"] > 12

        summary = ingest.ingest_folder(self.case, self.item.id,
                                       should_cancel=cancel_after_some,
                                       batch_size=3)
        self.assertEqual(summary.state, "cancelled")
        self.assertEqual(summary.manifest_sha256, "")
        rec = self.case.custody.last("ingest.cancelled", self.item.id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec["hashes"], {}, "no digest for a partial manifest")
        _rows, total = manifest.list_files(self.case, self.item.id)
        self.assertGreater(total, 0, "committed batches survive a cancel")
        resumed = ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(resumed.state, "completed")
        self.assertGreater(resumed.resumed, 0)

    def test_batches_stream_to_the_caller(self):
        seen = []
        ingest.ingest_folder(self.case, self.item.id, batch_size=4,
                             on_batch=seen.append)
        self.assertGreater(len(seen), 3)
        self.assertTrue(all(len(b) <= 4 for b in seen))

    def test_a_locked_file_is_explained_not_skipped_silently(self):
        locked = OSError(13, "The process cannot access the file")
        locked.winerror = 32
        real = ingest.blocker.open_evidence

        def fake(path):
            if str(path).endswith("History"):
                raise locked
            return real(path)

        with mock.patch("forensics_workshop.ingest.blocker.open_evidence", fake):
            summary = ingest.ingest_folder(self.case, self.item.id)
        self.assertEqual(summary.errors, 1)
        row = manifest.lookup(self.case, self.item.id,
                              "AppData/Local/Google/Chrome/User Data/Default/History")
        self.assertIn("locked by another process", row["error"])
        self.assertIsNone(row["sha256"])

    def test_a_cloud_placeholder_is_not_read(self):
        p = self.evidence / "Documents" / "report.pdf"
        st = os.stat(p)
        fake = SimpleNamespace(
            st_mode=st.st_mode, st_size=st.st_size, st_mtime_ns=st.st_mtime_ns,
            st_atime_ns=st.st_atime_ns, st_ctime_ns=st.st_ctime_ns,
            st_file_attributes=ingest.FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
            st_reparse_tag=0x9000001A)
        with mock.patch("forensics_workshop.ingest.blocker.open_evidence",
                        side_effect=AssertionError("it was opened")):
            row = ingest.read_file("E001", "Documents/report.pdf", str(p), fake)
        self.assertIn("would download it", row["not_read_reason"])
        self.assertIsNone(row["sha256"])

    def test_an_atime_that_moves_during_the_read_is_recorded(self):
        p = self.evidence / "Documents" / "notes.txt"
        st = os.stat(p)
        moved = SimpleNamespace(st_size=st.st_size, st_mtime_ns=st.st_mtime_ns,
                                st_atime_ns=st.st_atime_ns + 60_000_000_000)
        with mock.patch("forensics_workshop.ingest.os.stat", return_value=moved):
            row = ingest.read_file("E001", "Documents/notes.txt", str(p), st)
        self.assertEqual(row["atime_change_observed"], 1)
        self.assertEqual(row["changed_during_read"], 0)

    def test_ctime_meaning_is_stated(self):
        ingest.ingest_folder(self.case, self.item.id)
        row = manifest.lookup(self.case, self.item.id, "Documents/notes.txt")
        expected = "creation" if sys.platform == "win32" else "not creation"
        self.assertIn(expected, row["ctime_meaning"])

    def test_the_layout_is_rechecked_at_ingest_time(self):
        self.evidence.rename(self.tmp / "gone")
        with self.assertRaises(EvidenceError):
            ingest.ingest_folder(self.case, self.item.id)


class LayoutAtIngest(CorpusCase):
    def test_a_case_created_inside_evidence_later_is_refused(self):
        sneaky = Case.create(self.evidence / "Documents" / "case2",
                             case_id="SNEAK", examiner=EXAMINER)
        (self.evidence / "Documents" / "case2").rename(self.tmp / "case2")
        moved = Case.open(self.tmp / "case2", examiner=EXAMINER)
        moved.add_folder(self.evidence)   # fine: case is now outside
        with self.assertRaises(CaseLayoutError):
            inside = Case.create(self.evidence / "Pictures" / "c3",
                                 case_id="C3", examiner=EXAMINER)
            inside.add_folder(self.evidence)
        del sneaky


if __name__ == "__main__":
    unittest.main()
