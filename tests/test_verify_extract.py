"""Verify on demand, and hash-on-export."""

from __future__ import annotations

import sqlite3
import unittest

from _support import CorpusCase

from forensics_workshop import extract, ingest, verify
from forensics_workshop.errors import EvidenceError


class Verify(CorpusCase):
    def setUp(self):
        super().setUp()
        ingest.ingest_folder(self.case, self.item.id)

    def test_an_untouched_folder_verifies(self):
        summary = verify.verify_evidence(self.case, self.item.id)
        self.assertTrue(summary.all_matched, summary.as_dict())
        self.assertTrue(summary.manifest_digest_matches)
        last = verify.last_verification(self.case, self.item.id)
        self.assertTrue(last["detail"]["all_matched"])

    def test_a_changed_file_is_named(self):
        (self.evidence / "Documents" / "notes.txt").write_text("tampered\n")
        summary = verify.verify_evidence(self.case, self.item.id)
        self.assertFalse(summary.all_matched)
        self.assertEqual(summary.mismatched, 1)
        self.assertEqual(summary.mismatches[0]["relpath"], "Documents/notes.txt")

    def test_a_missing_file_is_named(self):
        (self.evidence / "Pictures" / "diagram.png").unlink()
        summary = verify.verify_evidence(self.case, self.item.id)
        self.assertEqual(summary.missing, 1)
        self.assertEqual(summary.missing_paths, ["Pictures/diagram.png"])

    def test_an_altered_index_is_caught_even_though_the_evidence_agrees(self):
        conn = sqlite3.connect(self.case.root / "index.db")
        conn.execute("UPDATE files SET size = size + 1 WHERE relpath = ?",
                     ("Documents/report.pdf",))
        conn.commit()
        conn.close()
        summary = verify.verify_evidence(self.case, self.item.id)
        self.assertFalse(summary.manifest_digest_matches)
        self.assertFalse(summary.all_matched)

    def test_a_cancelled_verification_is_not_an_answer(self):
        verify.verify_evidence(self.case, self.item.id,
                               should_cancel=lambda: True)
        self.assertIsNone(verify.last_verification(self.case, self.item.id))
        self.assertIsNotNone(self.case.custody.last("verify.cancelled",
                                                    self.item.id))


class Extract(CorpusCase):
    def setUp(self):
        super().setUp()
        ingest.ingest_folder(self.case, self.item.id)

    def test_a_copy_is_hashed_from_its_own_read_and_matches_the_manifest(self):
        out = extract.extract_file(self.case, self.item.id,
                                   "Documents/report.pdf", reason="review")
        self.assertTrue(out.matches_manifest)
        self.assertFalse(out.reused)
        dest = self.case.root / "extracted" / "E001" / "files" / "Documents" / "report.pdf"
        self.assertEqual(out.dest, str(dest))
        self.assertEqual(dest.read_bytes(),
                         (self.evidence / "Documents" / "report.pdf").read_bytes())
        rec = self.case.custody.last("file.extracted")
        self.assertEqual(rec["detail"]["reason"], "review")
        self.assertEqual(rec["hashes"]["sha256"], out.hashes["sha256"])

    def test_a_second_export_of_an_unchanged_file_is_reused(self):
        extract.extract_file(self.case, self.item.id, "Documents/report.pdf",
                             reason="one")
        again = extract.extract_file(self.case, self.item.id,
                                     "Documents/report.pdf", reason="two")
        self.assertTrue(again.reused)

    def test_a_changed_source_is_exported_beside_and_flagged(self):
        extract.extract_file(self.case, self.item.id, "Documents/notes.txt",
                             reason="one")
        (self.evidence / "Documents" / "notes.txt").write_text("changed\n")
        out = extract.extract_file(self.case, self.item.id,
                                   "Documents/notes.txt", reason="two")
        self.assertFalse(out.matches_manifest)
        self.assertTrue(out.dest.endswith("notes~2.txt"), out.dest)

    def test_a_reason_is_required(self):
        with self.assertRaises(EvidenceError):
            extract.extract_file(self.case, self.item.id,
                                 "Documents/report.pdf", reason="  ")
        with self.assertRaises(TypeError):
            extract.extract_file(self.case, self.item.id,
                                 "Documents/report.pdf")

    def test_paths_that_climb_out_are_refused(self):
        for bad in ("../outside.txt", "/etc/passwd", "C:/Windows/x", ""):
            with self.assertRaises(EvidenceError):
                extract.extract_file(self.case, self.item.id, bad,
                                     reason="attempt")

    def test_copies_never_overwrite(self):
        src = self.evidence / "Documents" / "report.pdf"
        dest = self.case.root / "extracted" / "manual.pdf"
        extract.copy_evidence_to_case(self.case, src, dest)
        with self.assertRaises(FileExistsError):
            extract.copy_evidence_to_case(self.case, src, dest)

    def test_a_copy_into_the_evidence_is_refused(self):
        from forensics_workshop.errors import CaseError
        with self.assertRaises(CaseError):
            extract.copy_evidence_to_case(
                self.case, self.evidence / "Documents" / "report.pdf",
                self.evidence / "copy.pdf")


if __name__ == "__main__":
    unittest.main()
