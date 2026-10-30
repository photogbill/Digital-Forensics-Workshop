"""The content a model hunt looks at (corpus.py, 2026-10-29): listed from the
manifest or from NTFS, read into memory through the read-only door, and —
for a video only — copied once into the case with custody."""

from __future__ import annotations

import os
from pathlib import Path

from _support import EXAMINER, CorpusCase, TempDirCase

import test_disk_case as tdc
from forensics_workshop import corpus, diskimage, ingest, ratchet, blocker
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError
from _support import PACKAGE


class FolderCorpus(CorpusCase):
    def setUp(self):
        super().setUp()
        ingest.ingest_folder(self.case, self.item.id)

    def test_images_are_listed_by_their_bytes_not_their_names(self):
        items = corpus.list_items(self.case, self.item.id, families=("image",))
        names = sorted(i.name for i in items)
        self.assertIn("holiday.jpg", names)
        self.assertIn("diagram.png", names)
        self.assertNotIn("vacation.jpg", names, "a zip named .jpg is no image")
        self.assertTrue(all(i.basis == "manifest" for i in items))

    def test_reading_writes_nothing_and_returns_the_bytes(self):
        item = next(i for i in corpus.list_items(self.case, self.item.id)
                    if i.name == "notes.txt")
        before = sorted(p for p in self.case.root.rglob("*"))
        data = corpus.read_item(self.case, item)
        self.assertEqual(data, (self.evidence / "Documents" /
                                "notes.txt").read_bytes())
        self.assertEqual(sorted(p for p in self.case.root.rglob("*")), before)
        self.assertEqual(corpus.read_item(self.case, item, limit=4), data[:4])

    def test_a_working_copy_is_made_once_inside_the_case_with_custody(self):
        item = next(i for i in corpus.list_items(self.case, self.item.id)
                    if i.name == "holiday.jpg")
        with self.assertRaises(EvidenceError):
            corpus.working_copy(self.case, item, reason=" ")
        first = corpus.working_copy(self.case, item, reason="frame sampling")
        self.assertFalse(first["reused"])
        self.assertTrue(blocker.is_inside(first["path"], self.case.root / "working"))
        self.assertEqual(Path(first["path"]).read_bytes(),
                         (self.evidence / "Pictures" / "holiday.jpg").read_bytes())
        again = corpus.working_copy(self.case, item, reason="frame sampling")
        self.assertTrue(again["reused"])
        rows = [r for r in self.case.custody.rows()
                if r["action"] == "working.copied"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["detail"]["reason"], "frame sampling")
        self.assertTrue(self.case.custody.verify().ok)


class NtfsCorpus(TempDirCase):
    def test_entries_are_listed_by_extension_and_read_from_the_image(self):
        disk, _facts = tdc.build_disk()
        img = self.tmp / "laptop.dd"
        img.write_bytes(disk)
        case = Case.create(self.tmp / "case", case_id="NTFS-1",
                           examiner=EXAMINER)
        item = case.add_image(img)
        diskimage.ingest_image(case, item.id)
        vol = next(v["volume"] for v in diskimage.list_volumes(case, item.id)
                   if v["fs_type"] == "ntfs")
        diskimage.parse_ntfs(case, item.id, vol)
        texts = corpus.list_items(case, item.id, families=("text",))
        plan = next(i for i in texts if i.name == "plan.txt")
        self.assertEqual((plan.source, plan.basis, plan.volume), ("ntfs",
                                                                  "extension", vol))
        self.assertEqual(corpus.read_item(case, plan), b"meet at the usual place")
        self.assertEqual(corpus.identify(b"meet at the usual place",
                                         "plan.txt")["family"], "text")
        docs = corpus.list_items(case, item.id, families=("document",))
        self.assertNotIn("ledger.xlsx", [i.name for i in docs],
                         "deleted entries only when asked for")
        docs = corpus.list_items(case, item.id, families=("document",),
                                 include_deleted=True)
        ledger = next(i for i in docs if i.name == "ledger.xlsx")
        self.assertTrue(ledger.deleted)


class Ratchet(TempDirCase):
    def test_corpus_writes_only_through_the_case_writer(self):
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        self.assertEqual(report.violations, [])
        self.assertFalse([s for s in report.sites
                          if s.qualname.startswith("corpus:")])


if __name__ == "__main__":
    import unittest
    unittest.main()
