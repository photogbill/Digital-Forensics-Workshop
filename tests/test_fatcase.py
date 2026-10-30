"""fatcase.py: a FAT32 volume inside a registered disk image, through the
case — parse into the index, list (deleted included), detail, preview
(nothing written), recover with a reason and custody, refusals."""

from __future__ import annotations

import os
import unittest

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

import disksynth as ds
import fatsynth as fs
from forensics_workshop import diskimage, fatcase, hashing, index
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError

START = 2048


def build_fat_disk() -> tuple[bytes, dict]:
    v = fs.FatImage("FAT32", label="CAMERA")
    photo = ds.jpeg_file() * 40                  # several clusters
    v.mkdir("", fs.sfn("DCIM"), "DCIM")
    kept = v.add_file("DCIM", fs.sfn("IMG_0001", "JPG"), photo, "IMG_0001.JPG")
    gone = v.add_file("DCIM", fs.sfn("IMG_0002", "JPG"), photo[::-1],
                      "IMG_0002.JPG")
    v.add_file("", fs.sfn("NOTES", "TXT"), b"meet at the pier\n", "notes.txt")
    v.delete("DCIM/IMG_0002.JPG")
    vol = bytes(v.build())
    sectors = len(vol) // 512
    disk = bytearray(ds.mbr_sector([(0, 0x0C, START, sectors)]))
    disk += bytes(START * 512 - len(disk)) + vol
    return bytes(disk), {"photo": photo, "gone": photo[::-1], "kept": kept,
                         "deleted": gone}


class FatInACase(TempDirCase):
    def setUp(self):
        super().setUp()
        disk, self.facts = build_fat_disk()
        image = self.tmp / "sdcard.dd"
        image.write_bytes(disk)
        self.case = Case.create(self.tmp / "case", case_id="FAT-1",
                                examiner=EXAMINER)
        self.eid = self.case.add_image(image, label="SD card").id
        diskimage.ingest_image(self.case, self.eid)
        vols = diskimage.list_volumes(self.case, self.eid)
        self.vol = next(v["volume"] for v in vols
                        if v.get("fs_type") in fatcase.FAT_TYPES)

    def _entry(self, path):
        rows, _ = fatcase.list_fat_entries(self.case, self.eid, self.vol,
                                           search=path)
        return next(r for r in rows if r["path"] == path)

    def test_parse_lists_live_and_deleted(self):
        s = fatcase.parse_fat(self.case, self.eid, self.vol)
        self.assertEqual(s.state, "completed")
        self.assertEqual(s.fs, "FAT32")
        self.assertEqual(s.label, "CAMERA")
        self.assertEqual(s.deleted, 1)
        rows, total = fatcase.list_fat_entries(self.case, self.eid, self.vol)
        paths = {r["path"] for r in rows}
        self.assertIn("DCIM/IMG_0001.JPG", paths)
        self.assertIn("notes.txt", paths)
        deleted, n = fatcase.list_fat_entries(self.case, self.eid, self.vol,
                                              filter="deleted")
        self.assertEqual(n, 1)
        self.assertTrue(deleted[0]["path"].endswith("IMG_0002.JPG"))
        self.assertEqual(deleted[0]["recovery_basis"], "contiguous-assumption")
        # FAT time is local: kept raw with its epoch, never as UTC
        self.assertEqual(deleted[0]["modified_epoch"], "fat-local")
        self.assertFalse(str(deleted[0]["modified_value"]).endswith("Z"))
        self.assertIsNotNone(self.case.custody.last("fat.completed"))
        self.assertTrue(self.case.custody.verify().ok)
        # the volume's own row lands in the artefacts index
        with index.session(self.case.root) as conn:
            n = conn.execute("SELECT COUNT(*) FROM artefacts WHERE parser = 'fat'"
                             ).fetchone()[0]
        self.assertEqual(n, 1)

    def test_reparse_replaces(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        _, first = fatcase.list_fat_entries(self.case, self.eid, self.vol)
        fatcase.parse_fat(self.case, self.eid, self.vol)
        _, second = fatcase.list_fat_entries(self.case, self.eid, self.vol)
        self.assertEqual(first, second)

    def test_preview_writes_nothing_and_reads_the_bytes(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        e = self._entry("DCIM/IMG_0001.JPG")
        before = sorted(p for p in self.case.root.rglob("*") if p.is_file())
        p = fatcase.preview_fat_entry(self.case, self.eid, self.vol,
                                      e["entry_id"], limit=1 << 20)
        self.assertEqual(p["refused"], "")
        self.assertEqual(p["data"], self.facts["photo"])
        self.assertEqual(p["type"]["type_id"], "jpeg")
        after = sorted(p for p in self.case.root.rglob("*") if p.is_file()
                       if p.name != "index.db")
        self.assertEqual([x for x in before if x.name != "index.db"], after)

    def test_recover_deleted_states_how(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        e = self._entry("DCIM/" + self._deleted_name())
        with self.assertRaises(EvidenceError):
            fatcase.recover_fat_entry(self.case, self.eid, self.vol,
                                      e["entry_id"], reason=" ")
        r = fatcase.recover_fat_entry(self.case, self.eid, self.vol,
                                      e["entry_id"], reason="suspect deleted it")
        from pathlib import Path
        data = Path(r.dest).read_bytes()
        self.assertEqual(data, self.facts["gone"])
        self.assertEqual(hashing.hash_bytes(data).sha256, r.hashes["sha256"])
        self.assertIn("ASSUMPTION", r.provenance["caution"])
        rec = self.case.custody.last("entry.recovered")
        self.assertEqual(rec["detail"]["method"], "fat-entry")
        self.assertEqual(rec["detail"]["reason"], "suspect deleted it")
        self.assertTrue(str(r.dest).startswith(os.fspath(self.case.root)))

    def _deleted_name(self):
        rows, _ = fatcase.list_fat_entries(self.case, self.eid, self.vol,
                                           filter="deleted")
        return rows[0]["path"].rsplit("/", 1)[1]

    def test_detail_checks_the_slot(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        e = self._entry("notes.txt")
        d = fatcase.fat_entry_detail(self.case, self.eid, self.vol, e["entry_id"])
        self.assertEqual(d["slot_check"], "matches the image")
        self.assertIn("fat-local", d["epochs"])
        # a stale index row is refused, not followed
        with index.session(self.case.root) as conn:
            conn.execute("UPDATE fat_entries SET slot_hex = ? WHERE entry_id = ?",
                         ("00" * 32, e["entry_id"]))
        p = fatcase.preview_fat_entry(self.case, self.eid, self.vol, e["entry_id"])
        self.assertIn("no longer matches", p["refused"])
        with self.assertRaises(EvidenceError):
            fatcase.recover_fat_entry(self.case, self.eid, self.vol,
                                      e["entry_id"], reason="x")

    def test_a_folder_is_not_previewed_as_a_file(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        e = self._entry("DCIM")
        p = fatcase.preview_fat_entry(self.case, self.eid, self.vol, e["entry_id"])
        self.assertIn("folder", p["refused"])

    def test_a_non_fat_volume_is_refused_before_anything_is_recorded(self):
        before = len(self.case.custody.rows())
        with self.assertRaises(EvidenceError):
            fatcase.parse_fat(self.case, self.eid, 999)
        self.assertEqual(len(self.case.custody.rows()), before)

    def test_run_everything_reads_fat_volumes(self):
        from forensics_workshop import pipeline
        s = pipeline.run_pipeline(self.case, self.eid)
        fat_steps = [r for r in s.results if r.step == "fat"]
        self.assertEqual([r.state for r in fat_steps], ["completed"])
        self.assertEqual(s.fat_volumes, [self.vol])
        self.assertEqual(s.tally["fat_deleted"], 1)
        again = pipeline.run_pipeline(self.case, self.eid)
        self.assertEqual([r.state for r in again.results if r.step == "fat"],
                         ["skipped"])

    def test_unknown_entry(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        with self.assertRaises(EvidenceError):
            fatcase.fat_entry_detail(self.case, self.eid, self.vol, 10 ** 6)


if __name__ == "__main__":
    unittest.main()
