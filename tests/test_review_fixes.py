"""The ten defects an independent review found on 2026-10-29 in the new
code, each held to its fix."""

from __future__ import annotations

import json
import os
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

import disksynth as ds
import fatsynth as fs
import prefetchsynth as ps
from test_winartifacts import PF, START, _hive
from forensics_workshop import (diskimage, fatcase, image, index, ingest,
                                parallel, pipeline, report, review,
                                winartifacts)
from forensics_workshop.artefacts import query
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError


def _disk_of(vol: bytes, ptype=0x0C) -> bytes:
    disk = bytearray(ds.mbr_sector([(0, ptype, START, len(vol) // 512)]))
    disk += bytes(START * 512 - len(disk)) + vol
    return bytes(disk)


class FatDeletedFolder(TempDirCase):
    """1. A hive inside a DELETED FOLDER is not a live file."""

    def test_a_hive_in_a_deleted_folder_is_not_read(self):
        v = fs.FatImage("FAT32", sectors=140000)
        v.mkdir("", fs.sfn("USERS"), "Users")
        v.mkdir("Users", fs.sfn("OLD"), "old")
        v.add_file("Users/old", fs.sfn("NTUSER", "DAT"), _hive(), "NTUSER.DAT")
        v.mkdir("", fs.sfn("WINDOWS"), "Windows")
        v.mkdir("Windows", fs.sfn("PREFETCH"), "Prefetch")
        v.add_file("Windows/Prefetch", fs.sfn("NOTEPA~1", "PF"),
                   ps.build_scca(30), PF)
        v.delete("Users/old")
        image_path = self.tmp / "d.dd"
        image_path.write_bytes(_disk_of(bytes(v.build())))
        case = Case.create(self.tmp / "case", case_id="R-1", examiner=EXAMINER)
        eid = case.add_image(image_path).id
        diskimage.ingest_image(case, eid)
        vol = next(x["volume"] for x in diskimage.list_volumes(case, eid)
                   if x.get("fs_type") in fatcase.FAT_TYPES)
        fatcase.parse_fat(case, eid, vol)
        rows, _ = fatcase.list_fat_entries(case, eid, vol, filter="in-deleted-dir")
        self.assertTrue(any(r["name"] == "NTUSER.DAT" for r in rows),
                        "the fixture puts the hive inside a deleted folder")
        s = winartifacts.analyse_volume(case, eid, vol, workers=0)
        self.assertNotIn("registry", s.files)
        self.assertTrue(any("inside a deleted folder" in x["reason"]
                            for x in s.skipped), s.skipped)
        self.assertEqual(s.files.get("prefetch"), 1)


class ReportHashes(unittest.TestCase):
    """2. The report shows the FIRST hash and flags any later difference."""

    def test_first_hash_and_disagreements(self):
        rows = [
            {"action": "image.completed", "target": "E001", "at": "t1",
             "hashes": {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}},
            {"action": "image.completed", "target": "E001", "at": "t2",
             "hashes": {"md5": "d" * 32, "sha1": "e" * 40, "sha256": "f" * 64}},
            {"action": "verify.completed", "target": "E001", "at": "t3",
             "detail": {"mismatched": 1, "missing": 0, "unreadable": 0}}]
        text = report._evidence_hashes(rows, "E001")
        self.assertIn("c" * 64, text)
        self.assertIn("A LATER HASHING DIFFERS", text)
        self.assertIn("VERIFICATION t3 FOUND 1 mismatched", text)
        self.assertLess(text.index("c" * 64), text.index("f" * 64))


class PipelineCancel(TempDirCase):
    """3. A step that caught a cancel itself still ends the run."""

    def test_cancelled_step_stops_the_run(self):
        v = fs.FatImage("FAT16")
        v.add_file("", fs.sfn("A", "TXT"), b"x", "a.txt")
        image_path = self.tmp / "c.dd"
        image_path.write_bytes(_disk_of(bytes(v.build()), 0x06))
        case = Case.create(self.tmp / "case", case_id="R-3", examiner=EXAMINER)
        eid = case.add_image(image_path).id

        class Out:
            state = "cancelled"

            def as_dict(self):
                return {"state": "cancelled"}

        with mock.patch.object(fatcase, "parse_fat", return_value=Out()):
            s = pipeline.run_pipeline(case, eid)
        self.assertEqual(s.state, "cancelled")
        self.assertNotIn("windows", [r.step for r in s.results])
        self.assertEqual(case.custody.last("pipeline.cancelled")["detail"]["state"],
                         "cancelled")


class PoolNeverHangs(unittest.TestCase):
    """4 and 7. A failure while feeding a job is an answer, not a hang; a
    closed pool starts no new worker."""

    def test_a_failed_send_is_answered_and_the_rest_continue(self):
        real = parallel._send
        calls = {"n": 0}

        def flaky(stream, obj):
            calls["n"] += 1
            if calls["n"] == 1:
                raise MemoryError("simulated")
            return real(stream, obj)

        job = ("winartifacts", ("lnk", b"not a shortcut", "x.lnk", "x.lnk", None))
        with mock.patch.object(parallel, "_send", flaky):
            with parallel.Pool(1) as pool:
                if not pool.started:
                    self.skipTest(pool.error)
                out = list(pool.imap([("job", job), ("job", job)]))
                restarts = pool.restarts
        self.assertEqual(out[0][1][0], "WorkerDied")
        self.assertIn("MemoryError", out[0][1][1])
        self.assertEqual(out[1][1][0], "FileSystemError")
        self.assertEqual(restarts, 1)

    def test_close_kills_and_does_not_restart(self):
        pool = parallel.Pool(2)
        if not pool.started:
            self.skipTest(pool.error)
        procs = list(pool._procs)
        pool.close(kill=True)
        self.assertEqual(pool.restarts, 0)
        self.assertTrue(all(p.poll() is not None for p in procs))
        self.assertTrue(all(p.poll() is not None for p in pool._procs))

    def test_large_bytes_cross_out_of_band_unchanged(self):
        data = os.urandom(3 << 20)
        with parallel.Pool(1) as pool:
            if not pool.started:
                self.skipTest(pool.error)
            job = ("winartifacts", ("lnk", data, "x.lnk", "x.lnk", None))
            out = list(pool.imap([("job", job)]))
        self.assertEqual(out[0][1][0], "FileSystemError")   # parsed, refused


class FolderManifest(TempDirCase):
    """5. A folder file changed since ingest is reported."""

    def test_changed_since_ingest(self):
        root = self.tmp / "triage" / "Windows" / "Prefetch"
        root.mkdir(parents=True)
        pf = root / PF
        pf.write_bytes(ps.build_scca(30))
        case = Case.create(self.tmp / "case", case_id="R-5", examiner=EXAMINER)
        eid = case.add_folder(self.tmp / "triage").id
        ingest.ingest_folder(case, eid)
        pf.write_bytes(ps.build_scca(30, run_count=99))
        s = winartifacts.analyse_folder(case, eid, workers=0)
        self.assertEqual([m["path"] for m in s.manifest_mismatches],
                         [f"Windows/Prefetch/{PF}"])
        with index.session(case.root) as conn:
            d = json.loads(conn.execute(
                "SELECT detail_json FROM artefacts LIMIT 1").fetchone()[0])
        self.assertIs(d["file"]["matches_manifest"], False)


class ImageGrows(TempDirCase):
    """6. An image that grows while hashed is refused, not mis-hashed."""

    def test_growth_is_refused(self):
        path = self.tmp / "g.dd"
        path.write_bytes(os.urandom(1 << 20))
        with image.ImageSource.open(path) as src:
            with open(path, "ab") as fh:          # the test's own file
                fh.write(b"more" * 1024)
            with self.assertRaisesRegex(EvidenceError, "grew"):
                image.hash_image(src)


class ExfatSlot(TempDirCase):
    """8. exFAT's slot check covers the Stream Extension slot."""

    def test_stream_slot_change_is_caught(self):
        v = fs.ExfatImage()
        info = v.add_file("", "photo.jpg", ds.jpeg_file() * 10)
        vol = bytes(v.build())
        path = self.tmp / "x.dd"
        path.write_bytes(_disk_of(vol, 0x07))
        case = Case.create(self.tmp / "case", case_id="R-8", examiner=EXAMINER)
        eid = case.add_image(path).id
        diskimage.ingest_image(case, eid)
        volno = next(x["volume"] for x in diskimage.list_volumes(case, eid)
                     if x.get("fs_type") in fatcase.FAT_TYPES)
        fatcase.parse_fat(case, eid, volno)
        rows, _ = fatcase.list_fat_entries(case, eid, volno, search="photo")
        e = rows[0]
        stored = fatcase._stored(case, eid, volno, e["entry_id"])
        self.assertEqual(len(stored["slot_hex"]), 128)
        # change the data length in the Stream Extension slot (+32+8)
        raw = bytearray(path.read_bytes())
        at = START * 512 + e["dir_entry_offset"] + 32 + 8
        raw[at] ^= 0xFF
        path.write_bytes(bytes(raw))
        p = fatcase.preview_fat_entry(case, eid, volno, e["entry_id"])
        self.assertIn("no longer matches", p["refused"])


class IocCsv(TempDirCase):
    """9. A CSV cell that a spreadsheet would run is neutralised."""

    def test_formula_cells(self):
        case = Case.create(self.tmp / "case", case_id="R-9", examiner=EXAMINER)
        folder = self.tmp / "ev"
        folder.mkdir()
        (folder / "a").write_text("a")
        eid = case.add_folder(folder).id
        fid = review.propose(case, source="engine", kind="selector:phone",
                             evidence_id=eid, title="phone",
                             detail={"value": "+44 20 7946 0000"})
        fid2 = review.propose(case, source="engine", kind="selector:email",
                              evidence_id=eid, title="e",
                              detail={"value": "=HYPERLINK(\"x\")@e.com"})
        review.decide(case, fid, "confirmed")
        review.decide(case, fid2, "confirmed")
        out = report.generate(case)
        csv_text = Path(out["files"]["iocs_csv"]["path"]).read_text("utf-8-sig")
        self.assertIn("'+44 20 7946 0000", csv_text)
        self.assertIn("'=HYPERLINK", csv_text)
        js = json.loads(Path(out["files"]["iocs_json"]["path"]).read_text("utf-8"))
        self.assertIn("+44 20 7946 0000", [i["value"] for i in js["iocs"]])


class SearchIsLiteral(TempDirCase):
    """10. '_' and '%' in a search are literal."""

    def test_underscore(self):
        case = Case.create(self.tmp / "case", case_id="R-10", examiner=EXAMINER)
        folder = self.tmp / "ev"
        folder.mkdir()
        (folder / "a").write_text("a")
        eid = case.add_folder(folder).id
        with index.session(case.root) as conn:
            conn.executemany(
                "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
                "parser, artefact, title, value, detail_json, provenance, "
                "row_ref) VALUES ('r', ?, 'x', 'p', 'k', ?, '', '{}', 't', ?)",
                [(eid, "plain", "1"), (eid, "with_underscore", "2"),
                 (eid, "100%", "3")])
        self.assertEqual(query.list_rows(case, eid, search="_")[1], 1)
        self.assertEqual(query.list_rows(case, eid, search="%")[1], 1)


if __name__ == "__main__":
    unittest.main()
