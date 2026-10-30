"""winartifacts.py: a Windows tree on a FAT32 volume inside a disk image —
a hive with its place, a shortcut (and a deleted one), a Jump List, a
Prefetch file and an event log — found by name and place, parsed by their
own modules, stored as artefact rows with their provenance, custody either
side; a file that is not its format is skipped with the reason."""

from __future__ import annotations

import json
import unittest

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

import disksynth as ds
import evtxsynth as xs
import fatsynth as fs
import jumplistsynth as js
import prefetchsynth as ps
import regsynth as rs
import shelllinksynth as ls
from test_jumplist import EXPLORER, lnk_to
from forensics_workshop import diskimage, fatcase, index, winartifacts
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError

START = 2048
PF = "NOTEPAD.EXE-D8414F97.pf"


def _hive() -> bytes:
    b = rs.HiveBuilder()
    r = b.root
    r.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run").sz(
        "Sync", "C:\\sync.exe")
    run = r.path("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    run.sz("a", "cmd\\1").sz("MRUList", "a")
    return bytes(b.build())


def _jumplist() -> bytes:
    dl = js.destlist(3, [js.destlist_entry(3, 1, "C:\\Cases\\one.txt", count=4)])
    data, _ = js.build_cfb([("DestList", dl),
                            ("1", lnk_to("C:\\Cases\\one.txt", (101, 1)))])
    return data


def build_windows_disk() -> bytes:
    v = fs.FatImage("FAT32", sectors=140000, label="WINDOWS")
    v.mkdir("", fs.sfn("WINDOWS"), "Windows")
    v.mkdir("Windows", fs.sfn("PREFETCH"), "Prefetch")
    v.add_file("Windows/Prefetch", fs.sfn("NOTEPA~1", "PF"), ps.build_scca(30), PF)
    v.mkdir("Windows", fs.sfn("SYSTEM32"), "System32")
    v.mkdir("Windows/System32", fs.sfn("WINEVT"), "winevt")
    v.mkdir("Windows/System32/winevt", fs.sfn("LOGS"), "Logs")
    v.add_file("Windows/System32/winevt/Logs", fs.sfn("SECURITY", "EVT"),
               xs.build([xs.chunk_of([xs.logon_4624(1)])]), "Security.evtx")
    v.mkdir("", fs.sfn("USERS"), "Users")
    v.mkdir("Users", fs.sfn("BILL"), "bill")
    v.add_file("Users/bill", fs.sfn("NTUSER", "DAT"), _hive(), "NTUSER.DAT")
    v.mkdir("Users/bill", fs.sfn("RECENT"), "Recent")
    v.add_file("Users/bill/Recent", fs.sfn("REPORT~1", "LNK"), ls.sample_lnk(),
               "report.docx.lnk")
    v.add_file("Users/bill/Recent", fs.sfn("GONE~1", "LNK"), ls.sample_lnk(),
               "gone.docx.lnk")
    v.add_file("Users/bill/Recent", fs.sfn("JUNK~1", "LNK"), b"not a shortcut" * 20,
               "junk.lnk")
    v.add_file("Users/bill/Recent", fs.sfn("F01B4D~1", "AUT"), _jumplist(), EXPLORER)
    v.delete("Users/bill/Recent/gone.docx.lnk")
    vol = bytes(v.build())
    disk = bytearray(ds.mbr_sector([(0, 0x0C, START, len(vol) // 512)]))
    disk += bytes(START * 512 - len(disk)) + vol
    return bytes(disk)


class WindowsOnFat(TempDirCase):
    def setUp(self):
        super().setUp()
        image = self.tmp / "win.dd"
        image.write_bytes(build_windows_disk())
        self.case = Case.create(self.tmp / "case", case_id="WIN-1",
                                examiner=EXAMINER)
        self.eid = self.case.add_image(image).id
        diskimage.ingest_image(self.case, self.eid)
        self.vol = next(v["volume"] for v in diskimage.list_volumes(self.case, self.eid)
                        if v.get("fs_type") in fatcase.FAT_TYPES)

    def _rows(self, parser=None):
        with index.session(self.case.root) as conn:
            sql = "SELECT * FROM artefacts WHERE evidence_id = ?"
            args = [self.eid]
            if parser:
                sql += " AND parser = ?"
                args.append(parser)
            return [dict(r) for r in conn.execute(sql, args)]

    def test_refuses_an_unparsed_volume(self):
        with self.assertRaisesRegex(EvidenceError, "parse the volume first"):
            winartifacts.analyse_volume(self.case, self.eid, self.vol)

    def test_every_kind_is_found_parsed_and_stored(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        s = winartifacts.analyse_volume(self.case, self.eid, self.vol)
        self.assertEqual(s.state, "completed", s.skipped)
        self.assertEqual(s.files, {"registry": 1, "lnk": 2, "jumplist": 1,
                                   "prefetch": 1, "evtx": 1})
        for parser in ("registry", "lnk", "jumplist", "prefetch", "evtx"):
            self.assertTrue(self._rows(parser), parser)
        kinds = {r["artefact"] for r in self._rows()}
        self.assertIn("evtx_logon", kinds)
        self.assertIn("prefetch-run", kinds)
        self.assertIn("runmru", kinds)
        # the junk shortcut is skipped with its reason, never guessed at
        self.assertEqual([x["path"] for x in s.skipped],
                         ["Users/bill/Recent/junk.lnk"])
        self.assertIn("not a Windows shortcut", s.skipped[0]["reason"])
        # every row says which file it came from, hashed
        for r in self._rows():
            if r["parser"] not in winartifacts.KINDS:
                continue                       # the FAT volume's own row
            f = json.loads(r["detail_json"])["file"]
            self.assertEqual(f["path"], r["source_relpath"])
            self.assertEqual(len(r["source_sha256"]), 64)
            self.assertTrue(r["row_ref"].startswith(f"v{self.vol}:fat"))
        self.assertTrue(self.case.custody.verify().ok)
        self.assertIsNotNone(self.case.custody.last("windows.completed"))

    def test_a_deleted_shortcut_is_read_and_says_so(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        s = winartifacts.analyse_volume(self.case, self.eid, self.vol)
        self.assertEqual(s.deleted_files, 1)
        gone = [r for r in self._rows("lnk") if "gone" in r["source_relpath"]
                or "GONE" in r["source_relpath"].upper()]
        self.assertTrue(gone)
        for r in gone:
            self.assertEqual(r["provenance"], "deleted-file")
            self.assertTrue(json.loads(r["detail_json"])["deleted"])

    def test_rerun_replaces_and_kinds_can_be_chosen(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        winartifacts.analyse_volume(self.case, self.eid, self.vol)
        n = len(self._rows())
        winartifacts.analyse_volume(self.case, self.eid, self.vol)
        self.assertEqual(len(self._rows()), n)
        s = winartifacts.analyse_volume(self.case, self.eid, self.vol,
                                        kinds=("prefetch",))
        self.assertEqual(s.files, {"prefetch": 1})
        self.assertEqual(len(self._rows()), n, "other kinds' rows are kept")

    def test_worker_processes_give_the_same_rows_in_the_same_order(self):
        fatcase.parse_fat(self.case, self.eid, self.vol)
        one = winartifacts.analyse_volume(self.case, self.eid, self.vol, workers=0)
        rows_one = [(r["parser"], r["artefact"], r["row_ref"], r["value"])
                    for r in self._rows() if r["parser"] != "fat"]
        two = winartifacts.analyse_volume(self.case, self.eid, self.vol, workers=2)
        rows_two = [(r["parser"], r["artefact"], r["row_ref"], r["value"])
                    for r in self._rows() if r["parser"] != "fat"]
        self.assertEqual(one.workers, 0)
        self.assertEqual(two.workers, 2, two.notes)
        self.assertEqual(rows_one, rows_two)
        self.assertEqual(one.skipped, two.skipped)
        self.assertEqual(two.worker_restarts, 0)

    def test_run_everything_includes_it(self):
        from forensics_workshop import pipeline
        s = pipeline.run_pipeline(self.case, self.eid)
        steps = {(r.step, r.state) for r in s.results}
        self.assertIn(("windows", "completed"), steps)
        self.assertGreater(s.tally["windows_rows"], 0)


def build_ntfs_windows_disk() -> bytes:
    """The same artefacts on NTFS (GPT disk), one shortcut deleted."""
    b = ds.NtfsBuilder(clusters=1024, label="OS")
    b.directory(64, "Windows")
    b.directory(65, "Prefetch", parent=64)
    b.file(66, PF, ps.build_scca(30), parent=65)
    b.directory(67, "Users")
    b.file(68, "NTUSER.DAT", _hive(), parent=67)
    b.file(69, "report.docx.lnk", ls.sample_lnk(), parent=67)
    b.file(70, "gone.docx.lnk", ls.sample_lnk(), parent=67, in_use=False, seq=2)
    b.file(71, "Security.evtx", xs.build([xs.chunk_of([xs.logon_4624(1)])]),
           parent=64)
    volume = b.build()
    lba = 2048
    sectors = lba + len(volume) // 512 + 4096
    disk = ds.gpt_disk(sectors, [dict(type=ds.BASIC_DATA, first=lba,
                                      last=lba + len(volume) // 512 - 1,
                                      name="Windows")])
    disk[lba * 512:lba * 512 + len(volume)] = volume
    return bytes(disk)


class WindowsOnNtfs(TempDirCase):
    def test_found_through_the_mft(self):
        image = self.tmp / "ntfs.dd"
        image.write_bytes(build_ntfs_windows_disk())
        case = Case.create(self.tmp / "case", case_id="WIN-2", examiner=EXAMINER)
        eid = case.add_image(image).id
        diskimage.ingest_image(case, eid)
        vol = next(v["volume"] for v in diskimage.list_volumes(case, eid)
                   if v.get("fs_type") == "ntfs")
        diskimage.parse_ntfs(case, eid, vol)
        s = winartifacts.analyse_volume(case, eid, vol)
        self.assertEqual(s.state, "completed", s.skipped)
        self.assertEqual(s.fs, "NTFS")
        self.assertEqual(s.files, {"registry": 1, "lnk": 2, "prefetch": 1,
                                   "evtx": 1})
        self.assertEqual(s.deleted_files, 1)
        with index.session(case.root) as conn:
            refs = [r[0] for r in conn.execute(
                "SELECT row_ref FROM artefacts WHERE parser = 'prefetch'")]
        self.assertTrue(refs and all(r.startswith(f"v{vol}:mft66") for r in refs))


class WindowsInAFolder(TempDirCase):
    """A triage collection (paths kept, as KAPE keeps them) and an exported
    mailbox, registered as a folder and ingested."""

    def test_folder(self):
        import pstsynth
        from forensics_workshop import ingest
        root = self.tmp / "triage" / "C"
        (root / "Windows" / "Prefetch").mkdir(parents=True)
        (root / "Windows" / "Prefetch" / PF).write_bytes(ps.build_scca(30))
        (root / "Users" / "bill").mkdir(parents=True)
        (root / "Users" / "bill" / "NTUSER.DAT").write_bytes(_hive())
        (root / "Users" / "bill" / "x.lnk").write_bytes(ls.sample_lnk())
        (root / "mail").mkdir()
        (root / "mail" / "bill.pst").write_bytes(pstsynth.standard()[0])
        case = Case.create(self.tmp / "case", case_id="WIN-3", examiner=EXAMINER)
        eid = case.add_folder(self.tmp / "triage").id
        with self.assertRaisesRegex(EvidenceError, "ingest"):
            winartifacts.analyse_folder(case, eid)
        ingest.ingest_folder(case, eid)
        s = winartifacts.analyse_folder(case, eid, workers=0)
        self.assertEqual(s.state, "completed", s.skipped)
        self.assertEqual(s.files, {"registry": 1, "lnk": 1, "prefetch": 1, "pst": 1})
        with index.session(case.root) as conn:
            kinds = {r[0] for r in conn.execute(
                "SELECT artefact FROM artefacts WHERE parser = 'pst'")}
            refs = [r[0] for r in conn.execute("SELECT row_ref FROM artefacts")]
        self.assertIn("email", kinds)
        self.assertIn("email-store", kinds)
        self.assertTrue(all(r.startswith("f:") for r in refs))


class Names(unittest.TestCase):
    def test_kind_of(self):
        k = winartifacts.kind_of
        self.assertEqual(k("Windows/System32/config/SYSTEM", "SYSTEM"), "registry")
        self.assertEqual(k("Users/a/NTUSER.DAT", "NTUSER.DAT"), "registry")
        self.assertIsNone(k("Users/a/NTUSER.DAT.LOG1", "NTUSER.DAT.LOG1"))
        self.assertEqual(k("x/y.lnk", "y.lnk"), "lnk")
        self.assertEqual(k("Windows/Prefetch/A.EXE-1.pf", "A.EXE-1.pf"), "prefetch")
        self.assertIsNone(k("Downloads/A.EXE-1.pf", "A.EXE-1.pf"))
        self.assertEqual(k("L/Security.evtx", "Security.evtx"), "evtx")
        self.assertEqual(k("r/x.customDestinations-ms", "x.customDestinations-ms"),
                         "jumplist")


if __name__ == "__main__":
    unittest.main()
