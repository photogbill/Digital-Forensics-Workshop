"""A disk image through a case, end to end: register, hash, partitions, NTFS,
journal, preview (which writes nothing), recovery (which says how), carving,
slack, verification — and the command line on top."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import sqlite3
import unittest
from pathlib import Path

from _support import EXAMINER, TempDirCase

import disksynth as ds
from forensics_workshop import carve, cli, diskimage, index, verify
from forensics_workshop.case import Case
from forensics_workshop.errors import (CaseLayoutError, EvidenceError,
                                       FileSystemError)

PART_LBA = 2048
SECRET = b"the slack remembers what the file forgot"


def build_disk():
    """GPT disk: partition 1 NTFS (a story), then unpartitioned space holding
    a planted JPEG. Returns (disk bytes, facts)."""
    b = ds.NtfsBuilder(clusters=768, label="CASEVOL")
    stomped = ds.filetime(ds.datetime(2018, 1, 1, tzinfo=ds.timezone.utc))
    b.directory(64, "Users")
    b.file(65, "plan.txt", b"meet at the usual place", parent=64,
           ads={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n"})
    deleted_data = bytes(range(256)) * 40                       # 10 240 bytes
    runs = b.file(66, "ledger.xlsx", deleted_data, parent=64, in_use=False,
                  seq=2, free_clusters=True)
    b.file(67, "tool.exe", b"MZ" + bytes(700), parent=64,
           si_times=(stomped,) * 4, fn_times=(ds.T0,) * 4)
    slack_runs = b.file(68, "letter.txt", b"L" * 5000, parent=64)
    b.write(slack_runs[0][0] + 1, b"L" * 904 + SECRET)
    png = ds.png_file(16, 16)
    free_lcn = b.next_free + 20                                  # unallocated
    b.write(free_lcn, png)
    b.journal(40, [dict(file=(66, 1), parent=(64, 1), time=ds.T0, reasons=0x100,
                        name="ledger.xlsx"),
                   dict(file=(66, 1), parent=(64, 1), time=ds.T0 + 99,
                        reasons=0x200 | 0x80000000, name="ledger.xlsx")])
    volume = b.build()
    sectors = PART_LBA + len(volume) // 512 + 4096
    last = PART_LBA + len(volume) // 512 - 1
    disk = ds.gpt_disk(sectors, [dict(type=ds.BASIC_DATA, first=PART_LBA,
                                      last=last, name="Windows")])
    disk[PART_LBA * 512:PART_LBA * 512 + len(volume)] = volume
    jpeg_at = (last + 64) * 512
    jpeg = ds.jpeg_file()
    disk[jpeg_at:jpeg_at + len(jpeg)] = jpeg
    return bytes(disk), dict(deleted=deleted_data, deleted_runs=runs, png=png,
                             png_at=PART_LBA * 512 + free_lcn * 4096,
                             jpeg=jpeg, jpeg_at=jpeg_at)


class _DiskFixture(TempDirCase):
    def setUp(self):
        super().setUp()
        self.disk, self.facts = build_disk()
        self.evidence = self.tmp / "evidence"
        self.evidence.mkdir()
        size = -(-len(self.disk) // 3)
        self.segments = []
        for i in range(3):
            path = self.evidence / f"laptop.{i + 1:03d}"
            path.write_bytes(self.disk[i * size:(i + 1) * size])
            self.segments.append(path)
        self.case = Case.create(self.tmp / "case", case_id="IMG-1",
                                examiner=EXAMINER)

    def case_files(self):
        out = set()
        for root, _dirs, files in os.walk(self.case.root):
            for f in files:
                out.add(os.path.relpath(os.path.join(root, f), self.case.root))
        return out


class DiskCase(_DiskFixture):
    def test_the_whole_story(self):
        item = self.case.add_image(self.segments[0], label="laptop")
        self.assertEqual(item.kind, "raw-image")
        self.assertEqual(len(self.case.sidecar(item.id)["segments"]), 3)
        self.assertEqual(set(map(str, self.case.evidence_roots())),
                         set(map(str, self.segments)))

        image = diskimage.ingest_image(self.case, item.id)
        self.assertEqual(image.state, "completed")
        self.assertEqual(image.sha256, hashlib.sha256(self.disk).hexdigest())
        self.assertEqual(image.scheme, "gpt")
        record = self.case.custody.last("image.completed", item.id)
        self.assertEqual(record["hashes"]["sha256"], image.sha256)
        volumes = diskimage.list_volumes(self.case, item.id)
        kinds = [(v["kind"], v["fs_type"]) for v in volumes]
        self.assertIn(("partition", "ntfs"), kinds)
        ntfs_vol = next(v["volume"] for v in volumes if v["fs_type"] == "ntfs")

        summary = diskimage.parse_ntfs(self.case, item.id, ntfs_vol)
        self.assertEqual(summary.state, "completed")
        self.assertEqual(summary.label, "CASEVOL")
        self.assertEqual(summary.deleted, 1)
        self.assertEqual(summary.deleted_fully_unallocated, 1)
        self.assertEqual(summary.ads, 3, "plan.txt's, and $UsnJrnl's $J and $Max")
        self.assertGreaterEqual(summary.with_indicators, 1)
        self.assertEqual(summary.journal["records"], 2)
        self.assertEqual(self.case.custody.last("ntfs.completed", item.id)
                         ["hashes"]["entries"], summary.entries_sha256)

        rows, _n = diskimage.list_entries(self.case, item.id, ntfs_vol,
                                          filter="deleted")
        self.assertEqual([r["path"] for r in rows], ["Users/ledger.xlsx"])
        self.assertEqual(rows[0]["clusters_now_allocated"], 0)
        rows, _n = diskimage.list_entries(self.case, item.id, ntfs_vol,
                                          filter="indicators")
        self.assertEqual([r["path"] for r in rows], ["Users/tool.exe"])
        self.assertTrue(rows[0]["si_created_utc"].startswith("2018-01-01"))
        rows, _n = diskimage.list_entries(self.case, item.id, ntfs_vol, filter="ads")
        self.assertEqual([r["path"] for r in rows],
                         ["$Extend/$UsnJrnl", "Users/plan.txt"])

        detail = diskimage.entry_detail(self.case, item.id, ntfs_vol, 67)
        self.assertEqual(detail["indicators"][0]["code"],
                         "si-created-before-fn-created")
        self.assertTrue(detail["indicators"][0]["also_produced_by"])
        journal = diskimage.entry_detail(self.case, item.id, ntfs_vol, 66)["journal"]
        self.assertEqual([r["reason_names"] for r in journal],
                         ["FILE_CREATE", "FILE_DELETE,CLOSE"])

        # preview writes nothing
        before = self.case_files()
        custody_before = len(self.case.custody.rows())
        pv = diskimage.preview_entry(self.case, item.id, ntfs_vol, 66)
        self.assertEqual(pv["data"], self.facts["deleted"])
        self.assertFalse(pv["in_use"])
        self.assertEqual(self.case_files(), before)
        self.assertEqual(len(self.case.custody.rows()), custody_before + 0,
                         "a preview is not a custodial action")

        # recovery says how
        rec = diskimage.recover_entry(self.case, item.id, ntfs_vol, 66,
                                      reason="deleted spreadsheet")
        self.assertEqual(Path(rec.dest).read_bytes(), self.facts["deleted"])
        self.assertEqual(rec.hashes["sha256"],
                         hashlib.sha256(self.facts["deleted"]).hexdigest())
        last = self.case.custody.last("entry.recovered")
        self.assertEqual(last["detail"]["method"], "mft-entry")
        self.assertEqual(last["detail"]["clusters_now_allocated"], 0)
        self.assertEqual(last["detail"]["path"], "Users/ledger.xlsx")
        ads = diskimage.recover_entry(self.case, item.id, ntfs_vol, 65,
                                      "Zone.Identifier", reason="origin")
        self.assertTrue(ads.dest.endswith("plan.txt~Zone.Identifier"))

        # carving the volume's unallocated clusters finds the planted PNG only
        cs = diskimage.carve_evidence(self.case, item.id, volume=ntfs_vol,
                                      unallocated=True)
        self.assertEqual(cs.state, "completed")
        rows, _n = carve.list_candidates(self.case, item.id, run_id=cs.run_id)
        png = [r for r in rows if r["offset"] == self.facts["png_at"]]
        self.assertEqual(len(png), 1)
        self.assertEqual((png[0]["type_id"], png[0]["status"], png[0]["length"]),
                         ("png", "complete", len(self.facts["png"])))
        self.assertFalse(any(r["type_id"] == "pe" for r in rows),
                         "tool.exe is allocated; an unallocated carve must not see it")
        before = self.case_files()
        pc = diskimage.preview_candidate(self.case, item.id, png[0]["id"])
        self.assertEqual(pc["data"], self.facts["png"])
        self.assertEqual(self.case_files(), before)
        got = diskimage.recover_candidate(self.case, item.id, png[0]["id"],
                                          reason="image in free space")
        self.assertEqual(Path(got.dest).read_bytes(), self.facts["png"])
        self.assertEqual(self.case.custody.last("carve.recovered")["detail"]["claim"],
                         "candidate")

        # the gap after the partition, carved on its own
        gap = next(v["volume"] for v in volumes if v["kind"] == "gap"
                   and v["offset"] <= self.facts["jpeg_at"] < v["offset"] + v["length"])
        gs = diskimage.carve_evidence(self.case, item.id, volume=gap)
        rows, _n = carve.list_candidates(self.case, item.id, run_id=gs.run_id)
        self.assertEqual([(r["type_id"], r["offset"]) for r in rows],
                         [("jpeg", self.facts["jpeg_at"])])

        # slack
        sl = diskimage.scrape_slack(self.case, item.id, ntfs_vol)
        self.assertEqual(sl.state, "completed")
        regions, _n = diskimage.list_slack(self.case, item.id, ntfs_vol)
        letter = [r for r in regions if r["path"] == "Users/letter.txt"]
        self.assertEqual(len(letter), 1)
        self.assertIn(SECRET.decode(), letter[0]["strings"])
        preview = diskimage.slack_preview(self.case, item.id, ntfs_vol, 68)
        self.assertTrue(preview["data"].startswith(SECRET))

        # verification: all matches; then one byte of segment 2 changes
        v = verify.verify_evidence(self.case, item.id)
        self.assertTrue(v.all_matched, v.as_dict())
        self.assertEqual(v.checked, 3)
        raw = bytearray(self.segments[1].read_bytes())
        raw[100] ^= 0xFF
        self.segments[1].write_bytes(bytes(raw))
        v = verify.verify_evidence(self.case, item.id)
        self.assertFalse(v.all_matched)
        self.assertEqual([m["relpath"] for m in v.mismatches],
                         ["(whole disk)", "laptop.002"])
        self.assertEqual(verify.last_verification(self.case, item.id)["detail"]
                         ["all_matched"], False)

        # the index altered afterwards is caught by the recorded digest
        with sqlite3.connect(self.case.root / index.FILENAME) as conn:
            conn.execute("UPDATE volumes SET length = length + 512 WHERE volume = 1")
        conn.close()
        v = verify.verify_evidence(self.case, item.id)
        self.assertIs(v.manifest_digest_matches, False)
        self.assertTrue(self.case.custody.verify().ok)

    # ------------------------------------------------------------------
    def test_registration_refusals(self):
        with self.assertRaisesRegex(EvidenceError, "first segment"):
            self.case.add_image(self.segments[1])
        e01 = self.evidence / "other.E01"
        e01.write_bytes(b"EVF\x09\x0d\x0a\xff\x00" + bytes(1024))
        with self.assertRaisesRegex(EvidenceError, "E01"):
            self.case.add_image(e01)
        self.case.add_image(self.segments[0])
        with self.assertRaisesRegex(EvidenceError, "already registered"):
            self.case.add_image(self.segments[0])
        inside = self.case.root / "extracted" / "x.raw"
        inside.write_bytes(bytes(1024))
        with self.assertRaises(CaseLayoutError):
            self.case.add_image(inside)

    def test_a_volume_that_is_not_ntfs_is_refused_by_name(self):
        item = self.case.add_image(self.segments[0])
        diskimage.ingest_image(self.case, item.id)
        gap = next(v["volume"] for v in diskimage.list_volumes(self.case, item.id)
                   if v["kind"] == "gap")
        with self.assertRaisesRegex(FileSystemError, "could not be read as NTFS"):
            diskimage.parse_ntfs(self.case, item.id, gap)

    def test_recovery_needs_a_reason_and_never_writes_near_evidence(self):
        item = self.case.add_image(self.segments[0])
        with self.assertRaisesRegex(EvidenceError, "reason"):
            diskimage.recover_candidate(self.case, item.id, 1, reason=" ")
        from forensics_workshop import extract
        with self.assertRaises(Exception):
            extract.copy_stream_to_case(self.case, [b"x"], self.segments[2])

    def test_an_older_case_index_is_upgraded_in_place(self):
        path = self.case.root / index.FILENAME
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE meta SET value = '1' WHERE key = 'schema_version'")
            conn.execute("DROP TABLE carve_candidates")
        conn.close()
        with index.session(self.case.root) as conn:
            self.assertEqual(conn.execute("SELECT value FROM meta WHERE key = "
                                          "'schema_version'").fetchone()[0], "2")
            conn.execute("SELECT COUNT(*) FROM carve_candidates").fetchone()


class CommandLine(_DiskFixture):
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([str(a) for a in argv])
        return code, out.getvalue(), err.getvalue()

    def test_the_image_commands(self):
        case, ex = self.case.root, ["--examiner", EXAMINER]
        code, out, err = self.cli("add-image", case, self.segments[0], *ex)
        self.assertEqual(code, 0, err)
        self.assertIn("hardware write blocker", err)
        eid = json.loads(out)["id"]
        self.assertEqual(self.cli("image", case, eid, *ex)[0], 0)
        code, out, _e = self.cli("volumes", case, eid, *ex)
        self.assertIn("NTFS", out)
        vol = next(v["volume"] for v in diskimage.list_volumes(self.case, eid)
                   if v["fs_type"] == "ntfs")
        self.assertEqual(self.cli("ntfs", case, eid, "--volume", vol, *ex)[0], 0)
        code, out, _e = self.cli("entries", case, eid, "--volume", vol,
                                 "--filter", "deleted", *ex)
        self.assertIn("Users/ledger.xlsx", out)
        code, out, _e = self.cli("preview", case, eid, "--volume", vol,
                                 "--record", 66, *ex)
        self.assertEqual(code, 0)
        self.assertIn("nothing written", out)
        code, out, _e = self.cli("usn", case, eid, "--volume", vol,
                                 "--reason", "FILE_DELETE", *ex)
        self.assertIn("ledger.xlsx", out)
        code, out, _e = self.cli("carve", case, eid, "--types", "png,jpeg", *ex)
        self.assertEqual(code, 0)
        code, out, _e = self.cli("candidates", case, eid, "--type", "png", *ex)
        self.assertIn("CANDIDATE", out)
        cid = int(out.split()[0])
        self.assertEqual(self.cli("carve-preview", case, eid, cid, *ex)[0], 0)
        code, out, _e = self.cli("carve-recover", case, eid, cid, "--reason",
                                 "suite", *ex)
        self.assertEqual(json.loads(out)["provenance"]["method"], "carved")
        self.assertEqual(self.cli("slack", case, eid, "--volume", vol, *ex)[0], 0)
        code, out, _e = self.cli("entry", case, eid, "--volume", vol, "--record",
                                 67, *ex)
        self.assertIn("si-created-before-fn-created", out)
        code, _o, err = self.cli("recover", case, eid, "--volume", vol,
                                 "--record", 3, "--reason", "x", *ex)
        self.assertEqual(code, 3, "record 3 ($Volume) has no data stream")
        self.assertIn("refused", err)
        self.assertEqual(self.cli("verify", case, eid, *ex)[0], 0)


if __name__ == "__main__":
    unittest.main()
