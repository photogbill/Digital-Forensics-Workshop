"""FAT12/16/32 and exFAT: type by cluster count, listings, long names, deleted
entries and directories, chains and their damage, boot/backup checks, local
versus UTC timestamps, artefact rows — against spec-built volumes, then
against volumes made by real tools (mkfs.vfat + mtools, fsck.exfat) where
those are installed, then against third-party images where present."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

import _support  # noqa: F401
import fatsynth as fs
from forensics_workshop import fat
from forensics_workshop.errors import Cancelled, FileSystemError

#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = Path(os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples") / "fat"


class Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


class FileReader:
    def __init__(self, path):
        self.f = open(path, "rb")
        self.size = os.path.getsize(path)

    def read_at(self, offset, length):
        if offset >= self.size:
            return b""
        self.f.seek(offset)
        return self.f.read(min(length, self.size - offset))

    def close(self):
        self.f.close()


def by_path(vol):
    return {e.path: e for e in vol.entries()}


def payload(n, seed=1):
    out = bytearray()
    block = seed.to_bytes(4, "little")
    while len(out) < n:
        block = hashlib.sha256(block).digest()
        out += block
    return bytes(out[:n])


# ---------------------------------------------------------------------------
# FAT12 / FAT16 / FAT32
# ---------------------------------------------------------------------------

class TypeAndBoot(unittest.TestCase):
    def bpb(self, total, spc=1, fatsz=64, root=512, fat32=False):
        b = bytearray(512)
        b[0:3] = b"\xeb\x3c\x90"
        struct.pack_into("<HBHBHHBHHHII", b, 11, 512, spc, 1, 2,
                         0 if fat32 else root, 0, 0xF8, 0 if fat32 else fatsz,
                         63, 255, 0, total)
        if fat32:
            struct.pack_into("<IHHIHH", b, 36, fatsz, 0, 0, 2, 1, 6)
        b[510:512] = b"\x55\xaa"
        return bytes(b)

    def test_the_cluster_count_decides_at_the_spec_boundaries(self):
        overhead = 1 + 2 * 64 + 32                  # reserved + FATs + root
        for count, want in ((4084, "FAT12"), (4085, "FAT16"),
                            (65524, "FAT16")):
            boot = fat.parse_fat_boot(self.bpb(overhead + count))
            self.assertEqual((boot.cluster_count, boot.fat_type), (count, want))
        boot = fat.parse_fat_boot(self.bpb(1 + 2 * 600 + 65525, fatsz=600,
                                           fat32=True))
        self.assertEqual((boot.cluster_count, boot.fat_type), (65525, "FAT32"))

    def test_a_fat32_layout_with_too_few_clusters_is_read_and_reported(self):
        boot = fat.parse_fat_boot(self.bpb(1 + 2 * 64 + 5000, fatsz=64,
                                           fat32=True))
        self.assertEqual(boot.fat_type, "FAT32")
        self.assertTrue(any("Microsoft rule" in p for p in boot.problems))

    def test_what_is_not_fat_is_refused_with_a_sentence(self):
        for data in (bytes(4096), b"\xeb\x52\x90NTFS    " + bytes(4085),
                     b"random garbage " * 400):
            with self.assertRaises(FileSystemError) as cm:
                fat.open_fat(Bytes(data))
            self.assertIn(" ", str(cm.exception))
            self.assertTrue(str(cm.exception).endswith("."))
        with self.assertRaises(FileSystemError):
            fat.open_fat(Bytes(b"\0" * 100))

    def test_types_label_serial_and_counts(self):
        for kind in ("FAT12", "FAT16", "FAT32"):
            b = fs.FatImage(kind, label="CARD")
            b.add_file("", fs.sfn("A", "TXT"), payload(10))
            vol = fat.open_fat(Bytes(b.build()))
            info = vol.info()
            self.assertEqual(vol.fs_type, kind)
            self.assertEqual((info["label"], info["label_boot"]), ("CARD", "CARD"))
            self.assertEqual(info["serial"], "2024-ABCD")
            self.assertEqual(info["total_clusters"], b.count)
            self.assertEqual(info["used_clusters"], len(b.fat))
            self.assertEqual(vol.problems, [], kind)
        self.assertEqual(info["fsinfo"]["free_count"], b.count - len(b.fat))


class Listing(unittest.TestCase):
    def setUp(self):
        b = fs.FatImage("FAT16")
        self.photos = b.mkdir("", fs.sfn("PHOTOS"), "Photos")
        self.big = payload(50_000)
        self.long = b.add_file("Photos", fs.sfn("HOLIDA~1", "JPG"), self.big,
                               "Holiday at the lake – 2024.jpg",
                               cdate=fs.dos_date(2023, 12, 31),
                               ctime=fs.dos_time(23, 59, 58), tenth=150,
                               adate=fs.dos_date(2024, 2, 29))
        self.lower = b.add_file("", fs.sfn("README", "TXT"), b"hello", ntres=0x18)
        self.frag_data = payload(5 * 2048, 7)
        b.next += 3
        self.frag = b.add_file("", fs.sfn("FRAG", "BIN"), self.frag_data,
                               clusters=[60, 61, 90, 40, 41])
        self.b = b
        self.vol = fat.open_fat(Bytes(b.build()))
        self.e = by_path(self.vol)

    def test_paths_names_and_case_flags(self):
        self.assertEqual(sorted(self.e), sorted([
            "Photos", "Photos/Holiday at the lake – 2024.jpg", "readme.txt",
            "FRAG.BIN"]))
        e = self.e["Photos/Holiday at the lake – 2024.jpg"]
        self.assertEqual((e.short_name, e.long_name, e.size), (
            "HOLIDA~1.JPG", "Holiday at the lake – 2024.jpg", 50_000))
        self.assertEqual(e.dir_entry_offset, self.long["offset"])
        self.assertEqual(e.slots, 4)                 # 3 long-name slots + 8.3
        self.assertEqual(e.attribute_names, ["archive"])
        self.assertTrue(self.e["Photos"].is_dir)
        self.assertEqual(self.e["readme.txt"].short_name, "readme.txt")

    def test_timestamps_are_local_naive_and_labelled(self):
        e = self.e["Photos/Holiday at the lake – 2024.jpg"]
        self.assertEqual(e.created.value, "2023-12-31T23:59:59.500000")  # 58 s + 1.50
        self.assertEqual(e.created.epoch, "fat-local")
        self.assertEqual(e.created.raw, fs.dos_date(2023, 12, 31) << 16
                         | fs.dos_time(23, 59, 58))
        self.assertEqual(e.created.fine_10ms, 150)
        self.assertEqual(e.modified.value, "2024-05-01T13:22:10.000000")
        self.assertFalse(e.modified.is_utc)
        self.assertEqual((e.accessed.value, e.accessed.epoch),
                         ("2024-02-29", "fat-local-date"))
        for t in (e.created, e.modified):
            self.assertNotIn("Z", t.value)
            self.assertNotIn("+", t.value)

    def test_invalid_and_zero_dates_decode_to_none_but_keep_raw(self):
        self.assertIsNone(fat.decode_fat_local(0))
        bad = fs.dos_date(2024, 2, 30) << 16 | fs.dos_time(10, 0, 0)
        t = fat.fat_time(bad >> 16, bad & 0xFFFF)
        self.assertEqual((t.raw, t.value), (bad, None))
        self.assertIsNone(fat.decode_fat_local(fs.D0 << 16 | 24 << 11))   # 24:00

    def test_content_round_trips_through_chains(self):
        e = self.e["Photos/Holiday at the lake – 2024.jpg"]
        self.assertEqual(self.vol.read_file(e), self.big)
        self.assertEqual(self.vol.read_file(e, 49_990, 100), self.big[49_990:])
        self.assertEqual(b"".join(self.vol.iter_file(e, chunk=3000)), self.big)
        f = self.e["FRAG.BIN"]
        self.assertEqual(f.chain, [(60, 2), (90, 1), (40, 2)])
        self.assertEqual(f.recovery_basis, "fat-chain")
        self.assertEqual(self.vol.read_file(f), self.frag_data)
        self.assertEqual(self.vol.read_file(f, 4000, 3000), self.frag_data[4000:7000])
        with self.assertRaises(FileSystemError):
            self.vol.read_file(self.e["Photos"])

    def test_cancel(self):
        with self.assertRaises(Cancelled):
            list(self.vol.entries(should_cancel=lambda: True))


class Deleted(unittest.TestCase):
    def test_a_deleted_file_with_a_long_name(self):
        b = fs.FatImage("FAT12")
        data = payload(6000, 3)
        made = b.add_file("", fs.sfn("SECRET~1", "DOC"), data, "secret plans.doc")
        b.delete("secret plans.doc")
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)["secret plans.doc"]
        self.assertTrue(e.deleted)
        self.assertEqual(e.short_name, "_ECRET~1.DOC")
        self.assertIn("'_'", e.name_note)
        self.assertEqual(e.short_name_inferred, "SECRET~1.DOC")
        self.assertIn("INFERRED", e.name_note)
        self.assertEqual(e.recovery_basis, "contiguous-assumption")
        self.assertEqual(e.recoverable, {"clusters": 3, "in_volume": 3,
                                         "now_allocated": 0,
                                         "measured_against": "FAT"})
        self.assertEqual(e.dir_entry_offset, made["offset"])
        self.assertEqual(vol.read_file(e), data)

    def test_a_deleted_83_only_name_shows_the_lost_character(self):
        b = fs.FatImage("FAT16")
        b.add_file("", fs.sfn("REPORT", "PDF"), b"%PDF-1.7")
        b.delete("REPORT.PDF")
        e = by_path(fat.open_fat(Bytes(b.build())))["_EPORT.PDF"]
        self.assertEqual((e.name, e.long_name, e.short_name_inferred),
                         ("_EPORT.PDF", "", ""))

    def test_reallocated_clusters_are_measured_not_judged(self):
        b = fs.FatImage("FAT16")
        old = b.add_file("", fs.sfn("OLD", "BIN"), payload(3 * 2048, 4))
        b.delete("OLD.BIN")
        b.add_file("", fs.sfn("NEW", "BIN"), payload(2048, 5),
                   clusters=[old["clusters"][1]])
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)["_LD.BIN"]
        self.assertEqual(e.recoverable["now_allocated"], 1)
        self.assertEqual(e.recoverable["clusters"], 3)
        self.assertEqual(vol.read_file(e)[2048:4096], payload(2048, 5))

    def test_a_deleted_directory_is_walked_and_its_contents_flagged(self):
        b = fs.FatImage("FAT16")
        d = b.mkdir("", fs.sfn("TRASH"), "Trash folder")
        kept = payload(3000, 9)
        b.add_file("Trash folder", fs.sfn("NOTE", "TXT"), kept)
        b.add_file("Trash folder", fs.sfn("DIARY~1", "TXT"), b"dear diary",
                   "diary entry.txt")
        b.delete("Trash folder/NOTE.TXT")
        b.delete("Trash folder/diary entry.txt")
        b.delete("Trash folder")
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        self.assertTrue(e["Trash folder"].deleted)
        self.assertEqual(e["Trash folder"].chain, [(d["clusters"][0], 1)])
        note = e["Trash folder/_OTE.TXT"]
        self.assertTrue(note.deleted and note.in_deleted_dir)
        self.assertEqual(vol.read_file(note), kept)
        self.assertTrue(e["Trash folder/diary entry.txt"].in_deleted_dir)

    def test_a_deleted_directory_whose_cluster_was_reused_is_not_walked(self):
        b = fs.FatImage("FAT16")
        d = b.mkdir("", fs.sfn("OLDDIR"))
        b.add_file("OLDDIR", fs.sfn("X", "TXT"), b"x")
        b.delete("OLDDIR/X.TXT")
        b.delete("OLDDIR")
        b.add_file("", fs.sfn("REUSED", "BIN"), payload(2048), clusters=[d["clusters"][0]])
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        self.assertNotIn("_LDDIR/_.TXT", e)
        self.assertTrue(any("now allocated" in p for p in e["_LDDIR"].problems))

    def test_a_deleted_directory_whose_cluster_holds_other_data_is_not_walked(self):
        b = fs.FatImage("FAT16")
        d = b.mkdir("", fs.sfn("OLDDIR"))
        b.delete("OLDDIR")
        b.content[d["clusters"][0]] = payload(2048, 11)     # overwritten, freed
        b.dirs["OLDDIR"].slots.clear()
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        self.assertEqual(list(e), ["_LDDIR"])
        self.assertTrue(any("'.' entry" in p for p in e["_LDDIR"].problems))

    def test_fat32_deleted_entry_with_zero_high_word_is_noted(self):
        b = fs.FatImage("FAT32")
        b.add_file("", fs.sfn("GONE", "BIN"), b"gone")
        b.delete("GONE.BIN")
        e = by_path(fat.open_fat(Bytes(b.build())))["_ONE.BIN"]
        self.assertTrue(any("high 16 bits" in p for p in e.problems))


class Damage(unittest.TestCase):
    def test_loop_cross_link_short_long_and_free_chains(self):
        b = fs.FatImage("FAT16")
        a = b.add_file("", fs.sfn("A", "BIN"), payload(3 * 2048, 1))
        c = b.add_file("", fs.sfn("C", "BIN"), payload(2 * 2048, 2),
                       clusters=[a["clusters"][2], 200])
        loop = b.add_file("", fs.sfn("LOOP", "BIN"), payload(4 * 2048, 3),
                          clusters=[300, 301, 302, 303])
        b.fat[303] = 301
        short = b.add_file("", fs.sfn("SHORT", "BIN"), payload(4 * 2048, 4),
                           clusters=[400, 401])
        long_ = b.add_file("", fs.sfn("LONG", "BIN"), payload(100, 5),
                           clusters=[500, 501])
        hole = b.add_file("", fs.sfn("HOLE", "BIN"), payload(3 * 2048, 6),
                          clusters=[600, 601, 602])
        del b.fat[601]
        out = b.add_file("", fs.sfn("OUT", "BIN"), payload(2 * 2048, 7),
                         clusters=[700, 701])
        b.fat[700] = 0xFFF0                       # beyond the cluster range
        bad = b.add_file("", fs.sfn("BAD", "BIN"), payload(2 * 2048, 8),
                         clusters=[800, 801])
        b.fat[800] = 0xFFF7
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        self.assertTrue(any("Cross-linked" in p and "C.BIN" in p
                            for p in e["A.BIN"].problems))
        self.assertTrue(any("Cross-linked" in p and "A.BIN" in p
                            for p in e["C.BIN"].problems))
        self.assertTrue(any("loops back to cluster 301" in p
                            for p in e["LOOP.BIN"].problems))
        self.assertTrue(any("shorter than size" in p for p in e["SHORT.BIN"].problems))
        self.assertTrue(any("longer than size" in p for p in e["LONG.BIN"].problems))
        self.assertTrue(any("marks cluster 601 free" in p for p in e["HOLE.BIN"].problems))
        self.assertTrue(any("0xfff0" in p for p in e["OUT.BIN"].problems))
        self.assertTrue(any("BAD" in p for p in e["BAD.BIN"].problems))
        # a read never runs past the chain or the size, and is never padded
        self.assertEqual(vol.read_file(e["SHORT.BIN"]), payload(4 * 2048, 4)[:2 * 2048])
        self.assertEqual(vol.read_file(e["LONG.BIN"]), payload(100, 5))
        for name in ("A.BIN", "C.BIN"):
            self.assertEqual(len(vol.read_file(e[name])), e[name].size)
        del a, c, loop, short, long_, hole, out, bad

    def test_lfn_checksum_mismatch_and_orphans(self):
        b = fs.FatImage("FAT16")
        made = b.add_file("", fs.sfn("PLAIN", "TXT"), b"p", "the long one.txt")
        d = b.dirs[""]
        first, _last = d.index["the long one.txt"]
        for i in range(first, _last):
            d.slots[i][13] ^= 0xFF                       # break the checksum
        orphan = fs.lfn_slots("left behind.txt", 0x42)
        b.raw_slots("", orphan)
        b.raw_slots("", [fs.sfn_slot(b".          ", attr=0x10)][:0])
        b.add_file("", fs.sfn("NEXT", "TXT"), b"n")
        b.dirs[""].slots.insert(len(b.dirs[""].slots) - 1,
                                bytearray(fs.lfn_slots("stray.txt", 0x11)[0]))
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        plain = e["PLAIN.TXT"]
        self.assertEqual(plain.dir_entry_offset, made["offset"])
        self.assertTrue(any("LFN checksum mismatch" in p and "the long one.txt" in p
                            for p in plain.problems))
        texts = {o["text"] for o in vol.orphan_names}
        self.assertIn("left behind.txt", texts)
        self.assertIn("stray.txt", texts)
        self.assertIn("the long one.txt", texts)
        self.assertIn("NEXT.TXT", e)

    def test_backup_boot_fat_copies_fsinfo_and_primary_loss(self):
        b = fs.FatImage("FAT32")
        b.add_file("", fs.sfn("KEEP", "BIN"), payload(4000, 2))
        b.fsinfo_free = 12345
        img = b.build()
        img[6 * 512 + 0x47:6 * 512 + 0x47 + 4] = b"XXXX"          # backup label
        fat2 = (b.rsvd + b.fatsz) * 512
        img[fat2 + 4 * 50] = 0x77                                  # FAT copy 2
        vol = fat.open_fat(Bytes(img))
        text = " | ".join(vol.problems)
        self.assertIn("backup boot sector (sector 6) differs", text)
        self.assertIn("FAT copy 2 differs", text)
        self.assertIn("FSInfo says 12,345 free", text)
        img[0:512] = bytes(512)                                    # primary gone
        vol = fat.open_fat(Bytes(img))
        self.assertIn("BACKUP boot sector (sector 6) was used", vol.problems[0])
        self.assertEqual(vol.read_file(by_path(vol)["KEEP.BIN"]), payload(4000, 2))

    def test_dot_dot_mismatch_trailing_data_and_truncation(self):
        b = fs.FatImage("FAT16")
        b.mkdir("", fs.sfn("SUB"))
        b.dirs["SUB"].slots[1][26] = 0x33                 # '..' → cluster 0x33
        img = b.build()
        root_end = b.root_dir_offset + 32 * len(b.dirs[""].slots)
        img[root_end + 100] = 0x41                        # junk past the end marker
        vol = fat.open_fat(Bytes(img[:len(img) - 4096]))
        e = by_path(vol)
        self.assertTrue(any("'..' entry" in p for p in e["SUB"].problems))
        text = " | ".join(vol.problems)
        self.assertIn("non-zero byte(s) follow the end-of-directory marker", text)
        self.assertIn("truncated", text)

    def test_duplicate_names_and_forbidden_characters(self):
        b = fs.FatImage("FAT16")
        b.add_file("", fs.sfn("SAME", "TXT"), b"1")
        b.add_file("", fs.sfn("SAME", "TXT"), b"2")
        b.add_file("", fs.sfn("SLASH~1", "TXT"), b"3", "a/b.txt")
        vol = fat.open_fat(Bytes(b.build()))
        es = list(vol.entries())
        self.assertTrue(any("same name" in p for p in es[1].problems))
        self.assertEqual((es[2].name, es[2].path), ("a/b.txt", "a\\x2fb.txt"))
        self.assertTrue(any("escaped" in p for p in es[2].problems))
        self.assertEqual([fat.path_piece(n) for n in ("", ".", "..", "a\tb")],
                         ["[no name]", "[.]", "[..]", "a\\x09b"])

    def test_entries_after_the_end_marker_are_parsed_and_flagged(self):
        b = fs.FatImage("FAT16")
        b.add_file("", fs.sfn("SEEN", "TXT"), b"seen")
        b.raw_slots("", [bytes(32)])                     # end-of-directory marker
        hidden = payload(3000, 77)
        b.add_file("", fs.sfn("HIDDEN~1", "BIN"), hidden, "hidden after the end.bin")
        vol = fat.open_fat(Bytes(b.build()))
        e = by_path(vol)
        h = e["hidden after the end.bin"]
        self.assertTrue(h.past_end_marker)
        self.assertFalse(e["SEEN.TXT"].past_end_marker)
        self.assertIn("end-of-directory marker", h.problems[0])
        self.assertEqual(vol.read_file(h), hidden)
        self.assertTrue(any("past_end_marker" in p for p in vol.problems))
        row = next(r for r in fat.to_rows(vol, source_path="x")
                   if r["title"] == h.path)
        self.assertTrue(row["detail"]["past_end_marker"])


class Rows(unittest.TestCase):
    def test_rows_are_lean_local_times_are_not_utc_and_refs_are_unique(self):
        b = fs.FatImage("FAT16")
        b.mkdir("", fs.sfn("DIR"))
        b.add_file("DIR", fs.sfn("A", "TXT"), b"a")
        b.add_file("", fs.sfn("GONE", "TXT"), b"g")
        b.delete("GONE.TXT")
        vol = fat.open_fat(Bytes(b.build()))
        rows = fat.to_rows(vol, source_path="E001/p1")
        kinds = [r["artefact"] for r in rows]
        self.assertEqual(kinds.count("fat-entry"), 3)
        self.assertEqual(kinds[-1], "fat-volume")
        json.dumps(rows)
        self.assertEqual(len({r["row_ref_suffix"] for r in rows}), len(rows))
        for r in rows:
            self.assertEqual(set(r), {"artefact", "at_utc", "at_raw", "at_epoch",
                                      "title", "value", "detail", "row_ref_suffix"})
            self.assertIsNone(r["at_utc"])
        a = next(r for r in rows if r["title"] == "DIR/A.TXT")
        self.assertEqual((a["at_raw"], a["at_epoch"]), (fs.D0 << 16 | fs.T0, "fat-local"))
        self.assertIn("local (no zone recorded)", a["value"])
        g = next(r for r in rows if r["title"] == "_ONE.TXT")
        self.assertTrue(g["detail"]["deleted"])
        self.assertEqual(g["detail"]["recovery_basis"], "contiguous-assumption")
        self.assertIn("found_as", g["detail"])
        entries_only = fat.to_rows(list(vol.entries()), source_path="x")
        self.assertEqual(len(entries_only), 3)


# ---------------------------------------------------------------------------
# exFAT
# ---------------------------------------------------------------------------

class Exfat(unittest.TestCase):
    def setUp(self):
        x = fs.ExfatImage(label="CAMERA")
        x.mkdir("", "DCIM")
        self.jpg = payload(9000, 21)
        x.add_file("DCIM", "IMG_0001.JPG", self.jpg,
                   times=(fs.exfat_stamp(2024, 5, 1, 13, 0, 0),) * 3,
                   tens=(150, 0), offsets=(0x80 | (0x80 - 16), 0x00, 0xA0))
        self.longname = "A name well past fifteen characters – ünïcode.txt"
        self.frag = payload(3 * 4096 - 10, 22)
        x.add_file("", self.longname, self.frag, clusters=[40, 41, 30],
                   nofatchain=False)
        self.vdl = x.add_file("", "prealloc.bin", payload(8192, 23), vdl=5000)
        self.gone = payload(5000, 24)
        x.add_file("", "deleted.bin", self.gone)
        x.delete("deleted.bin")
        self.x = x
        self.img = x.build()
        self.vol = fat.open_fat(Bytes(self.img))
        self.e = by_path(self.vol)

    def test_volume(self):
        info = self.vol.info()
        self.assertEqual((self.vol.fs_type, info["label"], info["serial"]),
                         ("exFAT", "CAMERA", "5EED-1234"))
        self.assertEqual(info["used_clusters"], len(self.x.used))
        self.assertEqual(self.vol.problems, [])

    def test_names_chains_and_content(self):
        self.assertEqual(sorted(self.e), sorted(["DCIM", "DCIM/IMG_0001.JPG",
                                                 self.longname, "prealloc.bin",
                                                 "deleted.bin"]))
        j = self.e["DCIM/IMG_0001.JPG"]
        self.assertEqual((j.recovery_basis, j.no_fat_chain), ("contiguous-nofatchain", True))
        self.assertEqual(self.vol.read_file(j), self.jpg)
        f = self.e[self.longname]
        self.assertEqual((f.chain, f.recovery_basis), ([(40, 2), (30, 1)], "fat-chain"))
        self.assertEqual(self.vol.read_file(f), self.frag)
        self.assertEqual(f.problems, [])

    def test_bytes_past_valid_data_length_read_as_zero(self):
        e = self.e["prealloc.bin"]
        self.assertEqual(e.valid_data_length, 5000)
        data = self.vol.read_file(e)
        self.assertEqual(data[:5000], payload(8192, 23)[:5000])
        self.assertEqual(data[5000:], bytes(8192 - 5000))

    def test_utc_offsets_decide_utc_or_local(self):
        j = self.e["DCIM/IMG_0001.JPG"]
        # created: local 13:00:01.50, offset valid, -16 x 15 min = UTC-4
        self.assertEqual(j.created.epoch, "exfat-utc")
        self.assertEqual(j.created.utc_offset_minutes, -240)
        self.assertEqual(j.created.value, "2024-05-01T17:00:01.500000Z")
        # modified: offset byte 0x00 → not valid → local, never UTC
        self.assertEqual(j.modified.epoch, "exfat-local")
        self.assertEqual(j.modified.value, "2024-05-01T13:00:00.000000")
        self.assertEqual(j.accessed.utc_offset_minutes, 32 * 15)
        rows = {r["title"]: r for r in fat.to_rows(self.vol, source_path="x")}
        self.assertIsNone(rows["DCIM/IMG_0001.JPG"]["at_utc"])
        # the builder's default offset byte 0xF0: valid, 0x70 = -16 x 15 min
        self.assertEqual(rows["DCIM"]["at_utc"], "2024-05-01T17:22:10.000000Z")
        self.assertEqual(rows["DCIM"]["at_epoch"], "exfat-utc")
        self.assertEqual(rows["DCIM"]["artefact"], "exfat-entry")

    def test_deleted_set_is_found_and_measured_against_the_bitmap(self):
        e = self.e["deleted.bin"]
        self.assertTrue(e.deleted)
        self.assertEqual(e.recovery_basis, "contiguous-nofatchain")
        self.assertEqual(e.recoverable["now_allocated"], 0)
        self.assertEqual(e.recoverable["measured_against"], "allocation bitmap")
        self.assertEqual(self.vol.read_file(e), self.gone)
        self.assertEqual(e.problems, [])               # checksum verified with InUse restored

    def test_deleted_fat_chained_files_and_deleted_directories(self):
        x = fs.ExfatImage()
        x.mkdir("", "Trash")
        kept = payload(2 * 4096 + 7, 30)
        x.add_file("Trash", "frag.bin", kept, clusters=[50, 45, 46], nofatchain=False)
        x.add_file("Trash", "zeroed.bin", payload(4096 * 2, 31), clusters=[60, 61],
                   nofatchain=False)
        x.delete("Trash/frag.bin")
        x.delete("Trash/zeroed.bin", zero_fat=True)
        x.delete("Trash")
        vol = fat.open_fat(Bytes(x.build()))
        e = by_path(vol)
        self.assertTrue(e["Trash"].deleted)
        f = e["Trash/frag.bin"]
        self.assertTrue(f.deleted and f.in_deleted_dir)
        self.assertEqual(f.recovery_basis, "fat-chain-left-after-deletion")
        self.assertEqual(vol.read_file(f), kept)
        z = e["Trash/zeroed.bin"]
        self.assertEqual((z.recovery_basis, z.chain), ("contiguous-assumption", [(60, 2)]))

    def test_damage_is_reported(self):
        img = bytearray(self.img)
        x = self.x
        root = x.dirs[""]
        first, _end = root["index"]["prealloc.bin"]
        off = x.slot_offset(root, first)
        img[off + 2] ^= 0xFF                                     # SetChecksum
        img[100] ^= 0x01                                         # serial, main region
        bm = x.cluster_offset(x.bitmap_clusters[0])
        img[bm + (40 - 2) // 8] &= ~(1 << ((40 - 2) % 8)) & 0xFF   # free a live cluster
        vol = fat.open_fat(Bytes(img))
        text = " | ".join(vol.problems)
        self.assertIn("checksum sector does not match", text)
        self.assertIn("backup boot region (sectors 12-23) differs", text)
        e = by_path(vol)
        self.assertTrue(any("Entry set checksum mismatch" in p
                            for p in e["prealloc.bin"].problems))
        self.assertTrue(any("marked free in the allocation bitmap" in p
                            for p in e[self.longname].problems))

    def test_name_hash_and_main_boot_loss(self):
        x = fs.ExfatImage()
        x.add_file("", "hashed.txt", b"h", bad_hash=True)
        img = x.build()
        vol = fat.open_fat(Bytes(img))
        self.assertTrue(any("Name hash mismatch" in p
                            for p in by_path(vol)["hashed.txt"].problems))
        img[0:512] = bytes(512)
        vol = fat.open_fat(Bytes(img))
        self.assertEqual(vol.fs_type, "exFAT")
        self.assertTrue(any("BACKUP boot sector" in p for p in vol.problems))

    def test_a_set_after_the_end_marker_is_parsed_and_flagged(self):
        x = fs.ExfatImage()
        x.add_file("", "visible.txt", b"v")
        x.dirs[""]["slots"].append(bytearray(32))           # end marker
        hidden = payload(5000, 78)
        x.add_file("", "hidden.bin", hidden)
        vol = fat.open_fat(Bytes(x.build()))
        e = by_path(vol)
        self.assertTrue(e["hidden.bin"].past_end_marker)
        self.assertFalse(e["visible.txt"].past_end_marker)
        self.assertEqual(vol.read_file(e["hidden.bin"]), hidden)
        self.assertEqual(e["hidden.bin"].recoverable["now_allocated"], 2)

    def test_cross_link(self):
        x = fs.ExfatImage()
        x.add_file("", "one.bin", payload(8192, 1), clusters=[40, 41], nofatchain=False)
        x.add_file("", "two.bin", payload(8192, 2), clusters=[41, 42], nofatchain=False)
        e = by_path(fat.open_fat(Bytes(x.build())))
        self.assertTrue(any("Cross-linked" in p for p in e["two.bin"].problems))
        self.assertTrue(any("Cross-linked" in p for p in e["one.bin"].problems))


class Helpers(unittest.TestCase):
    def test_checksums_against_independent_spellings(self):
        name = fs.sfn("LONGFI~1", "TXT")
        self.assertEqual(fat.lfn_checksum(name), fs.sfn_sum(name))
        chk = fs.sfn_sum(name)
        self.assertEqual(fat.first_byte_for_checksum(name[1:], chk), name[0])
        blob = payload(96, 3)
        self.assertEqual(fat.exfat_set_checksum(blob), fs.set_checksum(blob))
        reg = payload(11 * 512, 4)
        self.assertEqual(fat.exfat_boot_checksum(reg), fs.boot_checksum(reg))
        up = fat.parse_upcase(fs.upcase_table())
        self.assertEqual(fat.exfat_name_hash("Mixed Case.txt", up),
                         fs.name_hash("Mixed Case.txt"))

    def test_epochs_are_named_here_and_never_utc_for_local(self):
        self.assertIn("not UTC", fat.EPOCHS["fat-local"])
        self.assertIn("not UTC", fat.EPOCHS["exfat-local"])
        self.assertEqual(fat.utc_offset_minutes(0x80 | 0x7C), -60)
        self.assertIsNone(fat.utc_offset_minutes(0x7C))


# ---------------------------------------------------------------------------
# real tools
# ---------------------------------------------------------------------------

def _missing(tools) -> list[str]:
    return [t for t in tools if shutil.which(t) is None]


def run(*cmd, stdin=None):
    env = dict(os.environ, MTOOLS_SKIP_CHECK="1", LC_ALL="C.UTF-8")
    done = subprocess.run([str(c) for c in cmd], input=stdin, capture_output=True,
                          env=env)
    if done.returncode != 0:
        raise AssertionError(f"{cmd[0]} failed: {done.stderr[:300]!r}")
    return done.stdout


MTOOLS = ("mkfs.vfat", "mmd", "mcopy", "mdel", "mdir")


@unittest.skipIf(_missing(MTOOLS), f"needs {', '.join(_missing(MTOOLS))} "
                 "(apt install dosfstools mtools)")
class RealToolsFat(unittest.TestCase):
    """mkfs.vfat makes the volume, mtools writes long names, folders and
    deletions; mdir's listing and mcopy's bytes are the reference."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="dfw-fat-"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def build(self, kind, size_mb):
        img = self.tmp / f"{kind}.img"
        with open(img, "wb") as f:
            f.truncate(size_mb << 20)
        extra = ["-s", "1"] if kind == "32" else []
        run("mkfs.vfat", "-F", kind, *extra, "-n", "REALVOL", "-i", "C0FFEE01", img)
        files = {
            "Photos/Holiday 2024/IMG 0001 – lake.jpg": payload(70_000, 1),
            "Photos/A very long file name indeed.bin": payload(3_000, 2),
            "Docs/Ünïcode naмe.dat": payload(20_000, 3),
            "a.txt": b"hello\n",
            "Docs/to be deleted.txt": payload(5_000, 4),
            "GONE.BIN": payload(9_000, 5),
        }
        run("mmd", "-i", img, "::/Photos", "::/Photos/Holiday 2024", "::/Docs")
        for path, data in files.items():
            src = self.tmp / "src"
            src.write_bytes(data)
            run("mcopy", "-i", img, src, f"::/{path}")
        run("mdel", "-i", img, "::/Docs/to be deleted.txt", "::/GONE.BIN")
        return img, files

    def check(self, kind, size_mb):
        img, files = self.build(kind, size_mb)
        listing = run("mdir", "-/", "-b", "-a", "-i", img, "::").decode("utf-8")
        want = {line[3:].rstrip("/") for line in listing.splitlines() if line.startswith("::/")}
        reader = FileReader(img)
        try:
            vol = fat.open_fat(reader)
            self.assertEqual(vol.fs_type, f"FAT{kind}")
            self.assertEqual(vol.info()["label"], "REALVOL")
            self.assertEqual(vol.info()["serial"], "C0FF-EE01")
            entries = list(vol.entries())
            live = {e.path for e in entries if not e.deleted}
            self.assertEqual(live, want)
            for e in entries:
                if e.deleted or e.is_dir:
                    continue
                theirs = run("mcopy", "-n", "-i", img, f"::/{e.path}", "-")
                self.assertEqual(vol.read_file(e), theirs, e.path)
                self.assertEqual(theirs, files[e.path])
            gone = {e.path: e for e in entries if e.deleted}
            self.assertIn("Docs/to be deleted.txt", gone)
            self.assertIn("_ONE.BIN", gone)
            g = gone["Docs/to be deleted.txt"]
            self.assertEqual(g.recovery_basis, "contiguous-assumption")
            if g.recoverable["now_allocated"] == 0:
                self.assertEqual(vol.read_file(g), files["Docs/to be deleted.txt"])
            for e in entries:
                if not e.deleted:
                    self.assertEqual(e.problems, [], e.path)
            self.assertEqual(vol.problems, [])
        finally:
            reader.close()

    def test_fat12(self):
        self.check("12", 4)

    def test_fat16(self):
        self.check("16", 32)

    def test_fat32(self):
        self.check("32", 40)


@unittest.skipIf(_missing(("fsck.exfat",)), "needs fsck.exfat (apt install exfatprogs)")
class RealToolsExfat(unittest.TestCase):
    def test_fsck_exfat_accepts_the_builder_and_mkfs_exfat_volumes_parse(self):
        x = fs.ExfatImage(label="FSCKME")
        x.mkdir("", "DCIM")
        x.add_file("DCIM", "IMG_0001.JPG", payload(9000, 1))
        x.add_file("", "Long name that spans several entries.bin", payload(12000, 2),
                   clusters=[60, 50, 51], nofatchain=False)
        with tempfile.TemporaryDirectory(prefix="dfw-exfat-") as tmp:
            img = Path(tmp) / "x.img"
            img.write_bytes(x.build())
            done = subprocess.run(["fsck.exfat", "-n", str(img)], capture_output=True,
                                  text=True)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            self.assertIn("clean", done.stdout)
            if shutil.which("mkfs.exfat"):
                real = Path(tmp) / "real.img"
                with open(real, "wb") as f:
                    f.truncate(32 << 20)
                subprocess.run(["mkfs.exfat", "-L", "MKFSVOL", "-c", "8K", str(real)],
                               capture_output=True, check=True)
                r = FileReader(real)
                try:
                    vol = fat.open_fat(r)
                    info = vol.info()
                    self.assertEqual((info["label"], info["cluster_size"]),
                                     ("MKFSVOL", 8192))
                    self.assertEqual(list(vol.entries()), [])
                    self.assertEqual(vol.problems, [])
                finally:
                    r.close()


# ---------------------------------------------------------------------------
# third-party samples (never copied into tests/; read only where present)
# ---------------------------------------------------------------------------

EXFATPROGS = SAMPLES / "thirdparty" / "exfatprogs_imgs"

#: exfatprogs' fsck test images (GPL test data, read in place): the damage
#: each was built to carry, and what this parser must say about it.
EXPECTED = {
    "bs_bad_csum": ("vol", "checksum sector does not match"),
    "de_bad_csum": ("entry", "Entry set checksum mismatch"),
    "loop_chain": ("entry", "loops back"),
    "duplicate_clu": ("entry", "Cross-linked"),
    "bad_file_size": ("entry", "Chain shorter than size"),
    "bad_num_chain": ("entry", "BAD"),
    "bad_bitmap": ("entry", "marked free in the allocation bitmap"),
    "bad_bitmap_size": ("vol", "allocation bitmap is"),
    "bad_root": ("vol", "root directory's chain are marked free"),
    "duplicated_name": ("entry", "same name"),
    "rename_dot_entry": ("entry", "not one a driver writes"),
    "invalid_name": ("entry", "forbids"),
    "large_file_invalid_clus": ("entry", "free although it is in this chain"),
    "unused-dentries": ("entry", "AFTER its directory's end-of-directory marker"),
}


@unittest.skipUnless(EXFATPROGS.is_dir(), f"third-party images not present in "
                     f"{EXFATPROGS} (clone github.com/exfatprogs/exfatprogs and "
                     "untar tests/*/exfat.img.tar.xz there)")
class ThirdPartyExfat(unittest.TestCase):
    def test_each_corruption_is_reported(self):
        for name, (where, needle) in EXPECTED.items():
            path = EXFATPROGS / name / "exfat.img"
            if not path.exists():
                continue
            with self.subTest(image=name):
                r = FileReader(path)
                try:
                    vol = fat.open_fat(r)
                    entries = list(vol.entries())
                    found = list(vol.problems) if where == "vol" else \
                        [p for e in entries for p in e.problems]
                    self.assertTrue(any(needle in p for p in found),
                                    f"{name}: {found[:5]}")
                finally:
                    r.close()


FUSE_IMG = SAMPLES / "exfat_fuse.img"


@unittest.skipUnless((SAMPLES / "exfat_fuse.manifest.json").exists(),
                     f"no exfat-fuse sample in {SAMPLES}")
class ThirdPartyFuseExfat(unittest.TestCase):
    """An image written by the exfat-fuse driver (relan/exfat 1.4) with
    known files: live, fragmented, deleted, and a deleted folder tree."""

    def test_content_matches_the_manifest(self):
        manifest = json.loads((SAMPLES / "exfat_fuse.manifest.json").read_text())
        r = FileReader(FUSE_IMG)
        try:
            vol = fat.open_fat(r)
            e = by_path(vol)
            for path, (sha, deleted) in manifest.items():
                with self.subTest(path=path):
                    self.assertEqual(e[path].deleted, deleted)
                    got = hashlib.sha256(vol.read_file(e[path])).hexdigest()
                    self.assertEqual(got, sha)
        finally:
            r.close()


if __name__ == "__main__":
    unittest.main()
