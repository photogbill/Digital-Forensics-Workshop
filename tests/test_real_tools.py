"""The parsers against volumes and tables made by REAL tools, not by our builders.

A synthetic builder that shares a parser's misunderstanding passes every test
it is given. So wherever ntfs-3g (mkntfs, ntfscp, ntfsls, ntfsinfo, ntfscluster,
ntfstruncate, ntfsfallocate, ntfsundelete), sfdisk, sgdisk and mkfs.vfat are
installed, this file builds real NTFS volumes and real partition tables and
holds the parsers to what those tools say: record numbers, names, sizes,
content hashes, alternate streams, sparse and fragmented run lists with
negative offsets, free clusters from $Bitmap, $Extend paths, MBR/EBR/GPT
entries and GUIDs, and — for a deletion emulated the way NTFS performs one —
ntfsundelete's own recoverability percentage.

**Where the tools are missing (Windows, a bare CI image), every test here
SKIPS and names what is missing.** First watched passing 2026-09-11 on
Ubuntu 22.04 with ntfs-3g 2021.8.22 and util-linux sfdisk.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import unittest

from _support import TempDirCase

from forensics_workshop import image, ntfs, partitions

NTFS_TOOLS = ("mkntfs", "ntfscp", "ntfsls", "ntfsinfo", "ntfscluster",
              "ntfstruncate", "ntfsfallocate", "ntfsundelete")
TABLE_TOOLS = ("sfdisk", "sgdisk", "mkfs.vfat", "mkntfs")


def _missing(tools) -> list[str]:
    return [t for t in tools if shutil.which(t) is None]


def run(*cmd, stdin=None, check=True) -> str:
    done = subprocess.run([str(c) for c in cmd], input=stdin, capture_output=True,
                          text=True)
    if check and done.returncode != 0:
        raise AssertionError(f"{cmd[0]} failed: {done.stderr.strip()[:300]}")
    return done.stdout


def ls_rows(text: str) -> dict:
    rows = {}
    for line in text.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+\w{3} +\d+ \d\d:\d\d \d{4} (.+)$", line)
        if m and m.group(3) not in (".", ".."):
            rows[m.group(3)] = (int(m.group(1)), int(m.group(2)))
    return rows


def open_volume(path):
    src = image.ImageSource.open(path)
    return src, ntfs.NtfsVolume(image.Region(src, 0, src.size))


def by_path(vol):
    entries = {e.record: e for e in vol.iter_entries() if not e.is_extension}
    nodes = {}
    for e in entries.values():
        fn = e.preferred_name()
        nodes[e.record] = (e.sequence, e.in_use, e.is_dir,
                           fn.parent_record if fn else -1,
                           fn.parent_sequence if fn else 0, fn.name if fn else "")
    paths = ntfs.build_paths(nodes)
    return {paths[r][0]: e for r, e in entries.items() if e.in_use}, paths


class RealNtfs(TempDirCase):
    @classmethod
    def setUpClass(cls):
        missing = _missing(NTFS_TOOLS)
        if missing:
            raise unittest.SkipTest(f"ntfs-3g tools not installed: {missing}")

    def setUp(self):
        super().setUp()
        d = self.tmp
        self.vol = d / "vol.img"
        with open(self.vol, "wb") as fh:
            fh.truncate(64 << 20)
        run("mkntfs", "-F", "-Q", "-q", "-s", 512, "-c", 4096, "-L", "REALVOL", self.vol)
        self.files = {
            "small.txt": b"hello resident\n",
            "a.bin": os.urandom(10_000), "big.bin": os.urandom(3_000_000),
            "f1.bin": os.urandom(100_000), "f2.bin": os.urandom(100_000),
            "f3.bin": os.urandom(100_000), "empty.bin": b""}
        for name, data in self.files.items():
            (d / name).write_bytes(data)
            run("ntfscp", "-q", self.vol, d / name, f"/{name}")
        (d / "ads.txt").write_bytes(b"hidden in a stream\n")
        run("ntfscp", "-q", "-N", "secret", self.vol, d / "ads.txt", "/small.txt")
        run("ntfsfallocate", "-f", "-l", 8192, "-o", 1 << 20, self.vol, "/empty.bin")

    def test_records_names_sizes_and_content_match_ntfs_3g(self):
        src, vol = open_volume(self.vol)
        try:
            self.assertEqual(vol.volume_info()["label"], "REALVOL")
            found, paths = by_path(vol)
            listing = ls_rows(run("ntfsls", "-a", "-s", "-l", "-i", "-f", self.vol))
            self.assertGreater(len(listing), 15)
            for name, (inode, size) in listing.items():
                e = found[name]
                s = e.stream("")
                self.assertEqual(e.record, inode, name)
                if not e.is_dir and name != "$BadClus":
                    self.assertEqual(s.data_size if s else 0, size, name)
            for name, data in self.files.items():
                if name == "empty.bin":
                    continue
                got = b"".join(vol.iter_stream(found[name].stream("")))
                self.assertEqual(hashlib.sha256(got).digest(),
                                 hashlib.sha256(data).digest(), name)
            ads = found["small.txt"].stream("secret")
            self.assertEqual(vol.read_stream(ads), b"hidden in a stream\n")
            for line in run("ntfsls", "-a", "-s", "-i", "-f", "-p", "/$Extend",
                            self.vol, check=False).splitlines():
                m = re.match(r"\s*(\d+)\s+(\$\w+)$", line)
                if m:
                    self.assertEqual(paths[int(m.group(1))][0], f"$Extend/{m.group(2)}")
        finally:
            src.close()

    def test_a_sparse_file_and_free_space(self):
        src, vol = open_volume(self.vol)
        try:
            found, _p = by_path(vol)
            s = found["empty.bin"].stream("")
            info = run("ntfsinfo", "-f", "-v", "-F", "/empty.bin", self.vol)
            self.assertIn("<HOLE>", info)
            self.assertIsNone(s.runs[0][1])
            self.assertEqual(vol.read_stream(s), bytes(s.data_size))
            free = int(re.search(r"clusters of free space\s*:\s*(\d+)",
                                 run("ntfscluster", "-f", "-i", self.vol)).group(1))
            self.assertEqual(sum(n for _l, n in vol.free_extents()), free)
        finally:
            src.close()

    def test_a_fragmented_file_with_a_negative_run_offset(self):
        d = self.tmp
        free = int(re.search(r"clusters of free space\s*:\s*(\d+)",
                             run("ntfscluster", "-f", "-i", self.vol)).group(1))
        filler = d / "filler.bin"
        with open(filler, "wb") as fh:
            fh.truncate((free - 40) * 4096)
        run("ntfscp", "-q", self.vol, filler, "/filler.bin")
        filler.unlink()
        inode = ls_rows(run("ntfsls", "-a", "-l", "-i", "-f", self.vol))["f1.bin"][0]
        run("ntfstruncate", "-f", self.vol, inode, "0x80", 0)
        data = os.urandom(250_000)
        (d / "frag.bin").write_bytes(data)
        run("ntfscp", "-q", self.vol, d / "frag.bin", "/frag.bin")
        info = run("ntfsinfo", "-f", "-v", "-F", "/frag.bin", self.vol)
        want = [tuple(int(x, 16) for x in m) for m in re.findall(
            r"^\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s*$", info, re.M)]
        src, vol = open_volume(self.vol)
        try:
            found, _p = by_path(vol)
            s = found["frag.bin"].stream("")
            self.assertEqual([tuple(r) for r in s.runs], want)
            self.assertGreater(len(want), 1, "the fixture did not fragment")
            self.assertLess(s.runs[1][1], s.runs[0][1], "no negative offset")
            self.assertEqual(b"".join(vol.iter_stream(s)), data)
        finally:
            src.close()

    def test_an_emulated_deletion_agrees_with_ntfsundelete(self):
        src, vol = open_volume(self.vol)
        found, _p = by_path(vol)
        victim = found["a.bin"]
        runs = victim.stream("").runs
        bm_runs = vol.entry(6).stream("").runs
        mft_runs, cs, rs = vol.mft_runs, vol.cluster, vol.record_size
        rec0 = vol.read_record_bytes(0)
        src.close()

        def disk_offset(file_runs, logical):
            for vcn, lcn, n in file_runs:
                if vcn * cs <= logical < (vcn + n) * cs:
                    return lcn * cs + logical - vcn * cs
            raise AssertionError("offset not in runs")

        clusters = [lcn + i for _v, lcn, n in runs for i in range(n)]
        with open(self.vol, "r+b") as fh:
            at = disk_offset(mft_runs, victim.record * rs)
            fh.seek(at + 16)
            fh.write(struct.pack("<H", victim.sequence + 1))       # NTFS frees:
            fh.seek(at + 22)                                        # seq + 1,
            fh.write(struct.pack("<H", victim.flags & ~1))          # not in use
            for lcn in clusters:                                    # clusters free
                off = disk_offset(bm_runs, lcn >> 3)
                fh.seek(off)
                byte = fh.read(1)[0]
                fh.seek(off)
                fh.write(bytes([byte & ~(1 << (lcn & 7))]))
            pos = struct.unpack_from("<H", rec0, 20)[0]               # and $MFT:$BITMAP
            while struct.unpack_from("<I", rec0, pos)[0] != 0xB0:
                pos += struct.unpack_from("<I", rec0, pos + 4)[0]
            if rec0[pos + 8]:
                runs_off = struct.unpack_from("<H", rec0, pos + 32)[0]
                alen = struct.unpack_from("<I", rec0, pos + 4)[0]
                mb, _pr = ntfs.decode_runs(rec0[pos + runs_off:pos + alen])
                off = disk_offset(mb, victim.record >> 3)
            else:
                voff = struct.unpack_from("<H", rec0, pos + 20)[0]
                off = disk_offset(mft_runs, 0) + pos + voff + (victim.record >> 3)
            fh.seek(off)
            byte = fh.read(1)[0]
            fh.seek(off)
            fh.write(bytes([byte & ~(1 << (victim.record & 7))]))

        def undelete_percent():
            out = run("ntfsundelete", "-f", "-s", self.vol)
            row = [l for l in out.splitlines() if l.split()[:1] == [str(victim.record)]]
            self.assertTrue(row, out)
            return int(re.search(r"(\d+)%", row[0]).group(1))

        src, vol = open_volume(self.vol)
        e = vol.entry(victim.record)
        self.assertFalse(e.in_use)
        self.assertEqual(vol.count_allocated(e.stream("").runs), (len(clusters), 0))
        self.assertEqual(vol.read_stream(e.stream("")), self.files["a.bin"])
        src.close()
        self.assertEqual(undelete_percent(), 100)

        with open(self.vol, "r+b") as fh:                      # someone reuses 2 of 3
            for lcn in clusters[1:]:
                off = disk_offset(bm_runs, lcn >> 3)
                fh.seek(off)
                byte = fh.read(1)[0]
                fh.seek(off)
                fh.write(bytes([byte | (1 << (lcn & 7))]))
        src, vol = open_volume(self.vol)
        total, used = vol.count_allocated(vol.entry(victim.record).stream("").runs)
        src.close()
        self.assertEqual(undelete_percent(), 100 * (total - used) // total)


class RealTables(TempDirCase):
    @classmethod
    def setUpClass(cls):
        missing = _missing(TABLE_TOOLS)
        if missing:
            raise unittest.SkipTest(f"partitioning tools not installed: {missing}")

    def test_mbr_with_logical_partitions_matches_sfdisk(self):
        disk = self.tmp / "mbr.img"
        with open(disk, "wb") as fh:
            fh.truncate(256 << 20)
        run("sfdisk", "-q", disk, stdin=(
            "label: dos\nlabel-id: 0x1234abcd\n"
            "start=2048, size=40960, type=7, bootable\n"
            "start=43008, size=20480, type=83\nstart=65536, type=5\n"
            "start=67584, size=10240, type=b\nstart=79872, size=10240, type=7\n"
            "start=92160, size=10240, type=83\n"))
        ref = json.loads(run("sfdisk", "--json", disk))["partitiontable"]
        part = self.tmp / "p5.img"
        with open(part, "wb") as fh:
            fh.truncate(10240 * 512)
        run("mkfs.vfat", "-F", 32, "-n", "LOGICAL5", part)
        with open(disk, "r+b") as out:
            out.seek(67584 * 512)
            out.write(part.read_bytes())
        with image.ImageSource.open(disk) as src:
            t = partitions.read_table(src)
            ours = sorted((p.entry, p.start_lba, p.sectors, p.type_code)
                          for p in t.partitions)
            theirs = sorted(((("ebr" if int(p["node"].rsplit("img", 1)[1]) >= 5 else "mbr")
                              + ":" + p["node"].rsplit("img", 1)[1]),
                             p["start"], p["size"], "0x%02X" % int(p["type"], 16))
                            for p in ref["partitions"])
            self.assertEqual(ours, theirs)
            self.assertEqual(t.disk_id, "1234ABCD")
            fs = partitions.detect_filesystem(src, 67584 * 512, 10240 * 512)
            self.assertEqual((fs.type_id, fs.volume_label), ("fat32", "LOGICAL5"))

    def test_gpt_matches_sgdisk_and_tampering_is_caught(self):
        disk = self.tmp / "gpt.img"
        with open(disk, "wb") as fh:
            fh.truncate(128 << 20)
        run("sgdisk", "-o", "-n", "1:2048:+32M", "-t", "1:ef00", "-c", "1:EFI system",
            "-n", "2:0:+16M", "-t", "2:0c01", "-c", "2:MS reserved",
            "-n", "3:0:+40M", "-t", "3:0700", "-c", "3:Basic data",
            "-n", "4:0:0", "-t", "4:8300", "-c", "4:linux", "-A", "3:set:63", disk)
        ref = json.loads(run("sfdisk", "--json", disk))["partitiontable"]
        with image.ImageSource.open(disk) as src:
            t = partitions.read_table(src)
        self.assertEqual([(p.start_lba, p.sectors, p.type_code, p.name, p.guid)
                          for p in t.partitions],
                         [(p["start"], p["size"], p["type"], p.get("name", ""),
                           p["uuid"]) for p in ref["partitions"]])
        self.assertEqual(t.disk_id, ref["id"])
        self.assertEqual((t.problems, t.notes), ((), ()))
        with open(disk, "r+b") as fh:
            fh.seek(2 * 512 + 128 + 60)
            byte = fh.read(1)[0]
            fh.seek(2 * 512 + 128 + 60)
            fh.write(bytes([byte ^ 0x20]))
        with image.ImageSource.open(disk) as src:
            t = partitions.read_table(src)
        self.assertTrue(any("Entries that differ between the two: [2]" in p
                            for p in t.problems), t.problems)
        self.assertEqual(t.partitions[1].name, "MS reserved")


if __name__ == "__main__":
    unittest.main()
