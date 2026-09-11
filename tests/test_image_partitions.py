"""Raw and split images, the containers that are refused, and partition tables."""

from __future__ import annotations

import struct
import unittest

from _support import TempDirCase

import disksynth as ds
from forensics_workshop import image, partitions
from forensics_workshop.errors import EvidenceError


class Bytes:
    """A reader over bytes, for the table parser."""

    def __init__(self, data: bytes) -> None:
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


class SplitImages(TempDirCase):
    def _split(self, data: bytes, names, size: int):
        paths = []
        for i, name in enumerate(names):
            path = self.tmp / name
            path.write_bytes(data[i * size:(i + 1) * size])
            paths.append(path)
        return paths

    def test_numbered_segments_read_as_one_disk(self):
        disk = bytes(range(256)) * 40            # 10 240 bytes
        paths = self._split(disk, ["d.001", "d.002", "d.003"], 4096)
        with image.ImageSource.open(paths[0]) as src:
            self.assertEqual(src.info.format, "split-raw")
            self.assertEqual(src.size, len(disk))
            self.assertEqual(src.read_at(4000, 200), disk[4000:4200],
                             "a read across a segment boundary")
            self.assertEqual(src.read_at(0, len(disk)), disk)
            self.assertEqual(src.read_at(len(disk) - 10, 100), disk[-10:])
            self.assertEqual(src.read_at(len(disk) + 5, 10), b"")
            whole, per = image.hash_image(src)
        import hashlib
        self.assertEqual(whole.sha256, hashlib.sha256(disk).hexdigest())
        self.assertEqual([h.size for h in per], [4096, 4096, 2048])

    def test_lettered_segments(self):
        disk = b"x" * 3000
        paths = self._split(disk, ["img.aa", "img.ab"], 2000)
        self.assertEqual(image.discover_segments(paths[0]), paths)

    def test_a_segment_part_way_through_is_refused(self):
        paths = self._split(b"y" * 3000, ["d.001", "d.002"], 2000)
        with self.assertRaisesRegex(EvidenceError, "first segment"):
            image.discover_segments(paths[1])
        paths = self._split(b"y" * 3000, ["e.aa", "e.ab"], 2000)
        with self.assertRaisesRegex(EvidenceError, "not the first segment"):
            image.discover_segments(paths[1])

    def test_a_gap_in_a_set_is_refused(self):
        paths = self._split(b"z" * 8000, ["g.001", "g.002", "g.003", "g.004"], 2000)
        paths[2].unlink()
        with self.assertRaisesRegex(EvidenceError, "not contiguous"):
            image.discover_segments(paths[0])

    def test_names_that_merely_look_numbered_are_single_files(self):
        for name in ("backup.2024", "disk.dd", "history.db"):
            path = self.tmp / name
            path.write_bytes(b"q" * 600)
            self.assertEqual(image.discover_segments(path), [path], name)

    def test_a_short_middle_segment_is_noted(self):
        paths = [self.tmp / "s.001", self.tmp / "s.002", self.tmp / "s.003"]
        for p, n in zip(paths, (4096, 1000, 4096)):
            p.write_bytes(b"a" * n)
        info = image.describe(image.discover_segments(paths[0]))
        self.assertTrue(any("interrupted copy" in n for n in info.notes), info.notes)

    def test_containers_that_are_not_raw_are_refused_with_the_reason(self):
        cases = {"e.E01": b"EVF\x09\x0d\x0a\xff\x00" + bytes(600),
                 "v.vhdx": b"vhdxfile" + bytes(600),
                 "k.vmdk": b"KDMV" + bytes(600),
                 "q.qcow2": b"QFI\xfb" + bytes(600),
                 "dyn.vhd": b"conectix" + bytes(600)}
        for name, data in cases.items():
            path = self.tmp / name
            path.write_bytes(data)
            with self.assertRaises(EvidenceError, msg=name) as ctx:
                image.describe(image.discover_segments(path))
            self.assertIn("not", str(ctx.exception).lower())
        with self.assertRaisesRegex(EvidenceError, "licence"):
            image.describe([self.tmp / "e.E01"])

    def test_a_fixed_vhd_is_its_disk_plus_a_footer(self):
        path = self.tmp / "fixed.vhd"
        path.write_bytes(bytes(4096) + b"conectix" + bytes(504))
        info = image.describe([path])
        self.assertEqual(info.format, "vhd-fixed")
        self.assertEqual(info.size, 4096)
        self.assertEqual(info.file_bytes, 4608)
        with image.ImageSource(info) as src:
            self.assertEqual(src.read_at(4000, 1000), bytes(96))

    def test_the_reader_has_no_write(self):
        path = self.tmp / "r.raw"
        path.write_bytes(b"r" * 1024)
        with image.ImageSource.open(path) as src:
            src.read_at(0, 10)
            for handle in src._handles.values():
                with self.assertRaises(Exception):
                    handle.write(b"x")


class Mbr(unittest.TestCase):
    def test_primaries_extended_chain_and_logicals(self):
        disk = bytearray(200_000 * 512)
        disk[0:512] = ds.mbr_sector([(0x80, 0x07, 2048, 20_000),
                                     (0x00, 0x83, 22_048, 10_000),
                                     (0x00, 0x0F, 40_000, 100_000)])
        # EBR chain: logical 5 at +2048, next EBR at +30000; logical 6 at +2048
        disk[40_000 * 512:40_000 * 512 + 512] = ds.mbr_sector(
            [(0, 0x07, 2048, 8000), (0, 0x05, 30_000, 12_048)], disk_id=0)
        disk[70_000 * 512:70_000 * 512 + 512] = ds.mbr_sector(
            [(0, 0x0B, 2048, 10_000)], disk_id=0)
        t = partitions.read_table(Bytes(disk))
        self.assertEqual(t.scheme, "mbr")
        got = [(p.entry, p.kind, p.start_lba, p.sectors) for p in t.partitions]
        self.assertEqual(got, [("mbr:1", "partition", 2048, 20_000),
                               ("mbr:2", "partition", 22_048, 10_000),
                               ("mbr:3", "extended", 40_000, 100_000),
                               ("ebr:5", "partition", 42_048, 8000),
                               ("ebr:6", "partition", 72_048, 10_000)])
        self.assertEqual(t.partitions[0].flags, ("bootable",))
        self.assertFalse(t.problems)
        self.assertEqual(t.disk_id, "1234ABCD")

    def test_an_ebr_loop_stops_and_says_so(self):
        disk = bytearray(100_000 * 512)
        disk[0:512] = ds.mbr_sector([(0, 0x05, 10_000, 50_000)])
        disk[10_000 * 512:10_000 * 512 + 512] = ds.mbr_sector(
            [(0, 0x07, 63, 100), (0, 0x05, 0, 1000)], disk_id=0)   # next = itself
        t = partitions.read_table(Bytes(disk))
        ext = next(p for p in t.partitions if p.kind == "extended")
        self.assertTrue(any("loops" in p for p in ext.problems), ext.problems)

    def test_overlap_and_past_the_end_are_problems(self):
        disk = bytearray(10_000 * 512)
        disk[0:512] = ds.mbr_sector([(0, 0x07, 100, 5000), (0, 0x07, 4000, 8000)])
        t = partitions.read_table(Bytes(disk))
        a, b = t.partitions
        self.assertTrue(any("Overlaps" in p for p in a.problems))
        self.assertTrue(any("past the end" in p for p in b.problems))

    def test_a_boot_sector_at_zero_is_a_volume_not_a_table(self):
        vol = ds.NtfsBuilder(clusters=256).build()
        t = partitions.read_table(Bytes(vol))
        self.assertEqual(t.scheme, "none")
        self.assertEqual([p.kind for p in t.partitions], ["whole"])
        self.assertIn("single volume", t.notes[0])

    def test_protective_mbr_with_no_gpt_is_a_problem(self):
        disk = bytearray(10_000 * 512)
        disk[0:512] = ds.mbr_sector([(0, 0xEE, 1, 9999)])
        t = partitions.read_table(Bytes(disk))
        self.assertTrue(any("protective" in p for p in t.problems), t.problems)

    def test_gaps_are_reported_and_a_volume_in_one_is_noticed(self):
        disk = bytearray(20_000 * 512)
        disk[0:512] = ds.mbr_sector([(0, 0x07, 2048, 4000)])
        vol = ds.NtfsBuilder(clusters=256).build()
        disk[10_000 * 512:10_000 * 512 + len(vol)] = vol
        t = partitions.read_table(Bytes(disk))
        gaps = [(g.offset // 512, g.length // 512) for g in t.gaps]
        self.assertEqual(gaps, [(1, 2047), (6048, 20_000 - 6048)])
        found = partitions.detect_filesystem(Bytes(disk), 10_000 * 512, len(vol))
        self.assertEqual(found.type_id, "ntfs")


class Gpt(unittest.TestCase):
    PARTS = [dict(type=ds.EFI_SYSTEM, first=2048, last=4095, name="EFI"),
             dict(type=ds.BASIC_DATA, first=4096, last=12_287, name="Data",
                  attrs=1 << 63),
             dict(type=ds.LINUX_FS, first=12_288, last=19_900, name="linux")]

    def test_a_clean_table(self):
        disk = ds.gpt_disk(20_000, self.PARTS)
        t = partitions.read_table(Bytes(disk))
        self.assertEqual((t.scheme, t.sector_size), ("gpt", 512))
        self.assertEqual([(p.start_lba, p.sectors, p.name) for p in t.partitions],
                         [(2048, 2048, "EFI"), (4096, 8192, "Data"),
                          (12_288, 7613, "linux")])
        self.assertEqual(t.partitions[1].type_label, "Basic data (Windows)")
        self.assertIn("no-drive-letter", t.partitions[1].flags)
        self.assertEqual(t.disk_id, "11111111-2222-3333-4444-555555555555")
        self.assertEqual((t.problems, t.notes), ((), ()))

    def test_4k_sectors_are_found_at_byte_4096(self):
        parts = [dict(type=ds.BASIC_DATA, first=256, last=2000, name="4k")]
        disk = ds.gpt_disk(3000, parts, ss=4096)
        t = partitions.read_table(Bytes(disk))
        self.assertEqual(t.sector_size, 4096)
        self.assertEqual(t.partitions[0].offset, 256 * 4096)

    def test_an_altered_primary_array_is_caught_and_the_backup_used(self):
        disk = ds.gpt_disk(20_000, self.PARTS)
        entry = 2 * 512 + 128 * 1
        struct.pack_into("<Q", disk, entry + 32, 5000)        # move partition 2
        t = partitions.read_table(Bytes(disk))
        self.assertTrue(any("[2]" in p and "passes" in p for p in t.problems),
                        t.problems)
        self.assertEqual(t.partitions[1].start_lba, 4096, "listed from the good copy")

    def test_a_destroyed_primary_header_falls_back_to_the_backup(self):
        disk = ds.gpt_disk(20_000, self.PARTS)
        disk[512 + 16:512 + 20] = b"\xde\xad\xbe\xef"
        t = partitions.read_table(Bytes(disk))
        self.assertEqual(len(t.partitions), 3)
        self.assertTrue(any("BACKUP" in p for p in t.problems), t.problems)

    def test_a_truncated_image_is_noted_and_partitions_past_it_flagged(self):
        disk = ds.gpt_disk(20_000, self.PARTS)[:15_000 * 512]
        t = partitions.read_table(Bytes(disk))
        self.assertTrue(any("truncated" in n for n in t.notes), t.notes)
        self.assertTrue(any("past the end" in p for p in t.partitions[2].problems))

    def test_hybrid_and_missing_protective_mbr_are_noted(self):
        disk = ds.gpt_disk(20_000, self.PARTS, protective=False)
        self.assertIn("no protective", partitions.read_table(Bytes(disk)).notes[0])
        disk = ds.gpt_disk(20_000, self.PARTS)
        disk[0:512] = ds.mbr_sector([(0, 0xEE, 1, 2047), (0, 0x07, 4096, 8192)])
        self.assertTrue(any("Hybrid" in n for n in partitions.read_table(Bytes(disk)).notes))


if __name__ == "__main__":
    unittest.main()
