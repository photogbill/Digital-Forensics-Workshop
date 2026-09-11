"""NTFS parsing against synthetic volumes: records, streams, paths, deletion, damage."""

from __future__ import annotations

import hashlib
import struct
import unittest

import _support  # noqa: F401  (puts the package on sys.path)
import disksynth as ds
from forensics_workshop import ntfs, timeutil
from forensics_workshop.errors import FileSystemError


class Bytes:
    def __init__(self, data):
        self.data = bytearray(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return bytes(self.data[offset:offset + length])


def volume(builder: ds.NtfsBuilder) -> tuple[ntfs.NtfsVolume, Bytes]:
    reader = Bytes(builder.build())
    return ntfs.NtfsVolume(reader), reader


def entries(vol):
    return {e.record: e for e in vol.iter_entries() if not e.is_extension}


def paths(vol):
    nodes = {}
    for e in entries(vol).values():
        fn = e.preferred_name()
        nodes[e.record] = (e.sequence, e.in_use, e.is_dir,
                           fn.parent_record if fn else -1,
                           fn.parent_sequence if fn else 0,
                           fn.name if fn else "")
    return ntfs.build_paths(nodes)


class Structures(unittest.TestCase):
    def test_boot_sector_fields(self):
        vol, _r = volume(ds.NtfsBuilder(clusters=512, label="EVIDENCE"))
        b = vol.boot
        self.assertEqual((b.bytes_per_sector, b.sectors_per_cluster,
                          b.cluster_size, b.record_size), (512, 8, 4096, 1024))
        self.assertEqual(b.mft_lcn, 4)
        self.assertEqual(b.serial_short, "89AB-CDEF")
        self.assertEqual(vol.volume_info(), {"label": "EVIDENCE", "version": "3.1",
                                             "dirty": False})

    def test_large_cluster_encoding_and_record_size_field(self):
        data = bytearray(ds.NtfsBuilder(clusters=64).build()[:512])
        struct.pack_into("<Q", data, 0x28, 1 << 40)        # a big volume
        data[0x0D] = 0xF4                                  # 2^12 sectors
        self.assertEqual(ntfs.parse_boot_sector(bytes(data)).sectors_per_cluster, 4096)
        data[0x0D] = 8
        struct.pack_into("<b", data, 0x40, 2)              # 2 clusters per record
        with self.assertRaisesRegex(FileSystemError, "not plausible"):
            ntfs.parse_boot_sector(bytes(data))

    def test_not_ntfs_is_refused(self):
        with self.assertRaisesRegex(FileSystemError, "NTFS signature"):
            ntfs.NtfsVolume(Bytes(bytes(1 << 16)), try_backup=False)

    def test_a_wiped_primary_boot_sector_falls_back_to_the_backup(self):
        img = bytearray(ds.NtfsBuilder(clusters=256).build())
        img[0:512] = bytes(512)
        vol = ntfs.NtfsVolume(Bytes(img))
        self.assertEqual(vol.boot.source, "backup")
        self.assertTrue(any("BACKUP" in p for p in vol.problems))

    def test_data_runs_decode_signed_offsets_and_sparse_runs(self):
        runs = [(1000, 5), (None, 10), (40, 3), (70_000, 2)]
        encoded = ds.encode_runs(runs)
        decoded, problems = ntfs.decode_runs(encoded)
        self.assertEqual(problems, [])
        self.assertEqual(decoded, [(0, 1000, 5), (5, None, 10), (15, 40, 3),
                                   (18, 70_000, 2)])
        broken, problems = ntfs.decode_runs(encoded[:4])
        self.assertTrue(problems)

    def test_fixups_are_checked_not_just_applied(self):
        b = ds.NtfsBuilder(clusters=256)
        b.file(64, "torn.txt", b"abc", torn=True)
        b.file(65, "fine.txt", b"abc")
        vol, _r = volume(b)
        e = entries(vol)
        self.assertFalse(e[64].fixup_ok)
        self.assertTrue(any("torn" in p for p in e[64].problems))
        self.assertTrue(e[65].fixup_ok)
        self.assertEqual(vol.read_stream(e[65].stream("")), b"abc",
                         "the fixup bytes were restored before parsing")


class Files(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        b = ds.NtfsBuilder(clusters=1024)
        cls.big = bytes((i * 7) % 251 for i in range(50_000))
        cls.frag = hashlib.sha256(b"x").digest() * 3000          # 96 000 bytes
        b.directory(64, "Users")
        b.directory(65, "bill", parent=64)
        b.file(66, "notes.txt", b"short and resident", parent=65,
               ads={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n"})
        b.file(67, "big.bin", cls.big, parent=65)
        b.file(68, "frag.bin", cls.frag, parent=65, fragments=3)
        b.file(69, "report.docx", b"PK" + bytes(5000), parent=65,
               extra_names=[(65, 1, "REPORT~1.DOC", 2)])
        b.file(70, "compressed.dat", bytes(9000), parent=65, data_flags=0x0001)
        cls.vol, cls.reader = volume(b)
        cls.entries = entries(cls.vol)
        cls.paths = paths(cls.vol)

    def test_resident_and_nonresident_content(self):
        e = self.entries
        self.assertEqual(self.vol.read_stream(e[66].stream("")), b"short and resident")
        self.assertEqual(b"".join(self.vol.iter_stream(e[67].stream(""))), self.big)
        self.assertEqual(self.vol.read_stream(e[67].stream(""), 49_990, 100),
                         self.big[49_990:])

    def test_a_fragmented_file_reads_back_whole(self):
        s = self.entries[68].stream("")
        self.assertEqual(len(s.runs), 3)
        self.assertEqual(b"".join(self.vol.iter_stream(s)), self.frag)
        self.assertEqual(self.vol.run_problems(s), [])

    def test_alternate_data_streams(self):
        e = self.entries[66]
        self.assertEqual([s.name for s in e.ads()], ["Zone.Identifier"])
        self.assertIn(b"ZoneId=3", self.vol.read_stream(e.stream("Zone.Identifier")))

    def test_paths_and_the_long_name_is_preferred(self):
        self.assertEqual(self.paths[66], ("Users/bill/notes.txt", "ok"))
        self.assertEqual(self.paths[69], ("Users/bill/report.docx", "ok"))
        e = self.entries[69]
        self.assertEqual(sorted(n.namespace_name for n in e.names), ["DOS", "Win32"])

    def test_compressed_content_is_refused_with_the_reason(self):
        s = self.entries[70].stream("")
        self.assertTrue(s.compressed)
        with self.assertRaisesRegex(FileSystemError, "LZNT1"):
            self.vol.read_stream(s)

    def test_system_files_are_there(self):
        self.assertEqual(self.paths[0][0], "$MFT")
        self.assertEqual(self.entries[5].is_dir, True)
        self.assertEqual(self.paths[11][0], "$Extend")


class Deletion(unittest.TestCase):
    def test_a_deleted_file_with_its_clusters_free(self):
        b = ds.NtfsBuilder(clusters=512)
        data = bytes(range(256)) * 60
        b.file(64, "gone.bin", data, in_use=False, seq=2, free_clusters=True)
        vol, _r = volume(b)
        e = vol.entry(64)
        self.assertFalse(e.in_use)
        total, used = vol.count_allocated(e.stream("").runs)
        self.assertEqual((total, used), (4, 0))
        self.assertEqual(vol.read_stream(e.stream("")), data)

    def test_clusters_since_given_to_another_file_are_counted(self):
        b = ds.NtfsBuilder(clusters=512)
        runs = b.file(64, "gone.bin", bytes(16_384), in_use=False, seq=2,
                      free_clusters=True)
        lcn = runs[0][0]
        b.used[lcn + 1] = b.used[lcn + 2] = 1           # reused by someone else
        vol, _r = volume(b)
        total, used = vol.count_allocated(vol.entry(64).stream("").runs)
        self.assertEqual((total, used), (4, 2))

    def test_parent_sequence_decides_the_path(self):
        b = ds.NtfsBuilder(clusters=512)
        b.directory(64, "Projects", seq=3)
        b.file(65, "plan.txt", b"live", parent=64, parent_seq=3)
        # a deleted folder (freed: its sequence moved on by one) and its file
        b.directory(66, "Old", seq=5, in_use=False)
        b.file(67, "draft.txt", b"was here", parent=66, parent_seq=4, in_use=False)
        # a folder whose record was REUSED: the file still points at seq 1
        b.directory(68, "NewFolder", seq=9)
        b.file(69, "stranger.txt", b"orphaned", parent=68, parent_seq=1,
               in_use=False)
        # a parent that does not exist at all
        b.file(70, "nowhere.txt", b"x", parent=60, parent_seq=1, in_use=False)
        vol, _r = volume(b)
        p = paths(vol)
        self.assertEqual(p[65], ("Projects/plan.txt", "ok"))
        self.assertEqual(p[67], ("Old/draft.txt", "parent-deleted"))
        self.assertEqual(p[69], ("[record 68 reused]/stranger.txt", "parent-reused"))
        self.assertEqual(p[70], ("[no record 60]/nowhere.txt", "orphan"))

    def test_a_parent_loop_terminates(self):
        nodes = {5: (5, True, True, 5, 5, "."),
                 80: (1, True, True, 81, 1, "a"),
                 81: (1, True, True, 80, 1, "b")}
        out = ntfs.build_paths(nodes)
        self.assertEqual(out[80][1], "loop")
        self.assertEqual(out[81][1], "loop")


class FreeSpace(unittest.TestCase):
    def test_free_extents_match_a_bit_by_bit_count(self):
        b = ds.NtfsBuilder(clusters=1000)
        b.file(64, "a.bin", bytes(40_000))
        b.file(65, "b.bin", bytes(12_000), fragments=2)
        b.used[900] = 1
        b.used[903] = 1
        vol, _r = volume(b)
        bm = vol.bitmap()
        total = vol.boot.total_clusters       # 999: the last sector is the backup boot
        self.assertEqual(total, 999)
        naive, start = [], None
        for lcn in range(total):
            free = not (bm[lcn >> 3] >> (lcn & 7) & 1)
            if free and start is None:
                start = lcn
            if not free and start is not None:
                naive.append((start, lcn - start))
                start = None
        if start is not None:
            naive.append((start, total - start))
        self.assertEqual(list(vol.free_extents()), naive)
        self.assertIn((901, 2), naive)


class Slack(unittest.TestCase):
    def test_file_slack_is_the_tail_of_the_last_cluster(self):
        b = ds.NtfsBuilder(clusters=256)
        runs = b.file(64, "a.txt", b"A" * 5000)
        lcn = runs[0][0]
        b.write(lcn + 1, b"A" * (5000 - 4096) + b"OLD SECRET TEXT")
        vol, reader = volume(b)
        s = vol.entry(64).stream("")
        info = vol.file_slack(s)
        self.assertEqual(info["length"], 4096 - 904)
        self.assertEqual(info["offset"], (lcn + 1) * 4096 + 904)
        self.assertTrue(reader.read_at(info["offset"], 15) == b"OLD SECRET TEXT")
        self.assertEqual(vol.read_stream(s)[-3:], b"AAA",
                         "slack is never part of the content")


class Timestamps(unittest.TestCase):
    def test_indicators_are_measured_and_named(self):
        b = ds.NtfsBuilder(clusters=256)
        earlier = ds.filetime(ds.datetime(2019, 5, 1, 9, 0, 0, tzinfo=ds.timezone.utc))
        whole = (earlier, earlier, earlier, earlier)
        now = (ds.T0,) * 4                                   # $FILE_NAME: when it arrived
        b.file(64, "stomped.exe", b"MZ", si_times=whole, fn_times=now)
        b.file(65, "copied.txt", b"x", si_times=(ds.T0 - 50, ds.T0, ds.T0, ds.T0),
               fn_times=now)
        b.file(66, "normal.txt", b"x")
        b.file(67, "clock.txt", b"x", si_times=(ds.T0, ds.T0, ds.T0 - 10, ds.T0),
               fn_times=now)
        vol, _r = volume(b)
        e = entries(vol)
        self.assertEqual(e[64].indicators(), ["si-created-before-fn-created",
                                              "si-whole-seconds"])
        self.assertEqual(e[65].indicators(), ["si-created-before-fn-created"])
        self.assertEqual(e[66].indicators(), [])
        self.assertEqual(e[67].indicators(), ["si-changed-before-created"])
        for code in ntfs.INDICATORS:
            measured, benign = ntfs.INDICATORS[code]
            self.assertTrue(measured and benign, code)
        self.assertEqual(timeutil.filetime_fraction(earlier), 0)
        self.assertEqual(timeutil.decode(earlier, "filetime"),
                         "2019-05-01T09:00:00.000000Z")


class AttributeLists(unittest.TestCase):
    def test_attributes_kept_in_an_extension_record_are_followed(self):
        b = ds.NtfsBuilder(clusters=512)
        data = bytes(range(200)) * 50
        lcn = b.alloc(3)
        b.write(lcn, data)
        t = (ds.T0,) * 4
        data_attr = ds.nonresident(0x80, [(lcn, 3)], len(data), aid=7)
        listing = bytearray()
        for atype, aid, rec in ((0x10, 0, 64), (0x30, 1, 64), (0x80, 7, 65)):
            entry = bytearray(32)
            struct.pack_into("<IHBBQQH", entry, 0, atype, 32, 0, 26, 0,
                             rec | (1 << 48), aid)
            listing += entry
        b.raw(64, [ds.resident(0x10, ds.si_value(t)),
                   ds.resident(0x20, bytes(listing), aid=5),
                   ds.resident(0x30, ds.fn_value(5, 5, "listed.bin", t), aid=1)],
              seq=1)
        b.raw(65, [data_attr], seq=1, base_ref=64 | (1 << 48))
        vol, _r = volume(b)
        es = entries(vol)
        self.assertTrue(es[64].has_attribute_list)
        self.assertEqual(vol.read_stream(es[64].stream("")), data)
        extensions = [e for e in vol.iter_entries() if e.is_extension]
        self.assertEqual([x.record for x in extensions], [65])

    def test_a_list_pointing_at_a_record_that_moved_on_is_reported(self):
        b = ds.NtfsBuilder(clusters=512)
        t = (ds.T0,) * 4
        entry = bytearray(32)
        struct.pack_into("<IHBBQQH", entry, 0, 0x80, 32, 0, 26, 0, 70 | (1 << 48), 7)
        b.raw(64, [ds.resident(0x10, ds.si_value(t)),
                   ds.resident(0x20, bytes(entry), aid=5),
                   ds.resident(0x30, ds.fn_value(5, 5, "lost.bin", t), aid=1)])
        b.file(70, "someone-else.txt", b"not an extension")
        vol, _r = volume(b)
        e = vol.entry(64)
        self.assertIsNone(e.stream(""))
        self.assertTrue(any("no longer belongs" in p for p in e.problems), e.problems)


class Hostile(unittest.TestCase):
    def test_garbage_records_never_raise(self):
        import random
        rng = random.Random(7)
        b = ds.NtfsBuilder(clusters=256)
        for n in range(64, 80):
            b.file(n, f"f{n}.txt", bytes(rng.randrange(256) for _ in range(300)))
        img = bytearray(b.build())
        for n in range(64, 80):
            at = ds.NtfsBuilder.record_offset(n)
            for _ in range(40):
                img[at + rng.randrange(0x38, 1024)] = rng.randrange(256)
        vol = ntfs.NtfsVolume(Bytes(img))
        seen = 0
        for e in vol.iter_entries():
            seen += 1
            for s in e.streams:
                try:
                    vol.read_stream(s, 0, 4096)
                except FileSystemError:
                    pass
        self.assertGreater(seen, 16)


if __name__ == "__main__":
    unittest.main()
