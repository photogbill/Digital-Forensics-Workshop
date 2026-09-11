"""The change journal: V2/V3/V4 records, sparse zeroes, torn and trimmed journals."""

from __future__ import annotations

import unittest

import _support  # noqa: F401
import disksynth as ds
from forensics_workshop import ntfs, timeutil, usn

CREATE, DELETE, CLOSE = 0x100, 0x200, 0x80000000
BASIC = 0x8000


class Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


def stream(records: list[bytes], lead: int = 0, page: int = 4096) -> bytes:
    out = bytearray(lead)
    for blob in records:
        room = page - len(out) % page
        if len(blob) > room:
            out += bytes(room)
        out += blob
    return bytes(out)


class Records(unittest.TestCase):
    def test_v2_v3_v4_parse(self):
        v2 = ds.usn_v2(0, (70, 3), (5, 5), ds.T0, CREATE | CLOSE, "report.docx")
        rec = usn.parse_one(v2, 0, 0)
        self.assertEqual((rec.version, rec.file_record, rec.file_sequence,
                          rec.parent_record, rec.name), (2, 70, 3, 5, "report.docx"))
        self.assertEqual(usn.reason_names(rec.reasons), ["FILE_CREATE", "CLOSE"])
        v3 = ds.usn_v3(0, (71, 1), (64, 2), ds.T0, DELETE, "gone.txt")
        rec = usn.parse_one(v3, 0, 0)
        self.assertEqual((rec.version, rec.file_record, rec.parent_sequence, rec.name),
                         (3, 71, 2, "gone.txt"))
        v4 = ds.usn_v4(0, (72, 1), (5, 5), 0x1, [(0, 4096), (8192, 512)])
        rec = usn.parse_one(v4, 0, 0)
        self.assertEqual((rec.version, rec.extents), (4, ((0, 4096), (8192, 512))))

    def test_what_is_not_a_record_is_not_parsed(self):
        good = bytearray(ds.usn_v2(0, (70, 3), (5, 5), ds.T0, CREATE, "a.txt"))
        for corrupt in (lambda b: b.__setitem__(4, 9),          # major version
                        lambda b: b.__setitem__(0, 0x41),       # odd length
                        lambda b: b.__setitem__(0x3A, 0x40),    # name offset
                        lambda b: b.__setitem__(0x38, 0x7F)):   # name length
            b = bytearray(good)
            corrupt(b)
            self.assertIsNone(usn.parse_one(bytes(b), 0, 0))

    def test_unknown_reason_bits_are_shown_not_dropped(self):
        self.assertEqual(usn.reason_names(0x100 | 0x40000000),
                         ["FILE_CREATE", "0x40000000"])


class Scan(unittest.TestCase):
    def test_sparse_lead_and_page_padding_are_skipped_and_usn_is_the_offset(self):
        lead = 64 * 4096
        blobs, offset = [], lead
        expected = []
        for i in range(120):
            name = f"file-{i:03d}-" + "x" * (i % 40)
            probe = ds.usn_v2(0, (100 + i, 1), (5, 5), ds.T0 + i, CREATE, name)
            if len(probe) > 4096 - offset % 4096:
                offset += 4096 - offset % 4096
            blobs.append(ds.usn_v2(offset, (100 + i, 1), (5, 5), ds.T0 + i,
                                   CREATE, name))
            expected.append((offset, name))
            offset += len(probe)
        data = stream(blobs, lead)
        stats = usn.ScanStats()
        got = [(r.offset, r.name) for r in usn.scan(Bytes(data).read_at, len(data),
                                                    stats=stats)]
        self.assertEqual(got, expected)
        self.assertEqual(stats.usn_offset_mismatches, 0)
        self.assertEqual(stats.skipped_bytes, 0)
        self.assertGreaterEqual(stats.zero_bytes, lead)

    def test_extents_skip_holes_without_reading_them(self):
        blob = ds.usn_v2(1 << 30, (80, 1), (5, 5), ds.T0, CREATE, "late.txt")
        reads = []

        class Sparse:
            size = (1 << 30) + 4096

            def read_at(self, off, n):
                reads.append((off, n))
                if off >= 1 << 30:
                    return (blob + bytes(4096 - len(blob)))[off - (1 << 30):][:n]
                return bytes(n)

        found = list(usn.scan(Sparse().read_at, Sparse.size,
                              extents=[(1 << 30, (1 << 30) + 4096)]))
        self.assertEqual([r.name for r in found], ["late.txt"])
        self.assertTrue(all(off >= 1 << 30 for off, _n in reads), reads[:3])

    def test_a_trimmed_export_is_reported_by_a_constant_delta(self):
        lead = 8 * 4096
        blobs = [ds.usn_v2(lead + 0, (90, 1), (5, 5), ds.T0, CREATE, "a"),
                 ds.usn_v2(lead + 96, (91, 1), (5, 5), ds.T0, CREATE, "b")]
        trimmed = stream(blobs)                       # leading zeroes cut off
        stats = usn.ScanStats()
        records = list(usn.scan(Bytes(trimmed).read_at, len(trimmed), stats=stats))
        self.assertEqual(len(records), 2)
        self.assertEqual(stats.usn_offset_mismatches, 2)
        self.assertEqual(stats.first_usn_delta, lead)

    def test_garbage_between_records_is_skipped_and_counted(self):
        a = ds.usn_v2(0, (90, 1), (5, 5), ds.T0, CREATE, "a")
        b = ds.usn_v2(len(a) + 16, (91, 1), (5, 5), ds.T0, CREATE, "b")
        data = a + b"\xde\xad\xbe\xef" * 4 + b
        stats = usn.ScanStats()
        names = [r.name for r in usn.scan(Bytes(data).read_at, len(data), stats=stats)]
        self.assertEqual(names, ["a", "b"])
        self.assertEqual(stats.skipped_bytes, 16)

    def test_a_record_cut_by_a_chunk_edge_is_read_whole(self):
        filler = []
        offset = 0
        while offset < usn.CHUNK - 40:
            blob = ds.usn_v2(offset, (95, 1), (5, 5), ds.T0, CREATE, "n" * 20)
            filler.append(blob)
            offset += len(blob)
        data = b"".join(filler)
        edge = ds.usn_v2(len(data), (96, 1), (5, 5), ds.T0, DELETE, "straddler")
        data += edge
        records = list(usn.scan(Bytes(data).read_at, len(data)))
        self.assertEqual(records[-1].name, "straddler")
        self.assertEqual(len(records), len(filler) + 1)


class InAVolume(unittest.TestCase):
    def test_the_journal_is_found_in_extend_and_read_through_its_runs(self):
        b = ds.NtfsBuilder(clusters=512)
        b.file(64, "evidence.txt", b"data")
        written = b.journal(40, [
            dict(file=(64, 1), parent=(5, 5), time=ds.T0, reasons=CREATE, name="evidence.txt"),
            dict(file=(64, 1), parent=(5, 5), time=ds.T0 + 10, reasons=BASIC,
                 name="evidence.txt"),
            dict(file=(65, 1), parent=(5, 5), time=ds.T0 + 20, reasons=DELETE | CLOSE,
                 name="wiped.txt")], sparse_clusters=16)
        vol = ntfs.NtfsVolume(Bytes(b.build()))
        e = vol.entry(40)
        j = e.stream("$J")
        self.assertTrue(j.sparse)
        self.assertEqual(j.runs[0][1], None)
        cs = vol.cluster
        extents = [(v * cs, min((v + n) * cs, j.data_size))
                   for v, lcn, n in j.runs if lcn is not None]
        recs = list(usn.scan(lambda off, n: vol.read_stream(j, off, n), j.data_size,
                             extents=extents))
        self.assertEqual([(r.offset, r.name) for r in recs],
                         [(w["offset"], w["name"]) for w in written])
        self.assertEqual(timeutil.decode(recs[1].timestamp, "filetime"),
                         timeutil.decode(ds.T0 + 10, "filetime"))


if __name__ == "__main__":
    unittest.main()
