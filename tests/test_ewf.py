"""EWF-E01: a compressed container decoded to the exact raw disk, transparently.

Builds real E01 bytes (a volume section, a sectors blob of genuine zlib chunks
mixed with uncompressed ones, a base-offset table, a done section) and holds the
reader to reproducing the original disk byte-for-byte — including a short final
chunk and both storage forms — and to threading through the image pipeline so
partitions and hashing never learn it was compressed."""

from __future__ import annotations

import hashlib
import struct
import unittest
import zlib
from pathlib import Path

import _support  # noqa: F401
from _support import TempDirCase

from forensics_workshop import ewf, image
from forensics_workshop.errors import EvidenceError

SIG = b"EVF\x09\x0d\x0a\xff\x00"


def _descriptor(kind: bytes, next_offset: int, size: int) -> bytes:
    desc = bytearray(76)
    desc[0:len(kind)] = kind
    struct.pack_into("<QQ", desc, 16, next_offset, size)
    struct.pack_into("<I", desc, 72, zlib.adler32(bytes(desc[:72])))
    return bytes(desc)


def build_e01(disk: bytes, *, sectors_per_chunk: int = 4,
              bytes_per_sector: int = 512) -> bytes:
    """A valid single-segment EWF-E01 encoding `disk` (a multiple of the sector
    size). Compressible chunks are stored zlib-compressed, incompressible ones
    raw+adler32 — both paths exercised by the caller's choice of bytes."""
    chunk_size = sectors_per_chunk * bytes_per_sector
    assert len(disk) % bytes_per_sector == 0
    chunks = [disk[i:i + chunk_size] for i in range(0, len(disk), chunk_size)]

    stored, entry_flags = [], []
    for c in chunks:
        comp = zlib.compress(c, 6)
        if len(comp) < len(c):
            stored.append(comp)
            entry_flags.append(True)
        else:
            stored.append(c + struct.pack("<I", zlib.adler32(c)))
            entry_flags.append(False)

    out = bytearray()
    out += SIG + b"\x01" + struct.pack("<H", 1) + b"\x00\x00"

    # volume section (1052 bytes of data; only the first fields are read)
    vol = bytearray(1052)
    vol[0] = 0x01                                             # fixed media
    struct.pack_into("<III", vol, 4, len(chunks), sectors_per_chunk,
                     bytes_per_sector)
    struct.pack_into("<Q", vol, 16, len(disk) // bytes_per_sector)
    vol_start = len(out)
    vol_size = 76 + len(vol)
    out += _descriptor(b"volume", vol_start + vol_size, vol_size) + vol

    # sectors section: the stored chunks, back to back
    blob = b"".join(stored)
    sec_start = len(out)
    sec_size = 76 + len(blob)
    sectors_data_start = sec_start + 76
    out += _descriptor(b"sectors", sec_start + sec_size, sec_size) + blob

    # table section: header (count, pad, base_offset, pad, adler32) + entries
    rel, off = [], 0
    for s in stored:
        rel.append(off)
        off += len(s)
    table = bytearray(24)
    struct.pack_into("<I", table, 0, len(chunks))
    struct.pack_into("<Q", table, 8, sectors_data_start)      # base offset
    for r, compressed in zip(rel, entry_flags):
        table += struct.pack("<I", r | (0x80000000 if compressed else 0))
    tab_start = len(out)
    tab_size = 76 + len(table)
    out += _descriptor(b"table", tab_start + tab_size, tab_size) + bytes(table)

    # done section: points at itself
    done_start = len(out)
    out += _descriptor(b"done", done_start, 76)
    return bytes(out)


def a_disk() -> bytes:
    """13 sectors = 4 chunks of 2048 + a 512-byte tail: a zero chunk (packs
    tiny), a random chunk (stored raw), a patterned chunk, and a short tail."""
    import random
    rng = random.Random(1)
    zero = bytes(2048)
    rand = bytes(rng.getrandbits(8) for _ in range(2048))
    patt = (b"FORENSICS " * 205)[:2048]
    tail = bytes(rng.getrandbits(8) for _ in range(512))
    return zero + rand + patt + tail


class RoundTrip(TempDirCase):
    def setUp(self):
        super().setUp()
        self.disk = a_disk()
        self.path = self.tmp / "img.E01"
        self.path.write_bytes(build_e01(self.disk))

    def test_the_signature_is_recognised(self):
        self.assertTrue(ewf._is_ewf_e01(self.path.read_bytes()[:16]))

    def test_read_at_reproduces_the_whole_disk(self):
        with ewf.EwfImage([self.path]) as img:
            self.assertEqual(img.size, len(self.disk))
            self.assertEqual(img.read_at(0, img.size), self.disk)

    def test_reads_that_cross_chunk_boundaries_and_the_short_tail(self):
        with ewf.EwfImage([self.path]) as img:
            # a window spanning chunks 1-2 and into the boundary
            self.assertEqual(img.read_at(2000, 100), self.disk[2000:2100])
            # the short final chunk (offset 6144..6656)
            self.assertEqual(img.read_at(6144, 9999), self.disk[6144:])
            # a read past the end is clamped
            self.assertEqual(img.read_at(len(self.disk), 10), b"")

    def test_both_storage_forms_were_exercised(self):
        with ewf.EwfImage([self.path]) as img:
            forms = {c.compressed for c in img._chunks}
        self.assertEqual(forms, {True, False}, "need a compressed AND a raw chunk")

    def test_geometry_matches(self):
        with ewf.EwfImage([self.path]) as img:
            g = img.geometry
        self.assertEqual((g.sectors_per_chunk, g.bytes_per_sector), (4, 512))
        self.assertEqual(g.chunk_count, 4)
        self.assertEqual(g.disk_size, len(self.disk))


class ThroughTheImagePipeline(TempDirCase):
    def setUp(self):
        super().setUp()
        self.disk = a_disk()
        self.path = self.tmp / "case.E01"
        self.path.write_bytes(build_e01(self.disk))

    def test_describe_accepts_e01_and_reports_the_disk_size(self):
        info = image.describe(image.discover_segments(self.path))
        self.assertEqual(info.format, "ewf")
        self.assertEqual(info.size, len(self.disk))
        self.assertTrue(any("EWF-E01" in n for n in info.notes))

    def test_imagesource_reads_through_the_container(self):
        with image.ImageSource.open(self.path) as src:
            self.assertEqual(src.read_at(0, src.size), self.disk)
            self.assertEqual(src.read_at(3000, 1000), self.disk[3000:4000])

    def test_the_disk_hash_is_of_the_decompressed_stream(self):
        with image.ImageSource.open(self.path) as src:
            whole, per_segment = image.hash_image(src)
        self.assertEqual(whole.sha256, hashlib.sha256(self.disk).hexdigest())
        # the per-segment digest covers the physical .E01 file, not the disk
        self.assertEqual(per_segment[0].sha256,
                         hashlib.sha256(self.path.read_bytes()).hexdigest())
        self.assertNotEqual(whole.sha256, per_segment[0].sha256)


class Refusals(TempDirCase):
    def test_a_truncated_segment_is_reported_not_guessed(self):
        good = build_e01(a_disk())
        bad = self.tmp / "cut.E01"
        bad.write_bytes(good[:120])                  # header + a partial section
        with self.assertRaises(EvidenceError):
            image.describe([bad])

    def test_ex01_is_still_refused_by_name(self):
        # Ex01 uses the 'EVF2'/'EVFX' family — our filetype flags it as ewf2.
        self.assertIn("ewf2", image.CONTAINERS)
        self.assertIn("Ex01", image.CONTAINERS["ewf2"])


if __name__ == "__main__":
    unittest.main()
