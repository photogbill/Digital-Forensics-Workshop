"""One read of an E01 set gives every digest (2026-10-30, after Bill's bench
on Windows: two passes and chunk-at-a-time inflate ran at 105 MB/s).

`EwfImage.hash_pass` reads each segment file once — hashing the file as it
is read and inflating the chunks out of those same bytes on worker threads —
and must give exactly what hashlib gives over the disk and over each file."""

from __future__ import annotations

import hashlib
import os
import threading
import unittest
from pathlib import Path
from unittest import mock

import _support  # noqa: F401
from _support import TempDirCase

from forensics_workshop import ewf, ewfwrite, image
from forensics_workshop.errors import Cancelled, EvidenceError


def make_disk(n_mb: float) -> bytes:
    """Random, text and zeros, so chunks are stored both compressed and not."""
    size = int(n_mb * (1 << 20)) // 512 * 512
    rnd = os.urandom(size // 3)
    text = (b"evidence chunk " * (size // 15 + 1))[: size // 3]
    disk = rnd + text
    return disk + bytes(size - len(disk))


class OnePass(TempDirCase):
    def write(self, disk, *, compression="fast", segment_bytes=None, spc=64):
        base = self.tmp / "set"
        w = ewfwrite.EwfWriter(base, open_segment=lambda p: open(p, "xb"),
                               size=len(disk), compression=compression,
                               segment_bytes=segment_bytes, sectors_per_chunk=spc)
        for i in range(0, len(disk), 300_000):           # odd piece sizes
            w.write(disk[i:i + 300_000])
        return w.finish(hashlib.md5(disk).digest(), hashlib.sha1(disk).digest())

    def check(self, disk, paths, *, workers=None):
        with ewf.EwfImage(paths) as img:
            self.assertTrue(img._in_file_order())
            whole, per = img.hash_pass(workers=workers)
        self.assertEqual(whole.sha256, hashlib.sha256(disk).hexdigest())
        self.assertEqual(whole.md5, hashlib.md5(disk).hexdigest())
        self.assertEqual(whole.size, len(disk))
        self.assertEqual([h.sha256 for h in per],
                         [hashlib.sha256(Path(p).read_bytes()).hexdigest()
                          for p in paths])
        return whole, per

    def test_every_compression_one_segment(self):
        disk = make_disk(3)
        for comp in ("none", "fast", "best"):
            with self.subTest(compression=comp):
                for f in self.tmp.glob("set.E*"):
                    f.unlink()
                self.check(disk, self.write(disk, compression=comp))

    def test_split_set_and_chunk_count_not_a_batch_multiple(self):
        disk = make_disk(5.3)                 # 169.6 chunks of 32 KiB: a partial tail
        paths = self.write(disk, segment_bytes=1 << 20)
        self.assertGreaterEqual(len(paths), 2)
        self.check(disk, paths, workers=3)
        self.check(disk, paths, workers=1)

    def test_small_chunks_and_a_block_smaller_than_a_chunk(self):
        disk = make_disk(1)
        paths = self.write(disk, spc=1)                   # 512-byte chunks
        with mock.patch.object(ewf, "READ_BLOCK", 300):   # chunks straddle reads
            self.check(disk, paths)

    def test_hash_image_uses_it_and_matches_the_two_pass_way(self):
        disk = make_disk(2)
        paths = self.write(disk, segment_bytes=1 << 20)
        with image.ImageSource.open(paths[0]) as src:
            one = image.hash_image(src)
            with mock.patch.object(ewf.EwfImage, "hash_pass", return_value=None):
                two = image.hash_image(src)
        self.assertTrue(one[0].matches(two[0]))
        self.assertEqual([h.sha256 for h in one[1]], [h.sha256 for h in two[1]])

    def test_chunks_out_of_file_order_fall_back(self):
        disk = make_disk(1)
        paths = self.write(disk)
        with ewf.EwfImage(paths) as img:
            img._c_off[0], img._c_off[1] = img._c_off[1], img._c_off[0]
            self.assertFalse(img._in_file_order())
            self.assertIsNone(img.hash_pass())

    def test_a_truncated_segment_is_an_error_not_a_short_hash(self):
        disk = make_disk(2)
        paths = self.write(disk)
        with ewf.EwfImage(paths) as img:
            data = Path(paths[0]).read_bytes()
            cut = self.tmp / "cut.E01"
            cut.write_bytes(data[: len(data) // 2])
            img.segments = [str(cut)]
            with self.assertRaises(EvidenceError):
                img.hash_pass()

    def test_cancel_stops_it_and_leaves_no_thread(self):
        disk = make_disk(3)
        paths = self.write(disk, compression="none")
        before = threading.active_count()
        calls = {"n": 0}

        def cancel():
            calls["n"] += 1
            return calls["n"] > 3

        with ewf.EwfImage(paths) as img, \
                mock.patch.object(ewf, "READ_BLOCK", 64 << 10):
            with self.assertRaises(Cancelled):
                img.hash_pass(should_cancel=cancel)
        self.assertLessEqual(threading.active_count(), before + 1)

    def test_iter_stream_gives_the_disk(self):
        disk = make_disk(2)
        paths = self.write(disk, segment_bytes=1 << 20)
        with ewf.EwfImage(paths) as img:
            self.assertEqual(b"".join(img.iter_stream()), disk)


class ReadAhead(TempDirCase):
    def test_raw_image_hash_is_unchanged_by_reading_ahead(self):
        disk = os.urandom(9 << 20)                        # more than one block
        p = self.tmp / "d.dd"
        p.write_bytes(disk)
        with image.ImageSource.open(p) as src:
            whole, per = image.hash_image(src)
        self.assertEqual(whole.sha256, hashlib.sha256(disk).hexdigest())
        self.assertTrue(per[0].matches(whole))

    def test_cancel_and_errors_reach_the_caller(self):
        import io
        with self.assertRaises(Cancelled):
            list(image._read_ahead(io.BytesIO(b"x" * 100), lambda: True))

        class Broken(io.BytesIO):
            def read(self, n=-1):
                raise OSError("device gone")
        with self.assertRaises(OSError):
            list(image._read_ahead(Broken(), None))


if __name__ == "__main__":
    unittest.main()
