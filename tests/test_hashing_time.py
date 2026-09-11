"""Hashing and timestamp decoding — the two measured values everything rests on."""

from __future__ import annotations

import hashlib
import io
import unittest

from _support import TempDirCase

from forensics_workshop import hashing, timeutil
from forensics_workshop.errors import Cancelled


class Hashing(TempDirCase):
    def test_all_three_digests_match_hashlib_in_one_pass(self):
        data = b"evidence" * 400_000                   # > one 1 MiB chunk
        h, head = hashing.hash_stream(io.BytesIO(data), head_bytes=16)
        self.assertEqual(h.md5, hashlib.md5(data).hexdigest())
        self.assertEqual(h.sha1, hashlib.sha1(data).hexdigest())
        self.assertEqual(h.sha256, hashlib.sha256(data).hexdigest())
        self.assertEqual(h.size, len(data))
        self.assertEqual(head, data[:16])

    def test_sink_receives_exactly_what_was_hashed(self):
        data = bytes(range(256)) * 9000
        sink = io.BytesIO()
        h, _ = hashing.hash_stream(io.BytesIO(data), sink=sink)
        self.assertEqual(sink.getvalue(), data)
        self.assertEqual(h, hashing.hash_bytes(data))

    def test_matches_requires_size_as_well_as_digests(self):
        a = hashing.hash_bytes(b"abc")
        self.assertTrue(a.matches(hashing.Hashes(**a.as_dict())))
        self.assertFalse(a.matches(hashing.Hashes(a.md5, a.sha1, a.sha256, 4)))

    def test_cancel_is_checked_between_chunks(self):
        with self.assertRaises(Cancelled):
            hashing.hash_stream(io.BytesIO(b"x" * 10), should_cancel=lambda: True)

    def test_hash_evidence_goes_through_the_read_only_door(self):
        p = self.tmp / "f.bin"
        p.write_bytes(b"12345")
        self.assertEqual(hashing.hash_evidence(p).sha256,
                         hashlib.sha256(b"12345").hexdigest())


class Timestamps(unittest.TestCase):
    def test_webkit_and_prtime_decode_to_the_same_instant(self):
        from synth import PRTIME_2026, WEBKIT_2026
        self.assertEqual(timeutil.decode(WEBKIT_2026, "webkit_us"),
                         "2026-03-01T12:00:00.000000Z")
        self.assertEqual(timeutil.decode(PRTIME_2026, "prtime_us"),
                         "2026-03-01T12:00:00.000000Z")

    def test_zero_and_null_are_unset_not_1601(self):
        self.assertIsNone(timeutil.decode(0, "webkit_us"))
        self.assertIsNone(timeutil.decode(None, "prtime_us"))
        self.assertIsNone(timeutil.decode("not a number", "unix_s"))

    def test_out_of_range_is_none_not_an_exception(self):
        self.assertIsNone(timeutil.decode(10 ** 30, "unix_s"))

    def test_unknown_epoch_is_a_programming_error(self):
        with self.assertRaises(ValueError):
            timeutil.decode(1, "mayan")

    def test_unit_inference_is_by_magnitude(self):
        self.assertEqual(timeutil.infer_unix_unit(1772366400), "unix_s")
        self.assertEqual(timeutil.infer_unix_unit(1772366400000), "unix_ms")
        self.assertIsNone(timeutil.infer_unix_unit(0))

    def test_stat_nanoseconds_keep_microseconds(self):
        self.assertEqual(timeutil.from_ns(1_772_366_400_123_456_789),
                         "2026-03-01T12:00:00.123456Z")

    def test_local_offset_shape(self):
        self.assertRegex(timeutil.local_offset(), r"^[+-]\d\d:\d\d$")


if __name__ == "__main__":
    unittest.main()
