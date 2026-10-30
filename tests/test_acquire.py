"""The drive imager (acquire.py) and the E01 writer (ewfwrite.py), 2026-10-29.

A "drive" here is a file of synthetic disk bytes, with the three questions
the imager asks of the operating system — what kind of source is this, and
which physical disks hold the source and the destination — answered by the
test. Everything else is the real code: the read-only door, the guarded
writers, the E01 and RAW writers, the read-back through the engine's own
readers, custody and registration. Where libewf's `ewfverify` is installed,
every E01 is also handed to it: a reader this project did not write.
"""

from __future__ import annotations

import hashlib
import os
import random
import shutil
import subprocess
import time
import unittest
from pathlib import Path
from unittest import mock

from _support import EXAMINER, PACKAGE, TempDirCase

from forensics_workshop import acquire as A
from forensics_workshop import blocker, ewfwrite, image, ratchet
from forensics_workshop.case import Case
from forensics_workshop.errors import AcquisitionError, Cancelled


def synthetic_disk(size: int, seed: int = 3) -> bytes:
    """Zeros, text and noise in runs — compressible and not, like a disk."""
    rnd = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        n = min(rnd.choice([512, 4096, 65536, 200000]), size - len(out))
        pick = rnd.random()
        if pick < 0.4:
            out += b"\x00" * n
        elif pick < 0.7:
            out += (b"a line of text on a disk " * (n // 25 + 1))[:n]
        else:
            out += rnd.randbytes(n)
    return bytes(out)


class _FlakyRaw:
    """An unbuffered reader that fails every read touching `bad` byte
    ranges — `transient` ones only on their first attempt."""

    def __init__(self, raw, bad=(), transient=(), delay=0.0):
        self._raw, self.bad, self.transient = raw, list(bad), list(transient)
        self.delay = delay
        self._pos = 0
        self._failed_once: set = set()

    def seek(self, pos, whence=0):
        self._pos = self._raw.seek(pos, whence)
        return self._pos

    def read(self, n):
        lo, hi = self._pos, self._pos + n
        for a, b in self.bad:
            if lo < b and a < hi:
                if self.delay:
                    time.sleep(self.delay)
                raise OSError(5, "Input/output error")
        for a, b in self.transient:
            if lo < b and a < hi and (a, b) not in self._failed_once:
                self._failed_once.add((a, b))
                raise OSError(5, "Input/output error")
        data = self._raw.read(n)
        self._pos += len(data)
        return data


class _FlakyFile:
    def __init__(self, fh, **kw):
        self._fh = fh
        self.raw = _FlakyRaw(fh.raw, **kw)

    def seek(self, *a):
        return self._fh.seek(*a)

    def read(self, *a):
        return self._fh.read(*a)

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class Imager(TempDirCase):
    SIZE = 3 * (1 << 20) + 64 * 512 * 3          # not a whole number of reads

    def setUp(self):
        super().setUp()
        self.disk = synthetic_disk(self.SIZE)
        self.device = self.tmp / "device.bin"
        self.device.write_bytes(self.disk)
        self.case = Case.create(self.tmp / "case", case_id="ACQ-1",
                                examiner=EXAMINER, description="imager")
        self.dest = self.tmp / "images" / "drive1"
        for name, value in (("source_kind", "physical"),
                            ("disks_of_source", {"/dev/src"}),
                            ("disks_of_path", {"/dev/dst"}),
                            ("list_drives", []),
                            # Windows (first run there 2026-10-30): a raw read
                            # needs Administrator, and the size comes from the
                            # drive itself — the stand-in file answers both.
                            ("is_elevated", True)):
            patcher = mock.patch.object(A, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        for name, fn in (("_win_geometry",
                          lambda s: (os.path.getsize(s), 512)),
                         ("_win_length", lambda s: os.path.getsize(s))):
            patcher = mock.patch.object(A, name, side_effect=fn)
            patcher.start()
            self.addCleanup(patcher.stop)

    def run_acquire(self, **kw):
        kw.setdefault("examiner", EXAMINER)
        kw.setdefault("case", self.case)
        return A.acquire(str(self.device), self.dest, kw.pop("name", "drive1"),
                         **kw)

    def read_back(self, first) -> bytes:
        with image.ImageSource.open(first) as src:
            return src.read_at(0, src.size)

    def assert_libewf_agrees(self, first):
        tool = shutil.which("ewfverify")
        if not tool:
            return                     # not installed here; ewf.py still read it
        done = subprocess.run([tool, "-q", str(first)], capture_output=True,
                              text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    # -- the round trips --------------------------------------------------
    def test_e01_hashes_in_one_read_verifies_and_is_registered(self):
        result = self.run_acquire(segment_bytes=None, description="test disk",
                                  case_number="OP-1", evidence_number="E9",
                                  write_blocker="Tableau T35u (stated)")
        want = {"md5": hashlib.md5(self.disk).hexdigest(),
                "sha1": hashlib.sha1(self.disk).hexdigest(),
                "sha256": hashlib.sha256(self.disk).hexdigest(),
                "size": len(self.disk)}
        self.assertEqual(result.hashes, want)
        self.assertTrue(result.verified)
        self.assertEqual(result.state, "completed")
        self.assertEqual([Path(s["path"]).name for s in result.segments],
                         ["drive1.E01"])
        first = Path(result.segments[0]["path"])
        self.assertEqual(self.read_back(first), self.disk)
        self.assert_libewf_agrees(first)
        # custody: started, completed with the hashes, then registration
        actions = [r["action"] for r in self.case.custody.rows()]
        i = actions.index("acquisition.started")
        self.assertEqual(actions[i + 1:i + 3],
                         ["acquisition.completed", "evidence.registered"])
        done = self.case.custody.last("acquisition.completed")
        self.assertEqual(done["hashes"]["sha256"], want["sha256"])
        self.assertTrue(done["detail"]["verified"])
        item = self.case.evidence_item(result.evidence_id)
        self.assertEqual((item.kind, item.source), ("raw-image", str(first)))
        self.assertTrue(self.case.custody.verify().ok)
        log = Path(result.log).read_text(encoding="utf-8")
        for needle in (want["md5"], want["sha256"], ": verified", "OP-1",
                       "Tableau T35u (stated)", "Unreadable sectors",
                       blocker.HARDWARE_NOTICE[:40]):
            self.assertIn(needle, log)
        self.assertNotIn("MISMATCH", log)

    def test_raw_split_into_numbered_segments(self):
        result = self.run_acquire(fmt="raw", segment_bytes=1 << 20)
        names = [Path(s["path"]).name for s in result.segments]
        self.assertEqual(names, ["drive1.001", "drive1.002", "drive1.003",
                                 "drive1.004"])
        self.assertTrue(result.verified)
        self.assertEqual(self.read_back(result.segments[0]["path"]), self.disk)
        self.assertTrue(all(s.get("sha256") for s in result.segments))

    def test_raw_one_file_is_a_dd(self):
        result = self.run_acquire(fmt="raw", segment_bytes=None)
        self.assertEqual([Path(s["path"]).name for s in result.segments],
                         ["drive1.dd"])
        self.assertEqual(Path(result.segments[0]["path"]).read_bytes(),
                         self.disk)

    def test_e01_split_into_segments_every_reader_follows(self):
        for compression in ("none", "best"):
            with self.subTest(compression=compression):
                if self.dest.exists():
                    shutil.rmtree(self.dest)
                result = self.run_acquire(compression=compression,
                                          segment_bytes=1 << 20, case=None)
                names = [Path(s["path"]).name for s in result.segments]
                self.assertEqual(names[0], "drive1.E01")
                if compression == "none":
                    self.assertGreater(len(names), 2)
                self.assertTrue(result.verified)
                self.assertEqual(self.read_back(result.segments[0]["path"]),
                                 self.disk)
                self.assert_libewf_agrees(result.segments[0]["path"])

    # -- unreadable sectors -------------------------------------------------
    def test_unreadable_sectors_are_zeros_listed_everywhere(self):
        bad = (5 * 512, 7 * 512)               # sectors 5 and 6
        blip = (40 * 512, 41 * 512)            # fails once, then reads
        real = blocker.open_evidence

        def door(path):
            fh = real(path)
            if os.fspath(path) == str(self.device):
                return _FlakyFile(fh, bad=[bad], transient=[blip])
            return fh

        with mock.patch.object(blocker, "open_evidence", side_effect=door):
            result = self.run_acquire(segment_bytes=None)
        self.assertEqual(result.bad_sectors, [(5, 2)])
        zeroed = bytearray(self.disk)
        zeroed[bad[0]:bad[1]] = b"\x00" * (bad[1] - bad[0])
        self.assertEqual(result.hashes["sha256"],
                         hashlib.sha256(bytes(zeroed)).hexdigest(),
                         "the hashes are of what was written")
        self.assertTrue(result.verified)
        first = Path(result.segments[0]["path"])
        self.assertIn(b"error2", first.read_bytes())
        self.assert_libewf_agrees(first)
        done = self.case.custody.last("acquisition.completed")
        self.assertEqual(done["detail"]["bad_sector_runs"], 1)
        self.assertIn("sector 5 + 1 more",
                      Path(result.log).read_text(encoding="utf-8"))

    def _flaky(self, **kw):
        real = blocker.open_evidence

        def door(path):
            fh = real(path)
            if os.fspath(path) == str(self.device):
                return _FlakyFile(fh, **kw)
            return fh
        return mock.patch.object(blocker, "open_evidence", side_effect=door)

    def test_a_drive_that_goes_away_is_a_failure_never_an_image_of_zeros(self):
        """Review, 2026-10-29: on Windows an unplugged drive and a bad sector
        raise the same error; the first must not become a verified image."""
        gone = (1 << 20, self.SIZE)
        with self._flaky(bad=[gone]), \
                mock.patch.object(A, "_present", return_value=False), \
                self.assertRaises(AcquisitionError) as got:
            self.run_acquire(segment_bytes=None)
        self.assertIn("no longer attached", str(got.exception))
        self.assertEqual(self.case.evidence(), [])
        failed = self.case.custody.last("acquisition.failed")
        self.assertIn("no longer attached", failed["detail"]["error"])
        self.assertIn("MUST NOT BE USED", next(self.dest.glob("*.txt")).read_text(
            encoding="utf-8"))

    def test_a_long_dead_stretch_stops_the_run(self):
        with self._flaky(bad=[(1 << 20, 3 << 20)]), \
                self.assertRaises(AcquisitionError) as got:
            self.run_acquire(segment_bytes=None, max_bad_run=64 * 1024,
                             retries=0)
        self.assertIn("in a row would not read", str(got.exception))
        self.assertEqual(self.case.evidence(), [])

    def test_stop_is_heard_while_bad_sectors_are_retried(self):
        """2 MB of bad media at 10 ms a try is minutes of retries; Stop must
        still land within seconds."""
        calls = {"n": 0}

        def stop():
            calls["n"] += 1
            return calls["n"] > 3

        start = time.monotonic()
        with self._flaky(bad=[(1 << 20, 3 << 20)], delay=0.01), \
                self.assertRaises(Cancelled):
            self.run_acquire(segment_bytes=None, should_cancel=stop,
                             max_bad_run=1 << 40)
        self.assertLess(time.monotonic() - start, 15.0)

    def test_an_e01_that_would_run_out_of_segment_names_is_refused(self):
        with mock.patch.object(ewfwrite, "MAX_SEGMENTS", 2):
            self.assert_refused("segment names", segment_bytes=1 << 20)

    # -- refusals: nothing is written --------------------------------------
    def assert_refused(self, needle, **kw):
        before = sorted(self.tmp.rglob("*"))
        with self.assertRaises(AcquisitionError) as got:
            self.run_acquire(**kw)
        self.assertIn(needle, str(got.exception))
        self.assertEqual(sorted(self.tmp.rglob("*")), before,
                         "a refused acquisition writes nothing")

    def test_a_destination_that_is_not_empty_is_refused(self):
        self.dest.mkdir(parents=True)
        (self.dest / "keep.txt").write_text("x")
        self.assert_refused("not empty")

    def test_a_destination_on_the_source_drive_is_refused(self):
        with mock.patch.object(A, "disks_of_path", return_value={"/dev/src"}):
            self.assert_refused("on the drive being imaged")

    def test_a_destination_inside_a_case_is_refused(self):
        self.dest = self.case.root / "images"
        self.assert_refused("inside the case")

    def test_names_formats_and_whole_sectors(self):
        self.assert_refused("image name", name="../escape")
        self.assert_refused("not a format", fmt="vmdk")
        odd = self.tmp / "odd.bin"
        odd.write_bytes(self.disk[:1000])
        self.device = odd
        self.assert_refused("whole number of 512-byte sectors")
        result = self.run_acquire(fmt="raw", segment_bytes=None, case=None)
        self.assertEqual(result.hashes["size"], 1000)

    def test_raw_needs_the_room_and_e01_is_warned(self):
        small = shutil._ntuple_diskusage(10, 10, 100) if hasattr(
            shutil, "_ntuple_diskusage") else None
        with mock.patch.object(shutil, "disk_usage",
                               return_value=small or (10, 10, 100)):
            self.assert_refused("needs", fmt="raw")
            plan = A.check_plan(str(self.device), self.dest, "drive1")
        self.assertTrue(plan.ok)
        self.assertTrue(any("may run out of room" in w for w in plan.warnings))

    def test_a_file_is_not_a_drive(self):
        mock.patch.stopall()
        plan = A.check_plan(str(self.device), self.dest, "drive1")
        self.assertIn("is a file, not a drive", " ".join(plan.refusals))

    def test_an_examiner_is_named(self):
        with self.assertRaises(AcquisitionError):
            self.run_acquire(examiner="  ")

    # -- stopping ---------------------------------------------------------
    def test_a_stopped_acquisition_is_incomplete_and_never_registered(self):
        calls = {"n": 0}

        def stop():
            calls["n"] += 1
            return calls["n"] > 2

        with self.assertRaises(Cancelled) as got:
            self.run_acquire(should_cancel=stop, segment_bytes=None)
        self.assertIn("INCOMPLETE", str(got.exception))
        self.assertEqual(self.case.evidence(), [])
        self.assertIsNotNone(self.case.custody.last("acquisition.cancelled"))
        self.assertIsNone(self.case.custody.last("acquisition.completed"))
        log = next(self.dest.glob("*.txt")).read_text(encoding="utf-8")
        self.assertIn("MUST NOT BE USED AS EVIDENCE", log)


class Guards(unittest.TestCase):
    def test_drive_queries_are_read_only_codes_and_access(self):
        for code in A.READ_ONLY_IOCTLS:
            self.assertEqual(A.assert_query_only(0, code), code)
            A.assert_query_only(A.GENERIC_READ, code)
        with self.assertRaises(AcquisitionError):
            A.assert_query_only(0x40000000, A.IOCTL_DISK_GET_LENGTH_INFO)
        with self.assertRaises(AcquisitionError):
            A.assert_query_only(0, 0x0007C004)        # IOCTL_DISK_SET_*-like

    def test_the_writers_are_listed_and_guarded(self):
        expected = {"acquire:_make_destination": "acquisition",
                    "acquire:_open_output": "acquisition",
                    "acquire:_write_log": "acquisition",
                    "acquire:_win_query": "device-query"}
        for name, kind in expected.items():
            self.assertEqual(blocker.WRITERS.get(name), kind)
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        self.assertEqual(report.violations, [])
        sites = {s.qualname for s in report.sites
                 if s.qualname.startswith(("acquire:", "ewfwrite:"))}
        self.assertEqual(sites, set(expected),
                         "the E01 writer opens nothing itself")
        for kind, guard in (("acquisition", "assert_acquisition_path"),
                            ("device-query", "assert_query_only")):
            bare = ratchet.scan_source("def w(p):\n    open(p, 'xb')\n", "m",
                                       {"m:w": kind})
            self.assertTrue(any(guard in v for v in bare.violations), kind)

    def test_the_acquisition_guard(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            A.assert_acquisition_path(root / "d", root / "d" / "x.E01")
            with self.assertRaises(AcquisitionError):
                A.assert_acquisition_path(root / "d", root / "elsewhere.E01")
            (root / "case.json").write_text("{}")
            with self.assertRaises(AcquisitionError):
                A.assert_acquisition_path(root / "d", root / "d" / "x.E01")

    def test_listing_drives_never_raises(self):
        drives = A.list_drives()
        self.assertIsInstance(drives, list)
        for d in drives:
            self.assertTrue(d.label())


class EwfWriter(TempDirCase):
    def test_segment_names_follow_encase(self):
        self.assertEqual([ewfwrite.segment_suffix(n) for n in (1, 99, 100, 101,
                                                               125, 126, 775,
                                                               776, 14971)],
                         ["E01", "E99", "EAA", "EAB", "EAZ", "EBA", "EZZ",
                          "FAA", "ZZZ"])
        with self.assertRaises(ValueError):
            ewfwrite.segment_suffix(14972)
        # the reader walks the very same sequence (image._ewf_next_suffix)
        cur, names = "E01", ["E01"]
        while (nxt := image._ewf_next_suffix(cur)) is not None:
            names.append(nxt)
            cur = nxt
        self.assertEqual(names, [ewfwrite.segment_suffix(n) for n in
                                 range(1, ewfwrite.MAX_SEGMENTS + 1)])
        self.assertEqual(image._ewf_next_suffix("e99"), "eaa")

    def test_error2_never_wraps_a_sector_past_2_tib(self):
        self.assertTrue(ewfwrite.error2_fits(5, 2))
        self.assertFalse(ewfwrite.error2_fits(1 << 32, 1))
        w = ewfwrite.EwfWriter(self.tmp / "x", size=512 * 64,
                               open_segment=lambda p: open(p, "xb"))
        w.write(b"\x00" * 512 * 64)
        w.finish(b"\x00" * 16, b"\x00" * 20, [(5, 2), (1 << 32, 3)])
        self.assertEqual(w.error2_omitted, [(1 << 32, 3)])
        data = (self.tmp / "x.E01").read_bytes()
        at = data.index(b"error2") + 76
        self.assertEqual(int.from_bytes(data[at:at + 4], "little"), 1)

    def test_a_disk_of_part_sectors_is_refused_not_padded(self):
        with self.assertRaises(ValueError):
            ewfwrite.EwfWriter(self.tmp / "x", open_segment=open, size=1000)

    def test_writing_more_or_less_than_the_disk_is_refused(self):
        w = ewfwrite.EwfWriter(self.tmp / "x", size=1024,
                               open_segment=lambda p: open(p, "xb"))
        with self.assertRaises(ValueError):
            w.write(b"\x00" * 2048)
        w.write(b"\x00" * 512)
        with self.assertRaises(ValueError):
            w.finish(b"\x00" * 16, b"\x00" * 20)
        w.abandon()


if __name__ == "__main__":
    unittest.main()
