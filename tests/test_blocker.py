"""Read-only access, layout refusals, and the write probe that must be told."""

from __future__ import annotations

import errno
import io
import os
import sys
import unittest
from unittest import mock

from _support import TempDirCase

from forensics_workshop import blocker
from forensics_workshop.errors import CaseLayoutError, CasePathError


class ReadOnly(TempDirCase):
    def test_evidence_handle_cannot_write_at_either_layer(self):
        p = self.tmp / "evidence.bin"
        p.write_bytes(b"original")
        with blocker.open_evidence(p) as fh:
            self.assertEqual(fh.read(), b"original")
            self.assertFalse(fh.writable())
            with self.assertRaises(io.UnsupportedOperation):
                fh.write(b"x")
            with self.assertRaises(OSError) as ctx:
                os.write(fh.fileno(), b"x")      # the descriptor itself
            self.assertEqual(ctx.exception.errno, errno.EBADF)
        self.assertEqual(p.read_bytes(), b"original")

    @unittest.skipIf(sys.platform == "win32", "POSIX flag")
    def test_noatime_refusal_falls_back_to_plain_read_only(self):
        p = self.tmp / "e.bin"
        p.write_bytes(b"abc")
        real_open = os.open
        calls = []

        def fake_open(path, flags, *a):
            calls.append(flags)
            if blocker.NOATIME_FLAG and flags & blocker.NOATIME_FLAG:
                raise PermissionError(errno.EPERM, "not owner")
            return real_open(path, flags, *a)

        with mock.patch("forensics_workshop.blocker.os.open", fake_open):
            with blocker.open_evidence(p) as fh:
                self.assertEqual(fh.read(), b"abc")
        self.assertTrue(all(not (f & (os.O_WRONLY | os.O_RDWR)) for f in calls))

    def test_the_read_flags_contain_no_write_bit(self):
        for bit in ("O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"):
            self.assertFalse(blocker.READ_ONLY_FLAGS & getattr(os, bit), bit)


class Layout(TempDirCase):
    def test_is_inside(self):
        a = self.tmp / "a"
        (a / "b").mkdir(parents=True)
        self.assertTrue(blocker.is_inside(a / "b", a))
        self.assertTrue(blocker.is_inside(a, a))
        self.assertFalse(blocker.is_inside(a, a / "b"))
        self.assertFalse(blocker.is_inside(self.tmp / "ab", a),
                         "a shared PREFIX is not containment")

    def test_symlinked_case_into_evidence_is_still_caught(self):
        evidence = self.tmp / "evidence"
        (evidence / "deep").mkdir(parents=True)
        try:
            os.symlink(evidence / "deep", self.tmp / "innocent-looking",
                       target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("cannot create symlinks here")
        with self.assertRaises(CaseLayoutError):
            blocker.check_layout(self.tmp / "innocent-looking", evidence)

    def test_assert_case_path(self):
        case = self.tmp / "case"
        case.mkdir()
        self.assertEqual(blocker.assert_case_path(case, case / "x" / "y"),
                         case / "x" / "y")
        with self.assertRaises(CasePathError):
            blocker.assert_case_path(case, self.tmp / "elsewhere")
        with self.assertRaises(CasePathError):
            blocker.assert_case_path(case, case / ".." / "escape")

    def test_refuse_evidence_path_both_directions(self):
        ev = self.tmp / "ev"
        (ev / "sub").mkdir(parents=True)
        with self.assertRaises(CaseLayoutError):
            blocker.refuse_evidence_path(ev / "sub", [ev])
        with self.assertRaises(CaseLayoutError):
            blocker.refuse_evidence_path(self.tmp, [ev])
        blocker.refuse_evidence_path(self.tmp / "other", [ev])


class VolumeAndPolicy(TempDirCase):
    def test_volume_state_answers_and_warns_when_writable(self):
        state = blocker.volume_state(self.tmp)
        self.assertIn(state.read_only, (True, False, None))
        if state.read_only is False:
            self.assertEqual(state.warning, blocker.RW_WARNING)
        if state.read_only is None:
            self.assertTrue(state.warning)

    def test_volume_state_never_raises(self):
        with mock.patch("forensics_workshop.blocker._volume_state_posix",
                        side_effect=RuntimeError("boom")), \
                mock.patch("forensics_workshop.blocker._volume_state_windows",
                           side_effect=RuntimeError("boom")):
            state = blocker.volume_state(self.tmp)
        self.assertIsNone(state.read_only)
        self.assertIn("treat it as writable", state.warning)

    @unittest.skipIf(sys.platform == "win32", "non-Windows answer")
    def test_policy_off_windows_says_so(self):
        self.assertFalse(blocker.usb_policy_state().supported)
        self.assertFalse(blocker.apply_usb_policy(True).applied)

    def test_the_notice_names_the_real_thing(self):
        self.assertIn("hardware write blocker", blocker.HARDWARE_NOTICE)
        self.assertIn("NOT VERIFIED", blocker.POLICY_SCOPE)


class WriteProbe(TempDirCase):
    def test_it_will_not_run_unless_told_in_words(self):
        with self.assertRaises(TypeError):
            blocker.verify_write_refused(self.tmp)             # no keyword
        with self.assertRaises(ValueError):
            blocker.verify_write_refused(self.tmp, confirm_not_evidence=False)
        with self.assertRaises(ValueError):
            blocker.verify_write_refused(self.tmp, confirm_not_evidence="yes")

    def test_a_writable_folder_is_reported_not_protected_and_cleaned(self):
        result = blocker.verify_write_refused(self.tmp,
                                              confirm_not_evidence=True)
        self.assertFalse(result.refused)
        self.assertTrue(result.probe_created)
        self.assertTrue(result.probe_removed)
        self.assertIn("NOT PROTECTED", result.note)
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_a_refused_write_is_reported_as_refused(self):
        denied = OSError(errno.EROFS, "Read-only file system")
        with mock.patch("forensics_workshop.blocker.os.open",
                        side_effect=denied):
            result = blocker.verify_write_refused(self.tmp,
                                                  confirm_not_evidence=True)
        self.assertTrue(result.refused)
        self.assertFalse(result.probe_created)
        self.assertIn("EROFS", result.error)

    def test_it_refuses_to_probe_registered_evidence(self):
        ev = self.tmp / "ev"
        ev.mkdir()
        with self.assertRaises(CaseLayoutError):
            blocker.verify_write_refused(ev, confirm_not_evidence=True,
                                         evidence_roots=[ev])
        self.assertEqual(list(ev.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
