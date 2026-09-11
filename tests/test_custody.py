"""The custody log: append-only, durable, chained, and honest about damage."""

from __future__ import annotations

import json
import os
import threading
import unittest
from unittest import mock

from _support import TempDirCase

from forensics_workshop import custody
from forensics_workshop.errors import CustodyError, CustodyRefused


class CustodyLog(TempDirCase):
    def setUp(self):
        super().setUp()
        self.log = custody.CustodyLog(self.tmp)
        self.who = custody.examiner("Examiner One")

    def _fill(self, n=5):
        for i in range(n):
            self.log.record("test.action", actor=self.who, target=f"t{i}",
                            detail={"i": i})

    def test_records_chain_and_verify(self):
        self._fill()
        rows = self.log.rows()
        self.assertEqual([r["seq"] for r in rows], [1, 2, 3, 4, 5])
        self.assertEqual(rows[0]["prev"], custody.GENESIS)
        lines = self.log.path.read_bytes().split(b"\n")
        self.assertEqual(rows[1]["prev"], custody.line_hash(lines[0]))
        report = self.log.verify()
        self.assertTrue(report.ok, report.problems)
        self.assertEqual(report.records, 5)
        self.assertEqual((report.head_seq, report.head_sha256), self.log.head())

    def test_every_record_is_fsynced(self):
        with mock.patch("forensics_workshop.custody.os.fsync",
                        wraps=os.fsync) as fsync:
            self.log.record("test.action", actor=self.who)
            self.log.record("test.action", actor=self.who)
        self.assertGreaterEqual(fsync.call_count, 2)

    def test_a_model_is_not_an_actor(self):
        with self.assertRaises(CustodyRefused):
            self.log.record("hunt.flagged",
                            actor=custody.Actor("model", "magistral-24b"))
        self.assertFalse(self.log.path.exists())

    def test_an_unnamed_examiner_is_refused(self):
        for name in ("", "   ", "two\nlines"):
            with self.assertRaises(CustodyRefused):
                custody.examiner(name)

    def test_conclusions_are_refused_at_any_depth(self):
        for detail in ({"verdict": "guilty"}, {"a": {"b": [{"Finding": 1}]}},
                       {"assessment": "x"}):
            with self.assertRaises(CustodyRefused):
                self.log.record("test.action", actor=self.who, detail=detail)
        self.assertFalse(self.log.path.exists(),
                         "a refused record must leave no trace")

    def test_unserialisable_detail_leaves_no_trace(self):
        self._fill(1)
        size = self.log.path.stat().st_size
        with self.assertRaises(CustodyError):
            self.log.record("test.action", actor=self.who,
                            detail={"x": object()})
        self.assertEqual(self.log.path.stat().st_size, size)

    def test_bad_action_names_are_refused(self):
        with self.assertRaises(CustodyRefused):
            self.log.record("Not An Action", actor=self.who)

    def test_an_edited_line_breaks_the_chain_at_the_next_record(self):
        self._fill()
        lines = self.log.path.read_bytes().split(b"\n")
        row = json.loads(lines[2])
        row["target"] = "something else"
        lines[2] = json.dumps(row, sort_keys=True,
                              separators=(",", ":")).encode()
        self.log.path.write_bytes(b"\n".join(lines))
        report = self.log.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("record 4" in p for p in report.problems),
                        report.problems)

    def test_a_deleted_line_is_detected(self):
        self._fill()
        lines = self.log.path.read_bytes().split(b"\n")
        del lines[1]
        self.log.path.write_bytes(b"\n".join(lines))
        report = self.log.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("numbered 3" in p for p in report.problems))

    def test_reordering_is_detected(self):
        self._fill()
        lines = self.log.path.read_bytes().split(b"\n")
        lines[1], lines[2] = lines[2], lines[1]
        self.log.path.write_bytes(b"\n".join(lines))
        self.assertFalse(self.log.verify().ok)

    def test_a_torn_final_line_is_acknowledged_never_repaired(self):
        self._fill(3)
        with open(self.log.path, "ab") as fh:
            fh.write(b'{"seq": 4, "at": "2026-')     # a crash mid-write
        torn_offset = self.log.path.stat().st_size - len(b'{"seq": 4, "at": "2026-')
        before = self.log.verify()
        self.assertTrue(before.ok, "an interrupted tail is not tampering")
        self.assertTrue(any("interrupted write" in n for n in before.notes))

        self.log.record("test.after_crash", actor=self.who)
        data = self.log.path.read_bytes()
        self.assertIn(b'{"seq": 4, "at": "2026-\n', data,
                      "the torn bytes are still there, terminated, not repaired")
        rows = self.log.rows()
        notice = [r for r in rows if r["action"] == "custody.unreadable_line"]
        self.assertEqual(len(notice), 1)
        self.assertEqual(notice[0]["detail"]["offset"], torn_offset)
        self.assertEqual(notice[0]["actor"]["kind"], "tool")
        self.assertEqual(rows[-1]["action"], "test.after_crash")
        after = self.log.verify()
        self.assertTrue(after.ok, after.problems)
        self.assertTrue(any("acknowledged" in n for n in after.notes))

    def test_an_unacknowledged_garbage_line_in_the_middle_is_a_problem(self):
        self._fill(2)
        with open(self.log.path, "ab") as fh:
            fh.write(b"not json\n")
        self._fill(1)                     # acknowledges it
        lines = self.log.path.read_bytes().split(b"\n")
        # remove the acknowledgement AND re-chain by hand is not possible
        # without rewriting hashes; so instead insert new garbage mid-file.
        lines.insert(1, b"injected garbage")
        self.log.path.write_bytes(b"\n".join(lines))
        report = self.log.verify()
        self.assertFalse(report.ok)
        self.assertTrue(any("never acknowledged" in p for p in report.problems))

    def test_the_anchor_catches_a_complete_rewrite(self):
        self._fill(3)
        anchor = self.log.head()
        # Rewrite the whole log with a valid chain of different content.
        self.log.path.unlink()
        for i in range(3):
            self.log.record("forged.action", actor=self.who, target=f"f{i}")
        self.assertTrue(self.log.verify().ok,
                        "a rewritten chain is internally consistent")
        report = self.log.verify(anchor=anchor)
        self.assertFalse(report.ok)
        self.assertTrue(any("rewritten" in p for p in report.problems))

    def test_concurrent_appends_keep_one_chain(self):
        def worker(n):
            for i in range(25):
                self.log.record("test.thread", actor=self.who,
                                target=f"{n}:{i}")
        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        report = self.log.verify()
        self.assertTrue(report.ok, report.problems[:3])
        self.assertEqual(report.records, 100)

    def test_last_filters_by_action_and_target(self):
        self._fill(3)
        self.log.record("other.action", actor=self.who, target="t1")
        self.assertEqual(self.log.last("test.action", "t1")["detail"]["i"], 1)
        self.assertEqual(self.log.last()["action"], "other.action")
        self.assertIsNone(self.log.last("nope"))


if __name__ == "__main__":
    unittest.main()
