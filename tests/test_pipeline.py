"""The runbook and the review queue.

The runbook drives the deterministic steps end to end on a real (synthetic)
disk image — the same geotagged-photo / document / mail volume the DOMEX tests
plant — and is held to three properties the unattended case depends on: it runs
every step on every NTFS volume, one failing step does not abort the rest, and a
second run skips what is already done. The review queue is held to the line the
whole tool draws: a proposal is a candidate until an examiner confirms it, a
decision is a custodial act, and only a confirmed finding counts as admitted."""

from __future__ import annotations

import unittest
from unittest import mock

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

import test_domex as td
from forensics_workshop import diskimage, domex, pipeline, review
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError


# ---------------------------------------------------------------------------
# the review queue
# ---------------------------------------------------------------------------

class ReviewQueue(TempDirCase):
    def setUp(self):
        super().setUp()
        self.case = Case.create(self.tmp / "case", case_id="REV-1",
                                examiner=EXAMINER)

    def test_a_proposal_waits_and_is_not_a_custodial_act(self):
        before = len(self.case.custody.rows())
        fid = review.propose(self.case, source="engine", kind="hunt-hit",
                             evidence_id="E001", title="a candidate",
                             detail={"why": "matched a term"}, refs=["a:1"])
        got = review.finding(self.case, fid)
        self.assertEqual(got.status, "proposed")
        self.assertEqual(got.refs, ["a:1"])
        self.assertEqual(len(self.case.custody.rows()), before,
                         "proposing is not custodial — nothing was decided")

    def test_confirming_is_custodial_and_only_confirmed_is_admitted(self):
        fid = review.propose(self.case, source="model:local-x", kind="triage",
                             evidence_id="E001", title="read this first")
        self.assertEqual(review.confirmed(self.case), [])
        review.decide(self.case, fid, "confirmed", note="agree")
        admitted = review.confirmed(self.case)
        self.assertEqual([f.id for f in admitted], [fid])
        self.assertEqual(admitted[0].decided_by, EXAMINER)
        rec = self.case.custody.last("review.confirmed", f"finding:{fid}")
        self.assertEqual(rec["detail"]["finding_id"], fid)

    def test_a_finding_can_be_re_decided_and_the_latest_wins(self):
        fid = review.propose(self.case, source="engine", kind="hunt-hit",
                             evidence_id="E001", title="x")
        review.decide(self.case, fid, "confirmed")
        review.decide(self.case, fid, "rejected", note="on reflection, no")
        self.assertEqual(review.finding(self.case, fid).status, "rejected")
        self.assertEqual(review.confirmed(self.case), [])
        self.assertEqual(review.counts(self.case),
                         {"proposed": 0, "confirmed": 0, "rejected": 1})

    def test_a_decision_needs_a_known_finding_and_a_valid_verdict(self):
        with self.assertRaises(EvidenceError):
            review.decide(self.case, "deadbeef0000", "confirmed")
        fid = review.propose(self.case, source="engine", kind="x",
                             evidence_id="E001", title="y")
        with self.assertRaises(EvidenceError):
            review.decide(self.case, fid, "maybe")


# ---------------------------------------------------------------------------
# the runbook, over a real synthetic disk image
# ---------------------------------------------------------------------------

class Runbook(TempDirCase):
    def setUp(self):
        super().setUp()
        self.evidence = self.tmp / "evidence"
        self.evidence.mkdir()
        (self.evidence / "img.001").write_bytes(td.build_disk())
        self.case = Case.create(self.tmp / "case", case_id="AUTO-1",
                                examiner=EXAMINER)
        self.eid = self.case.add_image(self.evidence / "img.001").id

    def _completed_steps(self, summary):
        return {(r.step, r.state) for r in summary.results}

    def test_it_runs_every_step_and_mines_the_volume(self):
        summary = pipeline.run_pipeline(self.case, self.eid)
        self.assertEqual(summary.state, "completed", summary.problems)
        steps = {r.step: r.state for r in summary.results}
        self.assertEqual(steps.get("image"), "completed")
        self.assertEqual(steps.get("ntfs"), "completed")
        self.assertEqual(steps.get("domex"), "completed")
        self.assertEqual(steps.get("slack"), "completed")
        # DOMEX actually produced rows from the planted files
        _rows, total = domex.list_domex(self.case, self.eid)
        self.assertGreater(total, 0)
        self.assertGreaterEqual(summary.tally["domex_geotagged"], 1)

    def test_carve_is_off_by_default_and_on_when_asked(self):
        s1 = pipeline.run_pipeline(self.case, self.eid)
        self.assertNotIn("carve", {r.step for r in s1.results})
        s2 = pipeline.run_pipeline(self.case, self.eid, carve=True, force=True)
        self.assertIn("carve", {r.step for r in s2.results})

    def test_the_run_files_one_reviewable_summary_a_human_can_confirm(self):
        summary = pipeline.run_pipeline(self.case, self.eid)
        runs = review.list_findings(self.case, kind="pipeline-run")
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0].id, summary.finding_id)
        self.assertEqual(runs[0].source, "engine")
        self.assertGreaterEqual(runs[0].detail["tally"]["domex_images"], 1)
        review.decide(self.case, summary.finding_id, "confirmed")
        self.assertEqual([f.id for f in review.confirmed(self.case)],
                         [summary.finding_id])

    def test_a_second_run_skips_what_is_already_done(self):
        pipeline.run_pipeline(self.case, self.eid)
        again = pipeline.run_pipeline(self.case, self.eid)
        steps = {r.step: r.state for r in again.results}
        self.assertEqual(steps.get("ntfs"), "skipped")
        self.assertEqual(steps.get("domex"), "skipped")
        self.assertEqual(steps.get("slack"), "skipped")

    def test_one_failing_step_is_recorded_and_the_run_continues(self):
        with mock.patch.object(pipeline.domex, "analyse_volume",
                               side_effect=RuntimeError("boom")):
            summary = pipeline.run_pipeline(self.case, self.eid)
        steps = {r.step: r.state for r in summary.results}
        self.assertEqual(summary.state, "completed",
                         "one bad step must not abort the image")
        self.assertEqual(steps.get("domex"), "failed")
        self.assertEqual(steps.get("ntfs"), "completed")
        self.assertEqual(steps.get("slack"), "completed")
        self.assertTrue(any("boom" in p for p in summary.problems))

    def test_a_logical_folder_is_refused_with_a_reason(self):
        # the exact mistake Party Girl started with: an E01 registered as a
        # logical folder, which the pipeline (a disk-image runbook) refuses.
        folder = self.tmp / "logical"
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        litem = self.case.add_folder(folder)
        with self.assertRaisesRegex(EvidenceError, "not a disk image"):
            pipeline.run_pipeline(self.case, litem.id)


if __name__ == "__main__":
    unittest.main()
