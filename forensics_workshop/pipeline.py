# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The end-to-end runbook — deterministic, unattended, no model, stdlib only.

Two different things get called "automation," and the plan (§6) keeps them
apart: **sequencing the deterministic steps** — hash, partitions, MFT, DOMEX,
slack, carve — is a runbook a machine can run alone all night; **judging what
the results mean** is a model's proposal that waits for an examiner. This module
is only the first. It presses the buttons in order, on every volume, and writes
nothing a human has to stand behind — every step it runs is one the engine
already performs and already records in custody. There is no model here.

What that buys the examiner: point it at a registered disk image and get a
hashed, partitioned, MFT-parsed, DOMEX-mined, slack-scraped case back, with one
run-summary proposal sitting in the review queue as the top of the morning's
worklist. The judgement layer (the hunts and the local model of §10) files its
proposals into that same queue later; this runbook is what fills the queue with
parsed rows for it to read.

**Built to run alone.** One step failing — a volume that will not parse, a
DOMEX pass that hits an unreadable file — is recorded and the run carries on to
the next; it never aborts the whole image over one bad volume. It is
**resumable**: a step whose output is already in the index is skipped, so a
re-run costs only what is new (pass `force=True` to redo). It takes a
`should_cancel` and a `progress` callback, and it asks the examiner nothing
mid-run — an unattended run that stopped to ask a question no one is there to
answer would defeat the point.

Carving a whole disk's unallocated space is slow, so it is **off by default**;
turn it on for a triage pass that has the time. Everything else runs by default.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field

from . import diskimage as _disk
from . import domex
from . import index as _index
from . import review
from .errors import Cancelled, EvidenceError
from .timeutil import utc_now

#: Every step the runbook knows, in the order it runs them.
STEPS = ("image", "ntfs", "domex", "slack", "carve")
#: What runs unless asked otherwise. Carve is excluded — it is the slow one.
DEFAULT_STEPS = ("image", "ntfs", "domex", "slack")


@dataclass
class StepResult:
    step: str
    volume: int | None
    state: str                  # completed | skipped | failed | cancelled | …
    summary: dict = field(default_factory=dict)
    error: str = ""
    seconds: float = 0.0

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class PipelineSummary:
    evidence_id: str
    run_id: str
    state: str
    steps_requested: list = field(default_factory=list)
    carve: bool = False
    ntfs_volumes: list = field(default_factory=list)
    results: list = field(default_factory=list)
    tally: dict = field(default_factory=dict)
    finding_id: str = ""
    problems: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict:
        d = asdict(self)
        d["results"] = [r.as_dict() if isinstance(r, StepResult) else r
                        for r in self.results]
        return d


# -- resumability: has a step's output already landed in the index? ----------

def _count(case, sql: str, params) -> int:
    with _index.session(case.root) as conn:
        try:
            return conn.execute(sql, params).fetchone()[0]
        except Exception:                     # a table an older case lacks
            return 0


def _run_done(case, eid, kind, vol) -> bool:
    """A completed run of `kind` for this volume in the shared `runs` table —
    the reliable signal, true even for a step that found zero rows (slack that
    was all zeros, a volume with nothing to DOMEX)."""
    if vol is None:
        return _count(case, "SELECT COUNT(*) FROM runs WHERE evidence_id = ? "
                      "AND kind = ? AND state = 'completed'", (eid, kind)) > 0
    return _count(case, "SELECT COUNT(*) FROM runs WHERE evidence_id = ? AND "
                  "kind = ? AND volume = ? AND state = 'completed'",
                  (eid, kind, vol)) > 0


def _image_done(case, eid) -> bool:
    # the row fallback spares a 60 GB re-hash for a case parsed before runs
    # were recorded for it.
    return _run_done(case, eid, "image", None) or \
        _count(case, "SELECT COUNT(*) FROM volumes WHERE evidence_id = ?",
               (eid,)) > 0


def _ntfs_done(case, eid, vol) -> bool:
    return _run_done(case, eid, "ntfs", vol) or \
        _count(case, "SELECT COUNT(*) FROM ntfs_entries WHERE evidence_id = ? "
               "AND volume = ?", (eid, vol)) > 0


def _domex_done(case, eid, vol) -> bool:
    return _run_done(case, eid, "domex", vol) or \
        _count(case, "SELECT COUNT(*) FROM artefacts WHERE evidence_id = ? AND "
               "parser = 'domex' AND row_ref LIKE ?", (eid, f"v{vol}:%")) > 0


def _slack_done(case, eid, vol) -> bool:
    return _run_done(case, eid, "slack", vol)


def _carve_done(case, eid, vol) -> bool:
    return _run_done(case, eid, "carve", vol) or \
        _count(case, "SELECT COUNT(*) FROM carve_candidates WHERE "
               "evidence_id = ? AND volume = ?", (eid, vol)) > 0


# -- running one step, catching its failure but never a cancel ---------------

def _cancel_check(should_cancel) -> None:
    if should_cancel is not None and should_cancel():
        raise Cancelled("pipeline cancelled")


def _do(summary: PipelineSummary, step: str, vol, should_run: bool, fn):
    """Run one step. A skip and a failure both return a StepResult and the run
    continues; a cancellation propagates and stops the run."""
    if not should_run:
        return StepResult(step, vol, "skipped")
    t = time.monotonic()
    try:
        out = fn()
    except Cancelled:
        raise
    except BaseException as exc:              # noqa: BLE001 — one bad step ≠ abort
        error = f"{type(exc).__name__}: {exc}"
        summary.problems.append(
            f"{step}{f' v{vol}' if vol is not None else ''}: {error}")
        return StepResult(step, vol, "failed", error=error,
                          seconds=round(time.monotonic() - t, 2))
    d = out.as_dict() if hasattr(out, "as_dict") else {}
    return StepResult(step, vol, getattr(out, "state", "completed"),
                      summary=d, seconds=round(time.monotonic() - t, 2))


# -- the runbook -------------------------------------------------------------

def run_pipeline(case, evidence_id: str, *, steps=DEFAULT_STEPS,
                 carve: bool = False, domex_categories=domex.DEFAULT_CATEGORIES,
                 domex_path: str = "", domex_limit: int = 0,
                 max_file_mb: int = 512, force: bool = False,
                 progress=None, should_cancel=None) -> PipelineSummary:
    """Run every deterministic step on a registered disk image, in order, on
    each NTFS volume. Files one run-summary proposal into the review queue."""
    item = case.evidence_item(evidence_id)
    if item.kind != "raw-image":
        raise EvidenceError(
            f"{evidence_id} is a {item.kind}, not a disk image. The pipeline "
            "runs on an image registered with add-image (an E01 included).")
    steps = tuple(steps)
    run_id = uuid.uuid4().hex[:12]
    summary = PipelineSummary(evidence_id, run_id, "running",
                              steps_requested=list(steps), carve=carve,
                              started_at=utc_now())
    case.custody.record("pipeline.started", actor=case.actor(),
                        target=evidence_id,
                        detail={"run_id": run_id, "steps": list(steps),
                                "carve": carve, "force": force})
    r = summary.results
    try:
        _cancel_check(should_cancel)
        if "image" in steps:
            r.append(_do(summary, "image", None,
                         force or not _image_done(case, evidence_id),
                         lambda: _disk.ingest_image(
                             case, evidence_id, progress=progress,
                             should_cancel=should_cancel)))

        try:
            volumes = _disk.list_volumes(case, evidence_id)
        except EvidenceError:
            volumes = []
        ntfs = [v for v in volumes if v.get("fs_type") == "ntfs"]
        summary.ntfs_volumes = [v["volume"] for v in ntfs]

        for v in ntfs:
            vol = v["volume"]
            _cancel_check(should_cancel)
            if progress is not None:
                progress(f"volume {vol} "
                         f"({v.get('fs_volume_label') or v.get('fs_type')})")
            if "ntfs" in steps:
                r.append(_do(summary, "ntfs", vol,
                             force or not _ntfs_done(case, evidence_id, vol),
                             lambda vol=vol: _disk.parse_ntfs(
                                 case, evidence_id, vol, progress=progress,
                                 should_cancel=should_cancel)))
            if "domex" in steps:
                r.append(_do(summary, "domex", vol,
                             force or not _domex_done(case, evidence_id, vol),
                             lambda vol=vol: domex.analyse_volume(
                                 case, evidence_id, vol,
                                 categories=domex_categories,
                                 path_prefix=domex_path, limit=domex_limit,
                                 max_file_mb=max_file_mb, progress=progress,
                                 should_cancel=should_cancel)))
            if "slack" in steps:
                r.append(_do(summary, "slack", vol,
                             force or not _slack_done(case, evidence_id, vol),
                             lambda vol=vol: _disk.scrape_slack(
                                 case, evidence_id, vol, progress=progress,
                                 should_cancel=should_cancel)))
            if carve or "carve" in steps:
                r.append(_do(summary, "carve", vol,
                             force or not _carve_done(case, evidence_id, vol),
                             lambda vol=vol: _disk.carve_evidence(
                                 case, evidence_id, volume=vol,
                                 unallocated=True, progress=progress)))
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    finally:
        summary.finished_at = utc_now()
        summary.tally = _tally(case, evidence_id)
        summary.finding_id = _file_summary_finding(case, evidence_id, run_id,
                                                    summary)
        case.custody.record(f"pipeline.{summary.state}", actor=case.actor(),
                            target=evidence_id, detail=summary.as_dict())
    return summary


def _tally(case, eid) -> dict:
    with _index.session(case.root) as conn:
        def c(sql, extra=()):
            try:
                return conn.execute(sql, (eid, *extra)).fetchone()[0]
            except Exception:
                return 0
        base = "SELECT COUNT(*) FROM artefacts WHERE evidence_id = ? AND parser = 'domex'"
        return {
            "volumes": c("SELECT COUNT(*) FROM volumes WHERE evidence_id = ?"),
            "ntfs_entries": c("SELECT COUNT(*) FROM ntfs_entries WHERE evidence_id = ?"),
            "domex_rows": c(base),
            "domex_documents": c(base + " AND artefact = 'document'"),
            "domex_images": c(base + " AND artefact = 'image'"),
            "domex_email": c(base + " AND artefact = 'email'"),
            "domex_geotagged": c(base + " AND detail_json LIKE '%\"geo\":%'"),
            "carve_candidates": c("SELECT COUNT(*) FROM carve_candidates WHERE evidence_id = ?"),
            "slack_regions": c("SELECT COUNT(*) FROM slack_regions WHERE evidence_id = ?"),
        }


def _file_summary_finding(case, eid, run_id, summary: PipelineSummary) -> str:
    t = summary.tally
    title = (f"Auto run: {t['domex_documents']} documents, {t['domex_images']} "
             f"images ({t['domex_geotagged']} geotagged), {t['domex_email']} "
             f"email, {t['carve_candidates']} carve candidates")
    failed = [f"{r.step}{f' v{r.volume}' if r.volume is not None else ''}"
              for r in summary.results if r.state == "failed"]
    return review.propose(
        case, source="engine", kind="pipeline-run", evidence_id=eid,
        title=title,
        detail={"run_id": run_id, "state": summary.state, "tally": t,
                "steps": [r.as_dict() for r in summary.results],
                "failed_steps": failed, "problems": summary.problems})
