# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The review queue — where a proposal waits for an examiner, stdlib only.

The whole tool draws one line: a MEASUREMENT (a hash, a timestamp, an offset,
a parsed row) is a fact; a JUDGEMENT (this file matters, this thread is a
threat, these two numbers are one person) is a *proposal* until a human admits
it. This module is where the second kind lives. It is the man-in-the-middle the
plan's §6 and §10 describe: the engine's hunts and, later, a local model
PROPOSE findings here; only a finding an examiner has CONFIRMED reaches a report
or the contact graph.

**Two append-only logs, never mixed** (FORENSICS_PLAN.md §10.1):

    findings/findings.jsonl    proposals — who proposed, when, what they claim,
                               and the exact rows they cite. A proposal is NOT a
                               custodial act, so it is not written to
                               `custody.jsonl`; it is a candidate, not a fact.
    findings/decisions.jsonl   an examiner's confirm or reject of a finding —
                               which IS a custodial act, so each decision is
                               ALSO recorded in the custody log. Append-only and
                               re-decidable: the latest decision for a finding
                               wins, and the trail of how it got there stays.

`confirmed()` is the join the rest of the engine reads: a finding whose most
recent decision is `confirmed`. Nothing else may present a proposal as a
conclusion. Every write is flushed and fsynced, so an overnight run that files
ten thousand proposals loses none of them if the power goes.

A proposal's `source` is always kept and, for a model, names the model that
produced it (§6: model output is attributed and dated). The engine's own
deterministic proposals carry `source="engine"`.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import asdict, dataclass, field

from . import blocker
from .errors import EvidenceError
from .timeutil import utc_now

FINDINGS = "findings.jsonl"
DECISIONS = "decisions.jsonl"
DECISIONS_ALLOWED = ("confirmed", "rejected")


@dataclass
class Finding:
    id: str
    at: str
    source: str                 # "engine" | "model:<name>"
    kind: str                   # hunt-hit | triage | summary | pipeline-run | …
    evidence_id: str
    title: str
    detail: dict = field(default_factory=dict)
    refs: list = field(default_factory=list)
    status: str = "proposed"    # effective: proposed | confirmed | rejected
    decided_at: str = ""
    decided_by: str = ""
    decision_note: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _dir(case):
    return case.path("findings")


def _append(case, filename: str, obj: dict) -> None:
    """THE ONE WRITE this module makes: append one JSON line, flush, fsync."""
    path = blocker.assert_case_path(case.root, _dir(case) / filename)
    path.parent.mkdir(parents=True, exist_ok=True)
    existed = path.exists()
    line = json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8")
    with open(path, "ab") as fh:
        fh.write(line + b"\n")
        fh.flush()
        os.fsync(fh.fileno())
    if not existed and os.name != "nt":
        dfd = os.open(os.fspath(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


def _read(case, filename: str) -> list[dict]:
    path = _dir(case) / filename
    if not path.is_file():
        return []
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            out.append(json.loads(raw))
        except ValueError:
            continue                          # a torn line is skipped, not fatal
    return out


# -- proposing ---------------------------------------------------------------

def propose(case, *, source: str, kind: str, evidence_id: str, title: str,
            detail: dict | None = None, refs=()) -> str:
    """File a proposal. Returns its id. Not a custodial act — a proposal is a
    candidate for review, and the model that made one never writes custody."""
    if not source or not kind:
        raise EvidenceError("a finding needs a source and a kind.")
    fid = uuid.uuid4().hex[:12]
    _append(case, FINDINGS, {
        "id": fid, "at": utc_now(), "source": source, "kind": kind,
        "evidence_id": evidence_id, "title": title,
        "detail": detail or {}, "refs": list(refs)})
    return fid


# -- deciding (an examiner acts — custodial) ---------------------------------

def decide(case, finding_id: str, decision: str, *, note: str = "") -> dict:
    """Confirm or reject a finding. Append-only and re-decidable; the latest
    decision wins. Recorded in decisions.jsonl AND in the custody log, because
    an examiner admitting or rejecting a finding is a custodial act."""
    if decision not in DECISIONS_ALLOWED:
        raise EvidenceError(
            f"decision must be one of {DECISIONS_ALLOWED}, not {decision!r}.")
    known = {f["id"] for f in _read(case, FINDINGS)}
    if finding_id not in known:
        raise EvidenceError(f"no finding {finding_id!r} to decide on.")
    row = {"at": utc_now(), "finding_id": finding_id, "decision": decision,
           "actor": case.actor().as_dict(), "note": note}
    _append(case, DECISIONS, row)
    case.custody.record(f"review.{decision}", actor=case.actor(),
                        target=f"finding:{finding_id}",
                        detail={"finding_id": finding_id, "note": note})
    return row


# -- reading -----------------------------------------------------------------

def _latest_decisions(case) -> dict:
    latest: dict = {}
    for d in _read(case, DECISIONS):        # file order is chronological
        latest[d["finding_id"]] = d
    return latest


def _hydrate(raw: dict, decisions: dict) -> Finding:
    f = Finding(id=raw.get("id", ""), at=raw.get("at", ""),
                source=raw.get("source", ""), kind=raw.get("kind", ""),
                evidence_id=raw.get("evidence_id", ""),
                title=raw.get("title", ""), detail=raw.get("detail", {}) or {},
                refs=raw.get("refs", []) or [])
    d = decisions.get(f.id)
    if d:
        f.status = d.get("decision", "proposed")
        f.decided_at = d.get("at", "")
        f.decided_by = (d.get("actor") or {}).get("name", "")
        f.decision_note = d.get("note", "")
    return f


def list_findings(case, *, status: str = "", kind: str = "",
                  evidence_id: str = "", source: str = "") -> list[Finding]:
    """Every proposal with its effective status. Newest first."""
    decisions = _latest_decisions(case)
    out = []
    for raw in _read(case, FINDINGS):
        f = _hydrate(raw, decisions)
        if status and f.status != status:
            continue
        if kind and f.kind != kind:
            continue
        if evidence_id and f.evidence_id != evidence_id:
            continue
        if source and not f.source.startswith(source):
            continue
        out.append(f)
    out.reverse()
    return out


def finding(case, finding_id: str) -> Finding | None:
    decisions = _latest_decisions(case)
    for raw in _read(case, FINDINGS):
        if raw.get("id") == finding_id:
            return _hydrate(raw, decisions)
    return None


def confirmed(case, *, evidence_id: str = "", kind: str = "") -> list[Finding]:
    """The only findings the rest of the engine may treat as admitted: those
    whose most recent decision is `confirmed`. Report and graph read this."""
    return list_findings(case, status="confirmed", evidence_id=evidence_id,
                         kind=kind)


def counts(case) -> dict:
    """proposed / confirmed / rejected totals, for a queue badge."""
    tally = {"proposed": 0, "confirmed": 0, "rejected": 0}
    for f in list_findings(case):
        tally[f.status] = tally.get(f.status, 0) + 1
    return tally
