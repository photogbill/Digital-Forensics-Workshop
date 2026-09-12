# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Hunts — the deterministic backbone that turns parsed rows into leads.

The parsers fill the `artefacts` index with rows; this module reads those rows
and the file manifest and asks the reproducible questions an investigation
starts with: *does this text mention a term, does this corpus contain a phone
number or an email or a crypto address, does any file match a known-bad hash.*
Every hit is filed into the review queue as a PROPOSAL that cites the exact
rows it came from — a lead for an examiner to confirm, never a conclusion
(FORENSICS_PLAN.md §10.2). There is **no model here**: this is the deterministic
layer the local-LLM layer (topic classification, triage ranking) builds on, and
it is reproducible byte-for-byte.

Four hunts, plus a triage bundle:

* **selectors** — email, IPv4, Bitcoin and Ethereum addresses, credit-card
  numbers (validated by the Luhn checksum, not just their shape), and phone
  numbers (heuristic, and said to be). One finding per distinct value, with
  every row it appeared in — the same values that later seed the contact graph.
* **keywords** — a term across the parsed text; one finding per term, citing the
  rows. `watchlist` is the same search, filed under its own name because a
  watchlist hit means something different from a free-text keyword.
* **hashset** — a set of known-bad SHA-256 digests against the file manifest;
  one finding per matching file.
* **high-value** — the triage a goal like a kidnapping starts with: the
  geotagged photos (each a place and a time), and a count of the documents and
  email waiting to be read. The seed of the goal-directed playbooks.

Re-running is idempotent: each finding carries a stable `key`, and a hunt does
not re-propose a lead that is already in the queue (unless it was rejected and
the analyst runs the hunt again deliberately — a rejected lead stays rejected).
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field

from . import index as _index
from . import review
from .errors import EvidenceError
from .timeutil import utc_now

PARSER_VERSION = 1

#: Cap the rows cited on one finding — the true count is always kept.
MAX_REFS = 200
#: Cap findings per hunt, so a noisy corpus cannot flood the review queue.
MAX_FINDINGS = 500


# ===========================================================================
# selectors
# ===========================================================================

_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{11,71}"
                  r"|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_CARD = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_PHONE = re.compile(
    r"(?<![\w.])\+?\d[\d\s().\-]{8,17}\d(?![\w.])")

#: Which selectors run unless the caller narrows it. Phone is the noisy one; it
#: is included because a case usually turns on numbers, and its false positives
#: are a rejected proposal, not a wrong fact.
SELECTOR_KINDS = ("email", "ipv4", "btc", "eth", "card", "phone")


def _luhn_ok(digits: str) -> bool:
    """A credit-card number's shape is common in ordinary data; the Luhn
    checksum is what tells a real one from thirteen incidental digits."""
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _norm_phone(raw: str) -> str | None:
    digits = re.sub(r"\D", "", raw)
    if raw.strip().startswith("+"):
        digits = "+" + digits
    core = digits.lstrip("+")
    if not (10 <= len(core) <= 15):
        return None
    if len(set(core)) == 1:                   # 0000000000, 1111111111 …
        return None
    return digits


def find_selectors(text: str, kinds=SELECTOR_KINDS) -> dict:
    """{kind: set(values)} for the selector kinds present in `text`. Values are
    normalised so the same number written two ways collapses to one lead."""
    out: dict = {}
    if "email" in kinds:
        vals = {m.group(0).lower() for m in _EMAIL.finditer(text)}
        if vals:
            out["email"] = vals
    if "ipv4" in kinds:
        vals = {m.group(0) for m in _IPV4.finditer(text)}
        if vals:
            out["ipv4"] = vals
    if "btc" in kinds:
        vals = {m.group(0) for m in _BTC.finditer(text)}
        if vals:
            out["btc"] = vals
    if "eth" in kinds:
        vals = {m.group(0).lower() for m in _ETH.finditer(text)}
        if vals:
            out["eth"] = vals
    if "card" in kinds:
        vals = set()
        for m in _CARD.finditer(text):
            digits = re.sub(r"\D", "", m.group(0))
            if 13 <= len(digits) <= 19 and _luhn_ok(digits):
                vals.add(digits)
        if vals:
            out["card"] = vals
    if "phone" in kinds:
        vals = set()
        for m in _PHONE.finditer(text):
            norm = _norm_phone(m.group(0))
            if norm:
                vals.add(norm)
        if vals:
            out["phone"] = vals
    return out


# ===========================================================================
# the corpus
# ===========================================================================

def _artefact_text(row: dict) -> str:
    parts = [row.get("title") or "", row.get("value") or "", row.get("url") or ""]
    detail = row.get("detail_json") or ""
    if detail:
        parts.append(detail)
    return "\n".join(p for p in parts if p)


def _iter_artefacts(conn, evidence_id: str):
    for r in conn.execute(
            "SELECT id, evidence_id, parser, artefact, at_utc, url, title, "
            "value, detail_json, source_relpath, row_ref FROM artefacts "
            "WHERE evidence_id = ? ORDER BY id", (evidence_id,)):
        yield dict(r)


@dataclass
class _Lead:
    """A distinct value and the rows it was seen in, before it becomes a
    finding. Keeps counts true while capping what a finding carries."""
    value: str
    count: int = 0
    refs: list = field(default_factory=list)
    row_refs: list = field(default_factory=list)
    first_at: str = ""
    last_at: str = ""

    def add(self, row: dict) -> None:
        self.count += 1
        if len(self.refs) < MAX_REFS:
            self.refs.append(row["id"])
            if row.get("row_ref"):
                self.row_refs.append(row["row_ref"])
        at = row.get("at_utc") or ""
        if at:
            self.first_at = min(self.first_at, at) if self.first_at else at
            self.last_at = max(self.last_at, at)


# ===========================================================================
# hunts
# ===========================================================================

@dataclass
class HuntSummary:
    evidence_id: str
    state: str = "completed"
    by_hunt: dict = field(default_factory=dict)
    proposed: int = 0
    skipped_existing: int = 0
    capped: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _existing_keys(case, evidence_id: str) -> set:
    """Keys of findings already in the queue that were NOT rejected — so a
    re-run adds only what is new and never resurrects a rejected lead."""
    keys = set()
    for f in review.list_findings(case, evidence_id=evidence_id):
        key = (f.detail or {}).get("key")
        if key:
            keys.add(key)
    return keys


def _emit(case, evidence_id, kind, title, detail, refs, existing, summary):
    """File one finding unless its key is already in the queue."""
    key = detail.get("key")
    if key and key in existing:
        summary.skipped_existing += 1
        return
    review.propose(case, source="engine", kind=kind, evidence_id=evidence_id,
                   title=title, detail=detail, refs=refs)
    if key:
        existing.add(key)
    summary.proposed += 1
    summary.by_hunt[kind] = summary.by_hunt.get(kind, 0) + 1


def _leads_to_findings(case, evidence_id, kind, leads, label, existing,
                       summary) -> None:
    """Turn {value: _Lead} into findings, newest-effort-first, capped."""
    ordered = sorted(leads.values(), key=lambda l: (-l.count, l.value))
    if len(ordered) > MAX_FINDINGS:
        summary.capped.append(f"{kind}: {len(ordered)} values, kept {MAX_FINDINGS}")
        ordered = ordered[:MAX_FINDINGS]
    for lead in ordered:
        detail = {
            "hunt": kind, "key": f"{kind}:{lead.value.lower()}",
            "value": lead.value, "count": lead.count,
            "artefact_ids": lead.refs, "row_refs": lead.row_refs,
            "first_at": lead.first_at, "last_at": lead.last_at}
        title = f"{label}: {lead.value} — {lead.count} artefact(s)"
        _emit(case, evidence_id, kind, title, detail, lead.refs, existing,
              summary)


def hunt_selectors(case, evidence_id, *, kinds=SELECTOR_KINDS, existing=None,
                   summary=None) -> None:
    """Every selector value in the artefacts corpus, one finding each."""
    existing = _existing_keys(case, evidence_id) if existing is None else existing
    summary = summary or HuntSummary(evidence_id)
    buckets: dict = {k: {} for k in kinds}
    with _index.session(case.root) as conn:
        for row in _iter_artefacts(conn, evidence_id):
            found = find_selectors(_artefact_text(row), kinds)
            for kind, values in found.items():
                for value in values:
                    lead = buckets[kind].get(value)
                    if lead is None:
                        lead = buckets[kind][value] = _Lead(value)
                    lead.add(row)
    for kind in kinds:
        _leads_to_findings(case, evidence_id, "selector:" + kind,
                           buckets[kind], kind, existing, summary)


def hunt_terms(case, evidence_id, terms, *, kind="keyword", label="term",
               existing=None, summary=None) -> None:
    """Each term across the parsed text; one finding per term that matches."""
    terms = [t for t in (t.strip() for t in terms) if t]
    if not terms:
        return
    existing = _existing_keys(case, evidence_id) if existing is None else existing
    summary = summary or HuntSummary(evidence_id)
    leads = {t: _Lead(t) for t in terms}
    lowered = {t: t.lower() for t in terms}
    with _index.session(case.root) as conn:
        for row in _iter_artefacts(conn, evidence_id):
            text = _artefact_text(row).lower()
            for term in terms:
                if lowered[term] in text:
                    leads[term].add(row)
    for term in terms:
        lead = leads[term]
        if not lead.count:
            continue
        detail = {"hunt": kind, "key": f"{kind}:{term.lower()}", "term": term,
                  "count": lead.count, "artefact_ids": lead.refs,
                  "row_refs": lead.row_refs, "first_at": lead.first_at,
                  "last_at": lead.last_at}
        title = f"{label} '{term}': {lead.count} hit(s)"
        _emit(case, evidence_id, kind, title, detail, lead.refs, existing,
              summary)


def hunt_hashset(case, evidence_id, hashes, *, existing=None,
                 summary=None) -> None:
    """Files in the manifest whose SHA-256 is in a known-bad set."""
    wanted = {h.strip().lower() for h in hashes if h.strip()}
    if not wanted:
        return
    existing = _existing_keys(case, evidence_id) if existing is None else existing
    summary = summary or HuntSummary(evidence_id)
    with _index.session(case.root) as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT relpath, sha256, size FROM files WHERE evidence_id = ? AND "
            "sha256 IS NOT NULL", (evidence_id,))]
    n = 0
    for r in rows:
        if (r["sha256"] or "").lower() not in wanted:
            continue
        detail = {"hunt": "hashset", "key": f"hashset:{r['sha256'].lower()}",
                  "sha256": r["sha256"], "relpath": r["relpath"],
                  "size": r["size"]}
        _emit(case, evidence_id, "hashset",
              f"known-bad file: {r['relpath']}", detail, [], existing, summary)
        n += 1
        if n >= MAX_FINDINGS:
            summary.capped.append("hashset capped")
            break


def hunt_high_value(case, evidence_id, *, existing=None, summary=None) -> None:
    """The triage a goal-directed run starts with: geotagged photos as
    individual leads (each a place and a time), and the document/email counts."""
    existing = _existing_keys(case, evidence_id) if existing is None else existing
    summary = summary or HuntSummary(evidence_id)
    geo, docs, mail = [], 0, 0
    with _index.session(case.root) as conn:
        for row in _iter_artefacts(conn, evidence_id):
            if row["artefact"] == "document":
                docs += 1
            elif row["artefact"] == "email":
                mail += 1
            if row["artefact"] == "image" and '"geo"' in (row["detail_json"] or ""):
                try:
                    detail = json.loads(row["detail_json"])
                    g = detail.get("geo") or {}
                except ValueError:
                    g = {}
                if "lat" in g and "lon" in g:
                    geo.append((row, g))
    if len(geo) <= 25:
        for row, g in geo:
            key = f"high-value:geo:{row['id']}"
            detail = {"hunt": "high-value", "key": key, "lat": g["lat"],
                      "lon": g["lon"], "ts_utc": g.get("ts_utc"),
                      "path": (json.loads(row["detail_json"]).get("path")
                               if row["detail_json"] else None),
                      "artefact_ids": [row["id"]], "at_utc": row["at_utc"]}
            title = (f"geotagged photo at {g['lat']:.5f},{g['lon']:.5f}"
                     + (f" · {g['ts_utc']}" if g.get("ts_utc") else ""))
            _emit(case, evidence_id, "high-value", title, detail, [row["id"]],
                  existing, summary)
    elif geo:
        ids = [row["id"] for row, _g in geo[:MAX_REFS]]
        _emit(case, evidence_id, "high-value",
              f"{len(geo)} geotagged photos", {"hunt": "high-value",
              "key": "high-value:geo-summary", "count": len(geo),
              "artefact_ids": ids}, ids, existing, summary)
    for count, name, key in ((docs, "documents", "high-value:documents"),
                             (mail, "email messages", "high-value:email")):
        if count:
            _emit(case, evidence_id, "high-value", f"{count} {name} to review",
                  {"hunt": "high-value", "key": key, "count": count}, [],
                  existing, summary)


# ===========================================================================
# orchestrator
# ===========================================================================

def run_hunts(case, evidence_id: str, *, selectors=True,
              selector_kinds=SELECTOR_KINDS, terms=(), watchlist=(),
              hashset=(), high_value=True, progress=None) -> HuntSummary:
    """Run the requested hunts over one evidence item, filing every lead into
    the review queue. Reproducible; no model. Returns a summary."""
    case.evidence_item(evidence_id)                       # exists? else raises
    needs_artefacts = selectors or terms or watchlist or high_value
    if needs_artefacts and not _has_artefacts(case, evidence_id):
        raise EvidenceError(
            f"{evidence_id} has no parsed artefacts to hunt over yet. Run "
            "`auto` (or `domex`/`mobile`/`browser`) first — the text and "
            "selector hunts read the rows the parsers produced. (A hashset "
            "hunt over the file manifest does not need them.)")
    summary = HuntSummary(evidence_id, state="running", started_at=utc_now())
    existing = _existing_keys(case, evidence_id)
    case.custody.record("hunts.started", actor=case.actor(),
                        target=evidence_id,
                        detail={"selectors": bool(selectors), "terms": len(terms),
                                "watchlist": len(watchlist),
                                "hashset": len(hashset), "high_value": high_value,
                                "parser_version": PARSER_VERSION})
    try:
        if high_value:
            if progress:
                progress("high-value triage")
            hunt_high_value(case, evidence_id, existing=existing, summary=summary)
        if selectors:
            if progress:
                progress("selectors")
            hunt_selectors(case, evidence_id, kinds=selector_kinds,
                           existing=existing, summary=summary)
        if terms:
            if progress:
                progress("keywords")
            hunt_terms(case, evidence_id, terms, existing=existing,
                       summary=summary)
        if watchlist:
            if progress:
                progress("watchlist")
            hunt_terms(case, evidence_id, watchlist, kind="watchlist",
                       label="watchlist", existing=existing, summary=summary)
        if hashset:
            if progress:
                progress("known-bad hashset")
            hunt_hashset(case, evidence_id, hashset, existing=existing,
                         summary=summary)
        summary.state = "completed"
    finally:
        summary.finished_at = utc_now()
        case.custody.record("hunts.completed", actor=case.actor(),
                            target=evidence_id, detail=summary.as_dict())
    return summary


def _has_artefacts(case, evidence_id: str) -> bool:
    with _index.session(case.root) as conn:
        return conn.execute("SELECT COUNT(*) FROM artefacts WHERE "
                            "evidence_id = ?", (evidence_id,)).fetchone()[0] > 0
