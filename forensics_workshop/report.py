# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The case report and the IOC export (FORENSICS_PLAN §14 item 4, Bill,
2026-10-29: "build 1-5").

**ONLY CONFIRMED FINDINGS REACH THE REPORT.** A proposal — the engine's or a
model's — is a candidate until an examiner confirms it on the Findings page
(`review.py`); the report reads `review.confirmed()` and nothing else. The
number of proposals still awaiting review and of rejected ones is stated,
so the report never reads as more complete than it is.

**EVERY SENTENCE SAYS WHO WROTE IT.** A finding proposed by a local model is
marked as such beside its title — "proposed by a model (<file>), confirmed
by <examiner> on <date>" — and the model's own words are quoted, never
blended into the report's prose. The report's own prose is fixed text and
measurements read from the case (hashes, times, counts).

What it holds: the case (id, description, created, examiner), every evidence
item with the hashes custody recorded for it (ingest, image hashing,
acquisition), the acquisitions (source drive, write blocker as the examiner
stated it, verified or not), the confirmed findings grouped by kind with
their detail, the custody chain's verification at the moment of writing and
its head hash, and the limits every examiner should state.

**THE IOC EXPORT** (CSV and JSON) lists what confirmed findings name as
indicators: e-mail and IP addresses, phone numbers, cryptocurrency addresses,
known-bad SHA-256s, card numbers MASKED to their last four (a report is
shared; a full card number in it is a second disclosure). STIX is not
written: §5 says only if a consumer for it exists.

Everything is written inside the case (`reports/`), each file exclusive-
created, hashed, and recorded in custody (`report.generated`). The HTML is
one self-contained file — no script, no fetched fonts — so it opens on an
air-gapped machine and prints.
"""

from __future__ import annotations

import csv
import html
import io
import json
import os
from pathlib import Path

from . import __version__
from . import blocker, hashing, review
from .timeutil import utc_now

REPORTS_DIR = "reports"
IOC_KINDS = {"selector:email": "email", "selector:ipv4": "ipv4",
             "selector:phone": "phone", "selector:btc": "bitcoin",
             "selector:eth": "ethereum", "selector:card": "card",
             "hashset": "sha256"}
#: Evidence-level custody actions whose hashes describe the evidence itself.
HASH_ACTIONS = ("ingest.completed", "image.completed", "acquisition.completed")

LIMITS = (
    "Software read-only protection is not a hardware write blocker; where "
    "an acquisition names one, that is the examiner's statement.",
    "A finding is reported only once an examiner confirmed it. Proposals "
    "awaiting review and rejected proposals are counted, not reported.",
    "A finding proposed by a model is marked as such; the model's words are "
    "quoted as it wrote them and were checked by the examiner who confirmed "
    "them. A model's translation is not a certified translation.",
    "Times are stated as recorded, with their epoch; a time recorded without "
    "a zone (FAT, some registry values) is labelled local and is not UTC.",
    "Carved files are candidates; deleted entries are a state of a record, "
    "not a verdict about the data.",
)


def _write_case_file(case, target, data: bytes) -> dict:
    """THE ONE WRITE: a new file inside the case, never an existing one."""
    path = blocker.assert_case_path(case.root, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "xb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    return hashing.hash_bytes(data).as_dict()


def _e(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def mask_card(value: str) -> str:
    digits = [c for c in str(value) if c.isdigit()]
    return ("•" * max(0, len(digits) - 4)) + "".join(digits[-4:])


def _model_name(source: str) -> str:
    return source.split(":", 1)[1] if source.startswith("model:") else ""


def iocs(findings) -> list[dict]:
    """Indicators named by CONFIRMED findings, one row per value."""
    out, seen = [], set()
    for f in findings:
        kind = IOC_KINDS.get(f.kind)
        if kind is None:
            continue
        d = f.detail or {}
        value = d.get("sha256") if kind == "sha256" else d.get("value")
        if not value:
            continue
        shown = mask_card(value) if kind == "card" else str(value)
        key = (kind, shown.lower())
        if key in seen:
            continue
        seen.add(key)
        out.append({"type": kind, "value": shown,
                    "first_seen": d.get("first_at") or "",
                    "last_seen": d.get("last_at") or "",
                    "context": d.get("relpath") or "",
                    "finding_id": f.id, "evidence_id": f.evidence_id,
                    "confirmed_by": f.decided_by,
                    "confirmed_at": f.decided_at})
    return out


def _detail_html(f) -> str:
    d = f.detail or {}
    parts = []
    if f.kind == "ai-translation":
        parts.append(f"<p class=meta>{_e(d.get('source_language'))} → "
                     f"{_e(d.get('target_language'))} · the model's confidence: "
                     f"{_e(d.get('confidence'))}</p>")
        parts.append("<h4>Original (verbatim)</h4><pre>"
                     f"{_e(d.get('original'))}</pre>")
        parts.append("<h4>Translation (by the model)</h4><pre>"
                     f"{_e(d.get('translation'))}</pre>")
        reasons = d.get("reasoning") or []
        if reasons:
            parts.append("<h4>The model's stated reasoning</h4><ul>" + "".join(
                f"<li>“{_e(r.get('original'))}” → “{_e(r.get('rendered_as'))}”: "
                f"{_e(r.get('why'))}</li>" for r in reasons) + "</ul>")
        for u in d.get("uncertain") or []:
            parts.append(f"<p class=warn>Uncertain: {_e(u)}</p>")
    elif f.kind == "ai-text":
        parts.append(f"<blockquote>{_e(d.get('quote'))}</blockquote>"
                     f"<p class=meta>Quote check: {_e(d.get('quote_check'))}. "
                     f"The model's words: {_e(d.get('why'))}</p>")
    elif f.kind in ("ai-image", "ai-video"):
        if d.get("why"):
            parts.append(f"<p>The model's words: {_e(d.get('why'))}</p>")
        for fr in (d.get("frames") or [])[:30]:
            parts.append(f"<p class=meta>{float(fr.get('at_s', 0)):.2f} s — "
                         f"{_e(fr.get('severity'))}: {_e(fr.get('why'))}</p>")
    else:
        keep = {k: v for k, v in d.items() if k not in ("key", "artefact_ids",
                                                        "row_refs")}
        if keep:
            parts.append("<pre>" + _e(json.dumps(keep, indent=2,
                                                  ensure_ascii=False,
                                                  default=str)) + "</pre>")
    item = d.get("item") or {}
    if item:
        parts.append(f"<p class=meta>Item: {_e(item.get('path'))} "
                     f"({_e(item.get('ref'))})</p>")
    return "".join(parts)


CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1b1f24;
max-width:1100px}h1{margin-bottom:4px}h2{border-bottom:2px solid #2a6;
padding-bottom:4px;margin-top:32px}h3{margin:18px 0 4px}table{border-collapse:
collapse;width:100%;font-size:13px}td,th{border:1px solid #ccd;padding:4px 6px;
text-align:left;vertical-align:top}th{background:#eef2f6}pre{background:#f6f8fa;
padding:8px;white-space:pre-wrap;word-break:break-word;font-size:12px}
blockquote{border-left:4px solid #2a6;margin:6px 0;padding:4px 10px;
background:#f2fbf5}.meta{color:#566;font-size:12px}.model{background:#f3ecfd;
border:1px solid #b98cf0;border-radius:3px;padding:1px 6px;font-size:12px}
.engine{background:#e6f7fb;border:1px solid #39b;border-radius:3px;
padding:1px 6px;font-size:12px}.ok{color:#1a7f37;font-weight:600}.bad{color:#c62
;font-weight:600}.warn{color:#9a6700}.finding{border:1px solid #dde;
border-radius:4px;padding:8px 12px;margin:10px 0}@media print{.finding{
break-inside:avoid}}
"""


def build_html(case, *, title: str = "", generated_by: str = "") -> tuple[str, dict]:
    """(html, facts) — read-only: nothing is written here."""
    findings = review.confirmed(case)
    counts = review.counts(case)
    chain = case.custody.verify()
    head_n, head_hash = case.custody.head()
    rows = case.custody.rows()
    info = case.info
    out = ["<!doctype html><html><head><meta charset=utf-8>",
           f"<title>{_e(title or info.case_id)} — case report</title>",
           f"<style>{CSS}</style></head><body>",
           f"<h1>{_e(title or 'Case report')} — {_e(info.case_id)}</h1>",
           f"<p class=meta>Generated {_e(utc_now())} by "
           f"{_e(generated_by or case.examiner)} with ATK Digital Forensics "
           f"Workshop {_e(__version__)}.</p>"]
    out.append("<h2>Case</h2><table>")
    for label, value in (("Case ID", info.case_id),
                         ("Description", info.description),
                         ("Created", f"{info.created_at} by {info.created_by}"),
                         ("Examiner (this report)", case.examiner),
                         ("Case folder", os.fspath(case.root))):
        out.append(f"<tr><th>{_e(label)}</th><td>{_e(value)}</td></tr>")
    out.append("</table>")

    out.append("<h2>Evidence</h2><table><tr><th>ID</th><th>Kind</th>"
               "<th>Source</th><th>Label</th><th>Registered</th>"
               "<th>Hashes recorded in custody</th></tr>")
    for item in case.evidence():
        hashes = ""
        for row in reversed(rows):
            if row.get("action") in HASH_ACTIONS and (
                    row.get("target") == item.id or
                    os.path.normcase(str(row.get("target", ""))).startswith(
                        os.path.normcase(os.path.dirname(item.source)))):
                h = row.get("hashes") or {}
                if h.get("sha256"):
                    hashes = (f"MD5 {h.get('md5', '')}<br>SHA-1 {h.get('sha1', '')}"
                              f"<br>SHA-256 {h.get('sha256', '')}<br>"
                              f"<span class=meta>{_e(row.get('action'))} "
                              f"{_e(row.get('at'))}</span>")
                    break
        out.append(f"<tr><td>{_e(item.id)}</td><td>{_e(item.kind)}</td>"
                   f"<td>{_e(item.source)}</td><td>{_e(item.label)}</td>"
                   f"<td>{_e(item.added_at)}</td><td>{hashes or '—'}</td></tr>")
    out.append("</table>")

    acq = [r for r in rows if r.get("action") == "acquisition.completed"]
    if acq:
        out.append("<h2>Acquisitions</h2><table><tr><th>When</th><th>Source "
                   "drive</th><th>Write blocker (examiner's words)</th>"
                   "<th>Verified</th><th>Unreadable sector runs</th></tr>")
        for r in acq:
            d = r.get("detail") or {}
            src = d.get("source") or {}
            drive = " ".join(x for x in (src.get("vendor"), src.get("model"),
                                         src.get("serial")) if x)
            v = d.get("verified")
            out.append(f"<tr><td>{_e(r.get('at'))}</td><td>{_e(src.get('path'))}"
                       f" {_e(drive)}</td><td>{_e(d.get('write_blocker') or 'none stated')}"
                       f"</td><td class={'ok' if v else 'bad'}>"
                       f"{'yes' if v else 'NO' if v is False else 'not checked'}"
                       f"</td><td>{_e(d.get('bad_sector_runs', 0))}</td></tr>")
        out.append("</table>")

    out.append("<h2>Confirmed findings</h2>")
    out.append(f"<p class=meta>{len(findings)} confirmed · "
               f"{counts.get('proposed', 0)} still awaiting review and "
               f"{counts.get('rejected', 0)} rejected — neither is reported.</p>")
    by_kind: dict = {}
    for f in findings:
        by_kind.setdefault(f.kind, []).append(f)
    for kind in sorted(by_kind):
        out.append(f"<h3>{_e(kind)}</h3>")
        for f in by_kind[kind]:
            model = _model_name(f.source)
            badge = (f"<span class=model>proposed by a model ({_e(model)})</span>"
                     if model else "<span class=engine>found by the engine "
                                   "(deterministic)</span>")
            out.append(
                f"<div class=finding><b>{_e(f.title)}</b> {badge}"
                f"<p class=meta>Confirmed by {_e(f.decided_by)} on "
                f"{_e(f.decided_at)}" + (f" — note: {_e(f.decision_note)}"
                                         if f.decision_note else "")
                + f" · evidence {_e(f.evidence_id)} · finding {_e(f.id)}</p>"
                + _detail_html(f) + "</div>")
    if not findings:
        out.append("<p>No finding has been confirmed in this case yet.</p>")

    out.append("<h2>Chain of custody</h2>")
    if chain.ok:
        out.append(f"<p class=ok>Custody chain intact — {chain.records} records "
                   "at the time of writing.</p>")
    else:
        out.append("<p class=bad>CUSTODY CHAIN BROKEN at the time of writing: "
                   + _e("; ".join(chain.problems)) + "</p>")
    out.append(f"<p class=meta>Head: record {head_n}, SHA-256 {_e(head_hash)}. "
               "The report's own hash is recorded in the custody log as the "
               "next record.</p>")
    out.append("<h2>Limits</h2><ul>" + "".join(f"<li>{_e(x)}</li>" for x in LIMITS)
               + "</ul></body></html>")
    facts = {"confirmed": len(findings), "awaiting": counts.get("proposed", 0),
             "rejected": counts.get("rejected", 0), "chain_ok": chain.ok,
             "custody_head": head_hash, "custody_records": head_n,
             "model_findings": sum(1 for f in findings if _model_name(f.source))}
    return "\n".join(out), facts


def generate(case, *, title: str = "", iocs_too: bool = True) -> dict:
    """Write the report (and the IOC export) into `<case>/reports/`, hashed
    and recorded in custody. Returns the paths, hashes and facts."""
    stamp = utc_now()[:19].replace("-", "").replace(":", "")
    base = case.root / REPORTS_DIR / f"{case.info.case_id}-report-{stamp}Z"
    text, facts = build_html(case, title=title)
    written = {"html": {"path": os.fspath(base) + ".html",
                        **_write_case_file(case, Path(os.fspath(base) + ".html"),
                                           text.encode("utf-8"))}}
    if iocs_too:
        rows = iocs(review.confirmed(case))
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["type", "value", "first_seen",
                                                 "last_seen", "context",
                                                 "finding_id", "evidence_id",
                                                 "confirmed_by", "confirmed_at"],
                                lineterminator="\r\n")
        writer.writeheader()
        writer.writerows(rows)
        written["iocs_csv"] = {"path": os.fspath(base) + "-iocs.csv",
                               **_write_case_file(case, Path(os.fspath(base) + "-iocs.csv"),
                                                  buf.getvalue().encode("utf-8-sig"))}
        payload = json.dumps({"case_id": case.info.case_id,
                              "generated_at": utc_now(), "iocs": rows},
                             indent=2, ensure_ascii=False).encode("utf-8")
        written["iocs_json"] = {"path": os.fspath(base) + "-iocs.json",
                                **_write_case_file(case, Path(os.fspath(base) + "-iocs.json"),
                                                   payload)}
        facts["iocs"] = len(rows)
    case.custody.record(
        "report.generated", actor=case.actor(), target=written["html"]["path"],
        hashes={"sha256": written["html"]["sha256"]},
        detail={"files": {k: {"path": os.path.relpath(v["path"], case.root),
                              "sha256": v["sha256"]} for k, v in written.items()},
                **facts})
    return {"files": written, **facts}
