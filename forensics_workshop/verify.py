# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Verify on demand: re-hash the evidence and say what still matches.

**Verification is an action, not a setting.** An examiner is asked WHEN a
hash was last confirmed, not whether hashing is enabled — so this is a
first-class operation with a custody record of its own, and
`last_verification` answers the question directly.

Two things are checked, and they catch different failures:

* **The evidence against the manifest** — every file re-read through the
  read-only door and compared on all three digests and its size. A
  mismatch means the evidence changed since it was ingested.
* **The manifest against the custody log** — the index's digest recomputed
  and compared with the one recorded when the ingest completed. A mismatch
  there means the INDEX was altered afterwards, which a re-hash of the
  evidence could never notice, because it would compare against the
  altered values and agree with them.
"""

from __future__ import annotations

import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import blocker, hashing
from . import index as _index
from .errors import Cancelled, EvidenceError
from .extract import safe_relpath
from .ingest import explain_oserror, manifest_digest
from .timeutil import utc_now

#: How many mismatched paths a custody record lists by name. The counts are
#: always complete; a record naming 40,000 paths is not one anyone reads.
LISTED = 200


@dataclass
class VerifySummary:
    evidence_id: str
    state: str
    checked: int = 0
    matched: int = 0
    mismatched: int = 0
    missing: int = 0
    unreadable: int = 0
    atime_changes: int = 0
    manifest_digest_matches: bool | None = None
    mismatches: list = field(default_factory=list)
    missing_paths: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    @property
    def all_matched(self) -> bool:
        return (self.state == "completed" and self.mismatched == 0
                and self.missing == 0 and self.unreadable == 0
                and self.manifest_digest_matches is not False)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["all_matched"] = self.all_matched
        return data


def verify_evidence(case, evidence_id: str, *, progress=None,
                    should_cancel=None) -> VerifySummary:
    item = case.evidence_item(evidence_id)
    if item.kind == "raw-image":
        return verify_image(case, evidence_id, progress=progress,
                            should_cancel=should_cancel)
    root = Path(item.source)
    summary = VerifySummary(evidence_id, "running", started_at=utc_now())

    completed = case.custody.last("ingest.completed", evidence_id)
    if completed is not None:
        summary.manifest_digest_matches = (
            (completed.get("hashes") or {}).get("manifest")
            == manifest_digest(case, evidence_id))

    with _index.session(case.root) as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT relpath, size, md5, sha1, sha256, atime_ns FROM files "
            "WHERE evidence_id = ? AND kind = 'file' AND sha256 IS NOT NULL "
            "ORDER BY relpath", (evidence_id,))]

    last_report = 0.0
    try:
        for row in rows:
            if should_cancel is not None and should_cancel():
                raise Cancelled("verification cancelled")
            summary.checked += 1
            path = root.joinpath(*safe_relpath(row["relpath"]).parts)
            try:
                before = os.stat(path, follow_symlinks=False)
                now = hashing.hash_evidence(path, should_cancel=should_cancel)
                after = os.stat(path, follow_symlinks=False)
            except Cancelled:
                raise
            except FileNotFoundError:
                summary.missing += 1
                if len(summary.missing_paths) < LISTED:
                    summary.missing_paths.append(row["relpath"])
                continue
            except OSError as exc:
                summary.unreadable += 1
                if len(summary.mismatches) < LISTED:
                    summary.mismatches.append(
                        {"relpath": row["relpath"],
                         "unreadable": explain_oserror(exc)})
                continue
            summary.atime_changes += int(after.st_atime_ns != before.st_atime_ns)
            recorded = hashing.Hashes(row["md5"], row["sha1"], row["sha256"],
                                      row["size"])
            if now.matches(recorded):
                summary.matched += 1
            else:
                summary.mismatched += 1
                if len(summary.mismatches) < LISTED:
                    summary.mismatches.append(
                        {"relpath": row["relpath"],
                         "recorded_sha256": recorded.sha256,
                         "now_sha256": now.sha256,
                         "recorded_size": recorded.size, "now_size": now.size})
            tick = time.monotonic()
            if progress is not None and tick - last_report > 0.5:
                last_report = tick
                progress(f"verified {summary.checked:,} of {len(rows):,} — "
                         f"{summary.mismatched:,} mismatched")
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    finally:
        summary.finished_at = utc_now()
        case.custody.record(
            f"verify.{summary.state}", actor=case.actor(), target=evidence_id,
            detail=summary.as_dict())
    return summary


def verify_image(case, evidence_id: str, *, progress=None,
                 should_cancel=None) -> VerifySummary:
    """Re-hash a disk image — the whole disk and each segment — against the
    hashes recorded when it was ingested; and the volume rows against the
    digest recorded beside them.

    `checked` counts segments. A disk-level mismatch is listed first in
    `mismatches`, under the relpath `(whole disk)`.
    """
    from . import diskimage, image

    summary = VerifySummary(evidence_id, "running", started_at=utc_now())
    ingested = case.custody.last("image.completed", evidence_id)
    if ingested is None:
        raise EvidenceError(f"{evidence_id} has never been hashed. Ingest the "
                            "image first; verification compares against what "
                            "the ingest recorded.")
    recorded = ingested.get("hashes") or {}
    by_path = {s["path"]: s for s in ingested["detail"].get("segments") or []}
    summary.manifest_digest_matches = (
        recorded.get("volumes") == diskimage.volumes_digest(case, evidence_id))
    try:
        missing = [p for p in by_path if not Path(p).is_file()]
        summary.missing = len(missing)
        summary.missing_paths = missing[:LISTED]
        if missing:
            summary.checked = len(by_path)
            summary.state = "completed"
            return summary
        source = diskimage.open_image(case, evidence_id)
        try:
            whole, per_segment = image.hash_image(
                source, should_cancel=should_cancel, progress=progress)
        finally:
            source.close()
        if not (whole.md5 == recorded.get("md5") and whole.sha1 == recorded.get("sha1")
                and whole.sha256 == recorded.get("sha256")
                and whole.size == ingested["detail"].get("disk_bytes")):
            summary.mismatches.append({"relpath": "(whole disk)",
                                       "recorded_sha256": recorded.get("sha256"),
                                       "now_sha256": whole.sha256,
                                       "recorded_size": ingested["detail"].get("disk_bytes"),
                                       "now_size": whole.size})
        for seg, now in zip(source.info.segments, per_segment):
            summary.checked += 1
            was = by_path.get(seg.path)
            if was and was.get("sha256") == now.sha256 and was.get("size") == now.size:
                summary.matched += 1
            else:
                summary.mismatched += 1
                summary.mismatches.append({
                    "relpath": Path(seg.path).name,
                    "recorded_sha256": was.get("sha256") if was else None,
                    "now_sha256": now.sha256,
                    "recorded_size": was.get("size") if was else None,
                    "now_size": now.size})
        if summary.mismatches and not summary.mismatched:
            summary.mismatched = 1
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    finally:
        summary.finished_at = utc_now()
        case.custody.record(
            f"verify.{summary.state}", actor=case.actor(), target=evidence_id,
            detail=dict(summary.as_dict(), kind="raw-image"))
    return summary


def last_verification(case, evidence_id: str) -> dict | None:
    """The most recent COMPLETED verification of one evidence item, or None.

    A cancelled verification is not an answer to "when was this last
    confirmed", so it is never returned here.
    """
    return case.custody.last("verify.completed", evidence_id)
