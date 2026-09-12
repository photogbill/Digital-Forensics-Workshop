# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Reading the manifest back: listings, filters, counts and duplicates.

Every function here reads the index and nothing else. The filters exist
because the view an examiner needs is rarely "all 400,000 files" — it is
"the files whose bytes disagree with their names", "the files that exist
more than once", "the files that could not be read". And every listing is
LIMITED, with the true total reported beside it: an unbounded result handed
to a table widget is how ATK's RF panel learned to slow down until it
stopped.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from . import index as _index

FILTERS = {
    "all": "1 = 1",
    "files": "kind = 'file'",
    "mismatch": "ext_mismatch = 1",
    "errors": "(error IS NOT NULL OR not_read_reason IS NOT NULL)",
    "hidden": "(hidden = 1 OR system = 1)",
    "links": "kind = 'link'",
    "changed": "(changed_during_read = 1 OR atime_change_observed = 1)",
    "unknown": "kind = 'file' AND type_id = 'unknown'",
    "high-entropy": "kind = 'file' AND type_id = 'unknown' AND head_entropy > 7.5",
    "duplicates": ("kind = 'file' AND size > 0 AND sha256 IN (SELECT sha256 "
                   "FROM files WHERE kind = 'file' AND size > 0 AND sha256 "
                   "IS NOT NULL GROUP BY sha256 HAVING COUNT(*) > 1)"),
}

FILTER_LABELS = {
    "all": "Everything",
    "files": "Files only",
    "mismatch": "Name disagrees with contents",
    "duplicates": "Duplicates",
    "errors": "Not read / errors",
    "hidden": "Hidden or system",
    "links": "Links (not followed)",
    "changed": "Changed while being read",
    "unknown": "Unidentified",
    "high-entropy": "Unidentified, high entropy",
}


def list_files(case, evidence_id: str, *, filter: str = "all",
               search: str = "", min_size: int = 0, limit: int = 5000,
               offset: int = 0) -> tuple[list[dict], int]:
    """(rows, total matching). `search` is a substring of the path; `min_size`
    keeps only files of at least that many bytes (0 = no size floor), which
    skips the icon-sized thumbnails that bury the files that matter."""
    if filter not in FILTERS:
        raise ValueError(f"unknown filter {filter!r}; one of {sorted(FILTERS)}")
    where = f"evidence_id = ? AND {FILTERS[filter]}"
    params: list = [evidence_id]
    if search:
        where += " AND relpath LIKE ? ESCAPE '\\'"
        escaped = (search.replace("\\", "\\\\").replace("%", "\\%")
                   .replace("_", "\\_"))
        params.append(f"%{escaped}%")
    if min_size > 0:
        where += " AND size >= ?"
        params.append(int(min_size))
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM files WHERE {where}",
                             params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM files WHERE {where} ORDER BY relpath "
            "LIMIT ? OFFSET ?", [*params, int(limit), int(offset)])]
    return rows, total


def counts(case, evidence_id: str) -> dict:
    """Every filter's count in one pass — what a summary line needs."""
    out = {}
    with _index.session(case.root) as conn:
        for name, clause in FILTERS.items():
            out[name] = conn.execute(
                f"SELECT COUNT(*) FROM files WHERE evidence_id = ? AND {clause}",
                (evidence_id,)).fetchone()[0]
        out["bytes"] = conn.execute(
            "SELECT COALESCE(SUM(size), 0) FROM files WHERE evidence_id = ? "
            "AND kind = 'file'", (evidence_id,)).fetchone()[0]
    return out


@dataclass(frozen=True)
class DuplicateSet:
    sha256: str
    size: int
    members: tuple          # ((evidence_id, relpath), ...)

    def as_dict(self) -> dict:
        return asdict(self)


def duplicates(case, *, evidence_id: str | None = None, min_size: int = 1,
               limit: int = 1000) -> list[DuplicateSet]:
    """Files whose SHA-256 appears more than once, largest first.

    `min_size` defaults to 1 because every empty file has the same hash, and
    a report that leads with four thousand empty files as "duplicates" has
    hidden everything under them. Across evidence items when
    `evidence_id` is None — the same file on two seized devices is often the
    point.
    """
    scope = "AND evidence_id = ?" if evidence_id else ""
    params: list = [int(min_size)]
    if evidence_id:
        params.append(evidence_id)
    sql = (f"SELECT sha256, MAX(size) AS size FROM files WHERE kind = 'file' "
           f"AND sha256 IS NOT NULL AND size >= ? {scope} GROUP BY sha256 "
           "HAVING COUNT(*) > 1 ORDER BY size DESC, sha256 LIMIT ?")
    params.append(int(limit))
    out = []
    with _index.session(case.root) as conn:
        for group in conn.execute(sql, params).fetchall():
            members = conn.execute(
                f"SELECT evidence_id, relpath FROM files WHERE sha256 = ? "
                f"AND kind = 'file' {scope} ORDER BY evidence_id, relpath",
                [group["sha256"], *([evidence_id] if evidence_id else [])])
            out.append(DuplicateSet(group["sha256"], group["size"],
                                    tuple((m["evidence_id"], m["relpath"])
                                          for m in members)))
    return out


def lookup(case, evidence_id: str, relpath: str) -> dict | None:
    with _index.session(case.root) as conn:
        row = conn.execute("SELECT * FROM files WHERE evidence_id = ? AND "
                           "relpath = ?", (evidence_id, relpath)).fetchone()
    return dict(row) if row else None
