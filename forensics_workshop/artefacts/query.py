# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Read-only queries over the artefacts index, across every parser
(FORENSICS_PLAN §14 item 1, 2026-10-29: the pages for what is already
built).

Every parser — DOMEX, the phone backup, the browsers, and the Windows
artefacts and mailboxes — writes one row shape into `artefacts`. These
queries let one page show all of them, filtered by parser, kind, time and
text, and pick out the rows that state a position.

**A POSITION IS WHAT A FILE STATES.** A row is placeable when its detail
carries `geo: {lat, lon}` — today a photo's EXIF GPS. Whoever puts it on a
map labels it as reported by the file, never as where a person was.

Nothing here writes; nothing here opens evidence.
"""

from __future__ import annotations

import json

from .. import index as _index

#: A name for each parser an examiner will recognise. A parser not listed
#: here is still shown, under its own name.
PARSER_LABELS = {
    "domex": "Documents, pictures and mail files (DOMEX)",
    "browser": "Web browsers",
    "mobile": "Phone backups (iOS)",
    "registry": "Windows registry",
    "lnk": "Shortcuts (LNK)",
    "jumplist": "Jump Lists",
    "prefetch": "Prefetch",
    "evtx": "Windows event logs",
    "pst": "Outlook mailboxes (PST/OST)",
}


def _where(evidence_id, parser, artefact, geo_only, search, time_from,
           time_to):
    where, params = [], []
    if evidence_id:
        where.append("evidence_id = ?")
        params.append(evidence_id)
    if parser:
        where.append("parser = ?")
        params.append(parser)
    if artefact:
        where.append("artefact = ?")
        params.append(artefact)
    if geo_only:
        where.append("detail_json LIKE ?")
        params.append('%"geo":%')
    if search:
        where.append("(value LIKE ? OR title LIKE ? OR url LIKE ? OR "
                     "source_relpath LIKE ? OR detail_json LIKE ?)")
        params.extend([f"%{search}%"] * 5)
    if time_from:
        where.append("at_utc >= ?")
        params.append(time_from)
    if time_to:
        where.append("at_utc <= ?")
        params.append(time_to)
    return (" AND ".join(where) or "1=1"), params


def parsers(case, evidence_id: str = "") -> list[tuple[str, int]]:
    """(parser, rows) for every parser that has written rows."""
    clause, params = _where(evidence_id, "", "", False, "", "", "")
    with _index.session(case.root) as conn:
        return [(r[0], r[1]) for r in conn.execute(
            f"SELECT parser, COUNT(*) FROM artefacts WHERE {clause} "
            "GROUP BY parser ORDER BY parser", params)]


def kinds(case, evidence_id: str = "", parser: str = "") -> list[tuple[str, int]]:
    """(artefact kind, rows) under one parser (or all)."""
    clause, params = _where(evidence_id, parser, "", False, "", "", "")
    with _index.session(case.root) as conn:
        return [(r[0], r[1]) for r in conn.execute(
            f"SELECT artefact, COUNT(*) FROM artefacts WHERE {clause} "
            "GROUP BY artefact ORDER BY artefact", params)]


def list_rows(case, evidence_id: str = "", *, parser: str = "",
              artefact: str = "", geo_only: bool = False, search: str = "",
              time_from: str = "", time_to: str = "", limit: int = 5000,
              offset: int = 0) -> tuple[list[dict], int]:
    """Rows in time order (undated last), and the total that matched."""
    clause, params = _where(evidence_id, parser, artefact, geo_only, search,
                            time_from, time_to)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM artefacts WHERE {clause}",
                             params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM artefacts WHERE {clause} "
            "ORDER BY at_utc IS NULL, at_utc, id LIMIT ? OFFSET ?",
            [*params, int(limit), int(offset)])]
    return rows, total


def detail_of(row: dict) -> dict:
    try:
        d = json.loads(row.get("detail_json") or "{}")
    except (TypeError, ValueError):
        return {}
    return d if isinstance(d, dict) else {}


def geo_of(row: dict) -> dict | None:
    """The position a row states, or None. Out-of-range values are refused
    rather than drawn somewhere wrong."""
    g = detail_of(row).get("geo")
    if not isinstance(g, dict):
        return None
    try:
        lat, lon = float(g["lat"]), float(g["lon"])
    except (KeyError, TypeError, ValueError):
        return None
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None
    if lat == 0.0 and lon == 0.0:
        return None          # "null island": an unset fix, not a place
    return dict(g, lat=lat, lon=lon)
