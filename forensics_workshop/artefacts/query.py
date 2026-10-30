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
        # % and _ in what the examiner typed are literal, not wildcards
        like = "%" + (search.replace("\\", "\\\\").replace("%", "\\%")
                      .replace("_", "\\_")) + "%"
        where.append("(value LIKE ? ESCAPE '\\' OR title LIKE ? ESCAPE '\\' "
                     "OR url LIKE ? ESCAPE '\\' OR source_relpath LIKE ? "
                     "ESCAPE '\\' OR detail_json LIKE ? ESCAPE '\\')")
        params.extend([like] * 5)
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


# -- e-mail by source (Bill, 2026-10-30: "separate the emails by source and
#    count, with a final count at the bottom") ---------------------------------

#: Outlook item classes that are not mail, and what to call them
OUTLOOK_ITEMS = (("IPM.CONTACT", "contacts"), ("IPM.DISTLIST", "distribution lists"),
                 ("IPM.APPOINTMENT", "calendar items"), ("IPM.TASK", "tasks"),
                 ("IPM.STICKYNOTE", "notes"), ("IPM.ACTIVITY", "journal entries"))


def _source_kind(path: str) -> str:
    low = (path or "").lower()
    if low.endswith(".pst"):
        return "Outlook mailbox (PST)"
    if low.endswith(".ost"):
        return "Outlook offline store (OST)"
    if low.endswith(".eml"):
        return "EML files"
    if low.endswith((".mbox", ".mbx")) or "mbox" in low.rsplit("/", 1)[-1]:
        return "mbox"
    return "mail file"


def mail_by_source(case, evidence_id: str = "") -> dict:
    """Every e-mail the parsers found, counted by where it came from.

    A source is one mailbox file (a PST, an OST, an mbox); single EML files
    are counted together by the folder that holds them. E-mails are rows
    whose kind is `email` — messages only. Contacts, calendar items, tasks
    and notes from an Outlook mailbox are counted beside it, separately,
    and are NOT in the e-mail total. Rows from a deleted mailbox file are
    counted and marked."""
    where, params = ["artefact IN ('email', 'pst-item')"], []
    if evidence_id:
        where.append("evidence_id = ?")
        params.append(evidence_id)
    groups: dict = {}
    with _index.session(case.root) as conn:
        for r in conn.execute(
                "SELECT evidence_id, parser, source_relpath, artefact, provenance, "
                "COUNT(*) AS n FROM artefacts WHERE " + " AND ".join(where)
                + " GROUP BY evidence_id, parser, source_relpath, artefact, "
                "provenance", params):
            path = r["source_relpath"] or ""
            kind = _source_kind(path)
            source = (path.rsplit("/", 1)[0] + "/" if "/" in path else "") \
                + "*.eml" if kind == "EML files" else path
            key = (r["evidence_id"], source)
            g = groups.setdefault(key, {
                "evidence_id": r["evidence_id"], "source": source, "kind": kind,
                "parser": r["parser"], "emails": 0, "other": {},
                "other_total": 0, "from_deleted_file": 0})
            if r["artefact"] == "email":
                g["emails"] += r["n"]
            if r["provenance"] == "deleted-file":
                g["from_deleted_file"] += r["n"]
        # what the non-mail Outlook items are
        for r in conn.execute(
                "SELECT evidence_id, source_relpath, detail_json FROM artefacts "
                "WHERE artefact = 'pst-item'"
                + (" AND evidence_id = ?" if evidence_id else ""), params):
            try:
                cls = str(json.loads(r["detail_json"] or "{}")
                          .get("message_class") or "").upper()
            except ValueError:
                cls = ""
            label = next((name for prefix, name in OUTLOOK_ITEMS
                          if cls.startswith(prefix)), "other items")
            g = groups.get((r["evidence_id"], r["source_relpath"] or ""))
            if g is not None:
                g["other"][label] = g["other"].get(label, 0) + 1
                g["other_total"] += 1
    sources = sorted(groups.values(),
                     key=lambda g: (-g["emails"], g["evidence_id"], g["source"]))
    return {"sources": sources,
            "total_emails": sum(g["emails"] for g in sources),
            "total_other": sum(g["other_total"] for g in sources),
            "total_sources": sum(1 for g in sources if g["emails"])}
