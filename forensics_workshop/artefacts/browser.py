# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Browser history, downloads, searches and cookies — from SQLite, stdlib only.

Chromium-family browsers (Chrome, Edge, Brave, Opera, Vivaldi) and Firefox
keep their history in SQLite. That makes this the cheapest high-value
artefact in the whole plan: no third-party code, no licence question, and
real data on every machine an examiner will ever see.

**HOW A DATABASE IS FOUND — three layers, each named in the result.**
A candidate is a file the ingest identified BY SIGNATURE as SQLite, whose
name is one a browser uses (`History`, `places.sqlite` …). It is then
confirmed by its SCHEMA — the tables inside it — and only then parsed. The
browser's name comes from the folder path and says so (`browser_basis:
path`). A renamed database is not found by name; `all_sqlite=True` checks
the schema of every SQLite file instead.

**THE WAL IS WHERE THE RECENT HISTORY IS.** A browser that is running, or
that was not shut down cleanly, holds its latest writes in a `-wal` file
beside the database, not in the database itself. A parser that opens the
database alone silently loses exactly the most recent activity; one that
opens it in place replays the log INTO THE EVIDENCE. So both are copied
into the case, and the copy is read twice:

    merged/      database + -wal/-journal   what the browser would show
    main-only/   database alone             what had been committed

Every row is labelled by comparing the two:

    db           present in the committed database
    wal          present ONLY once the write-ahead log is applied
    wal-updated  present in both, but the log changes it
    rolled-back  present in the database but undone by a hot journal —
                 an interrupted transaction, kept and labelled, not dropped

**What this does NOT do.** It does not decrypt Chromium cookie values (they
are protected by DPAPI and, since Chrome 127, an app-bound key); the row
says the value is encrypted and how long it is. It does not recover deleted
rows from free pages — that is carving, and a later phase.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from .. import blocker
from .. import index as _index
from ..errors import Cancelled, EvidenceError
from ..extract import copy_evidence_to_case, copy_within_case, safe_relpath
from ..ingest import explain_oserror
from ..manifest import lookup
from ..timeutil import decode, infer_unix_unit, utc_now

PARSER_VERSION = 1

#: lower-cased file name -> the schema a browser puts in it
KNOWN_NAMES = {
    "history": "chromium-history",
    "places.sqlite": "firefox-places",
    "formhistory.sqlite": "firefox-formhistory",
    "cookies": "chromium-cookies",
    "cookies.sqlite": "firefox-cookies",
}

SIDECARS = ("-wal", "-journal", "-shm")

#: path fragment (lower case, forward slashes) -> browser. Checked in order.
BROWSER_PATHS = (
    ("google/chrome", "Google Chrome"),
    ("microsoft/edge", "Microsoft Edge"),
    ("bravesoftware/brave-browser", "Brave"),
    ("vivaldi", "Vivaldi"),
    ("opera software", "Opera"),
    ("chromium", "Chromium"),
    ("mozilla/firefox", "Mozilla Firefox"),
    ("librewolf", "LibreWolf"),
    ("waterfox", "Waterfox"),
    ("thunderbird", "Mozilla Thunderbird"),
)

CHROMIUM_TRANSITIONS = {
    0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe",
    4: "manual_subframe", 5: "generated", 6: "auto_toplevel",
    7: "form_submit", 8: "reload", 9: "keyword", 10: "keyword_generated"}
CHROMIUM_QUALIFIERS = {
    0x01000000: "forward_back", 0x02000000: "from_address_bar",
    0x04000000: "home_page", 0x08000000: "from_api",
    0x10000000: "chain_start", 0x20000000: "chain_end",
    0x40000000: "client_redirect", 0x80000000: "server_redirect"}
CHROMIUM_DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled",
                            3: "interrupted", 4: "interrupted"}
FIREFOX_VISIT_TYPES = {
    1: "link", 2: "typed", 3: "bookmark", 4: "embed",
    5: "redirect_permanent", 6: "redirect_temporary", 7: "download",
    8: "framed_link", 9: "reload"}


def decode_transition(raw) -> dict:
    try:
        value = int(raw) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return {"raw": raw}
    core = value & 0xFF
    return {"raw": raw,
            "core": CHROMIUM_TRANSITIONS.get(core, f"unknown({core})"),
            "qualifiers": [name for bit, name in CHROMIUM_QUALIFIERS.items()
                           if value & bit]}


def browser_from_path(relpath: str) -> tuple[str, str, str]:
    """(browser, basis, profile) from where the file sits."""
    lowered = relpath.replace("\\", "/").lower()
    parts = PurePosixPath(relpath.replace("\\", "/")).parts
    profile = parts[-2] if len(parts) >= 2 else ""
    if len(parts) >= 3 and parts[-2].lower() == "network":
        profile = parts[-3]              # Chromium moved Cookies into Network/
    for fragment, name in BROWSER_PATHS:
        if fragment in lowered:
            return name, "path", profile
    return "unidentified", "none", profile


def _cols(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info('{table}')")}


def _tables(conn) -> set:
    return {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'")}


def schema_kind(conn) -> str | None:
    tables = _tables(conn)
    if {"urls", "visits"} <= tables:
        return "chromium-history"
    if {"moz_places", "moz_historyvisits"} <= tables:
        return "firefox-places"
    if "moz_formhistory" in tables:
        return "firefox-formhistory"
    if "moz_cookies" in tables:
        return "firefox-cookies"
    if "cookies" in tables:
        return "chromium-cookies"
    return None


def _row(artefact, ref, *, at_raw=None, at_epoch="", url="", title="",
         value="", **detail) -> dict:
    return {"artefact": artefact, "row_ref": ref, "at_raw": at_raw,
            "at_epoch": at_epoch,
            "at_utc": decode(at_raw, at_epoch) if at_epoch else None,
            "url": url or "", "title": title or "", "value": value or "",
            "detail": detail}


def _pick(cols: set, *names) -> list[str]:
    return [n for n in names if n in cols]


# -- parsers ---------------------------------------------------------------

def parse_chromium_history(conn, problems: list) -> list[dict]:
    out: list[dict] = []
    vcols, ucols = _cols(conn, "visits"), _cols(conn, "urls")
    extra = ([f"v.{c} AS v_{c}" for c in _pick(vcols, "from_visit",
                                                "transition", "visit_duration")]
             + [f"u.{c} AS u_{c}" for c in _pick(ucols, "visit_count",
                                                  "typed_count")])
    sql = ("SELECT v.id AS visit_id, v.visit_time AS visit_time, "
           "u.url AS url, u.title AS title"
           + "".join(", " + e for e in extra)
           + " FROM visits v LEFT JOIN urls u ON u.id = v.url ORDER BY v.id")
    try:
        for r in conn.execute(sql):
            keys = r.keys()
            detail = {}
            if "v_transition" in keys:
                detail["transition"] = decode_transition(r["v_transition"])
            if "v_from_visit" in keys:
                detail["from_visit"] = r["v_from_visit"]
            if "v_visit_duration" in keys:
                detail["visit_duration_us"] = r["v_visit_duration"]
            for c in ("u_visit_count", "u_typed_count"):
                if c in keys:
                    detail[c[2:]] = r[c]
            out.append(_row("visit", f"visits:{r['visit_id']}",
                            at_raw=r["visit_time"], at_epoch="webkit_us",
                            url=r["url"], title=r["title"], **detail))
    except sqlite3.Error as exc:
        problems.append(f"visits: {exc}")

    tables = _tables(conn)
    if "downloads" in tables:
        dcols = _cols(conn, "downloads")
        fields = _pick(dcols, "id", "guid", "current_path", "target_path",
                       "start_time", "end_time", "received_bytes",
                       "total_bytes", "state", "danger_type",
                       "interrupt_reason", "opened", "last_access_time",
                       "referrer", "site_url", "tab_url", "tab_referrer_url",
                       "mime_type", "original_mime_type", "by_ext_name")
        chains: dict = {}
        if "downloads_url_chains" in tables:
            try:
                for c in conn.execute("SELECT id, chain_index, url FROM "
                                      "downloads_url_chains ORDER BY id, "
                                      "chain_index"):
                    chains.setdefault(c["id"], []).append(c["url"])
            except sqlite3.Error as exc:
                problems.append(f"downloads_url_chains: {exc}")
        try:
            for r in conn.execute(f"SELECT {', '.join(fields)} FROM downloads "
                                  "ORDER BY id"):
                d = {k: r[k] for k in r.keys()}
                chain = chains.get(d.get("id"), [])
                d["url_chain"] = chain
                d["state_label"] = CHROMIUM_DOWNLOAD_STATES.get(d.get("state"))
                for k in ("end_time", "last_access_time"):
                    if k in d:
                        d[f"{k}_utc"] = decode(d[k], "webkit_us")
                target = d.get("target_path") or d.get("current_path") or ""
                out.append(_row("download", f"downloads:{d.get('id')}",
                                at_raw=d.get("start_time"),
                                at_epoch="webkit_us",
                                url=(chain[-1] if chain else d.get("tab_url")),
                                title=os.path.basename(str(target)),
                                value=target, **d))
        except sqlite3.Error as exc:
            problems.append(f"downloads: {exc}")

    if "keyword_search_terms" in tables:
        try:
            for r in conn.execute(
                    "SELECT k.keyword_id AS keyword_id, k.url_id AS url_id, "
                    "k.term AS term, u.url AS url, u.last_visit_time AS t "
                    "FROM keyword_search_terms k LEFT JOIN urls u "
                    "ON u.id = k.url_id ORDER BY k.url_id"):
                out.append(_row(
                    "search", f"keyword_search_terms:{r['keyword_id']}:"
                              f"{r['url_id']}",
                    at_raw=r["t"], at_epoch="webkit_us", url=r["url"],
                    value=r["term"],
                    time_basis=("the result URL's LAST VISIT — Chromium does "
                                "not store when the term itself was typed")))
        except sqlite3.Error as exc:
            problems.append(f"keyword_search_terms: {exc}")
    return out


def parse_firefox_places(conn, problems: list) -> list[dict]:
    out: list[dict] = []
    try:
        for r in conn.execute(
                "SELECT v.id AS visit_id, v.visit_date AS visit_date, "
                "v.from_visit AS from_visit, v.visit_type AS visit_type, "
                "p.url AS url, p.title AS title, p.visit_count AS visit_count "
                "FROM moz_historyvisits v LEFT JOIN moz_places p "
                "ON p.id = v.place_id ORDER BY v.id"):
            out.append(_row(
                "visit", f"moz_historyvisits:{r['visit_id']}",
                at_raw=r["visit_date"], at_epoch="prtime_us", url=r["url"],
                title=r["title"], from_visit=r["from_visit"],
                visit_type={"raw": r["visit_type"],
                            "label": FIREFOX_VISIT_TYPES.get(r["visit_type"])},
                visit_count=r["visit_count"]))
    except sqlite3.Error as exc:
        problems.append(f"moz_historyvisits: {exc}")

    if {"moz_annos", "moz_anno_attributes"} <= _tables(conn):
        grouped: dict = {}
        try:
            for r in conn.execute(
                    "SELECT a.id AS id, a.place_id AS place_id, "
                    "a.content AS content, a.dateAdded AS added, "
                    "n.name AS name, p.url AS url FROM moz_annos a "
                    "JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id "
                    "LEFT JOIN moz_places p ON p.id = a.place_id "
                    "WHERE n.name IN ('downloads/destinationFileURI', "
                    "'downloads/metaData') ORDER BY a.place_id, a.id"):
                g = grouped.setdefault(r["place_id"], {"url": r["url"]})
                if r["name"] == "downloads/destinationFileURI":
                    g.update(dest=r["content"], added=r["added"],
                             anno_id=r["id"])
                else:
                    try:
                        g["meta"] = json.loads(r["content"] or "{}")
                    except ValueError:
                        g["meta_raw"] = r["content"]
        except sqlite3.Error as exc:
            problems.append(f"moz_annos: {exc}")
        for place_id, g in grouped.items():
            if "dest" not in g:
                continue
            meta = g.get("meta") or {}
            out.append(_row(
                "download", f"moz_annos:{g['anno_id']}", at_raw=g["added"],
                at_epoch="prtime_us", url=g["url"],
                title=os.path.basename(str(g["dest"]).replace("\\", "/")),
                value=g["dest"], place_id=place_id, metadata=meta,
                end_time_utc=decode(meta.get("endTime"), "unix_ms"),
                meta_raw=g.get("meta_raw")))
    return out


def parse_firefox_formhistory(conn, problems: list) -> list[dict]:
    out: list[dict] = []
    try:
        for r in conn.execute("SELECT id, fieldname, value, timesUsed, "
                              "firstUsed, lastUsed FROM moz_formhistory "
                              "ORDER BY id"):
            kind = ("search" if r["fieldname"] == "searchbar-history"
                    else "form-entry")
            out.append(_row(
                kind, f"moz_formhistory:{r['id']}", at_raw=r["lastUsed"],
                at_epoch="prtime_us", title=r["fieldname"], value=r["value"],
                times_used=r["timesUsed"], first_used_raw=r["firstUsed"],
                first_used_utc=decode(r["firstUsed"], "prtime_us"),
                time_basis="last use of the entry"))
    except sqlite3.Error as exc:
        problems.append(f"moz_formhistory: {exc}")
    return out


def parse_chromium_cookies(conn, problems: list) -> list[dict]:
    out: list[dict] = []
    cols = _cols(conn, "cookies")
    fields = _pick(cols, "creation_utc", "host_key", "name", "value", "path",
                   "expires_utc", "is_secure", "secure", "is_httponly",
                   "httponly", "last_access_utc", "has_expires",
                   "is_persistent", "persistent", "samesite",
                   "source_scheme", "last_update_utc")
    enc = ", length(encrypted_value) AS encrypted_len" if "encrypted_value" in cols else ""
    try:
        for r in conn.execute(f"SELECT rowid AS rid, {', '.join(fields)}{enc} "
                              "FROM cookies ORDER BY rowid"):
            d = {k: r[k] for k in r.keys() if k != "rid"}
            value = d.pop("value", "") or ""
            if not value and (d.get("encrypted_len") or 0) > 0:
                value = (f"[encrypted, {d['encrypted_len']} bytes — "
                         "not decrypted]")
            for k in ("expires_utc", "last_access_utc", "last_update_utc"):
                if k in d:
                    d[f"{k}_decoded"] = decode(d[k], "webkit_us")
            out.append(_row("cookie", f"cookies:rowid:{r['rid']}",
                            at_raw=d.get("creation_utc"),
                            at_epoch="webkit_us",
                            url=f"{d.get('host_key', '')}{d.get('path', '')}",
                            title=d.get("name", ""), value=value, **d))
    except sqlite3.Error as exc:
        problems.append(f"cookies: {exc}")
    return out


def parse_firefox_cookies(conn, problems: list) -> list[dict]:
    out: list[dict] = []
    cols = _cols(conn, "moz_cookies")
    fields = _pick(cols, "id", "originAttributes", "name", "value", "host",
                   "path", "expiry", "lastAccessed", "creationTime",
                   "isSecure", "isHttpOnly", "sameSite", "schemeMap")
    try:
        for r in conn.execute(f"SELECT {', '.join(fields)} FROM moz_cookies "
                              "ORDER BY id"):
            d = {k: r[k] for k in r.keys()}
            unit = infer_unix_unit(d.get("expiry"))
            d["expiry_unit"] = unit
            d["expiry_unit_basis"] = "inferred from magnitude"
            d["expiry_utc"] = decode(d.get("expiry"), unit) if unit else None
            d["last_accessed_utc"] = decode(d.get("lastAccessed"), "prtime_us")
            value = d.pop("value", "") or ""
            out.append(_row("cookie", f"moz_cookies:{d.get('id')}",
                            at_raw=d.get("creationTime"),
                            at_epoch="prtime_us",
                            url=f"{d.get('host', '')}{d.get('path', '')}",
                            title=d.get("name", ""), value=value, **d))
    except sqlite3.Error as exc:
        problems.append(f"moz_cookies: {exc}")
    return out


PARSERS = {
    "chromium-history": parse_chromium_history,
    "firefox-places": parse_firefox_places,
    "firefox-formhistory": parse_firefox_formhistory,
    "chromium-cookies": parse_chromium_cookies,
    "firefox-cookies": parse_firefox_cookies,
}


# -- provenance --------------------------------------------------------------

def _fingerprint(row: dict) -> str:
    return json.dumps([row["at_raw"], row["url"], row["title"], row["value"],
                       row["detail"]], sort_keys=True, default=str)


def label_provenance(merged: list[dict], main_only: list[dict] | None,
                     sidecars: list[str]) -> list[dict]:
    """Label every row by comparing the merged view with the committed one."""
    if main_only is None:
        for row in merged:
            row["provenance"] = "db"
        return merged
    committed = {r["row_ref"]: _fingerprint(r) for r in main_only}
    for row in merged:
        before = committed.get(row["row_ref"])
        if before is None:
            row["provenance"] = "wal" if "-wal" in sidecars else "db"
        elif before != _fingerprint(row) and "-wal" in sidecars:
            row["provenance"] = "wal-updated"
        else:
            row["provenance"] = "db"
    if "-journal" in sidecars:
        present = {r["row_ref"] for r in merged}
        for row in main_only:
            if row["row_ref"] not in present:
                merged.append(dict(row, provenance="rolled-back"))
    return merged


# -- discovery and extraction ------------------------------------------------

@dataclass(frozen=True)
class Candidate:
    relpath: str
    expected: str | None      # the schema its NAME suggests, or None


def discover(case, evidence_id: str, *, all_sqlite: bool = False) -> list[Candidate]:
    out = []
    with _index.session(case.root) as conn:
        for r in conn.execute(
                "SELECT relpath FROM files WHERE evidence_id = ? AND "
                "kind = 'file' AND type_id = 'sqlite' ORDER BY relpath",
                (evidence_id,)):
            name = r["relpath"].rsplit("/", 1)[-1].lower()
            expected = KNOWN_NAMES.get(name)
            if expected or all_sqlite:
                out.append(Candidate(r["relpath"], expected))
    return out


def _open_working_copy(case, path) -> sqlite3.Connection:
    """Open a WORKING COPY inside the case. Never evidence — asserted twice."""
    target = blocker.assert_case_path(case.root, path)
    blocker.refuse_evidence_path(target, case.evidence_roots())
    conn = sqlite3.connect(target, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = 1")
    return conn


@dataclass
class SourceResult:
    relpath: str
    kind: str | None
    expected: str | None
    browser: str = ""
    browser_basis: str = ""
    profile: str = ""
    rows: int = 0
    by_artefact: dict = field(default_factory=dict)
    by_provenance: dict = field(default_factory=dict)
    sidecars: list = field(default_factory=list)
    source_sha256: str = ""
    matches_manifest: bool | None = None
    working_copy: str = ""
    problems: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class BrowserSummary:
    evidence_id: str
    run_id: str
    state: str
    sources: list = field(default_factory=list)
    rows: int = 0
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _parse_copy(case, path, kind, problems):
    conn = _open_working_copy(case, path)
    try:
        return PARSERS[kind](conn, problems)
    finally:
        conn.close()


def process_source(case, evidence_id: str, run_id: str, n: int,
                   cand: Candidate) -> SourceResult:
    item = case.evidence_item(evidence_id)
    rel = safe_relpath(cand.relpath)
    src = Path(item.source).joinpath(*rel.parts)
    result = SourceResult(rel.as_posix(), None, cand.expected)
    result.browser, result.browser_basis, result.profile = browser_from_path(
        rel.as_posix())
    work = case.path("extracted", evidence_id, "browser", run_id,
                     f"{n:03d}-{rel.name}")
    merged_db = work / "merged" / rel.name
    main_db = work / "main-only" / rel.name
    result.working_copy = os.fspath(work)
    copied: dict = {}
    try:
        h = copy_evidence_to_case(case, src, merged_db)
    except OSError as exc:
        result.problems.append(f"could not copy: {explain_oserror(exc)}")
        return result
    copied[rel.as_posix()] = h.as_dict()
    result.source_sha256 = h.sha256
    row = lookup(case, evidence_id, rel.as_posix())
    result.matches_manifest = (None if not row or not row["sha256"]
                               else row["sha256"] == h.sha256)
    for suffix in SIDECARS:
        side = src.with_name(src.name + suffix)
        if not side.is_file():
            continue
        try:
            sh = copy_evidence_to_case(case, side,
                                       merged_db.with_name(rel.name + suffix))
        except OSError as exc:
            result.problems.append(f"{suffix} present but could not be copied: "
                                   f"{explain_oserror(exc)}")
            continue
        copied[rel.as_posix() + suffix] = sh.as_dict()
        result.sidecars.append(suffix)
    copy_within_case(case, merged_db, main_db)

    probe = _open_working_copy(case, merged_db)
    try:
        result.kind = schema_kind(probe)
    except sqlite3.Error as exc:
        result.problems.append(f"not readable as SQLite: {exc}")
    finally:
        probe.close()
    if result.kind is None:
        if not result.problems:
            result.problems.append("SQLite, but not a schema this parser "
                                   "recognises")
    else:
        merged = _parse_copy(case, merged_db, result.kind, result.problems)
        main_only = None
        if {"-wal", "-journal"} & set(result.sidecars):
            side_problems: list = []
            main_only = _parse_copy(case, main_db, result.kind, side_problems)
            result.problems.extend(f"main-only view: {p}"
                                   for p in side_problems)
        rows = label_provenance(merged, main_only, result.sidecars)
        _store(case, evidence_id, run_id, result, rows)
    case.custody.record(
        "artefacts.browser.source", actor=case.actor(),
        target=f"{evidence_id}:{result.relpath}", hashes=copied,
        detail=dict(result.as_dict(), run_id=run_id,
                    parser_version=PARSER_VERSION,
                    working_copies_note=(
                        "Hashes are of the copies as made. SQLite may modify "
                        "a working copy when it opens it (WAL replay, "
                        "checkpoint on close); the evidence is never opened "
                        "by SQLite.")))
    return result


def _store(case, evidence_id, run_id, result: SourceResult, rows) -> None:
    for r in rows:
        result.by_artefact[r["artefact"]] = result.by_artefact.get(r["artefact"], 0) + 1
        result.by_provenance[r["provenance"]] = result.by_provenance.get(r["provenance"], 0) + 1
    result.rows = len(rows)
    with _index.session(case.root) as conn:
        conn.execute("DELETE FROM artefacts WHERE evidence_id = ? AND "
                     "source_relpath = ? AND parser = 'browser'",
                     (evidence_id, result.relpath))
        conn.executemany(
            "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
            "source_sha256, parser, artefact, at_utc, at_raw, at_epoch, "
            "browser, browser_basis, profile, url, title, value, detail_json, "
            "provenance, row_ref) VALUES (?, ?, ?, ?, 'browser', ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, evidence_id, result.relpath, result.source_sha256,
              r["artefact"], r["at_utc"], r["at_raw"], r["at_epoch"],
              result.browser, result.browser_basis, result.profile, r["url"],
              r["title"], str(r["value"]),
              json.dumps(r["detail"], ensure_ascii=False, default=str),
              r["provenance"], r["row_ref"]) for r in rows])


def extract_browser_artefacts(case, evidence_id: str, *,
                              all_sqlite: bool = False, progress=None,
                              should_cancel=None) -> BrowserSummary:
    case.evidence_item(evidence_id)
    summary = BrowserSummary(evidence_id, uuid.uuid4().hex[:12], "running",
                             started_at=utc_now())
    candidates = discover(case, evidence_id, all_sqlite=all_sqlite)
    if not candidates and not case.custody.last("ingest.completed", evidence_id):
        raise EvidenceError(
            f"{evidence_id} has not been ingested yet. Browser databases are "
            "found through the manifest, so ingest the folder first.")
    case.custody.record(
        "artefacts.browser.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": summary.run_id, "candidates": len(candidates),
                "all_sqlite": all_sqlite, "parser_version": PARSER_VERSION})
    try:
        for n, cand in enumerate(candidates, 1):
            if should_cancel is not None and should_cancel():
                raise Cancelled("browser extraction cancelled")
            if progress is not None:
                progress(f"{n} of {len(candidates)} — {cand.relpath}")
            res = process_source(case, evidence_id, summary.run_id, n, cand)
            summary.sources.append(res.as_dict())
            summary.rows += res.rows
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    finally:
        summary.finished_at = utc_now()
        case.custody.record(
            f"artefacts.browser.{summary.state}", actor=case.actor(),
            target=evidence_id,
            detail={"run_id": summary.run_id, "rows": summary.rows,
                    "sources": len(summary.sources)})
    return summary


ARTEFACT_KINDS = ("visit", "download", "search", "form-entry", "cookie")


def list_artefacts(case, evidence_id: str, *, artefact: str = "",
                   search: str = "", provenance: str = "",
                   limit: int = 5000, offset: int = 0) -> tuple[list[dict], int]:
    where, params = ["evidence_id = ?", "parser = 'browser'"], [evidence_id]
    if artefact:
        where.append("artefact = ?")
        params.append(artefact)
    if provenance:
        where.append("provenance = ?")
        params.append(provenance)
    if search:
        where.append("(url LIKE ? OR title LIKE ? OR value LIKE ?)")
        params.extend([f"%{search}%"] * 3)
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM artefacts WHERE {clause}",
                             params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM artefacts WHERE {clause} "
            "ORDER BY at_utc IS NULL, at_utc, id LIMIT ? OFFSET ?",
            [*params, int(limit), int(offset)])]
    return rows, total
