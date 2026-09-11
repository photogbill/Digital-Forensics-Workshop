# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Mobile image analysis — an already-extracted iOS backup, stdlib only.

**This reads an image someone else acquired. It is NOT acquisition.** Getting
data off a phone needs physical-device protocols and, for a locked device,
exploits; that stays out of scope. What is squarely in scope, and native, is
reading a backup a phone already produced: an iTunes/Finder backup is plists
and a SQLite manifest, and every artefact inside it is a SQLite database or a
plist. No third-party code, no licence question (FORENSICS_PLAN.md §1.1).

**This module is the SPINE the artefact parsers hang off.** An iOS backup does
not store files under their real names. Every file is renamed to a hash and
dropped into a fan-out folder, and the map from a real path back to that hash
lives in `Manifest.db`:

    <backup>/Info.plist              device metadata, installed apps
    <backup>/Manifest.plist          whether the backup is ENCRYPTED
    <backup>/Manifest.db             SQLite: the Files table (the map)
    <backup>/ab/ab12cd…              a stored file, named by its fileID

    fileID = SHA-1( domain + "-" + relativePath )   e.g.
    HomeDomain-Library/SMS/sms.db  ->  3d0d7e5fb2ce288813306e4d4636395e047a3d28

So `analyse_backup` reads the three roots, and for every row of the Files
table resolves `domain` + `relativePath` to the fileID and the on-disk path
`<backup>/<fileID[:2]>/<fileID>`, records whether that file is actually
present, and writes the whole map to the case as `files.json`. A later pass
(the per-artefact parsers — SMS, calls, contacts, Safari, locations …) asks
this map "where is HomeDomain-Library/SMS/sms.db in this backup" and parses
the file it names. The map is the honest, testable foundation; without it a
parser is guessing at hashed names.

**Encryption is reported, not fought.** In an encrypted backup Manifest.db is
itself encrypted and cannot be read without the backup password (and, for the
files, per-file keys from the keybag). This module detects that from
`Manifest.plist` (`IsEncrypted`), says so plainly, and stops — decryption is a
later, separate decision (it needs a symmetric cipher the standard library
does not provide; see FORENSICS_PLAN.md §1.1).

Nothing here opens evidence for writing. Each manifest is copied into the case
and the COPY is read (SQLite may touch a file it opens; the evidence is never
handed to SQLite), exactly as the browser artefacts do.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import sqlite3
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .. import blocker
from .. import index as _index
from ..errors import Cancelled, EvidenceError
from ..extract import copy_evidence_to_case, copy_within_case, safe_relpath
from ..ingest import explain_oserror
from ..manifest import lookup
from ..timeutil import decode, infer_cocoa_unit, utc_now
from .browser import label_provenance

SIDECARS = ("-wal", "-journal", "-shm")

PARSER_VERSION = 1

#: Info.plist keys worth surfacing, in a stable order. Absent keys are skipped.
DEVICE_KEYS = (
    "Device Name", "Display Name", "Product Name", "Product Type",
    "Product Version", "Build Version", "Serial Number", "IMEI", "IMEI 2",
    "MEID", "ICCID", "Phone Number", "Target Identifier", "Unique Identifier",
    "GUID", "Last Backup Date", "iTunes Version", "Installed Applications",
)


def file_id(domain: str, relative_path: str) -> str:
    """The name iOS stores a file under: SHA-1 of 'domain-relativePath'."""
    return hashlib.sha1(f"{domain}-{relative_path}".encode()).hexdigest()


@dataclass
class BackupResult:
    backup: str                       # relpath of the backup root
    is_backup: bool = False
    encrypted: bool | None = None
    manifest_kind: str = ""           # "manifest-db" | "manifest-mbdb" | ""
    device: dict = field(default_factory=dict)
    apps: list = field(default_factory=list)
    files_total: int = 0
    files_present: int = 0
    files_missing: int = 0
    domains: dict = field(default_factory=dict)     # domain -> file count
    files_json: str = ""              # where the resolved map was written
    manifest_sha256: str = ""
    matches_manifest: bool | None = None
    artefact_rows: int = 0            # messages/calls/contacts/visits parsed
    by_artefact: dict = field(default_factory=dict)
    by_provenance: dict = field(default_factory=dict)
    problems: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class MobileSummary:
    evidence_id: str
    run_id: str
    state: str
    backups: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


# -- discovery ---------------------------------------------------------------

def discover_backups(case, evidence_id: str) -> list[str]:
    """Relpaths of iOS backup roots: a directory holding both Info.plist and a
    Manifest.db (or the legacy Manifest.mbdb), found through the manifest."""
    have: dict[str, set] = {}
    with _index.session(case.root) as conn:
        for r in conn.execute(
                "SELECT relpath FROM files WHERE evidence_id = ? AND "
                "kind = 'file' ORDER BY relpath", (evidence_id,)):
            rel = r["relpath"]
            name = rel.rsplit("/", 1)[-1]
            root = rel[: -len(name) - 1] if "/" in rel else ""
            if name in ("Info.plist", "Manifest.db", "Manifest.mbdb",
                        "Manifest.plist"):
                have.setdefault(root, set()).add(name)
    out = []
    for root, names in sorted(have.items()):
        if "Info.plist" in names and (
                "Manifest.db" in names or "Manifest.mbdb" in names):
            out.append(root)
    return out


# -- reading the three roots -------------------------------------------------

def _read_plist_copy(case, evidence_id, run_id, backup_root, name, problems):
    """Copy a plist out of evidence and load the copy. None if absent/bad."""
    rel = f"{backup_root}/{name}" if backup_root else name
    item = case.evidence_item(evidence_id)
    src = Path(item.source).joinpath(*safe_relpath(rel).parts)
    if not src.is_file():
        return None, None
    dest = case.path("extracted", evidence_id, "mobile", run_id, name)
    try:
        h = copy_evidence_to_case(case, src, dest)
    except OSError as exc:
        problems.append(f"{name}: could not copy ({explain_oserror(exc)})")
        return None, None
    try:
        with open(dest, "rb") as fh:
            return plistlib.load(fh), h
    except (plistlib.InvalidFileException, ValueError, OSError) as exc:
        problems.append(f"{name}: not a readable plist ({exc})")
        return None, h


def _plain(value):
    """A JSON- and custody-safe form of a plist value. plists carry datetimes
    and `data` blobs, which the custody log refuses; make them strings."""
    import datetime as _dt
    if isinstance(value, bool) or value is None or isinstance(value, (int, float, str)):
        return value
    if isinstance(value, _dt.datetime):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes>"
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    return str(value)


def _device_info(info: dict) -> tuple[dict, list]:
    device, apps = {}, []
    for key in DEVICE_KEYS:
        if key not in info:
            continue
        val = info[key]
        if key == "Installed Applications" and isinstance(val, list):
            apps = [_plain(v) for v in val]
        else:
            device[key] = _plain(val)
    if not apps and isinstance(info.get("Applications"), dict):
        apps = sorted(str(k) for k in info["Applications"].keys())
    return device, apps


def _manifest_files(conn) -> list[tuple[str, str, str, int]]:
    """(fileID, domain, relativePath, flags) from a Manifest.db Files table."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(Files)")}
    if not {"fileID", "domain", "relativePath"} <= cols:
        raise EvidenceError(
            "Manifest.db has no Files(fileID, domain, relativePath) table — "
            "not an iOS backup manifest this version understands.")
    has_flags = "flags" in cols
    rows = []
    for r in conn.execute(
            "SELECT fileID, domain, relativePath" +
            (", flags" if has_flags else "") + " FROM Files"):
        rows.append((r["fileID"], r["domain"] or "", r["relativePath"] or "",
                     (r["flags"] if has_flags else 0) or 0))
    return rows


# -- the analysis ------------------------------------------------------------

def _open_working_copy(case, path) -> sqlite3.Connection:
    target = blocker.assert_case_path(case.root, path)
    blocker.refuse_evidence_path(target, case.evidence_roots())
    conn = sqlite3.connect(target, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only = 1")
    return conn


def _write_file_map(case, evidence_id, run_id, backup_root, manifest_sha256,
                    resolved) -> str:
    """Write the resolved domain→file map into the case (never evidence)."""
    out = case.path("extracted", evidence_id, "mobile", run_id, "files.json")
    blocker.assert_case_path(case.root, out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(
        {"evidence_id": evidence_id, "run_id": run_id, "backup": backup_root,
         "manifest_sha256": manifest_sha256, "files": resolved},
        ensure_ascii=False, indent=1), encoding="utf-8")
    return out.name


def analyse_backup(case, evidence_id: str, run_id: str,
                   backup_root: str) -> BackupResult:
    result = BackupResult(backup=backup_root)
    problems = result.problems
    item = case.evidence_item(evidence_id)

    info, _ = _read_plist_copy(case, evidence_id, run_id, backup_root,
                               "Info.plist", problems)
    manifest_plist, _ = _read_plist_copy(case, evidence_id, run_id,
                                         backup_root, "Manifest.plist", problems)
    if isinstance(info, dict):
        result.is_backup = True
        result.device, result.apps = _device_info(info)
    if isinstance(manifest_plist, dict):
        result.is_backup = True
        enc = manifest_plist.get("IsEncrypted")
        result.encrypted = bool(enc) if enc is not None else None

    db_rel = f"{backup_root}/Manifest.db" if backup_root else "Manifest.db"
    mbdb_rel = f"{backup_root}/Manifest.mbdb" if backup_root else "Manifest.mbdb"
    db_src = Path(item.source).joinpath(*safe_relpath(db_rel).parts)
    mbdb_src = Path(item.source).joinpath(*safe_relpath(mbdb_rel).parts)

    if db_src.is_file():
        result.manifest_kind = "manifest-db"
        result.is_backup = True
    elif mbdb_src.is_file():
        result.manifest_kind = "manifest-mbdb"
        result.is_backup = True
        problems.append(
            "legacy Manifest.mbdb (iOS 9 and earlier) — its file map is not "
            "decoded yet; device metadata above is from Info.plist.")
        return result
    else:
        problems.append("no Manifest.db or Manifest.mbdb in this folder.")
        return result

    if result.encrypted:
        problems.append(
            "backup is ENCRYPTED: Manifest.db and the files it lists are "
            "encrypted with a key derived from the backup password. The file "
            "map cannot be read without it, and decryption is a later, "
            "separate step (FORENSICS_PLAN.md §1.1). Device metadata above is "
            "from Info.plist, which stays readable.")
        return result

    dest = case.path("extracted", evidence_id, "mobile", run_id, "Manifest.db")
    try:
        h = copy_evidence_to_case(case, db_src, dest)
    except OSError as exc:
        problems.append(f"Manifest.db: could not copy ({explain_oserror(exc)})")
        return result
    result.manifest_sha256 = h.sha256
    row = lookup(case, evidence_id, db_rel)
    result.matches_manifest = (None if not row or not row["sha256"]
                               else row["sha256"] == h.sha256)

    conn = _open_working_copy(case, dest)
    try:
        files = _manifest_files(conn)
    except sqlite3.Error as exc:
        problems.append(f"Manifest.db not readable as SQLite: {exc}")
        return result
    finally:
        conn.close()

    resolved, domains, present = [], {}, 0
    for fid, domain, rel_path, flags in files:
        stored = f"{fid[:2]}/{fid}" if fid else ""
        on_disk = (Path(item.source).joinpath(*safe_relpath(backup_root).parts,
                                              fid[:2], fid)
                   if fid and backup_root else
                   Path(item.source).joinpath(fid[:2], fid) if fid else None)
        is_present = bool(on_disk and on_disk.is_file())
        present += is_present
        # fileID recomputed from domain+path: a mismatch means a tampered or
        # non-standard manifest, and is worth surfacing rather than trusting.
        recomputed = file_id(domain, rel_path) if rel_path else fid
        resolved.append({
            "fileID": fid, "domain": domain, "relativePath": rel_path,
            "flags": flags, "stored_at": stored, "present": is_present,
            "fileID_matches": (fid == recomputed)})
        domains[domain] = domains.get(domain, 0) + 1

    result.files_total = len(resolved)
    result.files_present = present
    result.files_missing = len(resolved) - present
    result.domains = dict(sorted(domains.items()))
    result.files_json = _write_file_map(
        case, evidence_id, run_id, backup_root, result.manifest_sha256, resolved)

    mismatched = sum(1 for f in resolved if not f["fileID_matches"])
    if mismatched:
        problems.append(
            f"{mismatched} file ID(s) do not match SHA-1(domain-relativePath) "
            "— a non-standard or altered manifest; the stored names were used "
            "as given.")

    parse_backup_artefacts(case, evidence_id, run_id, backup_root, resolved,
                           result)
    return result


def analyse_evidence(case, evidence_id: str, *, progress=None,
                     should_cancel=None) -> MobileSummary:
    """Find and read every iOS backup in an ingested evidence tree."""
    case.evidence_item(evidence_id)
    summary = MobileSummary(evidence_id, uuid.uuid4().hex[:12], "running",
                            started_at=utc_now())
    backups = discover_backups(case, evidence_id)
    if not backups and not case.custody.last("ingest.completed", evidence_id):
        raise EvidenceError(
            f"{evidence_id} has not been ingested yet. iOS backups are found "
            "through the manifest, so ingest the folder first.")
    case.custody.record(
        "artefacts.mobile.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": summary.run_id, "backups": len(backups),
                "parser_version": PARSER_VERSION})
    try:
        for n, root in enumerate(backups, 1):
            if should_cancel is not None and should_cancel():
                raise Cancelled("mobile analysis cancelled")
            if progress is not None:
                progress(f"{n} of {len(backups)} — {root or '(root)'}")
            res = analyse_backup(case, evidence_id, summary.run_id, root)
            case.custody.record(
                "artefacts.mobile.backup", actor=case.actor(),
                target=f"{evidence_id}:{res.backup}",
                hashes=({"Manifest.db": {"sha256": res.manifest_sha256}}
                        if res.manifest_sha256 else {}),
                detail=dict(res.as_dict(), run_id=summary.run_id,
                            parser_version=PARSER_VERSION,
                            apps_count=len(res.apps)))
            summary.backups.append(res.as_dict())
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    finally:
        summary.finished_at = utc_now()
        case.custody.record(
            f"artefacts.mobile.{summary.state}", actor=case.actor(),
            target=evidence_id,
            detail={"run_id": summary.run_id, "backups": len(summary.backups)})
    return summary


# ===========================================================================
# Per-artefact parsers (increment 2). Each resolves a known database through
# the file map, is confirmed by its schema, and returns normalised rows. The
# raw timestamp is kept beside the decoded one, and the epoch is named — a
# mobile database is a minefield of Apple's 2001 epoch in three units.
# ===========================================================================

def _text(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        return value.decode("utf-8", "replace")
    return "" if value is None else str(value)


def _has_tables(conn, *tables) -> bool:
    have = {r[0] for r in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return all(t in have for t in tables)


def parse_sms(conn, problems) -> list[dict]:
    """iMessage/SMS: message + handle. iOS date is Mac-absolute, seconds
    before iOS 11 and nanoseconds since — inferred per row, epoch recorded."""
    if not _has_tables(conn, "message"):
        problems.append("sms.db has no message table")
        return []
    joined = _has_tables(conn, "handle")
    sql = ("SELECT m.ROWID AS rid, m.text AS text, m.date AS date, "
           "m.is_from_me AS mine, m.service AS service" +
           (", h.id AS address FROM message m LEFT JOIN handle h "
            "ON m.handle_id = h.ROWID" if joined else " FROM message m"))
    rows = []
    for r in conn.execute(sql):
        keys = r.keys()
        raw = r["date"]
        epoch = infer_cocoa_unit(raw)
        addr = _text(r["address"]) if "address" in keys else ""
        rows.append({
            "artefact": "message", "at_raw": raw, "at_epoch": epoch,
            "at_utc": decode(raw, epoch) if epoch else None,
            "source": "iOS Messages", "url": "",
            "title": addr or "(unknown)",
            "value": _text(r["text"]),
            "detail": {"from_me": bool(r["mine"]), "service": r["service"],
                       "address": addr},
            "row_ref": f"message:{r['rid']}"})
    return rows


def parse_calls(conn, problems) -> list[dict]:
    """Modern call history: Core Data ZCALLRECORD, ZDATE seconds since 2001."""
    if not _has_tables(conn, "ZCALLRECORD"):
        problems.append("no ZCALLRECORD table (not a CallHistory.storedata)")
        return []
    rows = []
    for r in conn.execute("SELECT * FROM ZCALLRECORD"):
        keys = r.keys()

        def g(col):
            return r[col] if col in keys else None
        raw = g("ZDATE")
        raw_i = int(raw) if isinstance(raw, (int, float)) else None
        outgoing = g("ZORIGINATED")
        duration = g("ZDURATION")
        addr = _text(g("ZADDRESS"))
        direction = ("outgoing" if outgoing else "incoming")
        rows.append({
            "artefact": "call", "at_raw": raw_i, "at_epoch": "cocoa_s",
            "at_utc": decode(raw_i, "cocoa_s") if raw_i else None,
            "source": "iOS Calls", "url": "",
            "title": f"{direction}, {int(duration or 0)}s",
            "value": addr or "(unknown)",
            "detail": {"direction": direction,
                       "duration_s": int(duration or 0),
                       "answered": bool(g("ZANSWERED")),
                       "service": _text(g("ZSERVICE_PROVIDER")) or None},
            "row_ref": f"call:{g('Z_PK')}"})
    return rows


def parse_calls_legacy(conn, problems) -> list[dict]:
    """Pre-iOS-8 call_history.db: `call` table, `date` in Unix seconds."""
    if not _has_tables(conn, "call"):
        problems.append("no call table (not a legacy call_history.db)")
        return []
    rows = []
    for r in conn.execute("SELECT ROWID AS rid, address, date, duration, "
                          "flags FROM call"):
        raw = r["date"]
        rows.append({
            "artefact": "call", "at_raw": raw, "at_epoch": "unix_s",
            "at_utc": decode(raw, "unix_s"),
            "source": "iOS Calls (legacy)", "url": "",
            "title": f"{int(r['duration'] or 0)}s",
            "value": _text(r["address"]) or "(unknown)",
            "detail": {"duration_s": int(r["duration"] or 0),
                       "flags": r["flags"]},
            "row_ref": f"call-legacy:{r['rid']}"})
    return rows


def parse_contacts(conn, problems) -> list[dict]:
    """AddressBook.sqlitedb: ABPerson, with phones/emails from ABMultiValue.
    CreationDate/ModificationDate are seconds since 2001."""
    if not _has_tables(conn, "ABPerson"):
        problems.append("no ABPerson table (not an AddressBook.sqlitedb)")
        return []
    points: dict = {}
    if _has_tables(conn, "ABMultiValue"):
        for r in conn.execute("SELECT record_id, value FROM ABMultiValue "
                              "WHERE value IS NOT NULL"):
            points.setdefault(r["record_id"], []).append(_text(r["value"]))
    rows = []
    for r in conn.execute("SELECT ROWID AS rid, First, Last, Organization, "
                          "Note, CreationDate, ModificationDate FROM ABPerson"):
        name = " ".join(p for p in (_text(r["First"]), _text(r["Last"])) if p)
        name = name or _text(r["Organization"]) or "(no name)"
        raw = r["CreationDate"]
        raw_i = int(raw) if isinstance(raw, (int, float)) else None
        rows.append({
            "artefact": "contact", "at_raw": raw_i, "at_epoch": "cocoa_s",
            "at_utc": decode(raw_i, "cocoa_s") if raw_i else None,
            "source": "iOS Contacts", "url": "", "title": "contact",
            "value": name,
            "detail": {"organization": _text(r["Organization"]) or None,
                       "note": _text(r["Note"]) or None,
                       "contact_points": points.get(r["rid"], []),
                       "modified_utc": decode(
                           int(r["ModificationDate"])
                           if isinstance(r["ModificationDate"], (int, float))
                           else None, "cocoa_s")},
            "row_ref": f"contact:{r['rid']}"})
    return rows


def parse_safari(conn, problems) -> list[dict]:
    """Safari History.db: history_visits joined to history_items,
    visit_time seconds since 2001."""
    if not _has_tables(conn, "history_items", "history_visits"):
        problems.append("no history_items/history_visits (not a Safari History.db)")
        return []
    rows = []
    for r in conn.execute(
            "SELECT v.id AS vid, i.url AS url, v.title AS title, "
            "v.visit_time AS t, i.visit_count AS visits "
            "FROM history_visits v JOIN history_items i "
            "ON v.history_item = i.id"):
        raw = r["t"]
        raw_i = int(raw) if isinstance(raw, (int, float)) else None
        rows.append({
            "artefact": "web-visit", "at_raw": raw_i, "at_epoch": "cocoa_s",
            "at_utc": decode(raw_i, "cocoa_s") if raw_i else None,
            "source": "iOS Safari", "url": _text(r["url"]),
            "title": _text(r["title"]), "value": "",
            "detail": {"visit_count": r["visits"]},
            "row_ref": f"safari-visit:{r['vid']}"})
    return rows


#: relativePath (lower-cased) a database is known by -> (source label, parser).
#: Matched against the file map; the schema is confirmed inside the parser, so
#: a renamed or unexpected database is skipped with a reason, never guessed.
ARTEFACT_DBS = (
    ("library/sms/sms.db", "iOS Messages", parse_sms),
    ("library/callhistorydb/callhistory.storedata", "iOS Calls", parse_calls),
    ("library/callhistory/call_history.db", "iOS Calls (legacy)",
     parse_calls_legacy),
    ("library/addressbook/addressbook.sqlitedb", "iOS Contacts",
     parse_contacts),
    ("library/safari/history.db", "iOS Safari", parse_safari),
)


def _resolve(resolved: list, relative_lower: str) -> dict | None:
    for f in resolved:
        if f["relativePath"].lower() == relative_lower and f["present"]:
            return f
    return None


def _on_disk(item_source, backup_root, fid) -> Path:
    parts = (*safe_relpath(backup_root).parts, fid[:2], fid) if backup_root \
        else (fid[:2], fid)
    return Path(item_source).joinpath(*parts)


def _copy_db_with_sidecars(case, evidence_id, run_id, backup_root, entry,
                           resolved, n, problems) -> tuple:
    """Copy a database and any -wal/-journal/-shm beside it into the case, in
    a `merged` (with the log) and a `main-only` (database alone) view, exactly
    as the browser parser does. Returns (merged_path, main_path, sidecars)."""
    item = case.evidence_item(evidence_id)
    fid = entry["fileID"]
    name = entry["relativePath"].rsplit("/", 1)[-1]
    work = case.path("extracted", evidence_id, "mobile", run_id, "artefacts",
                     f"{n:03d}-{name}")
    merged = work / "merged" / name
    main = work / "main-only" / name
    copy_evidence_to_case(case, _on_disk(item.source, backup_root, fid), merged)
    sidecars = []
    for suffix in SIDECARS:
        side = _resolve(resolved, (entry["relativePath"] + suffix).lower())
        if side is None:
            continue
        try:
            copy_evidence_to_case(
                case, _on_disk(item.source, backup_root, side["fileID"]),
                merged.with_name(name + suffix))
            sidecars.append(suffix)
        except OSError as exc:
            problems.append(f"{name}{suffix}: could not copy "
                            f"({explain_oserror(exc)})")
    copy_within_case(case, merged, main)
    return merged, main, sidecars


def parse_backup_artefacts(case, evidence_id, run_id, backup_root,
                           resolved, result) -> None:
    if result.manifest_kind != "manifest-db" or result.encrypted:
        return
    n = 0
    for relative_lower, source, parser in ARTEFACT_DBS:
        entry = _resolve(resolved, relative_lower)
        if entry is None:
            continue
        n += 1
        problems: list = []
        try:
            merged, main, sidecars = _copy_db_with_sidecars(
                case, evidence_id, run_id, backup_root, entry, resolved, n,
                problems)
        except OSError as exc:
            result.problems.append(
                f"{source}: could not copy ({explain_oserror(exc)})")
            continue
        conn = _open_working_copy(case, merged)
        try:
            rows = parser(conn, problems)
        except sqlite3.Error as exc:
            result.problems.append(f"{source}: not readable ({exc})")
            conn.close()
            continue
        conn.close()
        main_rows = None
        if {"-wal", "-journal"} & set(sidecars):
            mc = _open_working_copy(case, main)
            try:
                main_rows = parser(mc, [])
            except sqlite3.Error:
                main_rows = None
            finally:
                mc.close()
        rows = label_provenance(rows, main_rows, sidecars)
        _store_mobile(case, evidence_id, run_id, entry, source, rows)
        result.artefact_rows += len(rows)
        for row in rows:
            result.by_artefact[row["artefact"]] = \
                result.by_artefact.get(row["artefact"], 0) + 1
            result.by_provenance[row["provenance"]] = \
                result.by_provenance.get(row["provenance"], 0) + 1
        result.problems.extend(f"{source}: {p}" for p in problems)


def _store_mobile(case, evidence_id, run_id, entry, source, rows) -> None:
    relpath = entry["relativePath"]
    basis = f"{entry['domain']}:{relpath}"
    with _index.session(case.root) as conn:
        conn.execute("DELETE FROM artefacts WHERE evidence_id = ? AND "
                     "source_relpath = ? AND parser = 'mobile'",
                     (evidence_id, relpath))
        conn.executemany(
            "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
            "source_sha256, parser, artefact, at_utc, at_raw, at_epoch, "
            "browser, browser_basis, profile, url, title, value, detail_json, "
            "provenance, row_ref) VALUES (?, ?, ?, ?, 'mobile', ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?)",
            [(run_id, evidence_id, relpath, entry.get("fileID", ""),
              r["artefact"], r["at_utc"],
              r["at_raw"] if isinstance(r["at_raw"], int) else None,
              r["at_epoch"], source, basis, entry["domain"], r["url"],
              r["title"], _text(r["value"]),
              json.dumps(r["detail"], ensure_ascii=False, default=str),
              r["provenance"], r["row_ref"]) for r in rows])


ARTEFACT_KINDS = ("message", "call", "contact", "web-visit")


def list_mobile(case, evidence_id: str, *, artefact: str = "",
                search: str = "", limit: int = 5000,
                offset: int = 0) -> tuple[list[dict], int]:
    where, params = ["evidence_id = ?", "parser = 'mobile'"], [evidence_id]
    if artefact:
        where.append("artefact = ?")
        params.append(artefact)
    if search:
        where.append("(value LIKE ? OR title LIKE ? OR url LIKE ?)")
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
