# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows artefacts on a parsed volume or in a folder of evidence, into the
case (FORENSICS_PLAN §14 items 3 and 5, 2026-10-29): registry hives,
shortcuts, Jump Lists, Prefetch, event logs and Outlook mailboxes
(PST/OST).

The parsing is each format module's (`registry`, `shelllink`, `jumplist`,
`prefetch`, `evtx`, `pst`); this module finds their files — on a volume the
engine has already parsed, NTFS (`ntfs_entries`) or FAT/exFAT
(`fat_entries`), or in an ingested folder (a KAPE-style triage collection,
an exported mailbox: the `files` manifest) — reads each through the
read-only door, hands the bytes to the parser, and stores the rows the
parser makes in the artefacts index, where the Artifacts page, the hunts
and the timeline read them.

**EVERY CORE** (Bill, 2026-10-29: "the most badass and efficient setup").
Reading stays here, one file after another; PARSING runs in worker
processes, one per spare core (`parallel.py` — isolated, told no paths,
writing nothing). Rows are stored in the order the files were read whatever
the number of workers. A file too large to hand over (a big mailbox) is
parsed here, through a reader, without loading it whole.

**WHAT IS READ.** A file is chosen by its NAME and place, the way an
examiner would look for it: the registry hives (SAM, SYSTEM, SOFTWARE,
SECURITY, DEFAULT, NTUSER.DAT, UsrClass.dat, Amcache.hve — RegBack and
Windows.old copies included, each row saying which file it came from) with
their .LOG1/.LOG2 transaction logs replayed in memory; every *.lnk; every
automatic and custom destinations file; *.pf under a Prefetch folder; every
*.evtx; every *.pst and *.ost. A file that turns out not to be its format is skipped and the reason
recorded — never guessed at.

**DELETED FILES.** A shortcut, Jump List or Prefetch file whose own entry
is deleted is still read — those are small and often the point — and every
row from it says the file was deleted (`provenance` "deleted-file") and how
many of its clusters are now someone else's. Deleted hives, logs and
mailboxes are not read by default: they are large, and their clusters are
more often reused than not. On FAT, "deleted" includes an entry inside a
deleted folder and one hidden after an end-of-directory marker; the row says
which (`deleted_how`).

**A FOLDER'S FILES ARE CHECKED AGAINST ITS MANIFEST.** Each file's bytes are
hashed as they are read and compared with the SHA-256 the ingest recorded; a
file changed since then is still parsed, but its rows say so
(`matches_manifest` false) and the run lists it.

**THE ROWS ARE MEASUREMENTS.** "Prefetch records 7 runs of X.EXE, last at
…" — never "the user ran X". Each row keeps its time raw with its epoch; a
time with no zone stays out of `at_utc` (each parser's rule).

**ONE PASS, CUSTODY EITHER SIDE.** A run replaces the volume's earlier rows
from the parsers it ran, is recorded in the `runs` table, and is bracketed by
`windows.started` and `windows.completed` (or `.cancelled`/`.failed`) in
custody with the counts, every skipped file and why.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import blocker
from . import diskimage as _disk
from . import index as _index
from .errors import Cancelled, EvidenceError, FileSystemError
from .timeutil import utc_now

PARSER_VERSION = "winartifacts/1"
#: kinds in the order they run, and the artefacts-table `parser` each writes
KINDS = ("registry", "lnk", "jumplist", "prefetch", "evtx", "pst")
DEFAULT_KINDS = KINDS
#: kinds read from a DELETED file entry too
DELETED_OK = frozenset({"lnk", "jumplist", "prefetch"})
HIVE_NAMES = frozenset({"sam", "system", "software", "security", "default",
                        "ntuser.dat", "usrclass.dat", "amcache.hve"})
#: a file larger than this is handed to its parser as a reader, not bytes,
#: and is not hashed in this pass
IN_MEMORY_CAP = 512 << 20
MAX_SKIPPED_LISTED = 300
BATCH = 1000


def kind_of(path: str, name: str) -> str | None:
    """Which parser a file is for, by name and place — or None."""
    low = (name or "").lower()
    if low in HIVE_NAMES:
        return "registry"
    if low.endswith(".lnk"):
        return "lnk"
    if low.endswith((".automaticdestinations-ms", ".customdestinations-ms")):
        return "jumplist"
    if low.endswith(".pf") and "/prefetch/" in "/" + (path or "").lower():
        return "prefetch"
    if low.endswith(".evtx"):
        return "evtx"
    if low.endswith((".pst", ".ost")):
        return "pst"
    return None


@dataclass
class WinSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    fs: str = ""
    kinds: list = field(default_factory=list)
    files: dict = field(default_factory=dict)        # kind -> files read
    rows: dict = field(default_factory=dict)         # kind -> rows stored
    by_artefact: dict = field(default_factory=dict)  # artefact -> rows
    deleted_files: int = 0
    skipped: list = field(default_factory=list)      # [{path, kind, reason}]
    skipped_total: int = 0
    bytes_read: int = 0
    seconds: dict = field(default_factory=dict)      # {"total": wall seconds}
    manifest_mismatches: list = field(default_factory=list)  # changed since ingest
    workers: int = 0                                 # parsing processes used
    worker_restarts: int = 0
    notes: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)

    def skip(self, path: str, kind: str, reason: str) -> None:
        self.skipped_total += 1
        if len(self.skipped) < MAX_SKIPPED_LISTED:
            self.skipped.append({"path": path, "kind": kind, "reason": reason})


# -- the files, from the index; the bytes, from the image ----------------------

@dataclass
class _File:
    path: str
    name: str
    size: int
    deleted: bool
    ref: str                       # mft123 | fat45 — goes into row_ref
    key: int                       # MFT record or FAT entry id
    clusters: int | None = None
    clusters_now_allocated: int | None = None
    #: why it counts as deleted: "record not in use" (NTFS), "deleted entry",
    #: "inside a deleted folder", "after the end-of-directory marker" (FAT)
    deleted_how: str = ""
    #: a folder file's SHA-256 as the ingest recorded it (the manifest)
    manifest_sha256: str = ""


def _ntfs_files(case, evidence_id, volume) -> list[_File]:
    with _index.session(case.root) as conn:
        rows = conn.execute(
            "SELECT record, in_use, name, path, size, clusters, "
            "clusters_now_allocated FROM ntfs_entries WHERE evidence_id = ? AND "
            "volume = ? AND is_dir = 0 AND size > 0", (evidence_id, volume)
        ).fetchall()
    return [_File(r["path"] or r["name"], r["name"] or "", r["size"] or 0,
                  not r["in_use"], f"mft{r['record']}", r["record"],
                  r["clusters"], r["clusters_now_allocated"],
                  "" if r["in_use"] else "record not in use") for r in rows
            if kind_of(r["path"], r["name"])]


def _fat_files(case, evidence_id, volume) -> list[_File]:
    with _index.session(case.root) as conn:
        rows = conn.execute(
            "SELECT entry_id, deleted, in_deleted_dir, past_end_marker, name, "
            "path, size, clusters, clusters_now_allocated FROM fat_entries "
            "WHERE evidence_id = ? AND volume = ? AND is_dir = 0 AND size > 0",
            (evidence_id, volume)).fetchall()
    out = []
    for r in rows:
        if not kind_of(r["path"], r["name"]):
            continue
        # An entry inside a deleted folder, or hidden after an end-of-
        # directory marker, is NOT a live file even when its own mark is
        # clear: no driver would show it, and its clusters may be reused.
        how = ("deleted entry" if r["deleted"] else
               "inside a deleted folder" if r["in_deleted_dir"] else
               "after the end-of-directory marker" if r["past_end_marker"] else "")
        out.append(_File(r["path"] or r["name"], r["name"] or "", r["size"] or 0,
                         bool(how), f"fat{r['entry_id']}", r["entry_id"],
                         r["clusters"], r["clusters_now_allocated"], how))
    return out


class _Reader:
    """`.size` and `.read_at(offset, length)` over one file in the image —
    the interface every parser takes."""

    def __init__(self, size: int, read) -> None:
        self.size = size
        self._read = read

    def read_at(self, offset: int, length: int) -> bytes:
        if offset >= self.size or length <= 0:
            return b""
        return self._read(offset, min(length, self.size - offset))


class _NtfsOpener:
    def __init__(self, case, evidence_id, volume) -> None:
        self.source, self.vol, self.row = _disk.open_ntfs(case, evidence_id, volume)
        self.fs = "NTFS"

    def reader(self, f: _File) -> _Reader:
        e = self.vol.entry(f.key)
        if e is None:
            raise FileSystemError(f"MFT record {f.key} is empty now.")
        s = e.stream("")
        if s is None:
            raise FileSystemError(f"MFT record {f.key} has no data stream.")
        self.vol.refuse_unreadable(s)
        vol = self.vol
        return _Reader(s.data_size, lambda off, n: vol.read_stream(s, off, n))

    def close(self) -> None:
        self.source.close()


class _FatOpener:
    def __init__(self, case, evidence_id, volume) -> None:
        from . import fatcase
        self._fatcase = fatcase
        self.case, self.evidence_id, self.volume = case, evidence_id, volume
        self.source, self.vol, self.row = fatcase.open_fat_volume(
            case, evidence_id, volume)
        self.fs = self.vol.fs_type

    def reader(self, f: _File) -> _Reader:
        stored = self._fatcase._stored(self.case, self.evidence_id, self.volume,
                                       f.key)
        why = self._fatcase._check_slot(self.vol, stored)
        if why:
            raise FileSystemError(why)
        entry = self._fatcase._entry(stored["detail"])
        vol = self.vol
        return _Reader(entry.size, lambda off, n: vol.read_file(entry, off, n))

    def close(self) -> None:
        self.source.close()


def _read_all(reader: _Reader) -> bytes:
    out = bytearray()
    while len(out) < reader.size:
        piece = reader.read_at(len(out), min(16 << 20, reader.size - len(out)))
        if not piece:
            break
        out += piece
    return bytes(out)


# -- the parsers ---------------------------------------------------------------

def _parse(kind: str, src, f: _File, logs: dict | None) -> list[dict]:
    """Rows for one file. Raises FileSystemError when it is not its format."""
    if kind == "registry":
        from . import registry
        hive = registry.open_hive(src, f.name, logs=logs or None)
        return registry.to_rows(hive, source_path=f.path)
    if kind == "lnk":
        from . import shelllink
        return shelllink.to_rows(shelllink.parse_lnk(src), source_path=f.path)
    if kind == "jumplist":
        from . import jumplist
        return jumplist.to_rows(jumplist.parse_jumplist(src, file_name=f.name),
                                source_path=f.path)
    if kind == "prefetch":
        from . import prefetch
        return prefetch.to_rows(prefetch.parse_prefetch(src, file_name=f.name),
                                source_path=f.path)
    if kind == "evtx":
        from . import evtx
        stem = f.name.rsplit(".", 1)[0].replace("%4", "/")
        return evtx.to_rows(evtx.open_evtx(src), source_path=f.path,
                            channel_hint=stem)
    if kind == "pst":
        from . import pst
        return pst.to_rows(pst.open_pst(src), source_path=f.path)
    raise ValueError(f"unknown kind {kind!r}")


def _parse_job(kind: str, data: bytes, name: str, path: str,
               logs: dict | None) -> list[dict]:
    """One file's rows from its bytes — what a worker process runs."""
    return _parse(kind, data, _File(path, name, len(data), False, "", 0), logs)


def _logs_for(f: _File, by_path: dict, opener) -> dict:
    """A hive's .LOG1/.LOG2 transaction logs, read whole (they are small)."""
    out = {}
    for suffix in (".LOG1", ".LOG2", ".LOG"):
        other = by_path.get((f.path + suffix).lower())
        if other is None or other.deleted:
            continue
        try:
            out[other.name] = _read_all(opener.reader(other))
        except FileSystemError:
            continue
    return out


def _log_files(case, evidence_id, volume, fat: bool) -> dict:
    """lower(path) -> _File for every hive transaction log on the volume."""
    table, key = ("fat_entries", "entry_id") if fat else ("ntfs_entries", "record")
    alive = "deleted = 0" if fat else "in_use = 1"
    with _index.session(case.root) as conn:
        rows = conn.execute(
            f"SELECT {key} AS k, name, path, size FROM {table} WHERE "
            f"evidence_id = ? AND volume = ? AND {alive} AND (name LIKE "
            "'%.LOG1' OR name LIKE '%.LOG2' OR name LIKE '%.LOG')",
            (evidence_id, volume)).fetchall()
    return {(r["path"] or "").lower(): _File(
        r["path"], r["name"], r["size"] or 0, False,
        f"{'fat' if fat else 'mft'}{r['k']}", r["k"]) for r in rows}


# -- the pass ------------------------------------------------------------------

def _db_row(run_id, evidence_id, volume, f: _File, kind, sha256, r) -> tuple:
    detail = dict(r.get("detail") or {})
    detail["file"] = {"path": f.path, "ref": f.ref, "size": f.size,
                      "deleted": f.deleted, "sha256": sha256 or None}
    if not sha256:
        detail["file"]["sha256_note"] = (
            "not hashed in this pass: larger than the in-memory cap, read "
            "through a reader")
    if f.manifest_sha256:
        detail["file"]["manifest_sha256"] = f.manifest_sha256
        detail["file"]["matches_manifest"] = (
            None if not sha256 else sha256 == f.manifest_sha256)
    if f.deleted:
        detail["file"].update(clusters=f.clusters,
                              clusters_now_allocated=f.clusters_now_allocated,
                              deleted_how=f.deleted_how)
        detail["deleted"] = True
    suffix = r.get("row_ref_suffix") or ""
    raw = r.get("at_raw")
    return (run_id, evidence_id, f.path, sha256 or None, kind, r["artefact"],
            r.get("at_utc"), raw if isinstance(raw, int) else None,
            r.get("at_epoch"), r.get("title") or "", r.get("value") or "",
            json.dumps(detail, ensure_ascii=False, default=str),
            "deleted-file" if f.deleted else f"{kind}-native",
            f"v{volume}:{f.ref}" + (f":{suffix}" if suffix else ""))


def _store(case, batch) -> None:
    if not batch:
        return
    with _index.session(case.root) as conn:
        conn.executemany(
            "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
            "source_sha256, parser, artefact, at_utc, at_raw, at_epoch, title, "
            "value, detail_json, provenance, row_ref) VALUES "
            "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", batch)


class _FolderOpener:
    """Files of an ingested folder, through the read-only door."""

    def __init__(self, case, evidence_id) -> None:
        self.root = Path(case.evidence_item(evidence_id).source)
        self.fs = "folder"
        self._open: list = []

    def reader(self, f: _File) -> _Reader:
        path = self.root / _extract_safe(f.path)
        fh = blocker.open_evidence(path)
        self._open.append(fh)
        size = os.fstat(fh.fileno()).st_size
        lock = threading.Lock()

        def read(off, n):
            with lock:
                fh.seek(off)
                return fh.read(n)
        return _Reader(size, read)

    def release(self) -> None:
        for fh in self._open:
            fh.close()
        self._open.clear()

    def close(self) -> None:
        self.release()


def _extract_safe(relpath: str):
    from .extract import safe_relpath
    return safe_relpath(relpath)


def _folder_files(case, evidence_id) -> list[_File]:
    with _index.session(case.root) as conn:
        rows = conn.execute(
            "SELECT relpath, size, sha256 FROM files WHERE evidence_id = ? AND "
            "kind = 'file' AND size > 0", (evidence_id,)).fetchall()
    out = []
    for r in rows:
        name = r["relpath"].rsplit("/", 1)[-1]
        if kind_of(r["relpath"], name):
            out.append(_File(r["relpath"], name, r["size"] or 0, False,
                             "file", 0, manifest_sha256=r["sha256"] or ""))
    return out


def _folder_logs(case, evidence_id) -> dict:
    with _index.session(case.root) as conn:
        rows = conn.execute(
            "SELECT relpath, size FROM files WHERE evidence_id = ? AND kind = "
            "'file' AND (relpath LIKE '%.LOG1' OR relpath LIKE '%.LOG2' OR "
            "relpath LIKE '%.LOG')", (evidence_id,)).fetchall()
    return {r["relpath"].lower(): _File(r["relpath"], r["relpath"].rsplit("/", 1)[-1],
                                        r["size"] or 0, False, "file", 0)
            for r in rows}


def _row_ref(scope: str, f: _File, suffix: str) -> str:
    base = f"{scope}:{f.ref}" if f.ref != "file" else f"{scope}:{f.path}"
    return base + (f":{suffix}" if suffix else "")


def _db_row2(run_id, evidence_id, scope, f: _File, kind, sha256, r) -> tuple:
    row = list(_db_row(run_id, evidence_id, 0, f, kind, sha256, r))
    row[-1] = _row_ref(scope, f, r.get("row_ref_suffix") or "")
    return tuple(row)


def _run(case, evidence_id, *, scope, target, run_volume, files, opener, logs,
         kinds, progress, should_cancel, workers) -> WinSummary:
    """The pass itself, for a volume or a folder."""
    from . import parallel
    try:
        run_id, started = _disk._start_run(case, evidence_id, "windows",
                                           run_volume,
                                           {"kinds": list(kinds), "scope": scope,
                                            "parser_version": PARSER_VERSION})
    except BaseException:
        opener.close()
        raise
    summary = WinSummary(evidence_id, run_volume if run_volume is not None else -1,
                         run_id, "running", fs=opener.fs, kinds=list(kinds),
                         started_at=started)
    batch: list = []
    pool = None
    t_start = time.monotonic()
    try:
        case.custody.record("windows.started", actor=case.actor(), target=target,
                            detail={"run_id": run_id, "scope": scope,
                                    "kinds": list(kinds), "candidates": len(files),
                                    "parser_version": PARSER_VERSION})
        with _index.session(case.root) as conn:
            # only the kinds this run reads: a Prefetch-only pass leaves
            # the registry rows of an earlier pass where they are
            conn.execute(
                "DELETE FROM artefacts WHERE evidence_id = ? AND parser IN "
                f"({','.join('?' * len(kinds))}) AND row_ref LIKE ?",
                (evidence_id, *kinds, f"{scope}:%"))
        todo = [(kind_of(f.path, f.name), f) for f in files]
        todo = [(k, f) for k, f in todo if k in kinds]
        todo.sort(key=lambda kf: (KINDS.index(kf[0]), kf[1].path.lower()))
        n_workers = parallel.default_workers() if workers is None else int(workers)
        if len(todo) < 4:
            n_workers = 0
        pool = parallel.Pool(n_workers)
        summary.workers = pool.started
        if pool.error:
            summary.notes.append(f"parsing on one core: {pool.error}")
        meta: list = []

        def items():
            for n, (kind, f) in enumerate(todo, 1):
                if progress is not None and (n % 50 == 0 or kind in
                                             ("registry", "evtx", "pst")):
                    progress(f"{n:,} of {len(todo):,}: {kind} {f.path}")
                if f.deleted and kind not in DELETED_OK:
                    meta.append((kind, f, ""))
                    yield "ready", (None, f"{f.deleted_how or 'deleted'} (not "
                                          "read by default for this kind)")
                    continue
                try:
                    reader = opener.reader(f)
                    if reader.size <= IN_MEMORY_CAP:
                        data = _read_all(reader)
                        lg = _logs_for(f, logs, opener) if kind == "registry" else None
                        if hasattr(opener, "release"):
                            opener.release()
                        sha = hashlib.sha256(data).hexdigest()
                        summary.bytes_read += len(data)
                        meta.append((kind, f, sha))
                        yield "job", ("winartifacts",
                                      (kind, data, f.name, f.path, lg))
                    else:
                        # too big to hand over: parsed here, through a reader
                        meta.append((kind, f, ""))
                        try:
                            rows = _parse(kind, reader, f, None)
                            yield "ready", (True, rows)
                        except Exception as exc:          # noqa: BLE001
                            yield "ready", (False, (type(exc).__name__, str(exc)))
                        finally:
                            if hasattr(opener, "release"):
                                opener.release()
                except (FileSystemError, EvidenceError, OSError, ValueError) as exc:
                    meta.append((kind, f, ""))
                    yield "ready", (False, (type(exc).__name__, str(exc)))

        for result in pool.imap(items(), should_cancel=should_cancel):
            kind, f, sha = meta.pop(0)
            ok, payload = result
            if ok is None:
                summary.skip(f.path, kind, payload)
                continue
            if not ok:
                name, message = payload
                reason = (message if name in ("FileSystemError", "EvidenceError",
                                               "ValueError", "OSError")
                          else f"parser failed: {name}: {message}")
                summary.skip(f.path, kind, reason[:300])
                continue
            if f.manifest_sha256 and sha and sha != f.manifest_sha256:
                summary.manifest_mismatches.append(
                    {"path": f.path, "manifest_sha256": f.manifest_sha256,
                     "read_sha256": sha})
            summary.files[kind] = summary.files.get(kind, 0) + 1
            summary.deleted_files += f.deleted
            for r in payload:
                batch.append(_db_row2(run_id, evidence_id, scope, f, kind, sha, r))
                summary.rows[kind] = summary.rows.get(kind, 0) + 1
                summary.by_artefact[r["artefact"]] = \
                    summary.by_artefact.get(r["artefact"], 0) + 1
            if len(batch) >= BATCH:
                _store(case, batch)
                batch = []
        _store(case, batch)
        batch = []
        summary.state = "completed"
    except Cancelled:
        _store(case, batch)
        summary.state = "cancelled"
    except BaseException as exc:
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        if pool is not None:
            pool.close(kill=summary.state != "completed")
            summary.worker_restarts = pool.restarts
        opener.close()
        summary.seconds = {"total": round(time.monotonic() - t_start, 3)}
        summary.finished_at = utc_now()
        _disk._finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(f"windows.{summary.state}", actor=case.actor(),
                            target=target, detail=summary.as_dict())
    return summary


def analyse_volume(case, evidence_id: str, volume: int, *, kinds=DEFAULT_KINDS,
                   progress=None, should_cancel=None,
                   workers: int | None = None) -> WinSummary:
    """Find and parse the Windows artefacts on one parsed volume.
    `workers`: parsing processes (None = every core but two; 0 = here)."""
    kinds = tuple(k for k in KINDS if k in set(kinds))
    row = _disk.volume_row(case, evidence_id, volume)
    fat = row.get("fs_type") in ("fat", "fat32", "exfat")
    if row.get("fs_type") != "ntfs" and not fat:
        raise EvidenceError(
            f"Volume {volume} of {evidence_id} is "
            f"{row.get('fs_label') or row.get('fs_type') or 'not identified'}; "
            "Windows artefacts are read from NTFS, FAT and exFAT volumes.")
    files = (_fat_files if fat else _ntfs_files)(case, evidence_id, volume)
    if not files:
        with _index.session(case.root) as conn:
            table = "fat_entries" if fat else "ntfs_entries"
            parsed = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE "
                                  "evidence_id = ? AND volume = ?",
                                  (evidence_id, volume)).fetchone()[0]
        if not parsed:
            raise EvidenceError(
                f"Volume {volume} of {evidence_id} has not been parsed yet. "
                "Windows artefacts are found through the file system's "
                "entries: parse the volume first (Disk Image page).")
    opener = (_FatOpener if fat else _NtfsOpener)(case, evidence_id, volume)
    logs = _log_files(case, evidence_id, volume, fat) if "registry" in kinds else {}
    return _run(case, evidence_id, scope=f"v{volume}",
                target=f"{evidence_id}:v{volume}", run_volume=volume,
                files=files, opener=opener, logs=logs, kinds=kinds,
                progress=progress, should_cancel=should_cancel, workers=workers)


def analyse_folder(case, evidence_id: str, *, kinds=DEFAULT_KINDS,
                   progress=None, should_cancel=None,
                   workers: int | None = None) -> WinSummary:
    """The same for an ingested FOLDER of evidence — a triage collection
    (KAPE and the like keep the paths), an exported mailbox."""
    kinds = tuple(k for k in KINDS if k in set(kinds))
    item = case.evidence_item(evidence_id)
    if item.kind != "logical-folder":
        raise EvidenceError(f"{evidence_id} is a {item.kind}; for a disk image "
                            "read a parsed volume instead.")
    if not case.custody.last("ingest.completed", evidence_id):
        raise EvidenceError(f"{evidence_id} has not been ingested yet; the files "
                            "are found through the manifest, so ingest it first.")
    files = _folder_files(case, evidence_id)
    logs = _folder_logs(case, evidence_id) if "registry" in kinds else {}
    return _run(case, evidence_id, scope="f", target=evidence_id, run_volume=None,
                files=files, opener=_FolderOpener(case, evidence_id), logs=logs,
                kinds=kinds, progress=progress, should_cancel=should_cancel,
                workers=workers)
