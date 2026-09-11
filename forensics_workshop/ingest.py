# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Logical folder ingestion: walk, hash, identify, record.

Point it at a registered folder and every file is read once, through the
read-only door, producing MD5/SHA-1/SHA-256, a signature-based type, and the
file's own timestamps — before AND after it was read.

**Before and after, because reading a mounted volume can change it.** On a
live NTFS volume, reading a file may update its last-access time; on Linux
`O_NOATIME` prevents that only for the file's owner. This module does not
promise it did not happen. It MEASURES: `atime_change_observed` is set when
the value moved while the file was being read. NTFS updates last-access
lazily, so a change not observed is not proof no change occurred — the
column's name says "observed" for that reason.

**Links are recorded and never followed.** A symlink or junction can point
outside the evidence, or back up into it and loop forever. Its target is
written down; nothing beyond it is read.

**A cloud placeholder is recorded and NOT read.** OneDrive and its kin mark
files whose content is not on the disk; opening one downloads it — a network
fetch, and a change to the volume — so the row says why it was not read.

**It streams and it resumes.** Rows are committed in batches as they are
produced, so an ingest that dies at hour six keeps six hours, and running it
again skips every file whose size and modification time still match a
completed row. The custody log gets one record when an ingest starts and one
when it ends — with the manifest's digest, so an index altered afterwards
can be caught by `verify.verify_evidence`.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from . import blocker, filetype, hashing
from . import index as _index
from .errors import Cancelled, EvidenceError
from .timeutil import utc_now

BATCH = 200

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000
IO_REPARSE_TAG_MOUNT_POINT = 0xA0000003
IO_REPARSE_TAG_SYMLINK = 0xA000000C

FILE_COLUMNS = (
    "evidence_id", "relpath", "kind", "size", "mtime_ns", "atime_ns",
    "ctime_ns", "ctime_meaning", "attributes", "reparse_tag", "hidden",
    "system", "link_target", "md5", "sha1", "sha256", "type_id", "type_label",
    "type_family", "type_basis", "type_confidence", "type_note",
    "declared_ext", "ext_mismatch", "head_entropy", "atime_change_observed",
    "changed_during_read", "not_read_reason", "error", "read_at")

CTIME_MEANING = ("creation time (Windows)" if sys.platform == "win32"
                 else "inode change time (POSIX), not creation")

LOCKED_EXPLANATION = (
    "locked by another process — the program that owns it is running. A "
    "shadow copy is the usual way to read such a file (phase 4).")


@dataclass
class IngestSummary:
    evidence_id: str
    run_id: str
    state: str
    files: int = 0
    dirs: int = 0
    links: int = 0
    other: int = 0
    bytes: int = 0
    errors: int = 0
    resumed: int = 0
    not_read: int = 0
    atime_changes: int = 0
    changed_during_read: int = 0
    ext_mismatches: int = 0
    manifest_sha256: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def explain_oserror(exc: OSError) -> str:
    winerror = getattr(exc, "winerror", None)
    if winerror in (32, 33):
        return LOCKED_EXPLANATION
    if isinstance(exc, FileNotFoundError):
        return "vanished between being listed and being read"
    if isinstance(exc, PermissionError):
        return "access denied: " + blocker.describe_oserror(exc)
    return blocker.describe_oserror(exc)


def _kind(st) -> str:
    attrs = getattr(st, "st_file_attributes", 0) or 0
    tag = getattr(st, "st_reparse_tag", 0) or 0
    if stat.S_ISLNK(st.st_mode):
        return "link"
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT and tag in (
            IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT):
        return "link"
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    return "other"


def _base_row(evidence_id: str, relpath: str, kind: str, st) -> dict:
    attrs = getattr(st, "st_file_attributes", None)
    name = relpath.rsplit("/", 1)[-1]
    if attrs is not None:
        hidden = int(bool(attrs & FILE_ATTRIBUTE_HIDDEN))
        system = int(bool(attrs & FILE_ATTRIBUTE_SYSTEM))
    else:
        hidden, system = int(name.startswith(".")), 0
    row = dict.fromkeys(FILE_COLUMNS)
    row.update(evidence_id=evidence_id, relpath=relpath, kind=kind,
               size=st.st_size if kind == "file" else None,
               mtime_ns=st.st_mtime_ns, atime_ns=st.st_atime_ns,
               ctime_ns=st.st_ctime_ns, ctime_meaning=CTIME_MEANING,
               attributes=attrs, reparse_tag=getattr(st, "st_reparse_tag", None),
               hidden=hidden, system=system,
               declared_ext=filetype.declared_extension(name))
    return row


def walk(root: Path):
    """Yield (relpath, absolute path, stat or None, error or None).

    Sorted within each folder so two ingests of an unchanged folder produce
    rows in the same order. Directories are descended; links never are.
    """
    stack = [""]
    while stack:
        rel_dir = stack.pop()
        abs_dir = root / rel_dir if rel_dir else root
        try:
            with os.scandir(abs_dir) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as exc:
            yield rel_dir or ".", os.fspath(abs_dir), None, exc
            continue
        subdirs = []
        for entry in entries:
            rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError as exc:
                yield rel, entry.path, None, exc
                continue
            yield rel, entry.path, st, None
            if _kind(st) == "dir":
                subdirs.append(rel)
        stack.extend(reversed(subdirs))


def read_file(evidence_id: str, relpath: str, path: str, st, *,
              should_cancel=None) -> dict:
    """Hash and identify one file, measuring its timestamps either side."""
    row = _base_row(evidence_id, relpath, "file", st)
    attrs = row["attributes"] or 0
    if attrs & (FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_RECALL_ON_OPEN):
        row["not_read_reason"] = (
            "cloud placeholder or offline file: its content is not on this "
            "disk, and reading it would download it — changing the volume. "
            "Not read.")
        row["read_at"] = utc_now()
        return row
    row["read_at"] = utc_now()
    try:
        with blocker.open_evidence(path) as fh:
            hashes, head = hashing.hash_stream(
                fh, head_bytes=filetype.HEAD_BYTES,
                should_cancel=should_cancel)
            result = filetype.identify(head, name=relpath, size=hashes.size,
                                       reader=fh)
        after = os.stat(path, follow_symlinks=False)
    except Cancelled:
        raise
    except OSError as exc:
        row["error"] = explain_oserror(exc)
        return row
    row.update(md5=hashes.md5, sha1=hashes.sha1, sha256=hashes.sha256,
               type_id=result.type_id, type_label=result.label,
               type_family=result.family, type_basis=result.basis,
               type_confidence=result.confidence, type_note=result.note,
               ext_mismatch=int(result.ext_mismatch),
               head_entropy=result.head_entropy)
    row["atime_change_observed"] = int(after.st_atime_ns != st.st_atime_ns)
    row["changed_during_read"] = int(
        after.st_size != st.st_size or after.st_mtime_ns != st.st_mtime_ns
        or hashes.size != st.st_size)
    if row["changed_during_read"]:
        row["size"] = hashes.size
    return row


def manifest_digest(case, evidence_id: str) -> str:
    """One SHA-256 over every row's path, kind, size and SHA-256, in path
    order. What the custody log keeps so the index can be checked later."""
    digest = hashlib.sha256()
    with _index.session(case.root) as conn:
        for r in conn.execute(
                "SELECT relpath, kind, size, sha256 FROM files "
                "WHERE evidence_id = ? ORDER BY relpath", (evidence_id,)):
            line = (f"{r['relpath']}\t{r['kind']}\t"
                    f"{'' if r['size'] is None else r['size']}\t"
                    f"{r['sha256'] or ''}\n")
            digest.update(line.encode("utf-8"))
    return digest.hexdigest()


def _insert(conn, rows: list[dict]) -> None:
    placeholders = ", ".join("?" for _ in FILE_COLUMNS)
    conn.executemany(
        f"INSERT OR REPLACE INTO files ({', '.join(FILE_COLUMNS)}) "
        f"VALUES ({placeholders})",
        [tuple(r[c] for c in FILE_COLUMNS) for r in rows])


def ingest_folder(case, evidence_id: str, *,
                  progress: Callable[[str], None] | None = None,
                  should_cancel: Callable[[], bool] | None = None,
                  on_batch: Callable[[list], None] | None = None,
                  batch_size: int = BATCH) -> IngestSummary:
    """Walk one registered folder into the case index. Resumable."""
    item = case.evidence_item(evidence_id)
    if item.kind != "logical-folder":
        raise EvidenceError(f"{evidence_id} is a {item.kind}, not a folder.")
    root = Path(item.source)
    if not root.is_dir():
        raise EvidenceError(f"{root} is not reachable; is the volume attached?")
    blocker.check_layout(case.root, root)

    summary = IngestSummary(evidence_id, uuid.uuid4().hex[:12], "running",
                            started_at=utc_now())
    volume = blocker.volume_state(root).as_dict()
    conn = _index.connect(case.root)
    try:
        prior = conn.execute("SELECT COUNT(*) FROM files WHERE evidence_id = ?",
                             (evidence_id,)).fetchone()[0]
        conn.execute("INSERT INTO ingest_runs (run_id, evidence_id, "
                     "started_at, state) VALUES (?, ?, ?, 'running')",
                     (summary.run_id, evidence_id, summary.started_at))
        conn.commit()
    finally:
        conn.close()
    case.custody.record(
        "ingest.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": summary.run_id, "source": item.source,
                "resuming_over_rows": prior, "volume": volume})

    conn = _index.connect(case.root)
    pending: list[dict] = []
    last_report = 0.0

    def flush() -> None:
        if pending:
            _insert(conn, pending)
            conn.commit()
            if on_batch is not None:
                on_batch(list(pending))
            pending.clear()

    def unchanged(relpath, st) -> bool:
        r = conn.execute(
            "SELECT size, mtime_ns, sha256, error, not_read_reason FROM files "
            "WHERE evidence_id = ? AND relpath = ?",
            (evidence_id, relpath)).fetchone()
        return bool(r and r["size"] == st.st_size
                    and r["mtime_ns"] == st.st_mtime_ns
                    and (r["sha256"] or r["not_read_reason"])
                    and not r["error"])

    try:
        for relpath, path, st, exc in walk(root):
            if should_cancel is not None and should_cancel():
                raise Cancelled("ingest cancelled")
            if exc is not None:
                row = dict.fromkeys(FILE_COLUMNS)
                row.update(evidence_id=evidence_id, relpath=relpath,
                           kind="other", error=explain_oserror(exc),
                           read_at=utc_now())
                summary.errors += 1
                pending.append(row)
            else:
                kind = _kind(st)
                if kind == "dir":
                    summary.dirs += 1
                    pending.append(_base_row(evidence_id, relpath, kind, st))
                elif kind == "link":
                    summary.links += 1
                    row = _base_row(evidence_id, relpath, kind, st)
                    try:
                        row["link_target"] = os.readlink(path)
                    except (OSError, ValueError) as err:
                        row["link_target"] = f"(unreadable: {err})"
                    pending.append(row)
                elif kind == "other":
                    summary.other += 1
                    pending.append(_base_row(evidence_id, relpath, kind, st))
                elif unchanged(relpath, st):
                    summary.files += 1
                    summary.resumed += 1
                    summary.bytes += st.st_size
                else:
                    row = read_file(evidence_id, relpath, path, st,
                                    should_cancel=should_cancel)
                    summary.files += 1
                    summary.bytes += row["size"] or 0
                    summary.errors += 1 if row["error"] else 0
                    summary.not_read += 1 if row["not_read_reason"] else 0
                    summary.atime_changes += row["atime_change_observed"] or 0
                    summary.changed_during_read += row["changed_during_read"] or 0
                    summary.ext_mismatches += row["ext_mismatch"] or 0
                    pending.append(row)
            if len(pending) >= batch_size:
                flush()
            now = time.monotonic()
            if progress is not None and now - last_report > 0.5:
                last_report = now
                progress(f"{summary.files:,} files · {summary.bytes:,} bytes · "
                         f"{summary.errors:,} errors — {relpath}")
        flush()
        summary.state = "completed"
    except Cancelled:
        flush()
        summary.state = "cancelled"
    except BaseException as exc:
        try:
            flush()
        except Exception:                               # noqa: BLE001
            pass
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        conn.close()
        summary.finished_at = utc_now()
        hashes = {}
        if summary.state == "completed":
            summary.manifest_sha256 = manifest_digest(case, evidence_id)
            hashes = {"manifest": summary.manifest_sha256}
        with _index.session(case.root) as done:
            done.execute("UPDATE ingest_runs SET finished_at = ?, state = ?, "
                         "summary_json = ? WHERE run_id = ?",
                         (summary.finished_at, summary.state,
                          json.dumps(summary.as_dict()), summary.run_id))
        case.custody.record(
            f"ingest.{summary.state}", actor=case.actor(), target=evidence_id,
            hashes=hashes, detail=summary.as_dict())
    return summary
