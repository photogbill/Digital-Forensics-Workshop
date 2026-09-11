# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Disk images in a case: hash, partitions, NTFS, the journal, slack, recovery.

The parsers (`image`, `partitions`, `ntfs`, `usn`, `carve`) know nothing of
cases. This module ties what they read to the case index and the custody
log, under the same rules as the logical ingest:

* **Every job is a run with a custody record either side.** A completed run
  records a digest of the rows it produced — the image's MD5/SHA-1/SHA-256
  and a digest of its volume rows, a digest of an NTFS volume's entries, of a
  journal's records, of a carve's candidates — so an index altered later can
  be caught by comparing the two.
* **Preview writes nothing.** `preview_entry`, `preview_candidate` and
  `slack_preview` read bytes into memory for a host to show. Only the
  `recover_*` functions write, each with a reason, each into
  `extracted/<evidence>/…` through the one stream writer that hashes what it
  writes, and each leaves a custody record saying HOW the bytes were found —
  an MFT entry and how many of its clusters are now allocated to something
  else, or a carved offset and the basis of its length.
* **A recovered deleted file states the strength of the claim.** Clusters a
  deleted file's runs point to may since have been handed to another file;
  `clusters_now_allocated` is measured against `$Bitmap` and travels with the
  recovery into custody, so "recovered" is never flattened into "this is the
  file".
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import carve as _carve
from . import extract as _extract
from . import filetype, image, ntfs, partitions, timeutil, usn
from . import index as _index
from .errors import Cancelled, EvidenceError, FileSystemError
from .timeutil import utc_now

PREVIEW_BYTES = 1 << 16
PREVIEW_MAX = 32 << 20
BATCH = 500

ENTRY_FILTERS = ("all", "in-use", "deleted", "directories", "indicators",
                 "ads", "orphans", "problems")


# ---------------------------------------------------------------------------
# opening
# ---------------------------------------------------------------------------

def open_image(case, evidence_id: str) -> image.ImageSource:
    item = case.evidence_item(evidence_id)
    if item.kind != "raw-image":
        raise EvidenceError(f"{evidence_id} is a {item.kind}, not a disk image.")
    segments = case.sidecar(evidence_id).get("segments") or []
    if not segments:
        raise EvidenceError(f"{evidence_id}'s sidecar names no segments.")
    for seg in segments:
        if not Path(seg["path"]).is_file():
            raise EvidenceError(f"{seg['path']} is not reachable; is the "
                                "volume holding the image attached?")
    return image.ImageSource.from_segments([seg["path"] for seg in segments])


def segment_changes(case, evidence_id: str, source: image.ImageSource) -> list[str]:
    """Segments whose size differs from registration — evidence that changed."""
    out = []
    recorded = {s["path"]: s["size"] for s in
                case.sidecar(evidence_id).get("segments") or []}
    for seg in source.info.segments:
        was = recorded.get(seg.path)
        if was is not None and was != seg.size:
            out.append(f"{Path(seg.path).name} was {was:,} bytes when "
                       f"registered and is {seg.size:,} now.")
    return out


def volume_row(case, evidence_id: str, volume: int) -> dict:
    with _index.session(case.root) as conn:
        row = conn.execute("SELECT * FROM volumes WHERE evidence_id = ? AND "
                           "volume = ?", (evidence_id, volume)).fetchone()
    if row is None:
        raise EvidenceError(f"{evidence_id} has no volume {volume}. Ingest the "
                            "image first, then pick a volume from its list.")
    return _decode_volume(dict(row))


def open_ntfs(case, evidence_id: str, volume: int):
    """(image source, NtfsVolume, volume row). The caller closes the source."""
    row = volume_row(case, evidence_id, volume)
    source = open_image(case, evidence_id)
    try:
        vol = ntfs.NtfsVolume(image.Region(source, row["offset"], row["length"]))
    except FileSystemError as exc:
        source.close()
        raise FileSystemError(
            f"Volume {volume} ({row['entry']}, identified as "
            f"{row['fs_label'] or row['fs_type']}) could not be read as NTFS: "
            f"{exc}") from exc
    except BaseException:
        source.close()
        raise
    return source, vol, row


def _decode_volume(row: dict) -> dict:
    for key in ("flags", "problems"):
        try:
            row[key] = json.loads(row[key] or "[]")
        except ValueError:
            row[key] = []
    return row


def _start_run(case, evidence_id, kind, volume, settings) -> tuple[str, str]:
    run_id, started = uuid.uuid4().hex[:12], utc_now()
    with _index.session(case.root) as conn:
        conn.execute("INSERT INTO runs (run_id, evidence_id, kind, volume, "
                     "started_at, state, settings_json) VALUES (?, ?, ?, ?, ?, "
                     "'running', ?)", (run_id, evidence_id, kind, volume,
                                       started, json.dumps(settings)))
    return run_id, started


def _finish_run(case, run_id, state, summary: dict) -> None:
    with _index.session(case.root) as conn:
        conn.execute("UPDATE runs SET finished_at = ?, state = ?, summary_json "
                     "= ? WHERE run_id = ?",
                     (utc_now(), state, json.dumps(summary), run_id))


# ---------------------------------------------------------------------------
# image ingest: hash + partitions
# ---------------------------------------------------------------------------

@dataclass
class ImageSummary:
    evidence_id: str
    run_id: str
    state: str
    format: str = ""
    disk_bytes: int = 0
    file_bytes: int = 0
    segments: list = field(default_factory=list)
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    scheme: str = ""
    sector_size: int = 0
    sector_basis: str = ""
    volumes: int = 0
    problems: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    volumes_sha256: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


VOLUME_COLUMNS = ("evidence_id", "volume", "kind", "entry", "offset", "length",
                  "start_lba", "sectors", "sector_size", "type_code",
                  "type_label", "name", "guid", "flags", "fs_type", "fs_label",
                  "fs_volume_label", "fs_note", "problems")


def volume_rows(source, table: partitions.PartitionTable, evidence_id: str) -> list[dict]:
    items = sorted([*table.partitions, *table.gaps],
                   key=lambda p: (p.offset, p.kind != "extended"))
    rows = []
    for number, p in enumerate(items, start=1):
        fs = partitions.FileSystemGuess("", "", "", "", "")
        if p.kind in ("partition", "whole", "gap"):
            fs = partitions.detect_filesystem(source, p.offset, p.length)
        note = fs.note
        if p.kind == "gap" and fs.type_id not in ("", "unknown", "empty"):
            note = (f"A {fs.label} starts at the beginning of this "
                    "unpartitioned space — possibly a deleted or hidden "
                    "partition. " + note).strip()
        rows.append(dict(
            evidence_id=evidence_id, volume=number, kind=p.kind, entry=p.entry,
            offset=p.offset, length=p.length, start_lba=p.start_lba,
            sectors=p.sectors, sector_size=table.sector_size,
            type_code=p.type_code, type_label=p.type_label, name=p.name,
            guid=p.guid, flags=json.dumps(list(p.flags)), fs_type=fs.type_id,
            fs_label=fs.label, fs_volume_label=fs.volume_label, fs_note=note,
            problems=json.dumps(list(p.problems))))
    return rows


def volumes_digest(case, evidence_id: str) -> str:
    digest = hashlib.sha256()
    with _index.session(case.root) as conn:
        for r in conn.execute("SELECT volume, kind, entry, offset, length, "
                              "type_code, fs_type FROM volumes WHERE "
                              "evidence_id = ? ORDER BY volume", (evidence_id,)):
            digest.update("\t".join(str(r[k]) for k in r.keys()).encode("utf-8")
                          + b"\n")
    return digest.hexdigest()


def ingest_image(case, evidence_id: str, *, progress=None,
                 should_cancel=None) -> ImageSummary:
    """Hash the whole image (and each segment) and read its partition table."""
    source = open_image(case, evidence_id)
    run_id, started = _start_run(case, evidence_id, "image", None, {})
    summary = ImageSummary(evidence_id, run_id, "running", started_at=started,
                           format=source.info.format,
                           disk_bytes=source.info.size,
                           file_bytes=source.info.file_bytes,
                           notes=list(source.info.notes))
    case.custody.record(
        "image.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": run_id, "format": source.info.format,
                "segments": [s.as_dict() for s in source.info.segments]})
    table = None
    try:
        summary.problems.extend(segment_changes(case, evidence_id, source))
        whole, per_segment = image.hash_image(source, should_cancel=should_cancel,
                                              progress=progress)
        summary.md5, summary.sha1, summary.sha256 = whole.md5, whole.sha1, whole.sha256
        summary.segments = [dict(seg.as_dict(), md5=h.md5, sha1=h.sha1,
                                 sha256=h.sha256)
                            for seg, h in zip(source.info.segments, per_segment)]
        if progress is not None:
            progress("reading the partition table")
        table = partitions.read_table(source)
        rows = volume_rows(source, table, evidence_id)
        with _index.session(case.root) as conn:
            conn.execute("DELETE FROM volumes WHERE evidence_id = ?", (evidence_id,))
            conn.executemany(
                f"INSERT INTO volumes ({', '.join(VOLUME_COLUMNS)}) VALUES "
                f"({', '.join('?' for _ in VOLUME_COLUMNS)})",
                [tuple(r[c] for c in VOLUME_COLUMNS) for r in rows])
        summary.scheme, summary.sector_size = table.scheme, table.sector_size
        summary.sector_basis = table.sector_basis
        summary.volumes = len(rows)
        summary.problems.extend(table.problems)
        summary.notes.extend(table.notes)
        summary.volumes_sha256 = volumes_digest(case, evidence_id)
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    except BaseException as exc:
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        source.close()
        summary.finished_at = utc_now()
        _finish_run(case, run_id, summary.state, summary.as_dict())
        hashes = {}
        if summary.state == "completed":
            hashes = {"md5": summary.md5, "sha1": summary.sha1,
                      "sha256": summary.sha256, "volumes": summary.volumes_sha256}
        detail = summary.as_dict()
        if table is not None:
            detail["table"] = table.as_dict()
        case.custody.record(f"image.{summary.state}", actor=case.actor(),
                            target=evidence_id, hashes=hashes, detail=detail)
    return summary


def list_volumes(case, evidence_id: str) -> list[dict]:
    with _index.session(case.root) as conn:
        rows = [_decode_volume(dict(r)) for r in conn.execute(
            "SELECT * FROM volumes WHERE evidence_id = ? ORDER BY volume",
            (evidence_id,))]
    return rows


# ---------------------------------------------------------------------------
# NTFS
# ---------------------------------------------------------------------------

@dataclass
class NtfsSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    label: str = ""
    version: str = ""
    dirty: bool | None = None
    serial: str = ""
    cluster_size: int = 0
    record_size: int = 0
    records: int = 0
    entries: int = 0
    in_use: int = 0
    deleted: int = 0
    directories: int = 0
    extension_records: int = 0
    baad: int = 0
    torn: int = 0
    orphans: int = 0
    parent_reused: int = 0
    with_indicators: int = 0
    ads: int = 0
    deleted_fully_unallocated: int = 0
    deleted_partly_reallocated: int = 0
    problems: list = field(default_factory=list)
    entries_sha256: str = ""
    journal: dict | None = None
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


ENTRY_COLUMNS = (
    "evidence_id", "volume", "record", "sequence", "in_use", "is_dir",
    "link_count", "name", "namespace", "other_names", "parent_record",
    "parent_sequence", "path", "path_status", "si_created", "si_modified",
    "si_changed", "si_accessed", "fn_created", "fn_modified", "fn_changed",
    "fn_accessed", "file_attributes", "size", "allocated", "resident",
    "data_flags", "ads_count", "clusters", "clusters_now_allocated", "lsn",
    "usn", "fixup_ok", "indicators", "problems", "run_id")

STREAM_COLUMNS = ("evidence_id", "volume", "record", "name", "size",
                  "allocated", "initialized", "resident", "flags", "runs")


def _entry_row(evidence_id, volume, run_id, vol, e: ntfs.MftEntry) -> dict:
    fn = e.preferred_name()
    si = e.si
    main = e.stream("")
    clusters = allocated_now = None
    if main is not None and not main.resident and not e.in_use:
        clusters, allocated_now = vol.count_allocated(main.runs)
    elif main is not None and not main.resident:
        clusters = sum(n for _v, lcn, n in main.runs if lcn is not None)
    others = [{"name": n.name, "namespace": n.namespace_name,
               "parent_record": n.parent_record,
               "parent_sequence": n.parent_sequence}
              for n in e.names if n is not fn]
    return dict(
        evidence_id=evidence_id, volume=volume, record=e.record,
        sequence=e.sequence, in_use=int(e.in_use), is_dir=int(e.is_dir),
        link_count=e.link_count, name=fn.name if fn else "",
        namespace=fn.namespace_name if fn else "",
        other_names=json.dumps(others) if others else None,
        parent_record=fn.parent_record if fn else None,
        parent_sequence=fn.parent_sequence if fn else None,
        path=None, path_status=None,
        si_created=si.created if si else None,
        si_modified=si.modified if si else None,
        si_changed=si.changed if si else None,
        si_accessed=si.accessed if si else None,
        fn_created=fn.created if fn else None,
        fn_modified=fn.modified if fn else None,
        fn_changed=fn.changed if fn else None,
        fn_accessed=fn.accessed if fn else None,
        file_attributes=si.attributes if si else None,
        size=main.data_size if main else None,
        allocated=main.alloc_size if main else None,
        resident=None if main is None else int(main.resident),
        data_flags=main.flags if main else None, ads_count=len(e.ads()),
        clusters=clusters, clusters_now_allocated=allocated_now, lsn=e.lsn,
        usn=si.usn if si else None, fixup_ok=int(e.fixup_ok),
        indicators=json.dumps(e.indicators()), problems=json.dumps(e.problems),
        run_id=run_id)


def entries_digest(case, evidence_id: str, volume: int) -> str:
    digest = hashlib.sha256()
    with _index.session(case.root) as conn:
        for r in conn.execute(
                "SELECT record, sequence, in_use, path, size, si_created, "
                "si_modified, fn_created, indicators FROM ntfs_entries WHERE "
                "evidence_id = ? AND volume = ? ORDER BY record",
                (evidence_id, volume)):
            digest.update("\t".join("" if r[k] is None else str(r[k])
                                    for k in r.keys()).encode("utf-8") + b"\n")
    return digest.hexdigest()


def parse_ntfs(case, evidence_id: str, volume: int, *, journal: bool = True,
               progress=None, should_cancel=None) -> NtfsSummary:
    """Every MFT record of one NTFS volume into the index; then its journal."""
    source, vol, row = open_ntfs(case, evidence_id, volume)
    run_id, started = _start_run(case, evidence_id, "ntfs", volume,
                                 {"journal": journal})
    info = vol.volume_info()
    summary = NtfsSummary(evidence_id, volume, run_id, "running",
                          label=info["label"], version=info["version"],
                          dirty=info["dirty"], serial=vol.boot.serial_short,
                          cluster_size=vol.cluster,
                          record_size=vol.record_size,
                          records=vol.record_count,
                          problems=list(vol.problems), started_at=started)
    case.custody.record(
        "ntfs.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": run_id, "volume": volume, "entry": row["entry"],
                "offset": row["offset"], "boot": vol.boot.as_dict(),
                "volume_info": info})
    conn = _index.connect(case.root)
    entries: list = []
    streams: list = []
    nodes: dict = {}
    last = 0.0

    def flush():
        if entries:
            conn.executemany(
                f"INSERT OR REPLACE INTO ntfs_entries ({', '.join(ENTRY_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in ENTRY_COLUMNS)})",
                [tuple(r[c] for c in ENTRY_COLUMNS) for r in entries])
            entries.clear()
        if streams:
            conn.executemany(
                f"INSERT OR REPLACE INTO ntfs_streams ({', '.join(STREAM_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in STREAM_COLUMNS)})", streams)
            streams.clear()
        conn.commit()

    try:
        conn.execute("DELETE FROM ntfs_entries WHERE evidence_id = ? AND volume = ?",
                     (evidence_id, volume))
        conn.execute("DELETE FROM ntfs_streams WHERE evidence_id = ? AND volume = ?",
                     (evidence_id, volume))
        conn.commit()
        for e in vol.iter_entries(should_cancel=should_cancel):
            if e.signature == "BAAD":
                summary.baad += 1
            if e.is_extension:
                summary.extension_records += 1
                continue
            r = _entry_row(evidence_id, volume, run_id, vol, e)
            entries.append(r)
            summary.entries += 1
            summary.in_use += e.in_use
            summary.deleted += not e.in_use and e.signature == "FILE"
            summary.directories += e.is_dir
            summary.torn += not e.fixup_ok and e.signature == "FILE"
            summary.with_indicators += bool(e.indicators())
            summary.ads += len(e.ads())
            if not e.in_use and r["clusters"]:
                if r["clusters_now_allocated"] == 0:
                    summary.deleted_fully_unallocated += 1
                else:
                    summary.deleted_partly_reallocated += 1
            fn = e.preferred_name()
            nodes[e.record] = (e.sequence, e.in_use, e.is_dir,
                               fn.parent_record if fn else -1,
                               fn.parent_sequence if fn else 0,
                               fn.name if fn else "")
            for s in e.streams:
                streams.append((evidence_id, volume, e.record, s.name,
                                s.data_size, s.alloc_size, s.init_size,
                                int(s.resident), s.flags,
                                json.dumps(s.runs_as_list())))
            if len(entries) >= BATCH:
                flush()
            now = time.monotonic()
            if progress is not None and now - last > 0.5:
                last = now
                progress(f"record {e.record:,} of {vol.record_count:,} · "
                         f"{summary.deleted:,} deleted")
        flush()
        if progress is not None:
            progress("rebuilding paths")
        paths = ntfs.build_paths(nodes)
        updates = [(p, st, evidence_id, volume, rec) for rec, (p, st) in paths.items()
                   if rec in nodes]
        for i in range(0, len(updates), 5000):
            conn.executemany("UPDATE ntfs_entries SET path = ?, path_status = ? "
                             "WHERE evidence_id = ? AND volume = ? AND record = ?",
                             updates[i:i + 5000])
            conn.commit()
        summary.orphans = sum(1 for p, st in paths.values() if st == "orphan")
        summary.parent_reused = sum(1 for p, st in paths.values()
                                    if st == "parent-reused")
        summary.state = "completed"
    except Cancelled:
        flush()
        summary.state = "cancelled"
    except BaseException as exc:
        try:
            flush()
        except Exception:                                   # noqa: BLE001
            pass
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        conn.close()
        source.close()
        summary.finished_at = utc_now()
        hashes = {}
        if summary.state == "completed":
            summary.entries_sha256 = entries_digest(case, evidence_id, volume)
            hashes = {"entries": summary.entries_sha256}
        _finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(f"ntfs.{summary.state}", actor=case.actor(),
                            target=evidence_id, hashes=hashes,
                            detail=summary.as_dict())
    if summary.state == "completed" and journal:
        found = find_journal(case, evidence_id, volume)
        if found is not None:
            summary.journal = parse_journal(case, evidence_id, volume,
                                            progress=progress,
                                            should_cancel=should_cancel).as_dict()
        else:
            summary.journal = {"state": "absent", "volume": volume,
                               "note": "No $Extend\\$UsnJrnl on this volume: "
                                       "the change journal is not enabled, or "
                                       "was deleted."}
            case.custody.record("usn.absent", actor=case.actor(),
                                target=evidence_id, detail=summary.journal)
    return summary


def _decode_entry(row: dict) -> dict:
    for key in ("indicators", "problems", "other_names"):
        try:
            row[key] = json.loads(row[key]) if row[key] else []
        except ValueError:
            row[key] = []
    for key in ("si_created", "si_modified", "si_changed", "si_accessed",
                "fn_created", "fn_modified", "fn_changed", "fn_accessed"):
        row[f"{key}_utc"] = timeutil.decode(row[key], "filetime")
    row["time_epoch"] = "filetime"
    return row


def list_entries(case, evidence_id: str, volume: int, *, filter: str = "all",
                 search: str = "", limit: int = 500, offset: int = 0) -> tuple[list, int]:
    if filter not in ENTRY_FILTERS:
        raise ValueError(f"filter must be one of {ENTRY_FILTERS}")
    where = ["evidence_id = ?", "volume = ?"]
    args: list = [evidence_id, volume]
    where.append({
        "all": "1", "in-use": "in_use = 1", "deleted": "in_use = 0",
        "directories": "is_dir = 1", "indicators": "indicators != '[]'",
        "ads": "ads_count > 0",
        "orphans": "path_status IN ('orphan', 'parent-reused', 'loop')",
        "problems": "(problems != '[]' OR fixup_ok = 0)"}[filter])
    if search:
        where.append("path LIKE ? ESCAPE '\\'")
        args.append("%" + search.replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%")
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM ntfs_entries WHERE {clause}",
                             args).fetchone()[0]
        rows = [_decode_entry(dict(r)) for r in conn.execute(
            f"SELECT * FROM ntfs_entries WHERE {clause} ORDER BY path, record "
            "LIMIT ? OFFSET ?", [*args, limit, offset])]
    return rows, total


def entry_detail(case, evidence_id: str, volume: int, record: int) -> dict:
    """Everything one record says, re-read from the image — never from the
    index alone, so what is shown is what is on the disk now."""
    source, vol, _row = open_ntfs(case, evidence_id, volume)
    try:
        e = vol.entry(record)
        if e is None:
            raise EvidenceError(f"Record {record} is empty (no FILE signature).")

        def times(obj):
            return {k: {"raw": getattr(obj, k),
                        "utc": timeutil.decode(getattr(obj, k), "filetime"),
                        "fraction": timeutil.filetime_fraction(getattr(obj, k))}
                    for k in ("created", "modified", "changed", "accessed")}

        streams = []
        for s in e.streams:
            item = {"name": s.name, "size": s.data_size, "allocated": s.alloc_size,
                    "initialized": s.init_size, "resident": s.resident,
                    "compressed": s.compressed, "encrypted": s.encrypted,
                    "sparse": s.sparse, "runs": s.runs_as_list(),
                    "run_problems": vol.run_problems(s)}
            if not s.resident:
                total, used = vol.count_allocated(s.runs)
                item.update(clusters=total, clusters_now_allocated=used)
                item["slack"] = vol.file_slack(s)
            streams.append(item)
        return {
            "record": e.record, "signature": e.signature, "sequence": e.sequence,
            "in_use": e.in_use, "is_dir": e.is_dir, "link_count": e.link_count,
            "lsn": e.lsn, "fixup_ok": e.fixup_ok,
            "base_record": e.base_record, "has_attribute_list": e.has_attribute_list,
            "other_attributes": e.other_types,
            "standard_information": None if e.si is None else dict(
                times(e.si), attributes=e.si.attributes,
                attribute_names=[n for b, n in ntfs.FILE_ATTRIBUTES.items()
                                 if e.si.attributes & b],
                owner_id=e.si.owner_id, security_id=e.si.security_id,
                usn=e.si.usn),
            "file_names": [dict(times(n), name=n.name, namespace=n.namespace_name,
                                parent_record=n.parent_record,
                                parent_sequence=n.parent_sequence,
                                real_size=n.real_size, alloc_size=n.alloc_size)
                           for n in e.names],
            "streams": streams,
            "indicators": [{"code": c, "measured": ntfs.INDICATORS[c][0],
                            "also_produced_by": ntfs.INDICATORS[c][1]}
                           for c in e.indicators()],
            "problems": e.problems,
            "journal": journal_for(case, evidence_id, volume, record),
        }
    finally:
        source.close()


def _text_excerpt(data: bytes, limit: int = 2000) -> str:
    """Printable runs of ASCII and UTF-16LE text, for a preview pane."""
    found = [m.group().decode("ascii") for m in
             re.finditer(rb"[\x20-\x7e\t]{4,}", data)]
    found += [m.group().decode("utf-16-le", "replace") for m in
              re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)]
    out, used = [], 0
    for s in found:
        if used + len(s) > limit:
            break
        out.append(s)
        used += len(s) + 1
    return "\n".join(out)


def _hexdump(data: bytes, width: int = 16, rows: int = 32, base: int = 0) -> str:
    lines = []
    for i in range(0, min(len(data), width * rows), width):
        chunk = data[i:i + width]
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        lines.append(f"{base + i:08X}  {chunk.hex(' '):<{width * 3}} {text}")
    return "\n".join(lines)


def preview_entry(case, evidence_id: str, volume: int, record: int,
                  stream: str = "", *, limit: int = PREVIEW_BYTES) -> dict:
    """The first bytes of an entry's stream, identified — written nowhere."""
    limit = max(0, min(limit, PREVIEW_MAX))
    source, vol, _row = open_ntfs(case, evidence_id, volume)
    try:
        e = vol.entry(record)
        if e is None:
            raise EvidenceError(f"Record {record} is empty.")
        s = e.stream(stream)
        if s is None:
            raise EvidenceError(f"Record {record} has no stream {stream!r}.")
        fn = e.preferred_name()
        out = {"record": record, "sequence": e.sequence, "in_use": e.in_use,
               "name": fn.name if fn else "", "stream": stream,
               "size": s.data_size, "resident": s.resident, "refused": ""}
        if not s.resident:
            total, used = vol.count_allocated(s.runs)
            out.update(clusters=total, clusters_now_allocated=used)
        try:
            data = vol.read_stream(s, 0, limit)
        except FileSystemError as exc:
            out.update(refused=str(exc), data=b"", hex="", text="", type=None)
            return out
        found = filetype.identify(data[:filetype.HEAD_BYTES], name=out["name"],
                                  size=s.data_size)
        out.update(data=data, hex=_hexdump(data), text=_text_excerpt(data),
                   type=found.as_dict(), entropy=filetype.entropy(data[:65536]))
        return out
    finally:
        source.close()


def _safe_name(name: str, fallback: str) -> str:
    clean = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", name or "").strip(" .")
    if clean.upper().split(".")[0] in {"CON", "PRN", "AUX", "NUL", *(
            f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}:
        clean = "_" + clean
    return clean[:180] or fallback


@dataclass(frozen=True)
class Recovered:
    evidence_id: str
    dest: str
    hashes: dict
    provenance: dict

    def as_dict(self) -> dict:
        return asdict(self)


def recover_entry(case, evidence_id: str, volume: int, record: int,
                  stream: str = "", *, reason: str) -> Recovered:
    """Copy one MFT entry's stream out of the image, stating how it was found."""
    if not (reason or "").strip():
        raise EvidenceError("A recovery needs a reason; custody records why.")
    source, vol, row = open_ntfs(case, evidence_id, volume)
    try:
        e = vol.entry(record)
        if e is None:
            raise EvidenceError(f"Record {record} is empty.")
        s = e.stream(stream)
        if s is None:
            raise EvidenceError(f"Record {record} has no stream {stream!r}.")
        vol.refuse_unreadable(s)
        fn = e.preferred_name()
        with _index.session(case.root) as conn:
            known = conn.execute("SELECT path, path_status FROM ntfs_entries "
                                 "WHERE evidence_id = ? AND volume = ? AND "
                                 "record = ?", (evidence_id, volume, record)
                                 ).fetchone()
        name = _safe_name(fn.name if fn else "", f"record-{record}")
        if stream:
            name = f"{name}~{_safe_name(stream, 'stream')}"
        dest = _extract.free_name(case.path(
            "extracted", evidence_id, f"v{volume}", "mft",
            f"{record}-{e.sequence}", name))
        clusters = used = None
        if not s.resident:
            clusters, used = vol.count_allocated(s.runs)
        provenance = {
            "method": "mft-entry", "volume": volume, "volume_entry": row["entry"],
            "record": record, "sequence": e.sequence, "in_use": e.in_use,
            "name": fn.name if fn else "", "stream": stream,
            "path": known["path"] if known else None,
            "path_status": known["path_status"] if known else None,
            "size": s.data_size, "resident": s.resident,
            "runs": s.runs_as_list(), "run_problems": vol.run_problems(s),
            "clusters": clusters, "clusters_now_allocated": used,
            "reason": reason}
        if not e.in_use and used:
            provenance["caution"] = (
                f"{used} of this deleted file's {clusters} clusters are now "
                "allocated, so those bytes may belong to another file.")
        hashes = _extract.copy_stream_to_case(case, vol.iter_stream(s), dest)
        provenance["dest"] = os.fspath(dest)
        case.custody.record("entry.recovered", actor=case.actor(),
                            target=f"{evidence_id}:v{volume}:mft{record}"
                                   + (f":{stream}" if stream else ""),
                            hashes=hashes.as_dict(), detail=provenance)
        return Recovered(evidence_id, os.fspath(dest), hashes.as_dict(), provenance)
    finally:
        source.close()


# ---------------------------------------------------------------------------
# the change journal
# ---------------------------------------------------------------------------

@dataclass
class JournalSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    record: int | None = None
    stream_size: int = 0
    data_bytes: int = 0
    records: int = 0
    versions: dict = field(default_factory=dict)
    skipped_bytes: int = 0
    usn_offset_mismatches: int = 0
    first_usn_delta: int | None = None
    earliest_utc: str | None = None
    latest_utc: str | None = None
    records_sha256: str = ""
    notes: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


USN_COLUMNS = ("evidence_id", "volume", "offset", "usn", "version",
               "file_record", "file_sequence", "parent_record",
               "parent_sequence", "timestamp", "reasons", "reason_names",
               "source_info", "attributes", "name", "run_id")


def find_journal(case, evidence_id: str, volume: int) -> int | None:
    with _index.session(case.root) as conn:
        row = conn.execute("SELECT record FROM ntfs_entries WHERE evidence_id = ? "
                           "AND volume = ? AND name = '$UsnJrnl' AND "
                           "parent_record = ? AND in_use = 1",
                           (evidence_id, volume, ntfs.EXTEND)).fetchone()
    return None if row is None else row["record"]


def parse_journal(case, evidence_id: str, volume: int, *, progress=None,
                  should_cancel=None) -> JournalSummary:
    """`$Extend\\$UsnJrnl:$J` into the index. Needs the volume parsed first."""
    record = find_journal(case, evidence_id, volume)
    if record is None:
        raise EvidenceError(f"No $UsnJrnl is indexed for {evidence_id} volume "
                            f"{volume}. Parse the NTFS volume first; if it has "
                            "been parsed, the journal is absent.")
    source, vol, _row = open_ntfs(case, evidence_id, volume)
    run_id, started = _start_run(case, evidence_id, "usn", volume, {})
    summary = JournalSummary(evidence_id, volume, run_id, "running",
                             record=record, started_at=started)
    case.custody.record("usn.started", actor=case.actor(), target=evidence_id,
                        detail={"run_id": run_id, "volume": volume,
                                "record": record})
    conn = _index.connect(case.root)
    rows: list = []
    digest = hashlib.sha256()
    stats = usn.ScanStats()
    try:
        entry = vol.entry(record)
        j = entry.stream("$J") if entry else None
        if j is None:
            raise FileSystemError("$UsnJrnl has no $J stream.")
        summary.stream_size = j.data_size
        if j.resident:
            extents = [(0, j.data_size)]
        else:
            cs = vol.cluster
            extents = [(v * cs, min((v + n) * cs, j.data_size))
                       for v, lcn, n in j.runs if lcn is not None and v * cs < j.data_size]
        summary.data_bytes = sum(e - s for s, e in extents)
        conn.execute("DELETE FROM usn_records WHERE evidence_id = ? AND volume = ?",
                     (evidence_id, volume))
        earliest = latest = None
        last = 0.0
        for rec in usn.scan(lambda off, n: vol.read_stream(j, off, n), j.data_size,
                            extents=extents, should_cancel=should_cancel,
                            stats=stats):
            names = ",".join(usn.reason_names(rec.reasons))
            rows.append((evidence_id, volume, rec.offset, rec.usn, rec.version,
                         rec.file_record, rec.file_sequence, rec.parent_record,
                         rec.parent_sequence, rec.timestamp, rec.reasons, names,
                         rec.source_info, rec.attributes, rec.name, run_id))
            digest.update(f"{rec.offset}\t{rec.usn}\t{rec.file_record}\t"
                          f"{rec.file_sequence}\t{rec.timestamp}\t{rec.reasons}\t"
                          f"{rec.name}\n".encode("utf-8"))
            if rec.timestamp:
                earliest = rec.timestamp if earliest is None else min(earliest, rec.timestamp)
                latest = rec.timestamp if latest is None else max(latest, rec.timestamp)
            if len(rows) >= BATCH:
                conn.executemany(f"INSERT OR REPLACE INTO usn_records "
                                 f"({', '.join(USN_COLUMNS)}) VALUES "
                                 f"({', '.join('?' for _ in USN_COLUMNS)})", rows)
                conn.commit()
                rows.clear()
            now = time.monotonic()
            if progress is not None and now - last > 0.5:
                last = now
                progress(f"journal: {stats.records:,} records")
        if rows:
            conn.executemany(f"INSERT OR REPLACE INTO usn_records "
                             f"({', '.join(USN_COLUMNS)}) VALUES "
                             f"({', '.join('?' for _ in USN_COLUMNS)})", rows)
            conn.commit()
        summary.earliest_utc = timeutil.decode(earliest, "filetime")
        summary.latest_utc = timeutil.decode(latest, "filetime")
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    except BaseException as exc:
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        conn.close()
        source.close()
        summary.records = stats.records
        summary.versions = {str(k): v for k, v in (stats.versions or {}).items()}
        summary.skipped_bytes = stats.skipped_bytes
        summary.usn_offset_mismatches = stats.usn_offset_mismatches
        summary.first_usn_delta = stats.first_usn_delta
        if stats.usn_offset_mismatches:
            summary.notes.append(
                f"{stats.usn_offset_mismatches:,} records carry a USN that is "
                "not their offset in $J (first difference "
                f"{stats.first_usn_delta:,} bytes). Records are kept; the "
                "journal was altered or read from a copy that was trimmed.")
        summary.finished_at = utc_now()
        summary.records_sha256 = digest.hexdigest()
        _finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(
            f"usn.{summary.state}", actor=case.actor(), target=evidence_id,
            hashes=({"records": summary.records_sha256}
                    if summary.state == "completed" else {}),
            detail=summary.as_dict())
    return summary


def journal_for(case, evidence_id: str, volume: int, record: int,
                limit: int = 200) -> list[dict]:
    with _index.session(case.root) as conn:
        rows = [dict(r) for r in conn.execute(
            "SELECT * FROM usn_records WHERE evidence_id = ? AND volume = ? AND "
            "file_record = ? ORDER BY usn LIMIT ?",
            (evidence_id, volume, record, limit))]
    for r in rows:
        r["timestamp_utc"] = timeutil.decode(r["timestamp"], "filetime")
    return rows


def list_journal(case, evidence_id: str, volume: int, *, search: str = "",
                 reason: str = "", limit: int = 500, offset: int = 0) -> tuple[list, int]:
    where, args = ["evidence_id = ?", "volume = ?"], [evidence_id, volume]
    if search:
        where.append("name LIKE ?")
        args.append(f"%{search}%")
    if reason:
        bit = usn.REASON_BITS.get(reason.upper())
        if bit is None:
            raise ValueError(f"unknown reason {reason!r}")
        where.append("(reasons & ?) != 0")
        args.append(bit)
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM usn_records WHERE {clause}",
                             args).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM usn_records WHERE {clause} ORDER BY usn LIMIT ? "
            "OFFSET ?", [*args, limit, offset])]
    for r in rows:
        r["timestamp_utc"] = timeutil.decode(r["timestamp"], "filetime")
        r["source_names"] = usn.source_names(r["source_info"] or 0)
    return rows, total


# ---------------------------------------------------------------------------
# carving
# ---------------------------------------------------------------------------

def carve_evidence(case, evidence_id: str, *, volume: int | None = None,
                   unallocated: bool = False, types=None, aligned: int = 512,
                   progress=None, should_cancel=None) -> _carve.CarveSummary:
    """Carve the whole image, one volume or gap, or a volume's free clusters."""
    if unallocated and volume is None:
        raise EvidenceError("Unallocated-only carving needs a volume.")
    if volume is None:
        source = open_image(case, evidence_id)
        regions, scope = [(0, source.size)], "image"
    elif unallocated:
        source, vol, row = open_ntfs(case, evidence_id, volume)
        cs = vol.cluster
        regions = [(row["offset"] + lcn * cs, row["offset"] + (lcn + n) * cs)
                   for lcn, n in vol.free_extents()]
        scope = "unallocated"
    else:
        row = volume_row(case, evidence_id, volume)
        source = open_image(case, evidence_id)
        regions = [(row["offset"], row["offset"] + row["length"])]
        scope = "gap" if row["kind"] == "gap" else "volume"
    try:
        return _carve.carve(case, evidence_id, source, regions, scope=scope,
                            volume=volume, types=types, aligned=aligned,
                            progress=progress, should_cancel=should_cancel)
    finally:
        source.close()


def preview_candidate(case, evidence_id: str, candidate_id: int, *,
                      limit: int = PREVIEW_BYTES) -> dict:
    """A carve candidate's bytes in memory, with its row. Writes nothing."""
    row = _carve.candidate(case, evidence_id, candidate_id)
    limit = max(0, min(limit, PREVIEW_MAX))
    source = open_image(case, evidence_id)
    try:
        data = source.read_at(row["offset"], min(row["length"], limit))
    finally:
        source.close()
    found = filetype.identify(data[:filetype.HEAD_BYTES], size=row["length"])
    return dict(row, data=data, hex=_hexdump(data, base=0),
                text=_text_excerpt(data), type=found.as_dict(),
                complete_in_preview=len(data) >= row["length"])


def recover_candidate(case, evidence_id: str, candidate_id: int, *,
                      reason: str) -> Recovered:
    if not (reason or "").strip():
        raise EvidenceError("A recovery needs a reason; custody records why.")
    row = _carve.candidate(case, evidence_id, candidate_id)
    source = open_image(case, evidence_id)
    try:
        name = f"{row['offset']:012X}-{row['type_id']}.{row['ext'] or 'bin'}"
        dest = _extract.free_name(case.path("extracted", evidence_id, "carved",
                                            name))

        def chunks():
            pos, end = row["offset"], row["offset"] + row["length"]
            while pos < end:
                piece = source.read_at(pos, min(1 << 20, end - pos))
                if not piece:
                    break
                yield piece
                pos += len(piece)

        hashes = _extract.copy_stream_to_case(case, chunks(), dest)
    finally:
        source.close()
    provenance = {
        "method": "carved", "claim": "candidate", "offset": row["offset"],
        "length": row["length"], "basis": row["basis"], "status": row["status"],
        "note": row["note"], "type_id": row["type_id"], "label": row["label"],
        "scope": row["scope"], "volume": row["volume"], "run_id": row["run_id"],
        "candidate_id": candidate_id, "reason": reason, "dest": os.fspath(dest)}
    if hashes.size < row["length"]:
        provenance["caution"] = (f"Only {hashes.size:,} of {row['length']:,} "
                                 "bytes could be read: the image ends first.")
    case.custody.record("carve.recovered", actor=case.actor(),
                        target=f"{evidence_id}:carve{candidate_id}",
                        hashes=hashes.as_dict(), detail=provenance)
    return Recovered(evidence_id, os.fspath(dest), hashes.as_dict(), provenance)


# ---------------------------------------------------------------------------
# slack
# ---------------------------------------------------------------------------

@dataclass
class SlackSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    streams_examined: int = 0
    with_slack: int = 0
    slack_bytes: int = 0
    nonzero_regions: int = 0
    nonzero_bytes: int = 0
    regions_sha256: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def scrape_slack(case, evidence_id: str, volume: int, *, progress=None,
                 should_cancel=None) -> SlackSummary:
    """Read the file slack of every in-use non-resident stream on a parsed
    NTFS volume and index the regions that are not zero-filled."""
    source, vol, row = open_ntfs(case, evidence_id, volume)
    run_id, started = _start_run(case, evidence_id, "slack", volume, {})
    summary = SlackSummary(evidence_id, volume, run_id, "running",
                           started_at=started)
    case.custody.record("slack.started", actor=case.actor(), target=evidence_id,
                        detail={"run_id": run_id, "volume": volume})
    conn = _index.connect(case.root)
    digest = hashlib.sha256()
    pending: list = []
    try:
        streams = conn.execute(
            "SELECT s.record, s.name, s.size, s.allocated, s.initialized, "
            "s.flags, s.runs FROM ntfs_streams s JOIN ntfs_entries e ON "
            "e.evidence_id = s.evidence_id AND e.volume = s.volume AND "
            "e.record = s.record WHERE s.evidence_id = ? AND s.volume = ? AND "
            "s.resident = 0 AND s.size > 0 AND e.in_use = 1 ORDER BY s.record",
            (evidence_id, volume)).fetchall()
        if not streams and not conn.execute(
                "SELECT 1 FROM ntfs_entries WHERE evidence_id = ? AND volume = ? "
                "LIMIT 1", (evidence_id, volume)).fetchone():
            raise EvidenceError(f"Volume {volume} has not been parsed; parse "
                                "the NTFS volume first.")
        conn.execute("DELETE FROM slack_regions WHERE evidence_id = ? AND volume = ?",
                     (evidence_id, volume))
        last = 0.0
        for s in streams:
            if should_cancel is not None and should_cancel():
                raise Cancelled("slack scraping was cancelled")
            summary.streams_examined += 1
            stream = ntfs.Stream(s["name"], False, s["flags"], s["size"],
                                 s["allocated"], s["initialized"],
                                 [tuple(r) for r in json.loads(s["runs"])], b"",
                                 0, 1)
            info = vol.file_slack(stream)
            if not info or not info["length"]:
                continue
            summary.with_slack += 1
            summary.slack_bytes += info["length"]
            data = vol.reader.read_at(info["offset"], info["length"])
            nonzero = len(data) - data.count(0)
            if not nonzero:
                continue
            summary.nonzero_regions += 1
            summary.nonzero_bytes += nonzero
            disk_offset = row["offset"] + info["offset"]
            text = _text_excerpt(data, 400)
            pending.append((evidence_id, volume, s["record"], s["name"],
                            disk_offset, info["length"], nonzero,
                            filetype.entropy(data), text, run_id))
            digest.update(f"{s['record']}\t{s['name']}\t{disk_offset}\t"
                          f"{info['length']}\t{nonzero}\n".encode("utf-8"))
            if len(pending) >= BATCH:
                conn.executemany("INSERT OR REPLACE INTO slack_regions VALUES "
                                 "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", pending)
                conn.commit()
                pending.clear()
            now = time.monotonic()
            if progress is not None and now - last > 0.5:
                last = now
                progress(f"slack: {summary.streams_examined:,} streams, "
                         f"{summary.nonzero_regions:,} with data")
        if pending:
            conn.executemany("INSERT OR REPLACE INTO slack_regions VALUES "
                             "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", pending)
        conn.commit()
        summary.state = "completed"
    except Cancelled:
        summary.state = "cancelled"
    except BaseException as exc:
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        conn.close()
        source.close()
        summary.finished_at = utc_now()
        summary.regions_sha256 = digest.hexdigest()
        _finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(
            f"slack.{summary.state}", actor=case.actor(), target=evidence_id,
            hashes=({"regions": summary.regions_sha256}
                    if summary.state == "completed" else {}),
            detail=summary.as_dict())
    return summary


def list_slack(case, evidence_id: str, volume: int, *, limit: int = 500,
               offset: int = 0) -> tuple[list, int]:
    with _index.session(case.root) as conn:
        total = conn.execute("SELECT COUNT(*) FROM slack_regions WHERE "
                             "evidence_id = ? AND volume = ?",
                             (evidence_id, volume)).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            "SELECT r.*, e.path FROM slack_regions r LEFT JOIN ntfs_entries e ON "
            "e.evidence_id = r.evidence_id AND e.volume = r.volume AND "
            "e.record = r.record WHERE r.evidence_id = ? AND r.volume = ? "
            "ORDER BY r.nonzero DESC LIMIT ? OFFSET ?",
            (evidence_id, volume, limit, offset))]
    return rows, total


def slack_preview(case, evidence_id: str, volume: int, record: int,
                  stream: str = "") -> dict:
    """One stream's slack bytes, re-read from the image. Writes nothing."""
    source, vol, row = open_ntfs(case, evidence_id, volume)
    try:
        e = vol.entry(record)
        s = e.stream(stream) if e else None
        if s is None:
            raise EvidenceError(f"Record {record} has no stream {stream!r}.")
        info = vol.file_slack(s)
        if not info or not info["length"]:
            return {"record": record, "stream": stream, "slack": info,
                    "data": b"", "hex": "", "text": ""}
        data = vol.reader.read_at(info["offset"], info["length"])
        return {"record": record, "stream": stream, "slack": info,
                "disk_offset": row["offset"] + info["offset"], "data": data,
                "hex": _hexdump(data, base=info["offset"]),
                "text": _text_excerpt(data)}
    finally:
        source.close()
