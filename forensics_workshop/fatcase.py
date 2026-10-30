# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""FAT12/16/32 and exFAT volumes inside a case: parse, list, look, recover
(FORENSICS_PLAN §14 item 2, 2026-10-29).

The parsing is `fat.py`'s; this module is the case's side of it, shaped
like the NTFS functions in `diskimage.py` so a page treats both the same.

* `parse_fat` walks every directory of one FAT or exFAT volume of a
  registered image — live entries, deleted ones, entries in deleted folders
  and entries hidden after an end-of-directory marker — into the case index
  (`fat_entries`), with a run record and custody either side. The volume's
  own facts and problems land as one `fat-volume` row in the artefacts
  index, so a damaged boot sector or FAT is never lost from the corpus.
* `list_fat_entries`, `fat_entry_detail` read the index back.
* `preview_fat_entry` reads a file's bytes into memory (written nowhere);
  `recover_fat_entry` copies them into the case with a reason, and custody
  records HOW the bytes were found — through the FAT chain, or, for a
  deleted file whose chain FAT zeroed, on the contiguous assumption, with
  how many of those clusters are now allocated to something else.

**WHAT IS SHOWN IS WHAT IS ON THE IMAGE NOW.** The index keeps each entry's
directory slot as it was parsed — FAT's short-name slot; exFAT's File and
Stream Extension slots, which hold the first cluster, the size and the
NoFatChain flag — and a preview or a recovery re-reads it from the image and
refuses to go on if it differs (re-parse the volume), because the cluster
list it would follow came from that slot.

**A FAT TIME IS LOCAL, WITH NO ZONE.** It is kept raw with its epoch and a
naive decoded value, and is never written into a UTC column; exFAT's is UTC
only where its offset field was valid. See `fat.EPOCHS`.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field

from . import diskimage as _disk
from . import extract as _extract
from . import fat
from . import filetype, image
from . import index as _index
from .errors import Cancelled, EvidenceError, FileSystemError
from .timeutil import utc_now

PARSER_VERSION = "fatcase/1"
#: the `fs_type` values partitions.py gives a FAT or exFAT volume
FAT_TYPES = ("fat", "fat32", "exfat")
ENTRY_FILTERS = ("all", "in-use", "deleted", "directories", "problems",
                 "past-end", "in-deleted-dir")
BATCH = 2000

COLUMNS = ("evidence_id", "volume", "entry_id", "fs", "path", "name", "is_dir",
           "deleted", "in_deleted_dir", "past_end_marker", "size",
           "first_cluster", "attributes", "modified_raw", "modified_epoch",
           "modified_value", "created_raw", "created_epoch", "created_value",
           "accessed_raw", "accessed_epoch", "accessed_value",
           "dir_entry_offset", "slot_hex", "recovery_basis", "clusters",
           "clusters_now_allocated", "problems", "detail_json", "run_id")


@dataclass
class FatSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    fs: str = ""
    label: str = ""
    serial: str = ""
    entries: int = 0
    deleted: int = 0
    folders: int = 0
    in_deleted_dirs: int = 0
    past_end_marker: int = 0
    with_problems: int = 0
    orphan_names: int = 0
    volume_problems: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def open_fat_volume(case, evidence_id: str, volume: int):
    """(image source, FatVolume, volume row). The caller closes the source."""
    row = _disk.volume_row(case, evidence_id, volume)
    if row.get("fs_type") not in FAT_TYPES:
        raise EvidenceError(
            f"Volume {volume} of {evidence_id} was identified as "
            f"{row.get('fs_label') or row.get('fs_type') or 'unknown'}, not FAT "
            "or exFAT.")
    source = _disk.open_image(case, evidence_id)
    try:
        vol = fat.open_fat(image.Region(source, row["offset"], row["length"]))
    except FileSystemError as exc:
        source.close()
        raise FileSystemError(
            f"Volume {volume} ({row['entry']}) could not be read as FAT or "
            f"exFAT: {exc}") from exc
    except BaseException:
        source.close()
        raise
    return source, vol, row


def _slot_span(vol, e) -> int:
    """How many bytes from `dir_entry_offset` the slot check covers. FAT:
    the 32-byte short-name slot, which holds the first cluster and the size
    the content is read by. exFAT: the File slot AND the Stream Extension
    slot after it (first cluster, size, valid-data length, NoFatChain) —
    64 bytes — unless that second slot sits in the folder's NEXT cluster,
    which need not be adjacent; then the File slot only, and the detail says
    so."""
    if getattr(vol, "fs_type", "") != "exFAT":
        return fat.SLOT
    try:
        heap = vol.cluster_offset(2)
        cs = vol.cluster_size
    except Exception:                                     # noqa: BLE001
        return fat.SLOT
    rel = e.dir_entry_offset - heap
    if rel >= 0 and rel // cs == (rel + 2 * fat.SLOT - 1) // cs:
        return 2 * fat.SLOT
    return fat.SLOT


def _times(t) -> tuple:
    if t is None:
        return None, None, None
    return t.raw, t.epoch, t.value


def _db_row(evidence_id, volume, run_id, n, e, slot: bytes) -> tuple:
    d = e.as_dict()
    rec = e.recoverable or {}
    return (evidence_id, volume, n, e.fs, e.path, e.name, int(e.is_dir),
            int(e.deleted), int(e.in_deleted_dir), int(e.past_end_marker),
            e.size, e.first_cluster, e.attributes, *_times(e.modified),
            *_times(e.created), *_times(e.accessed), e.dir_entry_offset,
            slot.hex(), e.recovery_basis, e.clusters,
            rec.get("now_allocated"), json.dumps(list(e.problems)),
            json.dumps(d, ensure_ascii=False, default=str), run_id)


def parse_fat(case, evidence_id: str, volume: int, *, progress=None,
              should_cancel=None) -> FatSummary:
    """Every directory entry of one FAT/exFAT volume, live and deleted, into
    the case index. Re-running replaces the volume's rows."""
    # Opened first: a volume that is not FAT is refused before a run or a
    # custody record says one started.
    source, vol, _row = open_fat_volume(case, evidence_id, volume)
    try:
        run_id, started = _disk._start_run(case, evidence_id, "fat", volume,
                                           {"parser_version": PARSER_VERSION})
    except BaseException:
        source.close()
        raise
    summary = FatSummary(evidence_id, volume, run_id, "running",
                         started_at=started)
    try:
        case.custody.record("fat.started", actor=case.actor(),
                            target=f"{evidence_id}:v{volume}",
                            detail={"run_id": run_id, "volume": volume,
                                    "parser_version": PARSER_VERSION})
        # All entries first: a cross-link note can be added to an entry
        # after it was yielded (fat.FatVolume.entries).
        entries = []
        for e in vol.entries(should_cancel=should_cancel):
            entries.append(e)
            if progress is not None and len(entries) % 5000 == 0:
                progress(f"{len(entries):,} entries read")
        info = vol.info()
        summary.fs = vol.fs_type
        summary.label = info.get("label") or ""
        summary.serial = info.get("serial") or ""
        summary.volume_problems = list(info.get("problems") or [])[:200]
        summary.orphan_names = len(vol.orphan_names)
        rows = []
        for n, e in enumerate(entries, 1):
            slot = vol.reader.read_at(e.dir_entry_offset, _slot_span(vol, e))
            rows.append(_db_row(evidence_id, volume, run_id, n, e, slot))
            summary.entries += 1
            summary.deleted += e.deleted
            summary.folders += e.is_dir
            summary.in_deleted_dirs += e.in_deleted_dir
            summary.past_end_marker += e.past_end_marker
            summary.with_problems += bool(e.problems)
        marks = ",".join("?" * len(COLUMNS))
        with _index.session(case.root) as conn:
            conn.execute("DELETE FROM fat_entries WHERE evidence_id = ? AND "
                         "volume = ?", (evidence_id, volume))
            for i in range(0, len(rows), BATCH):
                conn.executemany(f"INSERT INTO fat_entries ({','.join(COLUMNS)}) "
                                 f"VALUES ({marks})", rows[i:i + BATCH])
            conn.execute("DELETE FROM artefacts WHERE evidence_id = ? AND "
                         "parser = 'fat' AND row_ref = ?",
                         (evidence_id, f"v{volume}:volume"))
            info.update(entries=summary.entries, deleted_entries=summary.deleted,
                        orphan_names=vol.orphan_names[:200],
                        orphan_names_total=summary.orphan_names)
            label = f" '{summary.label}'" if summary.label else ""
            conn.execute(
                "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
                "parser, artefact, title, value, detail_json, provenance, "
                "row_ref) VALUES (?, ?, ?, 'fat', ?, ?, ?, ?, 'fat-native', ?)",
                (run_id, evidence_id, f"volume {volume}",
                 "exfat-volume" if vol.fs_type == "exFAT" else "fat-volume",
                 f"{vol.fs_type} volume{label}",
                 f"{vol.fs_type}{label} serial {summary.serial} · "
                 f"{summary.entries:,} entries, {summary.deleted:,} deleted · "
                 f"{len(info.get('problems') or [])} problem(s)",
                 json.dumps(info, ensure_ascii=False, default=str),
                 f"v{volume}:volume"))
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
        _disk._finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(f"fat.{summary.state}", actor=case.actor(),
                            target=f"{evidence_id}:v{volume}",
                            detail=summary.as_dict())
    return summary


def _decode(row: dict) -> dict:
    try:
        row["problems"] = json.loads(row.get("problems") or "[]")
    except ValueError:
        row["problems"] = []
    try:
        row["detail"] = json.loads(row.pop("detail_json", None) or "{}")
    except ValueError:
        row["detail"] = {}
    row["attribute_names"] = row["detail"].get("attribute_names") or []
    return row


def list_fat_entries(case, evidence_id: str, volume: int, *,
                     filter: str = "all", search: str = "", limit: int = 500,
                     offset: int = 0) -> tuple[list, int]:
    if filter not in ENTRY_FILTERS:
        raise ValueError(f"filter must be one of {ENTRY_FILTERS}")
    where = ["evidence_id = ?", "volume = ?", {
        "all": "1", "in-use": "deleted = 0", "deleted": "deleted = 1",
        "directories": "is_dir = 1", "problems": "problems != '[]'",
        "past-end": "past_end_marker = 1",
        "in-deleted-dir": "in_deleted_dir = 1"}[filter]]
    args: list = [evidence_id, volume]
    if search:
        where.append("path LIKE ? ESCAPE '\\'")
        args.append("%" + search.replace("\\", "\\\\").replace("%", "\\%")
                    .replace("_", "\\_") + "%")
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM fat_entries WHERE {clause}",
                             args).fetchone()[0]
        rows = [_decode(dict(r)) for r in conn.execute(
            f"SELECT * FROM fat_entries WHERE {clause} ORDER BY path, entry_id "
            "LIMIT ? OFFSET ?", [*args, limit, offset])]
    return rows, total


def _stored(case, evidence_id, volume, entry_id) -> dict:
    with _index.session(case.root) as conn:
        row = conn.execute("SELECT * FROM fat_entries WHERE evidence_id = ? AND "
                           "volume = ? AND entry_id = ?",
                           (evidence_id, volume, entry_id)).fetchone()
    if row is None:
        raise EvidenceError(f"No entry {entry_id} on volume {volume} of "
                            f"{evidence_id}. Parse the volume first.")
    return _decode(dict(row))


def _entry(d: dict) -> fat.FatEntry:
    """The FatEntry the parse saw, rebuilt from the index — enough for
    `read_file`, which follows its chain and size."""
    return fat.FatEntry(
        fs=d.get("fs", ""), path=d.get("path", ""), name=d.get("name", ""),
        short_name=d.get("short_name", ""), long_name=d.get("long_name", ""),
        is_dir=bool(d.get("is_dir")), deleted=bool(d.get("deleted")),
        size=int(d.get("size") or 0), first_cluster=int(d.get("first_cluster") or 0),
        attributes=int(d.get("attributes") or 0), created=None, modified=None,
        accessed=None, dir_entry_offset=int(d.get("dir_entry_offset") or 0),
        set_offset=int(d.get("set_offset") or 0), slots=int(d.get("slots") or 1),
        chain=[tuple(r) for r in d.get("chain") or []],
        recovery_basis=d.get("recovery_basis") or "none",
        valid_data_length=d.get("valid_data_length"),
        no_fat_chain=d.get("no_fat_chain"))


def _check_slot(vol, stored: dict) -> str:
    """'' when the slot on the image is the one parsed, else why not."""
    span = max(fat.SLOT, len(stored.get("slot_hex") or "") // 2)
    now = vol.reader.read_at(stored["dir_entry_offset"], span).hex()
    if now != stored.get("slot_hex"):
        return ("The directory slot at volume offset "
                f"{stored['dir_entry_offset']:,} no longer matches what was "
                "parsed. Parse the volume again before reading this entry.")
    return ""


def fat_entry_detail(case, evidence_id: str, volume: int, entry_id: int) -> dict:
    """The entry as indexed, with its slot re-checked against the image."""
    stored = _stored(case, evidence_id, volume, entry_id)
    source, vol, row = open_fat_volume(case, evidence_id, volume)
    try:
        stored["slot_check"] = _check_slot(vol, stored) or "matches the image"
        if stored.get("fs") == "exFAT" and len(stored.get("slot_hex") or "") \
                < 4 * fat.SLOT:
            stored["slot_check"] += (" (the File slot only: its Stream "
                                     "Extension slot is in the folder's next "
                                     "cluster and is not re-checked)")
        stored["volume_entry"] = row["entry"]
        stored["epochs"] = {k: fat.EPOCHS[k] for k in {
            stored.get("modified_epoch"), stored.get("created_epoch"),
            stored.get("accessed_epoch")} if k in fat.EPOCHS}
    finally:
        source.close()
    return stored


def preview_fat_entry(case, evidence_id: str, volume: int, entry_id: int, *,
                      limit: int = _disk.PREVIEW_BYTES) -> dict:
    """The first bytes of a file, identified — written nowhere."""
    limit = max(0, min(limit, _disk.PREVIEW_MAX))
    stored = _stored(case, evidence_id, volume, entry_id)
    out = {"record": entry_id, "entry_id": entry_id, "in_use": not stored["deleted"],
           "name": stored["name"], "stream": "", "size": stored["size"],
           "resident": False, "refused": "",
           "recovery_basis": stored["recovery_basis"],
           "clusters": stored["clusters"],
           "clusters_now_allocated": stored["clusters_now_allocated"]}
    if stored["is_dir"]:
        out.update(refused="This is a folder; its content is directory "
                           "entries, which the table lists.",
                   data=b"", hex="", text="", type=None)
        return out
    source, vol, _row = open_fat_volume(case, evidence_id, volume)
    try:
        why = _check_slot(vol, stored)
        if why:
            out.update(refused=why, data=b"", hex="", text="", type=None)
            return out
        try:
            data = vol.read_file(_entry(stored["detail"]), 0, limit)
        except FileSystemError as exc:
            out.update(refused=str(exc), data=b"", hex="", text="", type=None)
            return out
        found = filetype.identify(data[:filetype.HEAD_BYTES], name=out["name"],
                                  size=stored["size"])
        out.update(data=data, hex=_disk._hexdump(data),
                   text=_disk._text_excerpt(data), type=found.as_dict(),
                   entropy=filetype.entropy(data[:65536]))
        return out
    finally:
        source.close()


def recover_fat_entry(case, evidence_id: str, volume: int, entry_id: int, *,
                      reason: str) -> _disk.Recovered:
    """Copy one FAT/exFAT file out of the image, stating how it was found."""
    if not (reason or "").strip():
        raise EvidenceError("A recovery needs a reason; custody records why.")
    stored = _stored(case, evidence_id, volume, entry_id)
    if stored["is_dir"]:
        raise EvidenceError(f"'{stored['path']}' is a folder; recover the files "
                            "in it one by one.")
    source, vol, row = open_fat_volume(case, evidence_id, volume)
    try:
        why = _check_slot(vol, stored)
        if why:
            raise EvidenceError(why)
        entry = _entry(stored["detail"])
        name = _disk._safe_name(stored["name"], f"entry-{entry_id}")
        dest = _extract.free_name(case.path(
            "extracted", evidence_id, f"v{volume}", "fat", str(entry_id), name))
        provenance = {
            "method": "fat-entry", "fs": stored["fs"], "volume": volume,
            "volume_entry": row["entry"], "entry_id": entry_id,
            "path": stored["path"], "deleted": bool(stored["deleted"]),
            "in_deleted_dir": bool(stored["in_deleted_dir"]),
            "size": stored["size"], "first_cluster": stored["first_cluster"],
            "chain": stored["detail"].get("chain"),
            "recovery_basis": stored["recovery_basis"],
            "clusters": stored["clusters"],
            "clusters_now_allocated": stored["clusters_now_allocated"],
            "dir_entry_offset": stored["dir_entry_offset"],
            "times": {k: {"raw": stored[f"{k}_raw"], "epoch": stored[f"{k}_epoch"],
                          "value": stored[f"{k}_value"]}
                      for k in ("modified", "created", "accessed")},
            "reason": reason}
        cautions = []
        if stored["recovery_basis"] == "contiguous-assumption":
            cautions.append("This deleted file's cluster chain was zeroed by "
                            "the deletion; its bytes were read on the ASSUMPTION "
                            "that it was contiguous, so a fragmented file reads "
                            "wrong past its first fragment.")
        if stored["deleted"] and stored["clusters_now_allocated"]:
            cautions.append(f"{stored['clusters_now_allocated']} of its "
                            f"{stored['clusters']} clusters are now allocated, "
                            "so those bytes may belong to another file.")
        if cautions:
            provenance["caution"] = " ".join(cautions)
        hashes = _extract.copy_stream_to_case(case, vol.iter_file(entry), dest)
        provenance["dest"] = os.fspath(dest)
        case.custody.record("entry.recovered", actor=case.actor(),
                            target=f"{evidence_id}:v{volume}:fat{entry_id}",
                            hashes=hashes.as_dict(), detail=provenance)
        return _disk.Recovered(evidence_id, os.fspath(dest), hashes.as_dict(),
                               provenance)
    finally:
        source.close()
