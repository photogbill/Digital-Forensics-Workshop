# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The case's content, for hunts that have to LOOK at it — the pictures, the
videos, the documents and the text — read through the read-only door into
memory (Bill, 2026-10-29).

The deterministic hunts (`hunts.py`) read parsed ROWS. The model's hunts in
ATK (image, video-frame, text and translation hunts) need the BYTES of the
files themselves. This module is how they get them without ATK ever touching
evidence: it lists the hunt-able items of an evidence item — a registered
folder's manifest, or a disk image's NTFS entries — and reads one into
memory through `blocker.open_evidence` or the image's own reader. **It
writes nothing**, with one stated exception:

**A VIDEO NEEDS A FILE.** FFmpeg seeks inside a video by path; a pipe cannot
seek, and an MP4 whose index is at the end cannot be read from a pipe at
all. So `working_copy` writes ONE hashed copy into `<case>/working/`, through
the engine's existing case writer (`extract.copy_stream_to_case`), records it
in custody with the reason, and reuses it on every later run. The evidence
is never handed to another program.

What an item IS is decided from the manifest's type (bytes, not names) for a
folder, and from the extension for an NTFS entry, whose bytes have not been
typed yet — `read_item` re-types the head it reads, and the hunt layer is
told which basis was used.
"""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from . import blocker, filetype
from . import diskimage as _disk
from . import extract as _extract
from . import index as _index
from .errors import EvidenceError
from .timeutil import utc_now

#: What the model's hunts look at.
HUNT_FAMILIES = ("image", "video", "document", "text", "email")
#: For an NTFS entry, whose bytes have not been typed: the extension's family.
EXT_FAMILY = {}
for _fam, _exts in {
        "image": "jpg jpeg jpe png gif bmp tif tiff webp heic heif",
        "video": "mp4 m4v mov avi mkv wmv 3gp 3g2 webm mpg mpeg ts mts m2ts flv",
        "document": "pdf doc docx docm xls xlsx xlsm ppt pptx odt ods odp rtf epub",
        "text": "txt csv tsv log md json xml html htm srt vtt ini cfg",
        "email": "eml mbox msg"}.items():
    for _e in _exts.split():
        EXT_FAMILY[_e] = _fam
#: The manifest's type families that count as each hunt family.
_MANIFEST_FAMILY = {"image": "image", "video": "video", "document": "document",
                    "text": "text"}
#: A manifest "text" file whose extension says email is treated as email.
_EMAIL_EXT = {"eml", "mbox"}
#: Hard cap on what one read brings into memory.
MAX_READ = 64 << 20
WORKING_DIR = "working"
COPY_CHUNK = 1 << 20


@dataclass(frozen=True)
class Item:
    """One file a model hunt can look at."""

    ref: str                 # E001:Users/x/a.jpg · E002:v4:mft1234
    evidence_id: str
    source: str              # file | ntfs
    path: str                # what to show an examiner
    name: str
    size: int
    family: str
    type_label: str
    basis: str               # manifest (typed by bytes) | extension
    sha256: str = ""
    volume: int | None = None
    record: int | None = None
    deleted: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _family_of_row(type_family: str, name: str) -> str:
    fam = _MANIFEST_FAMILY.get(type_family or "", "")
    if fam == "text" and _ext(name) in _EMAIL_EXT:
        return "email"
    if not fam:
        # a container or an unidentified file whose NAME says it is a hunt
        # family (a .docx is a zip; a .mov may not have been typed): trust
        # the bytes first, the name second, and say so in the basis.
        guess = EXT_FAMILY.get(_ext(name), "")
        if guess in ("document", "video", "email") and type_family in (
                "", None, "archive", "video", "audio", "document", "text"):
            return guess
    return fam


def list_items(case, evidence_id: str, *, families=HUNT_FAMILIES,
               include_deleted: bool = False, path_filter: str = "",
               limit: int | None = None) -> list[Item]:
    """Every hunt-able item of one evidence item, in path order."""
    wanted = set(families)
    item = case.evidence_item(evidence_id)
    needle = (path_filter or "").lower()
    out: list[Item] = []
    with _index.session(case.root) as conn:
        if item.kind == "logical-folder":
            rows = conn.execute(
                "SELECT relpath, size, sha256, type_family, type_label FROM "
                "files WHERE evidence_id = ? AND kind = 'file' ORDER BY "
                "relpath", (evidence_id,)).fetchall()
            for relpath, size, sha256, tfam, tlabel in rows:
                name = relpath.rsplit("/", 1)[-1]
                fam = _family_of_row(tfam, name)
                if fam not in wanted or (needle and needle not in relpath.lower()):
                    continue
                basis = "manifest" if _MANIFEST_FAMILY.get(tfam or "") else "extension"
                out.append(Item(f"{evidence_id}:{relpath}", evidence_id, "file",
                                relpath, name, int(size or 0), fam,
                                tlabel or "", basis, sha256 or ""))
                if limit and len(out) >= limit:
                    break
        else:
            rows = conn.execute(
                "SELECT volume, record, path, name, size, in_use FROM "
                "ntfs_entries WHERE evidence_id = ? AND is_dir = 0 ORDER BY "
                "volume, path", (evidence_id,)).fetchall()
            for volume, record, path, name, size, in_use in rows:
                if not in_use and not include_deleted:
                    continue
                fam = EXT_FAMILY.get(_ext(name or ""), "")
                shown = path or name or f"record {record}"
                if fam not in wanted or (needle and needle not in shown.lower()):
                    continue
                out.append(Item(f"{evidence_id}:v{volume}:mft{record}",
                                evidence_id, "ntfs", shown, name or "",
                                int(size or 0), fam, "", "extension",
                                volume=int(volume), record=int(record),
                                deleted=not in_use))
                if limit and len(out) >= limit:
                    break
    return out


def _file_path(case, item: Item) -> Path:
    evidence = case.evidence_item(item.evidence_id)
    rel = _extract.safe_relpath(item.path)
    path = Path(evidence.source).joinpath(*rel.parts)
    if not blocker.is_inside(path, evidence.source):
        raise EvidenceError(f"{item.path!r} resolves outside {item.evidence_id}.")
    return path


def _chunks(case, item: Item, limit: int):
    """The item's bytes in pieces, from the evidence, up to `limit`."""
    if item.source == "file":
        with blocker.open_evidence(_file_path(case, item)) as fh:
            left = limit
            while left > 0:
                block = fh.read(min(COPY_CHUNK, left))
                if not block:
                    break
                left -= len(block)
                yield block
        return
    source, vol, _row = _disk.open_ntfs(case, item.evidence_id, item.volume)
    try:
        entry = vol.entry(item.record)
        stream = entry.stream("") if entry is not None else None
        if stream is None:
            raise EvidenceError(f"{item.ref} has no data stream to read.")
        end = min(stream.data_size, limit)
        pos = 0
        while pos < end:
            block = vol.read_stream(stream, pos, min(COPY_CHUNK, end - pos))
            if not block:
                break
            pos += len(block)
            yield block
    finally:
        source.close()


def read_item(case, item: Item, *, limit: int = MAX_READ) -> bytes:
    """Up to `limit` bytes of the item, in memory. Written nowhere."""
    limit = max(0, min(int(limit), MAX_READ))
    return b"".join(_chunks(case, item, limit))


def identify(data: bytes, name: str = "", size: int | None = None) -> dict:
    """The type of bytes already read — the hunt layer's second opinion on
    an NTFS entry typed only by its extension."""
    found = filetype.identify(data[:filetype.HEAD_BYTES], name=name,
                              size=len(data) if size is None else size)
    return found.as_dict()


def _safe_part(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("._")[:120] or "item"


def working_copy(case, item: Item, *, reason: str) -> dict:
    """ONE hashed copy of the item inside `<case>/working/`, for a program
    that needs a file to seek in (FFmpeg). Reused when it is already there.
    Custody records the copy and the reason."""
    if not (reason or "").strip():
        raise EvidenceError("A working copy needs a reason; custody records why.")
    folder = case.path(WORKING_DIR, _safe_part(item.evidence_id),
                       _safe_part(item.ref.split(":", 1)[1]))
    dest = folder / _safe_part(item.name or "item")
    if dest.is_file():
        return {"path": os.fspath(dest), "reused": True}
    hashes = _extract.copy_stream_to_case(case, _chunks(case, item, 1 << 62),
                                          dest)
    case.custody.record(
        "working.copied", actor=case.actor(), target=item.ref,
        hashes=hashes.as_dict(),
        detail={"to": os.fspath(dest.relative_to(case.root)), "reason": reason,
                "source": item.source, "path": item.path, "at": utc_now()})
    return {"path": os.fspath(dest), "reused": False, **hashes.as_dict()}
