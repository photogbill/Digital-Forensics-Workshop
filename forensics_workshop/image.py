# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Disk images as one read-only byte stream: a raw file, or a split set.

A RAW/DD image is a disk's bytes in order; a split image is the same bytes
cut into segments (`disk.001`, `disk.002` … or `disk.aa`, `disk.ab` …) so they
fit on media with a file-size limit. Both are read here through
`blocker.open_evidence`, one handle per segment, and presented as a single
random-access stream. Nothing in this module can write.

**A CONTAINER IS NOT RAW, AND READING ONE AS RAW LIES.** EnCase E01, AFF,
dynamic VHD, VHDX, VMDK and QCOW images have headers, compression and
metadata of their own. Read as raw bytes they parse as a disk full of
garbage — partition tables that are not there, volumes at the wrong offsets
— and every result is wrong while looking right. So an image is identified
by its signature before it is accepted, and a container this engine cannot
read is REFUSED with the reason. E01 in particular waits on a native reader;
the library that reads it, libewf (pyewf), is licence-permitted, but native
is the default here for the offline property (FORENSICS_PLAN.md §1.1).

A fixed-size VHD is the exception that is honest to accept: it IS the raw
disk, followed by a 512-byte footer. The footer is found, excluded from the
disk, and the exclusion is stated.

**A split set must be complete and contiguous.** A missing `disk.003`
shortens the disk silently, and every partition after it would be read from
the wrong place. Discovery refuses a set with a gap, refuses a starting
point that is not the first segment, and reports a non-final segment that is
shorter than the first — which is what an interrupted copy looks like.
"""

from __future__ import annotations

import os
import re
import string
import threading
from collections import OrderedDict
from dataclasses import asdict, dataclass
from pathlib import Path

from . import blocker, filetype
from .errors import Cancelled, EvidenceError
from .hashing import CHUNK, Hasher, Hashes

#: Signatures of containers that are not raw disks, and why each is refused.
CONTAINERS = {
    "ewf": "an EnCase E01 image — compressed chunks with their own metadata. "
           "This version cannot read it yet; a native reader is planned "
           "(FORENSICS_PLAN.md §1.1). Convert it to raw with a trusted tool "
           "(FTK Imager, ewfexport) and register the raw image, recording "
           "that conversion in your notes.",
    "ewf2": "an EnCase Ex01 image. See E01: not readable in this version; a "
            "native reader is planned.",
    "aff": "an AFF image. Not readable in this version.",
    "aff4": "an AFF4 image. Not readable in this version.",
    "vhdx": "a Hyper-V VHDX disk — a block-allocation container, not raw.",
    "vhd": "a DYNAMIC VHD — its data is placed through a block allocation "
           "table, so the file's bytes are not the disk's bytes.",
    "vmdk": "a VMware disk (sparse extent or descriptor) — not raw.",
    "qcow": "a QEMU qcow image — not raw.",
}

VHD_FOOTER = b"conectix"
MAX_OPEN_SEGMENTS = 8

_NUMERIC = re.compile(r"^\d{2,}$")
_ALPHA = re.compile(r"^[a-z]{2}$|^[A-Z]{2}$")


@dataclass(frozen=True)
class Segment:
    path: str
    size: int
    offset: int                     # where this segment starts in the disk

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ImageInfo:
    format: str                     # raw | split-raw | vhd-fixed
    size: int                       # bytes of DISK, footers excluded
    file_bytes: int                 # bytes on the segments, footers included
    segments: tuple
    head_type: str
    head_label: str
    notes: tuple

    def as_dict(self) -> dict:
        data = asdict(self)
        data["segments"] = [s.as_dict() for s in self.segments]
        data["notes"] = list(self.notes)
        return data


def _next_alpha(suffix: str) -> str | None:
    letters = string.ascii_uppercase if suffix.isupper() else string.ascii_lowercase
    first, second = letters.index(suffix[0]), letters.index(suffix[1])
    second += 1
    if second == 26:
        first, second = first + 1, 0
    if first == 26:
        return None
    return letters[first] + letters[second]


def _prev_alpha(suffix: str) -> str | None:
    letters = string.ascii_uppercase if suffix.isupper() else string.ascii_lowercase
    first, second = letters.index(suffix[0]), letters.index(suffix[1])
    second -= 1
    if second < 0:
        first, second = first - 1, 25
    if first < 0:
        return None
    return letters[first] + letters[second]


def discover_segments(path) -> list[Path]:
    """The ordered segment paths of the image whose FIRST segment is `path`.

    A file with no numbered or lettered extension is a set of one, and so is
    one whose number or letters have no neighbours (`backup.2024`, `disk.dd`).
    Refuses a path that is part-way through a set, and a set with a gap.
    """
    first = Path(path)
    if not first.is_file():
        raise EvidenceError(f"{first} is not a file.")
    if "." not in first.name:
        return [first]
    stem, suffix = first.name.rsplit(".", 1)
    sibling = lambda s: first.parent / f"{stem}.{s}"            # noqa: E731
    if _NUMERIC.match(suffix):
        width, number = len(suffix), int(suffix)
        name = lambda n: f"{n:0{width}d}"                          # noqa: E731
        prev_exists = number > 0 and sibling(name(number - 1)).is_file()
        next_exists = sibling(name(number + 1)).is_file()
        if prev_exists:
            raise EvidenceError(
                f"{first} is segment {suffix} of a split image and "
                f"{stem}.{name(number - 1)} exists before it. Register the "
                "first segment; a set opened part-way through would put "
                "every partition at the wrong offset.")
        if number > 1 and next_exists:
            raise EvidenceError(
                f"{first} looks like segment {suffix} of a split image whose "
                "earlier segments are missing. Find the first segment before "
                "registering the image.")
        if not next_exists:
            return [first]
        segments, n = [first], number + 1
        while sibling(name(n)).is_file():
            segments.append(sibling(name(n)))
            n += 1
        _refuse_gap(segments, [sibling(name(n + k)) for k in range(1, 4)])
        return segments
    if _ALPHA.match(suffix):
        prev = _prev_alpha(suffix)
        nxt = _next_alpha(suffix)
        prev_exists = bool(prev) and sibling(prev).is_file()
        next_exists = bool(nxt) and sibling(nxt).is_file()
        if prev_exists:
            raise EvidenceError(
                f"{first} is not the first segment of a split image "
                f"({stem}.{prev} exists). Register the first segment.")
        if not next_exists:
            return [first]
        if suffix.lower() != "aa":
            raise EvidenceError(
                f"{first} looks like part of a split image that does not "
                f"start at .aa ({stem}.{nxt} follows it). Find the first "
                "segment before registering the image.")
        segments, cur = [first], suffix
        while True:
            nxt = _next_alpha(cur)
            if nxt is None or not sibling(nxt).is_file():
                break
            segments.append(sibling(nxt))
            cur = nxt
        beyond, probe = [], cur
        for _ in range(3):
            probe = _next_alpha(probe) if probe else None
            if probe:
                beyond.append(sibling(probe))
        _refuse_gap(segments, beyond[1:])
        return segments
    return [first]


def _refuse_gap(segments: list[Path], beyond: list[Path]) -> None:
    for later in beyond:
        if later.is_file():
            missing = segments[-1]
            raise EvidenceError(
                f"The split image is not contiguous: {later.name} exists but "
                f"the segment after {missing.name} does not. A missing "
                "segment shortens the disk and puts everything after it at "
                "the wrong offset; find it before registering the image.")


def describe(paths: list[Path]) -> ImageInfo:
    """Sizes, format, and the refusal for anything that is not a raw disk."""
    segments, offset = [], 0
    for p in paths:
        size = p.stat().st_size
        segments.append(Segment(os.fspath(p), size, offset))
        offset += size
    file_bytes = offset
    if file_bytes == 0:
        raise EvidenceError(f"{paths[0]} is empty; there is no disk to read.")
    with blocker.open_evidence(paths[0]) as fh:
        head = fh.read(filetype.HEAD_BYTES)
    kind = filetype.identify(head, size=segments[0].size)
    notes: list[str] = []
    if kind.type_id in CONTAINERS:
        raise EvidenceError(f"{paths[0]} is {CONTAINERS[kind.type_id]}")
    fmt = "split-raw" if len(paths) > 1 else "raw"
    size = file_bytes
    last = segments[-1]
    if last.size >= 512:
        with blocker.open_evidence(last.path) as fh:
            fh.seek(last.size - 512)
            tail = fh.read(512)
        if tail.startswith(VHD_FOOTER):
            fmt = "vhd-fixed"
            size = file_bytes - 512
            notes.append("Fixed-size VHD: the raw disk followed by a 512-byte "
                         "'conectix' footer. The footer is excluded; the disk "
                         f"is the first {size:,} bytes.")
    if len(segments) > 1:
        first_size = segments[0].size
        for seg in segments[1:-1]:
            if seg.size != first_size:
                notes.append(
                    f"{Path(seg.path).name} is {seg.size:,} bytes but the "
                    f"first segment is {first_size:,}. Split images cut "
                    "segments to one size; a short one in the middle is what "
                    "an interrupted copy looks like.")
    if size % 512:
        notes.append(f"The disk is {size:,} bytes, not a whole number of "
                     "512-byte sectors — the image may be truncated.")
    return ImageInfo(fmt, size, file_bytes, tuple(segments), kind.type_id,
                     kind.label, tuple(notes))


class ImageSource:
    """Random-access, read-only reading of one image. Thread-safe.

    Handles are opened on demand and at most `MAX_OPEN_SEGMENTS` are kept,
    so a set of two thousand segments does not hold two thousand handles.
    """

    def __init__(self, info: ImageInfo) -> None:
        self.info = info
        self.size = info.size
        self._handles: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    @classmethod
    def open(cls, path) -> "ImageSource":
        return cls(describe(discover_segments(path)))

    @classmethod
    def from_segments(cls, paths) -> "ImageSource":
        return cls(describe([Path(p) for p in paths]))

    def __enter__(self) -> "ImageSource":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            for fh in self._handles.values():
                fh.close()
            self._handles.clear()

    def _handle(self, index: int):
        fh = self._handles.get(index)
        if fh is not None:
            self._handles.move_to_end(index)
            return fh
        fh = blocker.open_evidence(self.info.segments[index].path)
        self._handles[index] = fh
        while len(self._handles) > MAX_OPEN_SEGMENTS:
            _old, stale = self._handles.popitem(last=False)
            stale.close()
        return fh

    def read_at(self, offset: int, length: int) -> bytes:
        """Up to `length` bytes of the DISK at `offset`; short only at its end."""
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        end = min(offset + length, self.size)
        if offset >= end:
            return b""
        out = bytearray()
        with self._lock:
            for index, seg in enumerate(self.info.segments):
                seg_end = seg.offset + seg.size
                if seg_end <= offset or seg.offset >= end:
                    continue
                start = max(offset, seg.offset)
                stop = min(end, seg_end)
                fh = self._handle(index)
                fh.seek(start - seg.offset)
                want = stop - start
                data = fh.read(want)
                out += data
                if len(data) < want:          # the file shrank since describe()
                    break
        return bytes(out)


class Region:
    """A window onto a reader — a partition within an image, say.

    Offsets are relative to the window; reads never leave it."""

    def __init__(self, reader, offset: int, length: int) -> None:
        self.reader = reader
        self.offset = offset
        self.size = max(0, min(length, reader.size - offset))

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        end = min(offset + length, self.size)
        if offset >= end:
            return b""
        return self.reader.read_at(self.offset + offset, end - offset)


class RegionFile:
    """A reader presented as a read-only file object, for code that wants
    `read`/`seek` (zipfile, filetype's container refinement). No `write`."""

    def __init__(self, reader) -> None:
        self._reader = reader
        self._pos = 0

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            n = self._reader.size - self._pos
        data = self._reader.read_at(self._pos, n)
        self._pos += len(data)
        return data

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == 1:
            pos += self._pos
        elif whence == 2:
            pos += self._reader.size
        self._pos = max(0, pos)
        return self._pos

    def tell(self) -> int:
        return self._pos

    def seekable(self) -> bool:
        return True

    def readable(self) -> bool:
        return True


def hash_image(source: ImageSource, *, should_cancel=None,
               progress=None) -> tuple[Hashes, list[Hashes]]:
    """The whole disk's digests and each segment's, in one read.

    For a fixed VHD the disk digest covers the disk only; the segment digest
    covers the file as it is on the media, footer included — the two answer
    different questions and both are kept.
    """
    whole = Hasher()
    per_segment: list[Hashes] = []
    done = 0
    for seg in source.info.segments:
        seg_hasher = Hasher()
        with blocker.open_evidence(seg.path) as fh:
            while True:
                if should_cancel is not None and should_cancel():
                    raise Cancelled("image hashing was cancelled")
                chunk = fh.read(CHUNK)
                if not chunk:
                    break
                seg_hasher.update(chunk)
                disk_room = source.size - whole.size
                if disk_room > 0:
                    whole.update(chunk[:disk_room])
                done += len(chunk)
                if progress is not None and done % (256 * CHUNK) < CHUNK:
                    progress(f"hashed {done:,} of {source.info.file_bytes:,} bytes")
        per_segment.append(seg_hasher.result())
    return whole.result(), per_segment
