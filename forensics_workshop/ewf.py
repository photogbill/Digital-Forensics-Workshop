# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""EnCase EWF-E01 images, read natively as one raw stream — stdlib `zlib` only.

An E01 is not raw bytes: it is the disk cut into fixed-size **chunks**, each one
stored either verbatim or zlib-compressed, indexed by a **table**, wrapped in a
chain of **sections**. This module reads that structure and presents the disk
back as `.size` + `.read_at(offset, length)` — the same interface a raw image
gives — so partitions, NTFS, carving and hashing work on an E01 unchanged and
never learn it was compressed. Nothing here writes.

**The format, only as much as reading needs** (libewf's EWF specification):

    file header   13 bytes: "EVF\\x09\\x0d\\x0a\\xff\\x00", 0x01, segment number
                  (u16 LE), 0x0000.
    section       a 76-byte descriptor: type[16] (nul-padded), next_offset (u64
                  LE, the file offset of the NEXT descriptor), size (u64 LE,
                  THIS section including its 76-byte descriptor), pad[40],
                  adler32. A section whose next_offset points at itself ends the
                  chain (`next` continues in the following segment; `done` ends
                  the set). Section data is the bytes between the descriptor and
                  next_offset.
    volume/disk   geometry: media type, chunk count (u32), sectors per chunk
                  (u32, ~64), bytes per sector (u32, ~512), sector count (u64).
                  chunk size = sectors_per_chunk x bytes_per_sector (~32 KiB);
                  disk size = sector_count x bytes_per_sector.
    sectors       the chunk data, back to back. No header.
    table         count (u32), pad, base offset (u64, EnCase 6/7), pad, adler32,
                  then `count` entries of u32 LE. In each entry the top bit is
                  the compression flag and the low 31 bits are the chunk's
                  offset, taken from the base offset when one is set (EnCase
                  6/7) and from the segment-file start otherwise (EnCase 5).
                  `table2` is a backup copy of `table`.

A chunk's stored length is the gap to the next entry's offset, and the last
chunk in a table runs to the end of its `sectors` data. A compressed chunk is a
zlib stream; an uncompressed one is the chunk's bytes followed by a 4-byte
adler32 that is dropped. The final chunk of the disk is short when the disk is
not a whole number of chunks, and is truncated to the remaining byte count.

**Ex01/EWFX are refused, not half-read.** EnCase 7's Ex01 adds bzip2 and a
different layout; guessing at it would corrupt evidence silently. It is named
and declined until it is built.
"""

from __future__ import annotations

import struct
import threading
import zlib
from collections import OrderedDict
from dataclasses import dataclass

from . import blocker
from .errors import EvidenceError

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESC_SIZE = 76
COMPRESSED = 0x80000000
OFFSET_MASK = 0x7FFFFFFF
MAX_ENTRIES = 1 << 24          # a sane cap: 16M chunks ≈ 512 GiB at 32 KiB
CACHE_CHUNKS = 64              # decompressed chunks kept in memory


@dataclass(frozen=True)
class Geometry:
    media_type: int
    chunk_count: int
    sectors_per_chunk: int
    bytes_per_sector: int
    sector_count: int

    @property
    def chunk_size(self) -> int:
        return self.sectors_per_chunk * self.bytes_per_sector

    @property
    def disk_size(self) -> int:
        return self.sector_count * self.bytes_per_sector


@dataclass(frozen=True)
class _Chunk:
    segment: int          # index into the segment path list
    offset: int           # byte offset of the stored chunk in that segment file
    stored: int           # bytes on disk (compressed size, or chunk+4)
    compressed: bool


def _is_ewf_e01(head: bytes) -> bool:
    return head[:8] == SIGNATURE


def _sections(fh):
    """Walk a segment file's section descriptors from the 13-byte header on.

    Yields (type, data_start, data_len) and stops after the section whose
    next_offset points at itself (`next`/`done`), or on `done`.
    """
    header = fh.read(13)
    if header[:8] != SIGNATURE:
        raise EvidenceError("not an EWF-E01 segment (bad EVF signature).")
    cur = 13
    seen = 0
    while True:
        fh.seek(cur)
        desc = fh.read(DESC_SIZE)
        if len(desc) < DESC_SIZE:
            raise EvidenceError("EWF section descriptor is truncated.")
        kind = desc[:16].split(b"\x00", 1)[0].decode("ascii", "replace")
        next_offset, size = struct.unpack_from("<QQ", desc, 16)
        if size < DESC_SIZE or next_offset < 0:
            raise EvidenceError(f"EWF section {kind!r} has an impossible size.")
        yield kind, cur + DESC_SIZE, size - DESC_SIZE
        seen += 1
        if seen > 1 << 20:
            raise EvidenceError("EWF section chain is unreasonably long.")
        if kind == "done" or next_offset == cur:
            return
        cur = next_offset


def _parse_geometry(data: bytes) -> Geometry:
    if len(data) < 24:
        raise EvidenceError("EWF volume/disk section is too small.")
    media_type = data[0]
    chunk_count, spc, bps = struct.unpack_from("<III", data, 4)
    (sector_count,) = struct.unpack_from("<Q", data, 16)
    if spc == 0 or bps == 0:
        raise EvidenceError("EWF geometry has a zero chunk or sector size.")
    return Geometry(media_type, chunk_count, spc, bps, sector_count)


def _parse_table(data: bytes):
    """(base_offset, [(offset, compressed), …]) from a table/table2 section."""
    if len(data) < 24:
        raise EvidenceError("EWF table section is too small.")
    (count,) = struct.unpack_from("<I", data, 0)
    (base_offset,) = struct.unpack_from("<Q", data, 8)
    if count == 0 or count > MAX_ENTRIES:
        raise EvidenceError(f"EWF table entry count {count} is out of range.")
    need = 24 + 4 * count
    if len(data) < need:
        raise EvidenceError("EWF table entry array is truncated.")
    entries = struct.unpack_from(f"<{count}I", data, 24)
    return base_offset, [(e & OFFSET_MASK, bool(e & COMPRESSED)) for e in entries]


class EwfImage:
    """A read-only EWF-E01 set, presented as one raw disk stream. Thread-safe."""

    def __init__(self, segment_paths) -> None:
        self.segments = [str(p) for p in segment_paths]
        self._handles: OrderedDict = OrderedDict()
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self.geometry: Geometry | None = None
        self._chunks: list[_Chunk] = []
        self._index()
        if self.geometry is None:
            raise EvidenceError("EWF set has no volume/disk section.")
        self.size = self.geometry.disk_size
        self._chunk_size = self.geometry.chunk_size

    # -- building the chunk index -------------------------------------------

    def _index(self) -> None:
        for seg_index, path in enumerate(self.segments):
            with blocker.open_evidence(path) as fh:
                sectors_end = 0
                for kind, data_start, data_len in _sections(fh):
                    if kind in ("volume", "disk") and self.geometry is None:
                        fh.seek(data_start)
                        self.geometry = _parse_geometry(fh.read(min(data_len, 1052)))
                    elif kind == "sectors":
                        sectors_end = data_start + data_len
                    elif kind == "table":
                        fh.seek(data_start)
                        base, entries = _parse_table(fh.read(data_len))
                        self._add_table(seg_index, base, entries, sectors_end)
                    # table2 is a backup of table; header/hash/digest/error2/
                    # session/ltree/data/next/done carry no chunk data we read.

    def _add_table(self, seg_index, base, entries, sectors_end) -> None:
        n = len(entries)
        for i, (rel, compressed) in enumerate(entries):
            start = base + rel
            if i + 1 < n:
                stored = base + entries[i + 1][0] - start
            else:
                stored = sectors_end - start
            if stored <= 0:
                raise EvidenceError(
                    f"EWF chunk {len(self._chunks)} has a non-positive stored "
                    "length — the table offsets are not understood.")
            self._chunks.append(_Chunk(seg_index, start, stored, compressed))

    # -- reading -------------------------------------------------------------

    def _handle(self, seg_index: int):
        fh = self._handles.get(seg_index)
        if fh is not None:
            self._handles.move_to_end(seg_index)
            return fh
        fh = blocker.open_evidence(self.segments[seg_index])
        self._handles[seg_index] = fh
        while len(self._handles) > 8:
            _old, stale = self._handles.popitem(last=False)
            stale.close()
        return fh

    def _chunk_bytes(self, index: int) -> bytes:
        cached = self._cache.get(index)
        if cached is not None:
            self._cache.move_to_end(index)
            return cached
        chunk = self._chunks[index]
        fh = self._handle(chunk.segment)
        fh.seek(chunk.offset)
        raw = fh.read(chunk.stored)
        expect = min(self._chunk_size, self.size - index * self._chunk_size)
        if chunk.compressed:
            try:
                data = zlib.decompress(raw)
            except zlib.error as exc:
                raise EvidenceError(
                    f"EWF chunk {index} did not decompress ({exc}); the image "
                    "may be damaged or its table misread.") from exc
        else:
            data = raw[:expect]                      # drop the trailing adler32
        if len(data) != expect:
            raise EvidenceError(
                f"EWF chunk {index} decoded to {len(data)} bytes, expected "
                f"{expect} — geometry and table disagree.")
        self._cache[index] = data
        while len(self._cache) > CACHE_CHUNKS:
            self._cache.popitem(last=False)
        return data

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        end = min(offset + length, self.size)
        if offset >= end:
            return b""
        cs = self._chunk_size
        out = bytearray()
        with self._lock:
            for ci in range(offset // cs, (end - 1) // cs + 1):
                data = self._chunk_bytes(ci)
                base = ci * cs
                lo = offset - base if ci == offset // cs else 0
                hi = end - base if ci == (end - 1) // cs else len(data)
                out += data[lo:hi]
        return bytes(out)

    def close(self) -> None:
        with self._lock:
            for fh in self._handles.values():
                fh.close()
            self._handles.clear()
            self._cache.clear()

    def __enter__(self) -> "EwfImage":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def notes(self) -> list[str]:
        g = self.geometry
        return [
            f"EnCase EWF-E01, read natively: {g.chunk_count:,} chunks of "
            f"{g.chunk_size:,} bytes ({g.sectors_per_chunk} x {g.bytes_per_sector}), "
            f"decompressed on read. The disk is {self.size:,} bytes "
            f"({g.sector_count:,} x {g.bytes_per_sector}); chunk data is "
            "verified against the geometry as it is read.",
        ]
