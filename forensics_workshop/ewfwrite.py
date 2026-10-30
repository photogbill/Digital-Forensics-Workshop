# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Writing EnCase EWF-E01 images — the format `ewf.py` reads, written natively
with stdlib `zlib`, from libewf's published description of the format.

Built 2026-10-29 for the drive imager (`acquire.py`). **This module opens no
file itself.** Every segment it writes is opened by the caller's guarded
writer (`acquire._open_output`), which refuses any path outside the
destination folder the examiner chose — so the read-only ratchet sees no
write site here at all, and none can creep in.

**What an E01 set is, as written here** (EnCase 4/5 layout, base offsets
used only past 2 GiB, which is what EnCase 6+ does):

    segment 1  file header · header2 · header · volume ·
               (sectors · table · table2)… · next | done
    segment n  file header · data · (sectors · table · table2)… · next | done
    last       … · error2 (only if sectors were unreadable) · hash · digest ·
               done

    file header   "EVF\\x09\\x0d\\x0a\\xff\\x00", 0x01, segment number u16, 0x0000
    descriptor    type[16] · next_offset u64 · size u64 (descriptor included)
                  · 40 zero bytes · adler32 of the 72 bytes before it.
                  `next` and `done` point at themselves and are 76 bytes.
    header2       zlib(UTF-16LE with BOM) of the EnCase 4 "main" category:
                  description, case, evidence number, examiner, notes, tool
                  version, OS, acquisition and system time (Unix seconds)
    header        zlib(ASCII, CRLF) of the same, times as "Y M D h m s"
    volume/data   1052 bytes: media type, chunk count, sectors per chunk,
                  bytes per sector, sector count, CHS, media flags,
                  compression level, error granularity, GUID, adler32
    sectors       the chunks back to back: a zlib stream when that is
                  smaller, else the chunk followed by its adler32
    table/table2  count u32 · pad · base offset u64 · pad · adler32 · count
                  x u32 (top bit = compressed; low 31 bits = offset from the
                  base) · adler32 of the entries. At most 16,375 entries, as
                  EnCase writes them.
    error2        count u32 · 512 zero bytes · adler32 · (first sector u32,
                  sector count u32)… · adler32 — the sectors that could not
                  be read and were written as zeros
    hash          MD5 · 16 zero bytes · adler32
    digest        MD5 · SHA-1 · 40 zero bytes · adler32

**Held to two readers.** The suite reads every image this writes back
through `ewf.py` and compares all three hashes; on a machine with libewf
installed it also opens them with `pyewf` — an independent implementation,
so a misunderstanding shared by this writer and this reader is caught.
"""

from __future__ import annotations

import os
import struct
import time
import uuid
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

SIGNATURE = b"EVF\x09\x0d\x0a\xff\x00"
DESC_SIZE = 76
COMPRESSED = 0x80000000
MAX_TABLE_ENTRIES = 16375
#: A table's offsets are 31 bits; past this a group gets a base offset.
OFFSET_LIMIT = 0x7FFFFFFF
VOLUME_SIZE = 1052
#: compression word -> (the volume section's level byte, zlib level or None)
COMPRESSION = {"none": (0, None), "fast": (1, 1), "best": (2, 9)}
#: media type byte
MEDIA_REMOVABLE, MEDIA_FIXED = 0x00, 0x01
#: media flags byte: an image file, of a physical device
FLAG_IMAGE, FLAG_PHYSICAL = 0x01, 0x02
#: What the final sections need, at most, so a segment never overruns.
_TAIL_RESERVE = 4096


def adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def descriptor(kind: str, offset: int, data_len: int, *,
               points_at_self: bool = False) -> bytes:
    """The 76-byte section descriptor for a section starting at `offset`."""
    name = kind.encode("ascii")
    if len(name) > 16:
        raise ValueError(f"section type {kind!r} is longer than 16 bytes")
    size = DESC_SIZE + data_len
    nxt = offset if points_at_self else offset + size
    head = name.ljust(16, b"\x00") + struct.pack("<QQ", nxt, size) + b"\x00" * 40
    return head + struct.pack("<I", adler32(head))


#: E01…E99 (99), then EAA…ZZZ (22 x 26 x 26) — libewf's and EnCase's limit.
MAX_SEGMENTS = 99 + 22 * 26 * 26


def segment_suffix(number: int) -> str:
    """E01 … E99, then EAA … EZZ, then FAA … ZZZ — EnCase's scheme
    (`image._ewf_next_suffix` reads it back)."""
    if number < 1:
        raise ValueError("segments are numbered from 1")
    if number <= 99:
        return f"E{number:02d}"
    n = number - 100
    if number > MAX_SEGMENTS:
        raise ValueError(f"more than {MAX_SEGMENTS:,} segments — more than "
                         "EWF can name (E01-ZZZ); use bigger segments")
    return chr(69 + n // 676) + chr(65 + (n // 26) % 26) + chr(65 + n % 26)


@dataclass
class CaseText:
    """What the header sections carry — the examiner's words, verbatim."""

    case_number: str = ""
    evidence_number: str = ""
    description: str = ""
    examiner: str = ""
    notes: str = ""
    version: str = ""
    os: str = ""
    acquired: float = field(default_factory=time.time)

    def _values(self) -> list[str]:
        clean = [str(v).replace("\t", " ").replace("\r", " ").replace("\n", " ")
                 for v in (self.description, self.case_number,
                           self.evidence_number, self.examiner, self.notes,
                           self.version, self.os)]
        return clean

    def header2(self) -> bytes:
        a, c, n, e, t, av, ov = self._values()
        stamp = str(int(self.acquired))
        text = ("1\nmain\na\tc\tn\te\tt\tav\tov\tm\tu\tp\n"
                f"{a}\t{c}\t{n}\t{e}\t{t}\t{av}\t{ov}\t{stamp}\t{stamp}\t0\n\n")
        return zlib.compress(b"\xff\xfe" + text.encode("utf-16-le"))

    def header(self) -> bytes:
        a, c, n, e, t, av, ov = self._values()
        tm = time.gmtime(self.acquired)
        stamp = (f"{tm.tm_year} {tm.tm_mon} {tm.tm_mday} {tm.tm_hour} "
                 f"{tm.tm_min} {tm.tm_sec}")
        text = ("1\r\nmain\r\nc\tn\ta\te\tt\tav\tov\tm\tu\tp\r\n"
                f"{c}\t{n}\t{a}\t{e}\t{t}\t{av}\t{ov}\t{stamp}\t{stamp}\t0\r\n"
                "\r\n")
        return zlib.compress(text.encode("ascii", "replace"))


def volume_data(*, size: int, bytes_per_sector: int, sectors_per_chunk: int,
                compression: str, media_type: int = MEDIA_FIXED,
                physical: bool = True, chs: tuple = (0, 0, 0),
                guid: bytes | None = None) -> bytes:
    """The 1052-byte volume (segment 1) / data (later segments) section."""
    sectors = -(-size // bytes_per_sector)
    chunks = -(-sectors // sectors_per_chunk)
    level = COMPRESSION[compression][0]
    out = bytearray(VOLUME_SIZE)
    out[0] = media_type
    struct.pack_into("<III", out, 4, chunks, sectors_per_chunk,
                     bytes_per_sector)
    struct.pack_into("<Q", out, 16, sectors)
    struct.pack_into("<III", out, 24, *[int(x) & 0xFFFFFFFF for x in chs])
    out[36] = FLAG_IMAGE | (FLAG_PHYSICAL if physical else 0)
    out[52] = level
    struct.pack_into("<I", out, 56, sectors_per_chunk)    # error granularity
    out[64:80] = guid if guid is not None else uuid.uuid4().bytes
    struct.pack_into("<I", out, 1048, adler32(bytes(out[:1048])))
    return bytes(out)


def table_data(entries: list[int], base_offset: int) -> bytes:
    head = struct.pack("<IIQI", len(entries), 0, base_offset, 0)
    head += struct.pack("<I", adler32(head))
    body = struct.pack(f"<{len(entries)}I", *entries)
    return head + body + struct.pack("<I", adler32(body))


def error2_fits(first: int, count: int) -> bool:
    """error2 holds 32-bit sector numbers: a run at or past sector 2^32 (2 TiB
    at 512-byte sectors) cannot be written there, and is never wrapped."""
    return 0 <= first and first + count <= 0xFFFFFFFF


def error2_data(ranges: list[tuple[int, int]]) -> bytes:
    """`ranges` are (first sector, sector count). Only runs that fit 32 bits;
    the caller lists the rest elsewhere (`EwfWriter.error2_omitted`)."""
    ranges = [(f, c) for f, c in ranges if error2_fits(f, c)]
    head = struct.pack("<I", len(ranges)) + b"\x00" * 512
    head += struct.pack("<I", adler32(head))
    body = b"".join(struct.pack("<II", first, count) for first, count in ranges)
    return head + body + struct.pack("<I", adler32(body))


def hash_data(md5: bytes) -> bytes:
    body = md5 + b"\x00" * 16
    return body + struct.pack("<I", adler32(body))


def digest_data(md5: bytes, sha1: bytes) -> bytes:
    body = md5 + sha1 + b"\x00" * 40
    return body + struct.pack("<I", adler32(body))


class EwfWriter:
    """Streams one disk into an E01 set, chunk by chunk.

    `open_segment(path) -> file` is the CALLER'S guarded writer: it must open
    a new file for binary writing and refuse to overwrite one. `base` is the
    path without its extension; segments are `base.E01`, `base.E02`, …
    `segment_bytes` (None = one segment) caps each file's size.

    Feed exactly `size` bytes through `write()`, in any piece sizes; then
    `finish(md5, sha1, bad_ranges)`. `paths` lists every segment written.
    """

    def __init__(self, base, *, open_segment, size: int,
                 bytes_per_sector: int = 512, sectors_per_chunk: int = 64,
                 segment_bytes: int | None = None, compression: str = "fast",
                 case_text: CaseText | None = None,
                 media_type: int = MEDIA_FIXED, physical: bool = True,
                 chs: tuple = (0, 0, 0), threads: int | None = None) -> None:
        if compression not in COMPRESSION:
            raise ValueError(f"compression is one of {sorted(COMPRESSION)}")
        if size <= 0 or bytes_per_sector <= 0 or sectors_per_chunk <= 0:
            raise ValueError("size, sector size and chunk size must be positive")
        if size % bytes_per_sector:
            # EWF describes a disk in whole sectors. A tail that is not one
            # would make the geometry promise bytes that were never read —
            # so it is refused, not padded: padding would change the hash.
            raise ValueError(
                f"{size:,} bytes is not a whole number of {bytes_per_sector}-"
                "byte sectors; an E01 cannot hold it exactly (write RAW).")
        self.base = str(base)
        self._open = open_segment
        self.size = int(size)
        self.bps = int(bytes_per_sector)
        self.spc = int(sectors_per_chunk)
        self.chunk_size = self.bps * self.spc
        self.compression = compression
        self._level = COMPRESSION[compression][1]
        self.segment_bytes = segment_bytes
        if segment_bytes is not None and segment_bytes < 1 << 20:
            raise ValueError("a segment must be at least 1 MiB")
        self.case_text = case_text or CaseText()
        self._volume = volume_data(
            size=self.size, bytes_per_sector=self.bps,
            sectors_per_chunk=self.spc, compression=compression,
            media_type=media_type, physical=physical, chs=chs)
        self.paths: list[str] = []
        self._fh = None
        self._pos = 0
        self._segment = 0
        self._pending = bytearray()
        self._written = 0
        self._group_start = None         # offset of the open sectors section
        self._group_entries: list[int] = []
        self._group_base = 0
        self.chunks_written = 0
        self.stored_bytes = 0
        self._finished = False
        #: Unreadable runs past sector 2^32, which error2 cannot hold.
        self.error2_omitted: list = []
        #: zlib releases the GIL, so chunks compress in parallel and are
        #: stored in order. One thread when there is nothing to compress.
        n = threads if threads is not None else min(4, os.cpu_count() or 1)
        self._pool = (ThreadPoolExecutor(max_workers=n,
                                         thread_name_prefix="ewf-zlib")
                      if self._level is not None and n > 1 else None)

    # -- low level ---------------------------------------------------------
    def _put(self, data: bytes) -> None:
        self._fh.write(data)
        self._pos += len(data)

    def _section(self, kind: str, data: bytes) -> None:
        self._put(descriptor(kind, self._pos, len(data)))
        self._put(data)

    def _terminal(self, kind: str) -> None:
        self._put(descriptor(kind, self._pos, 0, points_at_self=True))

    def _open_segment(self) -> None:
        self._segment += 1
        path = f"{self.base}.{segment_suffix(self._segment)}"
        self._fh = self._open(path)
        self.paths.append(path)
        self._pos = 0
        self._put(SIGNATURE + b"\x01" + struct.pack("<H", self._segment)
                  + b"\x00\x00")
        if self._segment == 1:
            self._section("header2", self.case_text.header2())
            self._section("header", self.case_text.header())
            self._section("volume", self._volume)
        else:
            self._section("data", self._volume)

    def _start_group(self) -> None:
        self._group_start = self._pos
        self._put(b"\x00" * DESC_SIZE)          # filled in by _end_group
        self._group_entries = []
        data_start = self._pos
        # Offsets are relative to the base. Absolute (base 0) while they fit
        # in 31 bits — what every EWF reader understands — and from the
        # group's own data past that, as EnCase 6 does.
        limit = data_start + MAX_TABLE_ENTRIES * (self.chunk_size + 4)
        self._group_base = 0 if limit <= OFFSET_LIMIT else data_start

    def _end_group(self) -> None:
        if self._group_start is None:
            return
        data_len = self._pos - self._group_start - DESC_SIZE
        end = self._pos
        self._fh.seek(self._group_start)
        self._fh.write(descriptor("sectors", self._group_start, data_len))
        self._fh.seek(end)
        table = table_data(self._group_entries, self._group_base)
        self._section("table", table)
        self._section("table2", table)
        self._group_start = None

    def _would_overflow(self) -> bool:
        if self.segment_bytes is None:
            return False
        n = len(self._group_entries) + 1
        tables = 2 * (DESC_SIZE + 28 + 4 * n)
        return (self._pos + self.chunk_size + 4 + tables + _TAIL_RESERVE
                > self.segment_bytes)

    def _pack(self, chunk: bytes) -> bytes | None:
        """The chunk compressed, or None when compressing does not shrink it
        (or compression is off)."""
        if self._level is None:
            return None
        packed = zlib.compress(chunk, self._level)
        return packed if len(packed) < len(chunk) else None

    def _store_chunk(self, chunk: bytes, packed: bytes | None = None,
                     prepacked: bool = False) -> None:
        if self._fh is None:
            self._open_segment()
        if self._group_start is not None and (
                len(self._group_entries) >= MAX_TABLE_ENTRIES
                or self._would_overflow()):
            self._end_group()
            if self._would_overflow():
                self._terminal("next")
                self._fh.close()
                self._fh = None
                self._open_segment()
        if self._group_start is None:
            self._start_group()
        if not prepacked:
            packed = self._pack(chunk)
        if packed is not None:
            stored, flag = packed, COMPRESSED
        else:
            stored, flag = chunk + struct.pack("<I", adler32(chunk)), 0
        rel = self._pos - self._group_base
        if rel > OFFSET_LIMIT:
            raise ValueError("chunk offset past 31 bits from its base — "
                             "the group should have been closed")
        self._group_entries.append(rel | flag)
        self._put(stored)
        self.chunks_written += 1
        self.stored_bytes += len(stored)

    # -- the stream --------------------------------------------------------
    def write(self, data: bytes) -> None:
        if self._finished:
            raise ValueError("the image is already finished")
        if self._written + len(data) > self.size:
            raise ValueError("more data than the disk size given")
        self._written += len(data)
        self._pending += data
        cs = self.chunk_size
        whole = len(self._pending) // cs
        if not whole:
            return
        chunks = [bytes(self._pending[i * cs:(i + 1) * cs])
                  for i in range(whole)]
        del self._pending[:whole * cs]
        if self._pool is not None and len(chunks) > 1:
            for chunk, packed in zip(chunks, self._pool.map(self._pack, chunks)):
                self._store_chunk(chunk, packed, prepacked=True)
        else:
            for chunk in chunks:
                self._store_chunk(chunk)

    def finish(self, md5: bytes, sha1: bytes, bad_ranges=()) -> list[str]:
        """Close the set: the last chunk, error2, hash, digest, done."""
        if self._written != self.size:
            raise ValueError(f"{self._written} of {self.size} bytes were "
                             "written; the image would not be the disk")
        if self._pending:
            self._store_chunk(bytes(self._pending))
            self._pending.clear()
        self._end_group()
        bad_ranges = list(bad_ranges)
        self.error2_omitted = [r for r in bad_ranges if not error2_fits(*r)]
        if any(error2_fits(*r) for r in bad_ranges):
            self._section("error2", error2_data(bad_ranges))
        self._section("hash", hash_data(md5))
        self._section("digest", digest_data(md5, sha1))
        self._terminal("done")
        self._fh.flush()
        try:
            os.fsync(self._fh.fileno())
        except (AttributeError, OSError, ValueError):
            pass                      # not a real file (the suite's sinks)
        self._fh.close()
        self._fh = None
        self._finished = True
        self._shutdown()
        return list(self.paths)

    def _shutdown(self) -> None:
        if self._pool is not None:
            self._pool.shutdown(wait=True)
            self._pool = None

    def abandon(self) -> list[str]:
        """Stop without finishing (a cancel or a failure): close what is open.
        The set is left INCOMPLETE — no `done` section — and the caller's log
        says so."""
        if self._fh is not None:
            try:
                self._fh.flush()
            finally:
                self._fh.close()
                self._fh = None
        self._shutdown()
        return list(self.paths)
