# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Signature carving: find files by their bytes, measure them, preview first.

Carving ignores the file system and looks for the start of known formats in
raw bytes — the way to find what a file system no longer describes.

**A CARVED FILE IS A CANDIDATE, ALL THE WAY TO THE REPORT.** A header was
found at an offset. Everything after that is a measurement with a basis, and
each candidate carries which one:

    structure   the format's own fields were walked to its end — PNG chunks
                to IEND with every CRC checked, a ZIP's end-of-central-
                directory matched back to its start, SQLite's page count,
                a RIFF size. The strongest basis there is, and still not proof
                the bytes in between belong to one file: a file fragmented on
                disk carves as its first fragment plus whatever followed it.
    footer      a trailing marker was found (a JPEG's EOI, a PDF's %%EOF).
    capped      a header and no end within the size cap; the length is the
                cap, and the tail is almost certainly not this file.

and a status: `complete` (the basis reached its end), `truncated` (the
structure ran past the end of the searched region or the image), or
`capped`.

**Preview before recovery** (FORENSICS_PLAN.md §2). A carve writes NOTHING
but index rows: offset, length, basis, type, a hex head and the entropy of
the first bytes. `preview_candidate` reads a candidate into memory for a
host to render — a thumbnail, a first page, a hex view — and still writes
nothing. Only `recover_candidate`, with a reason, copies bytes into the case,
hashing them as they are written and recording how they were found.

**Aim.** A whole image, one volume, an unpartitioned gap, or — for an NTFS
volume — only its unallocated clusters, which is where deleted files that
the MFT no longer describes are found. Headers are looked for at sector
boundaries by default (files start on cluster boundaries, which are sector
boundaries); `aligned=1` searches every byte, finding embedded files and
producing far more false starts.
"""

from __future__ import annotations

import json
import struct
import time
import uuid
import zlib
from dataclasses import asdict, dataclass

from . import filetype, hashing
from .image import Region, RegionFile
from . import index as _index
from .errors import Cancelled, EvidenceError
from .timeutil import utc_now

SCAN_CHUNK = 4 << 20
DEFAULT_CAP = 64 << 20
MAX_CANDIDATES = 200_000
PREVIEW_BYTES = 1 << 16


@dataclass(frozen=True)
class Measure:
    length: int
    basis: str          # structure | footer | capped
    status: str         # complete | truncated | capped
    note: str = ""


@dataclass(frozen=True)
class Carver:
    type_id: str
    label: str
    ext: str
    magic: bytes
    magic_offset: int
    cap: int
    measure: object


class _Reader:
    """Bounded, buffered reads for the measure functions."""

    def __init__(self, reader, start: int, limit: int) -> None:
        self.reader, self.start, self.limit = reader, start, limit
        self._buf_at, self._buf = -1, b""

    def get(self, rel: int, n: int) -> bytes:
        if rel < 0 or rel >= self.limit:
            return b""
        n = min(n, self.limit - rel)
        if not (self._buf_at <= rel and rel + n <= self._buf_at + len(self._buf)):
            self._buf_at = rel
            self._buf = self.reader.read_at(self.start + rel, max(n, 1 << 20))
        off = rel - self._buf_at
        return self._buf[off:off + n]


def _find(r: _Reader, needle: bytes, start: int, cap: int) -> int:
    """Offset of `needle` at or after `start`, below `cap`, or -1."""
    pos = start
    window = 1 << 20
    while pos < min(cap, r.limit):
        chunk = r.get(pos, window + len(needle))
        if not chunk:
            return -1
        at = chunk.find(needle)
        if at != -1 and pos + at < cap:
            return pos + at
        pos += window
    return -1


def _capped(r: _Reader, cap: int, note: str) -> Measure:
    """No end found. Either the size cap or the searched region stopped the
    search — and those are different statements."""
    if r.limit < cap:
        return Measure(r.limit, "capped", "truncated",
                       f"{note} before the searched region ended")
    return Measure(cap, "capped", "capped", f"{note} within the {cap:,}-byte cap")


def _sized(r: _Reader, cap: int, length: int, note: str) -> Measure:
    """A length the format's header states."""
    if length > cap:
        return Measure(min(cap, r.limit), "capped",
                       "capped" if cap <= r.limit else "truncated",
                       f"{note}: {length:,} bytes, beyond the {cap:,}-byte cap")
    if length > r.limit:
        return Measure(r.limit, "structure", "truncated",
                       f"{note}: {length:,} bytes, but the searched region "
                       f"ends after {r.limit:,}")
    return Measure(length, "structure", "complete", note)


# -- measure functions: (reader, cap) -> Measure | None (None = not this format)

def _m_png(r, cap):
    if r.get(12, 4) != b"IHDR":
        return None
    pos = 8
    while pos + 12 <= min(cap, r.limit):
        head = r.get(pos, 8)
        if len(head) < 8:
            break
        length = struct.unpack(">I", head[:4])[0]
        ctype = head[4:8]
        if length > 0x7FFFFFFF or not all(65 <= b <= 90 or 97 <= b <= 122 for b in ctype):
            if pos == 8:
                return None
            return Measure(pos, "structure", "truncated",
                           f"chunk at {pos} is not a PNG chunk; the image "
                           "stops there")
        body = r.get(pos + 8, length + 4)
        if len(body) < length + 4:
            return Measure(min(cap, r.limit), "structure", "truncated",
                           "the last chunk runs past the searched region")
        crc = struct.unpack(">I", body[length:length + 4])[0]
        if zlib.crc32(ctype + body[:length]) & 0xFFFFFFFF != crc:
            if pos == 8:
                return None
            return Measure(pos, "structure", "truncated",
                           f"chunk {ctype.decode('ascii', 'replace')} at {pos} "
                           "fails its CRC — damage, or another file's bytes")
        pos += 12 + length
        if ctype == b"IEND":
            return Measure(pos, "structure", "complete",
                           "every chunk CRC checked through IEND")
    return _capped(r, cap, "no IEND")


def _m_jpeg(r, cap):
    pos = 2
    scans = 0
    while pos + 4 <= min(cap, r.limit):
        marker = r.get(pos, 2)
        if len(marker) < 2 or marker[0] != 0xFF:
            if pos == 2:
                return None
            return Measure(pos, "structure", "truncated",
                           f"expected a marker at {pos}; the image is damaged "
                           "or fragmented there")
        code = marker[1]
        if code == 0xD9:
            return Measure(pos + 2, "footer", "complete",
                           f"segments walked, {scans} scan(s), EOI found")
        if code == 0xFF:
            pos += 1
            continue
        if 0xD0 <= code <= 0xD7 or code == 0x01:
            pos += 2
            continue
        seg = r.get(pos + 2, 2)
        if len(seg) < 2:
            break
        seg_len = struct.unpack(">H", seg)[0]
        if seg_len < 2:
            return None if pos == 2 else Measure(pos, "structure", "truncated",
                                                 "a segment length below 2")
        pos += 2 + seg_len
        if code == 0xDA:                        # start of scan: entropy data
            scans += 1
            while pos < min(cap, r.limit):
                block = r.get(pos, 1 << 16)
                if not block:
                    break
                at = 0
                found = False
                while True:
                    at = block.find(b"\xff", at)
                    if at == -1 or at + 1 >= len(block):
                        break
                    nxt = block[at + 1]
                    if nxt == 0x00 or 0xD0 <= nxt <= 0xD7 or nxt == 0xFF:
                        at += 1
                        continue
                    found = True
                    break
                if found:
                    pos += at
                    break
                pos += max(1, len(block) - 1)
    return _capped(r, cap, "no EOI")


def _m_gif(r, cap):
    lsd = r.get(6, 7)
    if len(lsd) < 7:
        return None
    flags = lsd[4]
    pos = 13 + (3 * (2 << (flags & 7)) if flags & 0x80 else 0)
    while pos < min(cap, r.limit):
        b = r.get(pos, 1)
        if not b:
            break
        if b[0] == 0x3B:
            return Measure(pos + 1, "structure", "complete",
                           "blocks walked to the trailer")
        if b[0] == 0x21:
            pos += 2
        elif b[0] == 0x2C:
            desc = r.get(pos + 1, 9)
            if len(desc) < 9:
                break
            lflags = desc[8]
            pos += 10 + (3 * (2 << (lflags & 7)) if lflags & 0x80 else 0) + 1
        else:
            return (None if pos == 13 else
                    Measure(pos, "structure", "truncated",
                            f"byte 0x{b[0]:02X} at {pos} starts no GIF block"))
        while True:                                   # data sub-blocks
            size = r.get(pos, 1)
            if not size:
                return _capped(r, cap, "GIF sub-blocks do not end")
            pos += 1 + size[0]
            if size[0] == 0:
                break
    return _capped(r, cap, "no GIF trailer")


def _m_bmp(r, cap):
    head = r.get(0, 30)
    if len(head) < 30:
        return None
    size, reserved, data_off, dib = struct.unpack_from("<IIII", head, 2)
    if reserved != 0 or dib not in (12, 40, 52, 56, 108, 124) or \
            not 14 + dib <= data_off < size or size < 58:
        return None
    return _sized(r, cap, size, "file size field in the header")


def _m_pdf(r, cap):
    if r.get(5, 3)[:1] not in (b"1", b"2"):
        return None
    pos = 5
    end = -1
    while True:
        at = _find(r, b"%%EOF", pos, cap)
        if at == -1:
            break
        end = at + 5
        tail = r.get(end, 4096).lstrip(b"\r\n \t")
        if not (tail[:4] == b"xref" or tail[:1].isdigit() and b" obj" in tail[:40]):
            break                                   # no incremental update follows
        pos = end
    if end == -1:
        return _capped(r, cap, "no %%EOF")
    eol = r.get(end, 2)
    end += 2 if eol == b"\r\n" else 1 if eol[:1] in (b"\n", b"\r") else 0
    return Measure(end, "footer", "complete",
                   "to the last %%EOF that is not followed by an incremental "
                   "update")


def _m_zip(r, cap):
    local = r.get(0, 30)
    if len(local) < 30 or struct.unpack_from("<H", local, 4)[0] > 63:
        return None
    pos = 0
    while True:
        at = _find(r, b"PK\x05\x06", pos, cap)
        if at == -1:
            return _capped(r, cap, "no end-of-central-directory")
        eocd = r.get(at, 22)
        if len(eocd) < 22:
            return _capped(r, cap, "end-of-central-directory cut off")
        cd_size, cd_off, comment = struct.unpack_from("<IIH", eocd, 12)
        if cd_off + cd_size == at and r.get(cd_off, 4) == b"PK\x01\x02":
            return Measure(at + 22 + comment, "structure", "complete",
                           "end-of-central-directory points back to this "
                           "archive's start")
        if cd_off == 0xFFFFFFFF:
            return Measure(at + 22 + comment, "structure", "complete",
                           "ZIP64 archive; ended at its end-of-central-"
                           "directory record")
        pos = at + 4


def _m_sqlite(r, cap):
    head = r.get(0, 100)
    if len(head) < 100:
        return None
    page_size = struct.unpack_from(">H", head, 16)[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        return None
    change, pages = struct.unpack_from(">II", head, 24)
    valid_for = struct.unpack_from(">I", head, 92)[0]
    if pages and valid_for == change:
        return _sized(r, cap, pages * page_size,
                      "page count × page size from the header")
    return _capped(r, cap, "the header's page count is not current (written by "
                           "an old SQLite), so no length is known; no end")


_RIFF_FORMS = {b"WAVE": ("wav", "WAV audio"), b"AVI ": ("avi", "AVI video"),
               b"WEBP": ("webp", "WebP image"), b"RMID": ("rmi", "RIFF MIDI"),
               b"ACON": ("ani", "Animated cursor")}


def _m_riff(r, cap):
    head = r.get(0, 12)
    if len(head) < 12 or head[8:12] not in _RIFF_FORMS:
        return None
    length = struct.unpack_from("<I", head, 4)[0] + 8
    return _sized(r, cap, length + (length & 1), "RIFF size field")


def _m_ole(r, cap):
    head = r.get(0, 512)
    if len(head) < 512 or struct.unpack_from("<H", head, 0x1C)[0] != 0xFFFE:
        return None
    shift = struct.unpack_from("<H", head, 0x1E)[0]
    if shift not in (9, 12):
        return None
    ss = 1 << shift
    fat_count = struct.unpack_from("<I", head, 0x2C)[0]
    difat = [struct.unpack_from("<I", head, 0x4C + 4 * i)[0] for i in range(109)]
    fat_sectors = [s for s in difat if s < 0xFFFFFFFA][:fat_count]
    highest = -1
    for i, sector in enumerate(fat_sectors):
        highest = max(highest, sector)
        fat = r.get((sector + 1) * ss, ss)
        if len(fat) < ss:
            return _capped(r, cap, "a FAT sector lies outside what was read")
        for j in range(ss // 4):
            if struct.unpack_from("<I", fat, 4 * j)[0] != 0xFFFFFFFF:
                highest = max(highest, i * (ss // 4) + j)
    if fat_count > 109:
        return _capped(r, cap, "more FAT sectors than the header's DIFAT holds; "
                               "the length is a cap")
    return _sized(r, cap, (highest + 2) * ss,
                  "highest allocated sector in the compound file's FAT")


def _m_pe(r, cap):
    head = r.get(0, 0x40)
    if len(head) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", head, 0x3C)[0]
    if not 0x40 <= e_lfanew <= 0x1000:
        return None
    pe = r.get(e_lfanew, 0x108)
    if pe[:4] != b"PE\x00\x00" or len(pe) < 24:
        return None
    sections, _t, _p, _n, opt_size = struct.unpack_from("<HIIIH", pe, 6)
    magic = struct.unpack_from("<H", pe, 24)[0] if len(pe) >= 26 else 0
    if magic not in (0x10B, 0x20B) or not 0 < sections <= 96:
        return None
    table = e_lfanew + 24 + opt_size
    end = table + 40 * sections
    for i in range(sections):
        sec = r.get(table + 40 * i, 40)
        if len(sec) < 40:
            return _capped(r, cap, "the section table runs past the region")
        raw_size, raw_ptr = struct.unpack_from("<II", sec, 16)
        if raw_size:
            end = max(end, raw_ptr + raw_size)
    dirs_at = 24 + (96 if magic == 0x10B else 112)
    if len(pe) >= dirs_at + 40:
        cert_off, cert_size = struct.unpack_from("<II", pe, dirs_at + 32)
        if cert_off and cert_size:
            end = max(end, cert_off + cert_size)
    return _sized(r, cap, end, "end of the last section or the certificate "
                               "table; data appended after it (an overlay) is "
                               "not included")


def _m_isobmff(r, cap):
    pos = 0
    boxes = 0
    known = (b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid",
             b"meta", b"moof", b"mfra", b"pdin", b"styp", b"sidx", b"pnot",
             b"idat", b"iinf", b"iloc", b"iprp", b"iref", b"pitm", b"dinf")
    while pos + 8 <= min(cap, r.limit):
        head = r.get(pos, 16)
        if len(head) < 8:
            break
        size, btype = struct.unpack(">I4s", head[:8])
        if btype not in known and not (boxes and all(0x20 <= c < 0x7F for c in btype)
                                        and btype[:1].isalpha()):
            if boxes == 0:
                return None
            return Measure(pos, "structure", "complete",
                           f"{boxes} top-level boxes, ending where the next "
                           "bytes are not a box")
        if size == 1:
            if len(head) < 16:
                break
            size = struct.unpack(">Q", head[8:16])[0]
        elif size == 0:
            return _capped(r, cap, "the last box runs to the end of its file, "
                                   "which carving cannot know")
        if size < 8:
            return (None if boxes == 0 else
                    Measure(pos, "structure", "truncated", "a box smaller than its header"))
        boxes += 1
        pos += size
    return _sized(r, cap, pos, f"{boxes} top-level boxes")


def _m_gzip(r, cap):
    if r.get(2, 1) != b"\x08":
        return None
    d = zlib.decompressobj(wbits=31)
    pos = 0
    try:
        while pos < min(cap, r.limit):
            block = r.get(pos, 1 << 16)
            if not block:
                break
            d.decompress(block, 1 << 20)
            while d.unconsumed_tail:
                d.decompress(d.unconsumed_tail, 1 << 20)
            if d.eof:
                used = len(block) - len(d.unused_data)
                return Measure(pos + used, "structure", "complete",
                               "decompressed to the end of the stream and its "
                               "CRC checked")
            pos += len(block)
    except zlib.error:
        return None if pos == 0 else Measure(pos, "structure", "truncated",
                                             "the deflate stream breaks here")
    return _capped(r, cap, "the deflate stream does not end")


def _m_7z(r, cap):
    head = r.get(0, 32)
    if len(head) < 32:
        return None
    crc = struct.unpack_from("<I", head, 8)[0]
    if zlib.crc32(head[12:32]) & 0xFFFFFFFF != crc:
        return None
    off, size = struct.unpack_from("<QQ", head, 12)
    return _sized(r, cap, 32 + off + size,
                  "start header CRC checked; next header position and size")


CARVERS = (
    Carver("jpeg", "JPEG image", "jpg", b"\xff\xd8\xff", 0, 64 << 20, _m_jpeg),
    Carver("png", "PNG image", "png", b"\x89PNG\r\n\x1a\n", 0, 256 << 20, _m_png),
    Carver("gif", "GIF image", "gif", b"GIF87a", 0, 64 << 20, _m_gif),
    Carver("gif", "GIF image", "gif", b"GIF89a", 0, 64 << 20, _m_gif),
    Carver("bmp", "BMP image", "bmp", b"BM", 0, 256 << 20, _m_bmp),
    Carver("pdf", "PDF document", "pdf", b"%PDF-", 0, 256 << 20, _m_pdf),
    Carver("zip", "ZIP archive", "zip", b"PK\x03\x04", 0, 1 << 30, _m_zip),
    Carver("sqlite", "SQLite database", "sqlite", b"SQLite format 3\x00", 0,
           4 << 30, _m_sqlite),
    Carver("riff", "RIFF (WAV/AVI/WebP)", "riff", b"RIFF", 0, 4 << 30, _m_riff),
    Carver("ole2", "OLE2 compound file", "ole", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
           0, 1 << 30, _m_ole),
    Carver("pe", "Windows executable (PE)", "exe", b"MZ", 0, 256 << 20, _m_pe),
    Carver("mp4", "MPEG-4 / QuickTime / HEIF", "mp4", b"ftyp", 4, 4 << 30,
           _m_isobmff),
    Carver("gzip", "gzip stream", "gz", b"\x1f\x8b\x08", 0, 256 << 20, _m_gzip),
    Carver("7z", "7-Zip archive", "7z", b"7z\xbc\xaf\x27\x1c", 0, 4 << 30, _m_7z),
)

TYPES = tuple(sorted({c.type_id for c in CARVERS}))


@dataclass
class Candidate:
    offset: int
    length: int
    type_id: str
    label: str
    ext: str
    basis: str
    status: str
    note: str
    head_hex: str
    entropy: float | None
    nested_in: int | None = None

    def as_dict(self) -> dict:
        return asdict(self)


def measure_at(reader, offset: int, carver: Carver, region_end: int) -> Candidate | None:
    """Measure one header. `region_end` bounds the structure walk: a carve of
    a region never claims bytes beyond it as complete."""
    limit = min(region_end, reader.size) - offset
    if limit <= len(carver.magic):
        return None
    r = _Reader(reader, offset, limit)
    m = carver.measure(r, carver.cap)
    if m is None:
        return None
    head = reader.read_at(offset, 256)
    type_id, label, ext = carver.type_id, carver.label, carver.ext
    if carver.type_id == "riff":
        form = _RIFF_FORMS.get(head[8:12])
        if form:
            ext, label = form
            type_id = ext
    elif carver.type_id in ("zip", "ole2", "mp4"):
        region = Region(reader, offset, m.length)
        found = filetype.identify(region.read_at(0, filetype.HEAD_BYTES),
                                  size=m.length, reader=RegionFile(region))
        if found.type_id not in ("unknown", "zip", "ole2") and found.extensions:
            type_id, label = found.type_id, found.label
            ext = next((e for e in found.extensions if e), ext)
    return Candidate(offset, m.length, type_id, label, ext, m.basis, m.status,
                     m.note, head[:32].hex(), filetype.entropy(head))


@dataclass
class CarveSummary:
    run_id: str
    evidence_id: str
    scope: str
    volume: int | None
    state: str
    types: list
    aligned: int
    regions: int = 0
    bytes_searched: int = 0
    headers_seen: int = 0
    candidates: int = 0
    by_type: dict = None            # type: ignore[assignment]
    complete: int = 0
    capped: bool = False
    candidates_sha256: str = ""
    started_at: str = ""
    finished_at: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def carve_regions(reader, regions, *, types=None, aligned: int = 512,
                  should_cancel=None, progress=None, summary=None):
    """Yield candidates found in [(start, end)] disk byte ranges, in order.

    A candidate's structure walk is bounded by the end of ITS region, so a
    carve of unallocated space reports a file that continues into allocated
    clusters as truncated rather than borrowing its neighbour's bytes.
    """
    wanted = [c for c in CARVERS if types is None or c.type_id in types]
    if not wanted:
        raise EvidenceError(f"No carvers for types {types}; known: {TYPES}.")
    longest = max(len(c.magic) + c.magic_offset for c in wanted)
    open_intervals: list = []
    last_report = 0.0
    for start, end in regions:
        pos = start
        while pos < end:
            if should_cancel is not None and should_cancel():
                raise Cancelled("carving was cancelled")
            size = min(SCAN_CHUNK, end - pos)
            chunk = reader.read_at(pos, size + longest)
            if not chunk:
                break
            hits = []
            for c in wanted:
                at = chunk.find(c.magic)
                while at != -1:
                    begin = pos + at - c.magic_offset
                    if at - c.magic_offset < size and begin >= start and \
                            (aligned <= 1 or begin % aligned == 0):
                        hits.append((begin, c))
                    at = chunk.find(c.magic, at + 1)
            hits.sort(key=lambda h: h[0])
            for begin, c in hits:
                if summary is not None:
                    summary.headers_seen += 1
                cand = measure_at(reader, begin, c, end)
                if cand is None:
                    continue
                open_intervals = [iv for iv in open_intervals
                                  if iv[1] > begin]
                for iv_start, iv_end, iv_basis in open_intervals:
                    if iv_start < begin < iv_end and iv_basis != "capped":
                        cand.nested_in = iv_start
                        break
                open_intervals.append((begin, begin + cand.length, cand.basis))
                yield cand
            pos += size
            if summary is not None:
                summary.bytes_searched += size
            now = time.monotonic()
            if progress is not None and now - last_report > 0.5:
                last_report = now
                progress(f"searched {pos:,} bytes"
                         + (f" · {summary.candidates:,} candidates" if summary else ""))


CANDIDATE_COLUMNS = ("run_id", "evidence_id", "volume", "scope", "offset",
                     "length", "type_id", "label", "ext", "basis", "status",
                     "note", "head_hex", "entropy", "nested_in")


def carve(case, evidence_id: str, reader, regions, *, scope: str,
          volume: int | None = None, types=None, aligned: int = 512,
          progress=None, should_cancel=None) -> CarveSummary:
    """Carve `regions` of an image into candidate rows. Writes no file."""
    types = sorted(set(types)) if types else list(TYPES)
    summary = CarveSummary(uuid.uuid4().hex[:12], evidence_id, scope, volume,
                           "running", types, aligned, regions=len(regions),
                           by_type={}, started_at=utc_now())
    with _index.session(case.root) as conn:
        conn.execute("INSERT INTO runs (run_id, evidence_id, kind, volume, "
                     "started_at, state, settings_json) VALUES "
                     "(?, ?, 'carve', ?, ?, 'running', ?)",
                     (summary.run_id, evidence_id, volume, summary.started_at,
                      json.dumps({"scope": scope, "types": types,
                                  "aligned": aligned})))
    case.custody.record(
        "carve.started", actor=case.actor(), target=evidence_id,
        detail={"run_id": summary.run_id, "scope": scope, "volume": volume,
                "types": types, "aligned": aligned,
                "regions": len(regions),
                "bytes": sum(e - s for s, e in regions)})
    conn = _index.connect(case.root)
    pending: list = []
    digest = hashing.Hasher()

    def flush():
        if pending:
            conn.executemany(
                f"INSERT INTO carve_candidates ({', '.join(CANDIDATE_COLUMNS)}) "
                f"VALUES ({', '.join('?' for _ in CANDIDATE_COLUMNS)})", pending)
            conn.commit()
            pending.clear()

    try:
        for cand in carve_regions(reader, regions, types=types, aligned=aligned,
                                  should_cancel=should_cancel,
                                  progress=progress, summary=summary):
            summary.candidates += 1
            summary.by_type[cand.type_id] = summary.by_type.get(cand.type_id, 0) + 1
            summary.complete += cand.status == "complete"
            digest.update(f"{cand.offset}\t{cand.length}\t{cand.type_id}\t"
                          f"{cand.basis}\t{cand.status}\n".encode())
            pending.append((summary.run_id, evidence_id, volume, scope,
                            cand.offset, cand.length, cand.type_id, cand.label,
                            cand.ext, cand.basis, cand.status, cand.note,
                            cand.head_hex, cand.entropy, cand.nested_in))
            if len(pending) >= 500:
                flush()
            if summary.candidates >= MAX_CANDIDATES:
                summary.capped = True
                break
        flush()
        summary.state = "completed"
    except Cancelled:
        flush()
        summary.state = "cancelled"
    except BaseException as exc:
        try:
            flush()
        except Exception:                                     # noqa: BLE001
            pass
        summary.state = "failed"
        summary.error = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        conn.close()
        summary.finished_at = utc_now()
        summary.candidates_sha256 = digest.result().sha256
        with _index.session(case.root) as done:
            done.execute("UPDATE runs SET finished_at = ?, state = ?, "
                         "summary_json = ? WHERE run_id = ?",
                         (summary.finished_at, summary.state,
                          json.dumps(summary.as_dict()), summary.run_id))
        case.custody.record(
            f"carve.{summary.state}", actor=case.actor(), target=evidence_id,
            hashes=({"candidates": summary.candidates_sha256}
                    if summary.state == "completed" else {}),
            detail=summary.as_dict())
    return summary


def list_candidates(case, evidence_id: str, *, run_id: str | None = None,
                    type_id: str = "", status: str = "", min_size: int = 0,
                    limit: int = 500, offset: int = 0) -> tuple[list, int]:
    where, args = ["evidence_id = ?"], [evidence_id]
    if run_id:
        where.append("run_id = ?")
        args.append(run_id)
    if type_id:
        where.append("type_id = ?")
        args.append(type_id)
    if status:
        where.append("status = ?")
        args.append(status)
    if min_size > 0:
        where.append("length >= ?")
        args.append(int(min_size))
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM carve_candidates WHERE {clause}",
                             args).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM carve_candidates WHERE {clause} ORDER BY offset "
            "LIMIT ? OFFSET ?", [*args, limit, offset])]
    return rows, total


def candidate(case, evidence_id: str, candidate_id: int) -> dict:
    with _index.session(case.root) as conn:
        row = conn.execute("SELECT * FROM carve_candidates WHERE id = ? AND "
                           "evidence_id = ?", (candidate_id, evidence_id)).fetchone()
    if row is None:
        raise EvidenceError(f"No carve candidate {candidate_id} in {evidence_id}.")
    return dict(row)
