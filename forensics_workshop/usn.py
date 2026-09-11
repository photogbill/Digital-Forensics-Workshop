# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The NTFS change journal, `$Extend\\$UsnJrnl:$J`, read record by record.

Windows appends a record to `$J` for changes to files on a volume where the
journal is enabled: created, written, renamed, deleted, attributes or
timestamps altered. Each record names the file by its MFT reference and its
name AT THE TIME, which is why the journal remembers files whose MFT records
have long since been reused.

**What is checked.** `$J` is a sparse stream: Windows discards the oldest
records by deallocating the start of the stream, so a live journal begins
with a long run of zeroes. Records are found by walking forward on 8-byte
boundaries; a candidate is accepted only when its length, version, name
offset and name length are all consistent with the documented layouts
(USN_RECORD_V2, V3 and V4). A record's USN is the byte offset at which
Windows wrote it, so `usn == offset` is checked on every record — an exported
`$J` whose leading sparse zeroes were trimmed by a collection tool will fail
that check by a constant amount, and the summary says so rather than
rejecting every record.

**What a record means is not decided here.** A `BASIC_INFO_CHANGE` beside a
file whose timestamps look set by hand is two measurements, listed together;
the conclusion is the examiner's.
"""

from __future__ import annotations

import re
import struct
from dataclasses import asdict, dataclass

from .errors import Cancelled

CHUNK = 1 << 20
MAX_RECORD = 0x10000

REASONS = (
    (0x00000001, "DATA_OVERWRITE"), (0x00000002, "DATA_EXTEND"),
    (0x00000004, "DATA_TRUNCATION"), (0x00000010, "NAMED_DATA_OVERWRITE"),
    (0x00000020, "NAMED_DATA_EXTEND"), (0x00000040, "NAMED_DATA_TRUNCATION"),
    (0x00000100, "FILE_CREATE"), (0x00000200, "FILE_DELETE"),
    (0x00000400, "EA_CHANGE"), (0x00000800, "SECURITY_CHANGE"),
    (0x00001000, "RENAME_OLD_NAME"), (0x00002000, "RENAME_NEW_NAME"),
    (0x00004000, "INDEXABLE_CHANGE"), (0x00008000, "BASIC_INFO_CHANGE"),
    (0x00010000, "HARD_LINK_CHANGE"), (0x00020000, "COMPRESSION_CHANGE"),
    (0x00040000, "ENCRYPTION_CHANGE"), (0x00080000, "OBJECT_ID_CHANGE"),
    (0x00100000, "REPARSE_POINT_CHANGE"), (0x00200000, "STREAM_CHANGE"),
    (0x00400000, "TRANSACTED_CHANGE"), (0x00800000, "INTEGRITY_CHANGE"),
    (0x01000000, "DESIRED_STORAGE_CLASS_CHANGE"), (0x80000000, "CLOSE"),
)
REASON_BITS = {name: bit for bit, name in REASONS}

SOURCES = ((0x1, "DATA_MANAGEMENT"), (0x2, "AUXILIARY_DATA"),
           (0x4, "REPLICATION_MANAGEMENT"), (0x8, "CLIENT_REPLICATION_MANAGEMENT"))

_NONZERO = re.compile(rb"[^\x00]")


def reason_names(mask: int) -> list[str]:
    names = [name for bit, name in REASONS if mask & bit]
    unknown = mask & ~sum(bit for bit, _n in REASONS)
    if unknown:
        names.append(f"0x{unknown:08X}")
    return names


def source_names(mask: int) -> list[str]:
    return [name for bit, name in SOURCES if mask & bit]


@dataclass(frozen=True)
class UsnRecord:
    offset: int                 # where the record starts in $J
    version: int
    file_record: int
    file_sequence: int
    parent_record: int
    parent_sequence: int
    usn: int
    timestamp: int              # raw FILETIME; 0 for V4, which carries none
    reasons: int
    source_info: int
    security_id: int
    attributes: int
    name: str
    extents: tuple              # V4 range records only: ((offset, length), …)

    def as_dict(self) -> dict:
        data = asdict(self)
        data["reason_names"] = reason_names(self.reasons)
        data["extents"] = [list(e) for e in self.extents]
        return data


def _ref64(value: int) -> tuple[int, int]:
    return value & 0xFFFFFFFFFFFF, value >> 48


def _ref128(raw: bytes) -> tuple[int, int]:
    """A FILE_ID_128 on NTFS carries the 64-bit reference in its low half."""
    low = struct.unpack_from("<Q", raw, 0)[0]
    return _ref64(low)


def _name(buf: bytes, pos: int, rec_len: int, off: int, length: int) -> str | None:
    if length % 2 or off + length > rec_len:
        return None
    raw = bytes(buf[pos + off:pos + off + length])
    text = raw.decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def parse_one(buf: bytes, pos: int, offset: int) -> UsnRecord | None:
    """The record at `buf[pos:]`, or None if what is there is not one."""
    if pos + 8 > len(buf):
        return None
    rec_len, major, minor = struct.unpack_from("<IHH", buf, pos)
    if minor != 0 or major not in (2, 3, 4) or rec_len % 8 or \
            rec_len > MAX_RECORD or pos + rec_len > len(buf):
        return None
    if major == 2:
        if rec_len < 0x40:
            return None
        (fref, pref, usn, ts, reasons, source, sec, attrs, nlen, noff
         ) = struct.unpack_from("<QQqqIIIIHH", buf, pos + 8)
        if noff != 0x3C:
            return None
        name = _name(buf, pos, rec_len, noff, nlen)
        if name is None:
            return None
        fr, fs = _ref64(fref)
        pr, ps = _ref64(pref)
        return UsnRecord(offset, 2, fr, fs, pr, ps, usn, ts, reasons, source,
                         sec, attrs, name, ())
    if major == 3:
        if rec_len < 0x50:
            return None
        fr, fs = _ref128(buf[pos + 8:pos + 24])
        pr, ps = _ref128(buf[pos + 24:pos + 40])
        (usn, ts, reasons, source, sec, attrs, nlen, noff
         ) = struct.unpack_from("<qqIIIIHH", buf, pos + 40)
        if noff != 0x4C:
            return None
        name = _name(buf, pos, rec_len, noff, nlen)
        if name is None:
            return None
        return UsnRecord(offset, 3, fr, fs, pr, ps, usn, ts, reasons, source,
                         sec, attrs, name, ())
    if rec_len < 0x40:
        return None
    fr, fs = _ref128(buf[pos + 8:pos + 24])
    pr, ps = _ref128(buf[pos + 24:pos + 40])
    usn, reasons, source, _remaining, count, ext_size = struct.unpack_from(
        "<qIIIHH", buf, pos + 40)
    if ext_size != 16 or 0x40 + count * 16 > rec_len:
        return None
    extents = tuple(struct.unpack_from("<qq", buf, pos + 0x40 + 16 * i)
                    for i in range(count))
    return UsnRecord(offset, 4, fr, fs, pr, ps, usn, 0, reasons, source, 0, 0,
                     "", extents)


@dataclass
class ScanStats:
    records: int = 0
    skipped_bytes: int = 0          # non-zero bytes that were not a record
    zero_bytes: int = 0
    usn_offset_mismatches: int = 0
    first_usn_delta: int | None = None
    versions: dict = None           # type: ignore[assignment]

    def as_dict(self) -> dict:
        return asdict(self)


def scan(read_at, size: int, *, extents=None, should_cancel=None,
         stats: ScanStats | None = None):
    """Yield every record in a `$J` presented by `read_at(offset, n)`.

    `extents` — [(start, end)] byte ranges that hold data — lets a caller
    skip a sparse stream's holes without reading gigabytes of zeroes. Ranges
    are aligned outward to 8 bytes.
    """
    stats = stats if stats is not None else ScanStats()
    if stats.versions is None:
        stats.versions = {}
    ranges = [(0, size)] if extents is None else sorted(extents)
    for start, end in ranges:
        pos = start - start % 8
        end = min(size, end + (-end % 8))
        while pos < end:
            if should_cancel is not None and should_cancel():
                raise Cancelled("journal parsing was cancelled")
            want = min(CHUNK + MAX_RECORD, end - pos)
            buf = read_at(pos, want)
            if not buf:
                break
            limit = min(len(buf), CHUNK) if pos + len(buf) < end else len(buf)
            i = 0
            while i < limit:
                if i + 4 > len(buf):
                    break
                rec_len = struct.unpack_from("<I", buf, i)[0]
                if rec_len == 0:
                    m = _NONZERO.search(buf, i, limit)
                    nxt = limit if m is None else m.start() - m.start() % 8
                    if nxt <= i:
                        nxt = i + 8
                    stats.zero_bytes += nxt - i
                    i = nxt
                    continue
                record = parse_one(buf, i, pos + i)
                if record is None:
                    if i + rec_len > len(buf) and 0 < rec_len <= MAX_RECORD \
                            and pos + len(buf) < end:
                        break                     # truncated by the chunk edge
                    stats.skipped_bytes += 8
                    i += 8
                    continue
                stats.records += 1
                stats.versions[record.version] = stats.versions.get(
                    record.version, 0) + 1
                if record.usn != record.offset:
                    stats.usn_offset_mismatches += 1
                    if stats.first_usn_delta is None:
                        stats.first_usn_delta = record.usn - record.offset
                yield record
                i += rec_len
            if i == 0:
                i = 8
            pos += i
