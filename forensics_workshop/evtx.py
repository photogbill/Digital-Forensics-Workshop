# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows XML Event Logs (`.evtx`) from the bytes: header, chunks, records, Binary XML.

Nothing here asks Windows to open the log. The file is a byte stream and every
structure is parsed from it, from Microsoft's `[MS-EVEN6]` Binary XML
description and Joachim Metz's published EVTX format document, so a log
copied off a dead disk, a dirty log from a live system and a damaged one are
read the same way.

**Layout.** A 4096-byte file header (`ElfFile\\0`: chunk counts, next record
identifier, version, the DIRTY and FULL flags, a CRC32 of its first 120
bytes), then 64 KiB chunks (`ElfChnk\\0`). Each chunk has a 512-byte header
(record number and identifier ranges, the offset of its last record and of
its free space, a CRC32 of the header and a CRC32 of the record data) and
then records: `**\\0\\0`, size, record identifier, the FILETIME the record
was written, a Binary XML document, and a copy of the size.

**Binary XML.** Element and attribute names are stored once per chunk and
referred to by chunk offset afterwards; so are templates. A record is almost
always a template instance: a reference to a template definition (an element
tree with numbered substitution slots, cached here per chunk by its offset)
plus the values for those slots, each typed (strings, integers, FILETIME,
SYSTEMTIME, SID, GUID, hex integers, nested Binary XML, arrays …). Each
record is rendered to an XML string (`EvtxRecord.xml`) and to a dict
(`EvtxRecord.as_dict`) holding the System fields and the EventData / UserData
values flattened by name (a repeated name keeps every value: `Name`,
`Name_2` …). An element whose content is an array is repeated once per item,
as `[MS-EVEN6]` specifies; a nested Binary XML value holding more than one
fragment (EventData followed by RenderingInfo, say) is rendered whole.

**What is checked, and what happens to damage.** Every CRC is computed and a
mismatch is reported, never silently accepted or used as a reason to stop.
Each record's size is checked against its trailing copy. A chunk whose
signature is wrong is reported, scanned for records, and the walk goes on to
the next one; a chunk of zeroes (never used) is noted, not reported. A record
that is broken is reported with its chunk and offset, and the rest of that
chunk is scanned for record signatures — what is found that way is flagged
RECOVERED, with how it was found, as is anything found by scanning the unused
space after a chunk's last record (older records survive there when a chunk
is reused; a slack record must have a matching size copy and a written time
between 1990 and 2100 to be believed, and one whose Binary XML cannot be read
is counted, not listed). A recovered record may only use element and
attribute names stored inline in itself or already read from this chunk's
records: when a chunk is reused, an old record's references to names stored
elsewhere point into new data, and rendering them would put wrong labels on
its values. The residual risk is a stale reference that lands exactly on a
well-formed name the new data also holds; that cannot be told apart from the
bytes alone, which is why recovered records always say how they were found.
Unused space also holds exact copies of records that are live elsewhere;
those are yielded as recovered, and `to_rows` folds them into the live row. A chunk past the file header's chunk count — what a log
copied while Windows was still writing it looks like — is read; its records
are live records the header had not yet counted, and they say so
(`found_by`). The file is read one chunk at a time; nothing holds the whole
log. The oldest chunk number following the newest is a log that has wrapped,
not damage.

**Time.** The record's written time and `System/TimeCreated/@SystemTime` are
FILETIMEs; both are kept raw beside a decoded UTC value (epoch `filetime`).
A SYSTEMTIME value inside event data carries no time zone; it is rendered
without one and never labelled UTC.

**What it does NOT do.** It does not render the event MESSAGE text: that
lives in the provider's message DLLs on the system that wrote the log, not in
the `.evtx` (a forwarded event's own RenderingInfo is kept when present).
ANSI strings are decoded as Windows-1252, because the code page is not
recorded in the file. Control characters XML cannot carry are written as
`\\xNN` in the XML string only; the dict keeps them. A slack record that is a
copy of a live record in ANOTHER chunk is not recognised as such by the walk
itself. The legacy `.evt` format (Windows XP / 2003) is a different format
and is not read here.

**Checked against real logs.** Record identifiers, written times, XML trees
and EventData values agree with pyevtx-rs on the EVTX-ATTACK-SAMPLES corpus
and the pyevtx-rs / python-evtx test logs, including dirty and damaged ones;
where those tools stop at damage, this reader carries on and says so.

**Measurements, not conclusions.** `to_rows` emits rows for a catalogue of
event identifiers worth an examiner's attention (`CATALOGUE`, extensible);
each row states what the record says ("Security 4624 records logon type 10
for CORP\\alice from 10.0.0.5"), never what it means.
"""

from __future__ import annotations

import re
import struct
import zlib
from dataclasses import dataclass, field
from datetime import timedelta

from . import timeutil
from .errors import Cancelled, FileSystemError

FILE_SIGNATURE = b"ElfFile\x00"
CHUNK_SIGNATURE = b"ElfChnk\x00"
RECORD_SIGNATURE = b"**\x00\x00"
FILE_HEADER_SIZE = 4096
CHUNK_SIZE = 0x10000
CHUNK_HEADER_SIZE = 512
RECORD_MIN_SIZE = 28            # signature, size, id, written, size copy

FLAG_DIRTY = 0x0001
FLAG_FULL = 0x0002

#: How deep elements and nested Binary XML may go before the record is
#: treated as damaged (real logs nest a handful of levels).
MAX_DEPTH = 64
#: Messages kept in `Evtx.problems`; beyond this they are only counted.
MAX_PROBLEM_MESSAGES = 500

VALUE_TYPES = {
    0x00: "Null", 0x01: "String", 0x02: "AnsiString", 0x03: "Int8",
    0x04: "UInt8", 0x05: "Int16", 0x06: "UInt16", 0x07: "Int32",
    0x08: "UInt32", 0x09: "Int64", 0x0A: "UInt64", 0x0B: "Real32",
    0x0C: "Real64", 0x0D: "Bool", 0x0E: "Binary", 0x0F: "GUID",
    0x10: "SizeT", 0x11: "FILETIME", 0x12: "SYSTEMTIME", 0x13: "SID",
    0x14: "HexInt32", 0x15: "HexInt64", 0x20: "EvtHandle", 0x21: "BinXml",
    0x23: "EvtXml",
}

#: Fixed item sizes of the scalar types (also the array item sizes).
_FIXED = {0x03: 1, 0x04: 1, 0x05: 2, 0x06: 2, 0x07: 4, 0x08: 4, 0x09: 8,
          0x0A: 8, 0x0B: 4, 0x0C: 8, 0x0D: 4, 0x0F: 16, 0x11: 8, 0x12: 16,
          0x14: 4, 0x15: 8}
_INT_FORMATS = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i",
                0x08: "<I", 0x09: "<q", 0x0A: "<Q"}

_ENTITIES = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}

_U16 = struct.Struct("<H").unpack_from
_U32 = struct.Struct("<I").unpack_from
_U64 = struct.Struct("<Q").unpack_from

_TEXT_ESC = {ord("&"): "&amp;", ord("<"): "&lt;", ord(">"): "&gt;"}
_ATTR_ESC = {**_TEXT_ESC, ord('"'): "&quot;"}
for _c in list(range(0x00, 0x09)) + [0x0B, 0x0C] + list(range(0x0E, 0x20)):
    _TEXT_ESC[_c] = _ATTR_ESC[_c] = f"\\x{_c:02x}"
_NEEDS_TEXT = re.compile(r'[&<>\x00-\x08\x0b\x0c\x0e-\x1f]')
_NEEDS_ATTR = re.compile(r'[&<>"\x00-\x08\x0b\x0c\x0e-\x1f]')


def _esc_text(s: str) -> str:
    """XML text content. Characters XML 1.0 cannot carry (control codes)
    are written as `\\xNN` in the XML view only; the dict keeps them as is."""
    return s.translate(_TEXT_ESC) if _NEEDS_TEXT.search(s) else s


def _esc_attr(s: str) -> str:
    return s.translate(_ATTR_ESC) if _NEEDS_ATTR.search(s) else s


def _utf16(raw) -> str:
    """UTF-16LE as Windows stores it — which permits unpaired surrogates.
    Those are kept as `\\udXXX` escapes rather than replaced."""
    raw = bytes(raw)
    try:
        return raw.decode("utf-16-le")
    except UnicodeDecodeError:
        text = raw[:len(raw) & ~1].decode("utf-16-le", "surrogatepass")
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _ansi(raw) -> str:
    return bytes(raw).decode("cp1252", "backslashreplace")


def filetime_text(raw: int) -> str:
    """A FILETIME as Windows renders it in event XML: 100 ns precision, `Z`."""
    try:
        secs, frac = divmod(int(raw), 10_000_000)
        dt = timeutil.WEBKIT_EPOCH + timedelta(seconds=secs)
        return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:"
                f"{dt.minute:02d}:{dt.second:02d}.{frac:07d}Z")
    except (OverflowError, ValueError):
        return f"0x{int(raw):016X}"


def guid_text(raw) -> str:
    a, b, c = struct.unpack_from("<IHH", raw, 0)
    d = bytes(raw[8:16])
    return (f"{{{a:08X}-{b:04X}-{c:04X}-{d[0]:02X}{d[1]:02X}-"
            f"{d[2:].hex().upper()}}}")


def sid_text(raw) -> tuple[str, int] | None:
    """A binary SID → ('S-1-5-…', bytes used), or None if it is not one."""
    if len(raw) < 8:
        return None
    rev, count = raw[0], raw[1]
    if len(raw) < 8 + 4 * count:
        return None
    auth = int.from_bytes(bytes(raw[2:8]), "big")
    subs = struct.unpack_from(f"<{count}I", raw, 8)
    auth_text = str(auth) if auth < 1 << 32 else f"0x{auth:012X}"
    return "-".join(["S", str(rev), auth_text, *map(str, subs)]), 8 + 4 * count


def _real_text(value: float, single: bool) -> str:
    if value != value:
        return "-1.#IND"
    if value in (float("inf"), float("-inf")):
        return "1.#INF" if value > 0 else "-1.#INF"
    if single:
        return format(value, ".7g")
    return repr(value)


# ---------------------------------------------------------------------------
# file and chunk headers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileHeader:
    signature_ok: bool
    first_chunk: int
    last_chunk: int
    next_record_id: int
    header_size: int
    minor_version: int
    major_version: int
    block_size: int
    chunk_count: int
    flags: int
    checksum: int
    checksum_computed: int
    problems: tuple

    @property
    def dirty(self) -> bool:
        return bool(self.flags & FLAG_DIRTY)

    @property
    def full(self) -> bool:
        return bool(self.flags & FLAG_FULL)

    @property
    def checksum_ok(self) -> bool:
        return self.checksum == self.checksum_computed

    @property
    def wrapped(self) -> bool:
        """The log is circular: when it has filled, Windows reuses its oldest
        chunk, so the oldest (first) chunk number can follow the newest."""
        return self.first_chunk > self.last_chunk

    def flag_names(self) -> list[str]:
        names = [n for bit, n in ((FLAG_DIRTY, "DIRTY"), (FLAG_FULL, "FULL"))
                 if self.flags & bit]
        other = self.flags & ~(FLAG_DIRTY | FLAG_FULL)
        if other:
            names.append(f"0x{other:08X}")
        return names

    def as_dict(self) -> dict:
        return {"signature_ok": self.signature_ok,
                "first_chunk": self.first_chunk, "last_chunk": self.last_chunk,
                "next_record_id": self.next_record_id,
                "header_size": self.header_size,
                "version": f"{self.major_version}.{self.minor_version}",
                "block_size": self.block_size,
                "chunk_count": self.chunk_count, "wrapped": self.wrapped,
                "flags": self.flags, "flag_names": self.flag_names(),
                "dirty": self.dirty, "full": self.full,
                "checksum": f"0x{self.checksum:08X}",
                "checksum_computed": f"0x{self.checksum_computed:08X}",
                "checksum_ok": self.checksum_ok,
                "problems": list(self.problems)}


def parse_file_header(data: bytes) -> FileHeader:
    """The first 4096 bytes of a log. Raises FileSystemError only when what
    is there cannot be a header at all; inconsistencies are listed."""
    if len(data) < 128:
        raise FileSystemError("The file is too short to hold an event log "
                              "header (128 bytes are needed).")
    problems = []
    sig_ok = data[:8] == FILE_SIGNATURE
    if not sig_ok:
        problems.append("The file header does not start with the ElfFile "
                        "signature; its fields are shown but not trusted.")
    first, last, next_id, hsize = struct.unpack_from("<QQQI", data, 8)
    minor, major, block, count = struct.unpack_from("<HHHH", data, 36)
    flags, checksum = struct.unpack_from("<II", data, 120)
    computed = zlib.crc32(data[:120]) & 0xFFFFFFFF
    if sig_ok:
        if checksum != computed:
            problems.append(f"The file header checksum does not match: stored "
                            f"0x{checksum:08X}, computed 0x{computed:08X}. Its "
                            "counts may be stale or damaged.")
        if (major, minor) not in ((3, 1), (3, 2)):
            problems.append(f"Format version {major}.{minor} is not one this "
                            "reader has been checked against (3.1, 3.2).")
        if hsize != 128:
            problems.append(f"The header says it is {hsize} bytes, not 128.")
        if block != FILE_HEADER_SIZE:
            problems.append(f"The header block size is {block}, not 4096; "
                            "chunks are read from offset 4096 regardless.")
        if count and max(first, last) >= count:
            problems.append(f"The header's oldest/newest chunk numbers "
                            f"({first}, {last}) are not below its chunk count "
                            f"({count}).")
    return FileHeader(sig_ok, first, last, next_id, hsize, minor, major, block,
                      count, flags, checksum, computed, tuple(problems))


@dataclass
class ChunkReport:
    """What one 64 KiB chunk slot held, and what was wrong with it."""
    index: int
    offset: int                     # in the file
    status: str                     # ok | empty | no-signature | short
    listed: bool                    # within the file header's chunk count
    first_record_number: int = 0
    last_record_number: int = 0
    first_record_id: int = 0
    last_record_id: int = 0
    last_record_offset: int = 0
    free_space_offset: int = 0
    header_checksum_ok: bool | None = None
    records_checksum_ok: bool | None = None
    records: int = 0                # walked from the chunk's record area
    recovered: int = 0              # found by signature scan
    slack_copies: int = 0           # slack records identical to a live one
    problems: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {"index": self.index, "offset": self.offset,
                "status": self.status, "listed": self.listed,
                "first_record_number": self.first_record_number,
                "last_record_number": self.last_record_number,
                "first_record_id": self.first_record_id,
                "last_record_id": self.last_record_id,
                "last_record_offset": self.last_record_offset,
                "free_space_offset": self.free_space_offset,
                "header_checksum_ok": self.header_checksum_ok,
                "records_checksum_ok": self.records_checksum_ok,
                "records": self.records, "recovered": self.recovered,
                "slack_copies": self.slack_copies,
                "problems": list(self.problems), "notes": list(self.notes)}


# ---------------------------------------------------------------------------
# Binary XML: parsed template trees (cached per chunk) and decoded values
# ---------------------------------------------------------------------------

class _BadXml(Exception):
    """Binary XML that cannot be read; caught per record."""


class _Sub:
    __slots__ = ("index", "vtype", "optional")

    def __init__(self, index, vtype, optional):
        self.index, self.vtype, self.optional = index, vtype, optional


class _Ref:
    """A literal markup piece: character or entity reference, CDATA, PI."""
    __slots__ = ("text", "xml")

    def __init__(self, text, xml):
        self.text, self.xml = text, xml


class _El:
    __slots__ = ("name", "attrs", "children")

    def __init__(self, name, attrs, children):
        self.name, self.attrs, self.children = name, attrs, children


class _Template:
    __slots__ = ("offset", "guid", "nodes", "max_sub")

    def __init__(self, offset, guid, nodes, max_sub):
        self.offset, self.guid, self.nodes, self.max_sub = (
            offset, guid, nodes, max_sub)


class _Inst:
    __slots__ = ("template", "values")

    def __init__(self, template, values):
        self.template, self.values = template, values


class _Val:
    """One substitution value: `text` is None for NULL; `nodes` is set for
    nested Binary XML; `raw` is the typed value (int, list, …) or None;
    `texts` holds an array's items as text."""
    __slots__ = ("vtype", "text", "raw", "nodes", "texts")

    def __init__(self, vtype, text, raw=None, nodes=None, texts=None):
        self.vtype, self.text, self.raw, self.nodes, self.texts = (
            vtype, text, raw, nodes, texts)


_NULL = _Val(0x00, None)
#: What an element, attribute, entity or PI name may not contain.
_NAME_OK = re.compile(r'^[^\x00-\x20<>&"\'=/\\]+$')
_VALUE_TOKENS = frozenset({0x05, 0x45, 0x08, 0x48, 0x09, 0x49, 0x0D, 0x0E})


class _ChunkXml:
    """Binary XML reader over one chunk's bytes; positions are chunk offsets.
    Names and template definitions are cached by offset for this chunk only."""

    def __init__(self, buf: bytes):
        self.b = buf
        self.names: dict[int, tuple[str, int]] = {}
        self.templates: dict[int, _Template] = {}
        self._building: set[int] = set()
        self.problems: list[str] = []
        self._max_sub = -1
        #: Set while reading a record found by signature scan: it may only use
        #: names stored inline in itself or already read from this chunk's
        #: records. A recovered record's references to names stored elsewhere
        #: point into space the chunk may since have reused for other data.
        self.strict = False

    # -- names --------------------------------------------------------------
    def name(self, off: int, inline_at: int) -> tuple[str, int]:
        """The name at chunk offset `off`; `inline_at` is where it would sit
        if stored inline at this point."""
        hit = self.names.get(off)
        if hit is not None:
            return hit
        if self.strict and off != inline_at:
            raise _BadXml(f"it refers to a name at chunk offset 0x{off:X} that "
                          "no record read in this chunk defines; that space "
                          "has been reused")
        b = self.b
        if off < CHUNK_HEADER_SIZE or off + 8 > len(b):
            raise _BadXml(f"a name is referenced at chunk offset 0x{off:X}, "
                          "outside the chunk's record area")
        count = _U16(b, off + 6)[0]
        end = off + 8 + 2 * count
        if count == 0 or end + 2 > len(b) or b[end] or b[end + 1]:
            raise _BadXml(f"no well-formed name at chunk offset 0x{off:X}")
        text = _utf16(b[off + 8:end])
        if not _NAME_OK.match(text):
            raise _BadXml(f"the name at chunk offset 0x{off:X} holds characters "
                          "no XML name can hold")
        hit = (text, 10 + 2 * count)
        self.names[off] = hit
        return hit

    def _name_plausible(self, off: int, inline_at: int, before: int) -> bool:
        b = self.b
        if not (off == inline_at or CHUNK_HEADER_SIZE <= off < before):
            return False
        if off + 8 > len(b):
            return False
        count = _U16(b, off + 6)[0]
        end = off + 8 + 2 * count
        return 0 < count < 0x400 and end + 2 <= len(b) and \
            b[end] == 0 and b[end + 1] == 0

    def _has_dependency_id(self, pos: int) -> bool:
        """Elements inside a template definition carry a 2-byte dependency
        identifier; elements stored directly (nested Binary XML) are
        documented as not carrying it. Which layout is present is decided by
        which one yields a name offset that points at a well-formed name."""
        b = self.b
        if pos + 11 <= len(b) and \
                self._name_plausible(_U32(b, pos + 7)[0], pos + 11, pos):
            return True
        if pos + 9 <= len(b) and \
                self._name_plausible(_U32(b, pos + 5)[0], pos + 9, pos):
            return False
        return True

    # -- structure ----------------------------------------------------------
    def nodes(self, pos: int, end: int, in_template: bool, depth: int = 0):
        """Fragments, elements and template instances up to an end-of-file
        token or `end`. Returns (parts, position after)."""
        if depth > MAX_DEPTH:
            raise _BadXml("Binary XML nested deeper than this reader allows")
        b = self.b
        parts: list = []
        while pos < end:
            tok = b[pos]
            if tok == 0x00:
                return parts, pos + 1
            if tok == 0x0F:
                if pos + 4 > end:
                    raise _BadXml(f"a fragment header at 0x{pos:X} is cut short")
                pos += 4
            elif tok == 0x0C:
                inst, pos = self.instance(pos, end, depth + 1)
                parts.append(inst)
            elif tok & 0xBF == 0x01:
                dep = True if in_template else self._has_dependency_id(pos)
                el, pos = self.element(pos, end, dep, depth + 1)
                parts.append(el)
            elif tok == 0x0A:
                ref, pos = self._pi(pos, end)
                parts.append(ref)
            else:
                raise _BadXml(f"token 0x{tok:02X} at chunk offset 0x{pos:X} "
                              "cannot start a fragment")
        return parts, pos

    def element(self, pos: int, end: int, dep: bool, depth: int):
        if depth > MAX_DEPTH:
            raise _BadXml("elements nested deeper than this reader allows")
        b = self.b
        has_attrs = b[pos] & 0x40
        p = pos + (3 if dep else 1)
        name_off = _U32(b, p + 4)[0]
        p += 8
        name, size = self.name(name_off, p)
        if name_off == p:
            p += size
        attrs = []
        if has_attrs:
            attr_end = p + 4 + _U32(b, p)[0]
            p += 4
            while p < end:
                tok = b[p]
                if tok & 0xBF != 0x06:
                    break
                aoff = _U32(b, p + 1)[0]
                p += 5
                aname, asize = self.name(aoff, p)
                if aoff == p:
                    p += asize
                parts, p = self._value_parts(p, end)
                attrs.append((aname, parts))
                if not tok & 0x40:
                    break
            if p != attr_end:
                raise _BadXml(f"the attribute list of <{name}> at chunk offset "
                              f"0x{pos:X} does not end where its size says")
        if p >= end:
            raise _BadXml(f"<{name}> at chunk offset 0x{pos:X} is cut short")
        tok = b[p]
        if tok == 0x03:
            return _El(name, attrs, []), p + 1
        if tok != 0x02:
            raise _BadXml(f"<{name}> at chunk offset 0x{pos:X} is not closed "
                          f"(token 0x{tok:02X})")
        p += 1
        children: list = []
        while True:
            if p >= end:
                raise _BadXml(f"<{name}> at chunk offset 0x{pos:X} has no end tag")
            tok = b[p]
            if tok == 0x04:
                return _El(name, attrs, children), p + 1
            base = tok & 0xBF
            if base == 0x01:
                child, p = self.element(p, end, dep, depth + 1)
                children.append(child)
            elif tok in _VALUE_TOKENS:
                part, p = self._value_token(p, end)
                children.append(part)
            elif base == 0x07:
                n = _U16(b, p + 1)[0]
                text = _utf16(b[p + 3:p + 3 + 2 * n])
                children.append(_Ref(text, f"<![CDATA[{text}]]>"))
                p += 3 + 2 * n
            elif tok == 0x0A:
                ref, p = self._pi(p, end)
                children.append(ref)
            elif tok == 0x0C:
                inst, p = self.instance(p, end, depth + 1)
                children.append(inst)
            else:
                raise _BadXml(f"token 0x{tok:02X} at chunk offset 0x{p:X} "
                              f"inside <{name}>")

    def _value_parts(self, p: int, end: int):
        parts = []
        while p < end and self.b[p] in _VALUE_TOKENS:
            part, p = self._value_token(p, end)
            parts.append(part)
        return parts, p

    def _value_token(self, p: int, end: int):
        b = self.b
        tok = b[p]
        base = tok & 0xBF
        if base == 0x05:
            vtype = b[p + 1]
            if vtype != 0x01:
                raise _BadXml(f"a value token at chunk offset 0x{p:X} has type "
                              f"0x{vtype:02X}, not a string")
            n = _U16(b, p + 2)[0]
            if p + 4 + 2 * n > end:
                raise _BadXml(f"the text at chunk offset 0x{p:X} runs past "
                              "its record")
            return _utf16(b[p + 4:p + 4 + 2 * n]), p + 4 + 2 * n
        if base in (0x0D, 0x0E):
            index = _U16(b, p + 1)[0]
            if index > self._max_sub:
                self._max_sub = index
            return _Sub(index, b[p + 3], base == 0x0E), p + 4
        if base == 0x08:
            n = _U16(b, p + 1)[0]
            return _Ref(chr(n) if n < 0x110000 else "", f"&#{n};"), p + 3
        # entity reference
        off = _U32(b, p + 1)[0]
        p += 5
        name, size = self.name(off, p)
        if off == p:
            p += size
        return _Ref(_ENTITIES.get(name, f"&{name};"), f"&{name};"), p

    def _pi(self, p: int, end: int):
        b = self.b
        off = _U32(b, p + 1)[0]
        p += 5
        target, size = self.name(off, p)
        if off == p:
            p += size
        data = ""
        if p < end and b[p] == 0x0B:
            n = _U16(b, p + 1)[0]
            data = _utf16(b[p + 3:p + 3 + 2 * n])
            p += 3 + 2 * n
        return _Ref("", f"<?{target} {data}?>" if data else f"<?{target}?>"), p

    def template(self, off: int, template_id: int) -> _Template:
        hit = self.templates.get(off)
        if hit is None:
            b = self.b
            if off < CHUNK_HEADER_SIZE or off + 24 > len(b):
                raise _BadXml(f"a template is referenced at chunk offset "
                              f"0x{off:X}, outside the chunk's record area")
            if off in self._building:
                raise _BadXml(f"the template at chunk offset 0x{off:X} refers "
                              "to itself")
            size = _U32(b, off + 20)[0]
            start, stop = off + 24, off + 24 + size
            if stop > len(b) or b[start] != 0x0F:
                raise _BadXml(f"no template definition at chunk offset "
                              f"0x{off:X}")
            outer_max, self._max_sub = self._max_sub, -1
            self._building.add(off)
            try:
                nodes, _end = self.nodes(start, stop, True)
            finally:
                self._building.discard(off)
            hit = _Template(off, bytes(b[off + 4:off + 20]), nodes, self._max_sub)
            self._max_sub = outer_max
            self.templates[off] = hit
        if _U32(hit.guid, 0)[0] != template_id:
            raise _BadXml(f"the template at chunk offset 0x{off:X} is not the "
                          f"one this record names (0x{template_id:08X}) — the "
                          "space was reused")
        return hit

    def instance(self, pos: int, end: int, depth: int):
        b = self.b
        if pos + 10 > end:
            raise _BadXml(f"the template instance at 0x{pos:X} is cut short")
        template_id, def_off = struct.unpack_from("<II", b, pos + 2)
        p = pos + 10
        if def_off == p:
            tmpl = self.template(def_off, template_id)
            p = def_off + 24 + _U32(b, def_off + 20)[0]
        else:
            tmpl = self.template(def_off, template_id)
        if p + 4 > end:
            raise _BadXml(f"the template instance at 0x{pos:X} has no values")
        count = _U32(b, p)[0]
        p += 4
        if p + 4 * count > end:
            raise _BadXml(f"the template instance at 0x{pos:X} claims {count} "
                          "values, more than its record can hold")
        descs = [struct.unpack_from("<HB", b, p + 4 * i) for i in range(count)]
        p += 4 * count
        values = []
        for size, vtype in descs:
            if p + size > end:
                raise _BadXml(f"value {len(values)} of the template instance "
                              f"at 0x{pos:X} runs past its record")
            values.append(self.value(vtype, p, size, depth))
            p += size
        if tmpl.max_sub >= count:
            self.problems.append(
                f"The template asks for substitution {tmpl.max_sub} but the "
                f"record supplies {count} values; the missing ones are empty.")
        return _Inst(tmpl, values), p

    # -- values -------------------------------------------------------------
    def value(self, vtype: int, pos: int, size: int, depth: int = 0) -> _Val:
        b = self.b
        if vtype == 0x00:
            return _NULL
        if vtype == 0x21:
            nodes, _p = self.nodes(pos, pos + size, False, depth + 1)
            return _Val(vtype, "", None, nodes)
        raw = b[pos:pos + size]
        if size == 0:
            if vtype & 0x80:
                return _Val(vtype, "", [], None, [])
            return _Val(vtype, "", None)
        if vtype == 0x01:
            text = _utf16(raw).rstrip("\x00")
            return _Val(vtype, text, text)
        if vtype == 0x02:
            text = _ansi(raw).rstrip("\x00")
            return _Val(vtype, text, text)
        if vtype & 0x80:
            return self._array(vtype, raw)
        item = self._scalar(vtype, raw)
        if item is None:
            name = VALUE_TYPES.get(vtype, f"0x{vtype:02X}")
            self.problems.append(f"A {size}-byte value of type {name} could "
                                 "not be interpreted; it is shown as hex.")
            return _Val(vtype, bytes(raw).hex().upper(), None)
        return _Val(vtype, item[0], item[1])

    @staticmethod
    def _scalar(vtype: int, raw) -> tuple[str, object] | None:
        size = len(raw)
        fmt = _INT_FORMATS.get(vtype)
        if fmt is not None:
            if size != _FIXED[vtype]:
                return None
            v = struct.unpack(fmt, raw)[0]
            return str(v), v
        if vtype in (0x14, 0x15, 0x10):
            if size not in (4, 8) or (vtype != 0x10 and size != _FIXED[vtype]):
                return None
            v = int.from_bytes(raw, "little")
            return f"0x{v:x}", v
        if vtype == 0x11:
            if size != 8:
                return None
            v = int.from_bytes(raw, "little")
            return filetime_text(v), v
        if vtype == 0x0D:
            if size not in (1, 2, 4):
                return None
            v = int.from_bytes(raw, "little")
            # Only 0 and 1 are defined; any other value is shown as itself.
            return ("true" if v == 1 else "false" if v == 0 else str(v)), v
        if vtype == 0x0F:
            if size != 16:
                return None
            text = guid_text(raw)
            return text, text
        if vtype == 0x13:
            sid = sid_text(raw)
            if sid is None or sid[1] != size:
                return None
            return sid[0], sid[0]
        if vtype == 0x12:
            if size != 16:
                return None
            y, mo, _dow, d, h, mi, s, ms = struct.unpack("<8H", raw)
            return (f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}."
                    f"{ms:03d}"), [y, mo, _dow, d, h, mi, s, ms]
        if vtype in (0x0B, 0x0C):
            if size != _FIXED[vtype]:
                return None
            v = struct.unpack("<f" if vtype == 0x0B else "<d", raw)[0]
            return _real_text(v, vtype == 0x0B), v
        if vtype == 0x0E:
            text = bytes(raw).hex().upper()
            return text, text
        return None                       # EvtHandle, EvtXml, unknown

    def _array(self, vtype: int, raw) -> _Val:
        base = vtype & 0x7F
        items: list = []
        texts: list = []
        if base in (0x01, 0x02):
            text = _utf16(raw) if base == 0x01 else _ansi(raw)
            items = text.split("\x00")
            if items and items[-1] == "":
                items.pop()
            texts = items
        elif base == 0x13:
            pos = 0
            while pos < len(raw):
                sid = sid_text(raw[pos:])
                if sid is None:
                    break
                items.append(sid[0])
                pos += sid[1]
            if pos != len(raw):
                self.problems.append("A SID array has trailing bytes that are "
                                     "not a SID; they were left out.")
            texts = items
        else:
            width = _FIXED.get(base)
            if base == 0x10:
                width = 8 if len(raw) % 8 == 0 else 4
            if width is None or len(raw) % width:
                name = VALUE_TYPES.get(base, f"0x{base:02X}")
                self.problems.append(f"An array of {name} of {len(raw)} bytes "
                                     "could not be split; it is shown as hex.")
                return _Val(vtype, bytes(raw).hex().upper(), None)
            for i in range(0, len(raw), width):
                one = self._scalar(0x15 if base == 0x10 and width == 8 else
                                   0x14 if base == 0x10 else base,
                                   raw[i:i + width])
                if one is None:
                    return _Val(vtype, bytes(raw).hex().upper(), None)
                texts.append(one[0])
                items.append(one[1])
        return _Val(vtype, ",".join(texts), items, None, texts)


# ---------------------------------------------------------------------------
# resolved trees: template + values → elements
# ---------------------------------------------------------------------------

class XmlElement:
    """One rendered element. `attrs` holds (name, text, xml, raw) and
    `children` XmlElement or (text, xml or None, raw) tuples; `raw` is the
    typed value where the text came from a substitution, else None."""
    __slots__ = ("name", "attrs", "children")

    def __init__(self, name, attrs, children):
        self.name, self.attrs, self.children = name, attrs, children

    def elements(self):
        return [c for c in self.children if type(c) is XmlElement]

    def find(self, name: str):
        for c in self.children:
            if type(c) is XmlElement and c.name == name:
                return c
        return None

    def attr(self, name: str):
        for a in self.attrs:
            if a[0] == name:
                return a
        return None

    def text(self) -> str | None:
        """The element's character content, or None when it has none."""
        pieces = [c[0] for c in self.children if type(c) is tuple]
        if not pieces:
            return None
        return pieces[0] if len(pieces) == 1 else "".join(pieces)

    def raw(self):
        pieces = [c for c in self.children if type(c) is tuple]
        if len(pieces) == 1:
            return pieces[0][2]
        return None

    def to_xml(self) -> str:
        out: list[str] = []
        _render(self, out)
        return "".join(out)


def _render(el: XmlElement, out: list) -> None:
    out.append("<" + el.name)
    for name, _text, xml, _raw in el.attrs:
        out.append(f' {name}="{xml}"')
    if not el.children:
        out.append("/>")
        return
    out.append(">")
    for c in el.children:
        if type(c) is XmlElement:
            _render(c, out)
        else:
            out.append(c[1] if c[1] is not None else _esc_text(c[0]))
    out.append(f"</{el.name}>")


def _resolve(parts, values, out: list, depth: int = 0, keep=None) -> None:
    if depth > MAX_DEPTH:
        return
    for part in parts:
        kind = type(part)
        if kind is str:
            if keep is None:
                out.append((part, None, None))
        elif kind is _El:
            if keep is None or part.name in keep:
                array = _array_child(part, values)
                if array is None:
                    out.append(_resolve_el(part, values, depth + 1))
                else:
                    # An element whose content is an array is repeated once
                    # per item ([MS-EVEN6]); an empty array gives one empty
                    # element.
                    index, val = array
                    base = val.vtype & 0x7F
                    pairs = list(zip(val.texts, val.raw)) or [("", None)]
                    for text, item in pairs:
                        vals = list(values)
                        vals[index] = _Val(base, text, item)
                        out.append(_resolve_el(part, vals, depth + 1))
        elif kind is _Sub:
            val = values[part.index] if part.index < len(values) else _NULL
            if val.nodes is not None:
                _resolve(val.nodes, (), out, depth + 1, keep)
            elif val.text is not None and keep is None:
                out.append((val.text, None, val.raw))
        elif kind is _Inst:
            _resolve(part.template.nodes, part.values, out, depth + 1, keep)
        elif keep is None:                      # _Ref
            out.append((part.text, part.xml, None))


def _array_child(el: _El, values):
    for c in el.children:
        if type(c) is _Sub and c.index < len(values):
            v = values[c.index]
            if v.texts is not None and isinstance(v.raw, list):
                return c.index, v
    return None


def _resolve_el(el: _El, values, depth: int, keep=None) -> XmlElement:
    attrs = []
    for name, parts in el.attrs:
        texts, xmls, raw, present = [], [], None, False
        for part in parts:
            kind = type(part)
            if kind is str:
                texts.append(part)
                xmls.append(_esc_attr(part))
                present = True
            elif kind is _Sub:
                val = values[part.index] if part.index < len(values) else _NULL
                if val.nodes is not None:
                    inner: list = []
                    _resolve(val.nodes, (), inner, depth + 1)
                    text = "".join(c.to_xml() if type(c) is XmlElement else c[0]
                                   for c in inner)
                    texts.append(text)
                    xmls.append(_esc_attr(text))
                    present = True
                elif val.text is None:
                    continue              # NULL: contributes nothing
                else:
                    texts.append(val.text)
                    xmls.append(_esc_attr(val.text))
                    raw = val.raw if len(parts) == 1 else None
                    present = True
            else:                                # _Ref
                texts.append(part.text)
                xmls.append(part.xml)
                present = True
        if present:
            attrs.append((name, "".join(texts), "".join(xmls), raw))
    children: list = []
    _resolve(el.children, values, children, depth, keep)
    return XmlElement(el.name, attrs, children)


def _root_of(doc, keep=None) -> XmlElement | None:
    out: list = []
    for part in doc:
        if type(part) is _Inst:
            for node in part.template.nodes:
                if type(node) is _El:
                    return _resolve_el(node, part.values, 0, keep)
            _resolve(part.template.nodes, part.values, out, 0)
        elif type(part) is _El:
            return _resolve_el(part, (), 0, keep)
    for node in out:
        if type(node) is XmlElement:
            return node
    return None


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

FOUND_BY = {
    "chunk": "walked from the chunk's record area",
    "unlisted-chunk": "walked from a chunk past the file header's chunk count "
                      "(not yet counted when the copy was taken)",
    "scan-after-damage": "found by signature scan after a damaged record",
    "chunk-slack": "found by signature scan in the chunk's unused space",
    "scan-bad-chunk": "found by signature scan in a chunk whose header is "
                      "not readable",
    "scan-partial-chunk": "found by signature scan in a chunk cut short by "
                          "the end of the file",
}
RECOVERED_BY = frozenset({"scan-after-damage", "chunk-slack", "scan-bad-chunk",
                          "scan-partial-chunk"})


class EvtxRecord:
    """One event record. Parsed when read; rendered to XML / dict on demand."""

    __slots__ = ("record_id", "written_raw", "offset", "chunk", "chunk_offset",
                 "size", "found_by", "problems", "_doc", "_root", "_system",
                 "_dict")

    def __init__(self, record_id, written_raw, offset, chunk, chunk_offset,
                 size, found_by, problems, doc):
        self.record_id = record_id
        self.written_raw = written_raw
        self.offset = offset                # in the file
        self.chunk = chunk
        self.chunk_offset = chunk_offset
        self.size = size
        self.found_by = found_by
        self.problems = problems
        self._doc = doc                     # None when Binary XML was unreadable
        self._root = None
        self._system = None
        self._dict = None

    @property
    def recovered(self) -> bool:
        return self.found_by in RECOVERED_BY

    @property
    def written_utc(self) -> str | None:
        return timeutil.decode(self.written_raw, "filetime")

    @property
    def readable(self) -> bool:
        return self._doc is not None

    def root(self) -> XmlElement | None:
        if self._root is None and self._doc is not None:
            self._root = _root_of(self._doc)
        return self._root

    def xml(self) -> str:
        root = self.root()
        return root.to_xml() if root is not None else ""

    def system(self) -> dict:
        """The System fields only — cheaper than `as_dict` (EventData is not
        rendered). Empty when the record's Binary XML was unreadable."""
        if self._system is None:
            if self._dict is not None:
                self._system = self._dict
            elif self._doc is None:
                self._system = {}
            else:
                src = self._root if self._root is not None else \
                    _root_of(self._doc, keep={"System"})
                self._system = _system_fields(src, self)
        return self._system

    def as_dict(self) -> dict:
        if self._dict is None:
            root = self.root()
            d = _system_fields(root, self)
            data, source = _event_data(root) if root is not None else ({}, "")
            d["event_data"] = data
            d["event_data_source"] = source
            self._dict = d
            self._system = d
        out = dict(self._dict)
        out["problems"] = list(self.problems)
        return out


def _int_of(text, raw):
    if isinstance(raw, int) and not isinstance(raw, bool):
        return raw
    if text is None:
        return None
    t = text.strip()
    try:
        return int(t, 16) if t[:2].lower() == "0x" else int(t)
    except ValueError:
        return None


def _system_fields(root: XmlElement | None, rec: EvtxRecord) -> dict:
    d = {"record_id": rec.record_id, "written_raw": rec.written_raw,
         "written_utc": rec.written_utc, "epoch": "filetime",
         "event_id": None, "event_qualifiers": None, "version": None,
         "level": None, "task": None, "opcode": None, "keywords": None,
         "provider_name": None, "provider_guid": None,
         "event_source_name": None, "channel": None, "computer": None,
         "user_sid": None, "process_id": None, "thread_id": None,
         "event_record_id": None, "activity_id": None,
         "time_created_raw": None, "time_created_utc": None,
         "time_created_text": None, "recovered": rec.recovered,
         "found_by": rec.found_by, "chunk": rec.chunk, "offset": rec.offset}
    system = root.find("System") if root is not None else None
    if system is None:
        return d
    for el in system.children:
        if type(el) is not XmlElement:
            continue
        name = el.name
        if name == "Provider":
            for an, text, _x, _r in el.attrs:
                if an == "Name":
                    d["provider_name"] = text
                elif an == "Guid":
                    d["provider_guid"] = text
                elif an == "EventSourceName":
                    d["event_source_name"] = text
        elif name == "EventID":
            d["event_id"] = _int_of(el.text(), el.raw())
            q = el.attr("Qualifiers")
            if q is not None:
                d["event_qualifiers"] = _int_of(q[1], q[3])
        elif name in ("Version", "Level", "Task", "Opcode"):
            d[name.lower()] = _int_of(el.text(), el.raw())
        elif name == "Keywords":
            d["keywords"] = el.text()
        elif name == "TimeCreated":
            a = el.attr("SystemTime")
            if a is not None:
                d["time_created_text"] = a[1]
                if isinstance(a[3], int):
                    d["time_created_raw"] = a[3]
                    d["time_created_utc"] = timeutil.decode(a[3], "filetime")
        elif name == "EventRecordID":
            d["event_record_id"] = _int_of(el.text(), el.raw())
        elif name == "Correlation":
            a = el.attr("ActivityID")
            if a is not None:
                d["activity_id"] = a[1]
        elif name == "Execution":
            for an, text, _x, raw in el.attrs:
                if an == "ProcessID":
                    d["process_id"] = _int_of(text, raw)
                elif an == "ThreadID":
                    d["thread_id"] = _int_of(text, raw)
        elif name == "Channel":
            d["channel"] = el.text()
        elif name == "Computer":
            d["computer"] = el.text()
        elif name == "Security":
            a = el.attr("UserID")
            if a is not None:
                d["user_sid"] = a[1]
    if d["event_record_id"] is not None and d["event_record_id"] != rec.record_id:
        msg = (f"System/EventRecordID is {d['event_record_id']} but the record "
               f"header says {rec.record_id}.")
        if msg not in rec.problems:
            rec.problems.append(msg)
    return d


def _put(data: dict, key: str, value) -> None:
    if key in data:
        n = 2
        while f"{key}_{n}" in data:
            n += 1
        key = f"{key}_{n}"
    data[key] = value


def _flatten(data: dict, el: XmlElement, path: str) -> None:
    for name, text, _x, _r in el.attrs:
        if name == "xmlns" or name.startswith("xmlns:"):
            continue
        _put(data, f"{path}@{name}" if path else f"@{name}", text)
    kids = el.elements()
    if not kids:
        _put(data, path or el.name, el.text())
        return
    for k in kids:
        _flatten(data, k, f"{path}.{k.name}" if path else k.name)


def _event_data(root: XmlElement) -> tuple[dict, str]:
    """EventData/Data by Name (unnamed ones as Data_1, Data_2 …), Binary as
    `Binary`; UserData's single child flattened by element path."""
    data: dict = {}
    sources = []
    for section in root.elements():
        if section.name == "EventData":
            sources.append("EventData")
            unnamed = 0
            for d in section.elements():
                if d.name == "Data":
                    a = d.attr("Name")
                    if a is None or a[1] == "":
                        unnamed += 1
                        key = f"Data_{unnamed}"
                    else:
                        key = a[1]
                    _put(data, key, d.text())
                elif d.name == "Binary":
                    _put(data, "Binary", d.text())
                else:
                    _flatten(data, d, d.name)
        elif section.name == "UserData":
            for top in section.elements():
                sources.append(f"UserData/{top.name}")
                _flatten(data, top, "")
        elif section.name in ("ProcessingErrorData", "DebugData",
                              "BinaryEventData"):
            sources.append(section.name)
            _flatten(data, section, section.name)
    return data, ", ".join(sources)


# ---------------------------------------------------------------------------
# the file
# ---------------------------------------------------------------------------

class _BytesReader:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        return self.data[offset:offset + length]


def _plausible_filetime(raw: int) -> bool:
    # 1990-01-01 .. 2100-01-01: what a recovered record's written time must
    # fall within before the bytes are believed to be a record at all.
    return 119_600_064_000_000_000 <= raw <= 159_454_368_000_000_000


class Evtx:
    """An event log presented by a reader with `.size` and `.read_at`."""

    def __init__(self, reader) -> None:
        self.reader = reader
        self.size = int(reader.size)
        if self.size < FILE_HEADER_SIZE + CHUNK_HEADER_SIZE:
            raise FileSystemError(
                f"The file is {self.size} bytes — too short to be a Windows "
                "event log (.evtx), which starts with a 4096-byte file header "
                "followed by 64 KiB chunks.")
        head = reader.read_at(0, FILE_HEADER_SIZE)
        self.header = parse_file_header(head)
        if not self.header.signature_ok and \
                reader.read_at(FILE_HEADER_SIZE, 8) != CHUNK_SIGNATURE:
            raise FileSystemError(
                "This is not a Windows XML event log (.evtx): it carries "
                "neither the ElfFile signature at its start nor a chunk "
                "signature at offset 4096. A Windows XP/2003 .evt log is a "
                "different format.")
        self.problems: list[str] = []
        self.problem_counts: dict[str, int] = {}
        self.chunk_reports: list[ChunkReport] = []
        self._reset()

    @property
    def chunk_slots(self) -> int:
        return (self.size - FILE_HEADER_SIZE) // CHUNK_SIZE

    def _reset(self) -> None:
        self.problems = []
        self.problem_counts = {}
        self.chunk_reports = []
        for p in self.header.problems:
            self._report("header", p)
        if self.header.dirty:
            self._report("dirty", "The file header's DIRTY flag is set: the log "
                         "was copied or left while Windows still had changes "
                         "unflushed (normal for a log taken from a running "
                         "system). Header counts may be stale; chunks past "
                         "them are read too.")
        if self.header.signature_ok and self.header.chunk_count > self.chunk_slots:
            self._report("truncated", f"The file header lists "
                         f"{self.header.chunk_count} chunks but the file holds "
                         f"only {self.chunk_slots}; the copy may be truncated.")
        tail = (self.size - FILE_HEADER_SIZE) % CHUNK_SIZE
        if tail:
            self._report("tail", f"The file ends {tail} bytes into a chunk "
                         "slot; that partial chunk is scanned for records only.")

    def _report(self, kind: str, message: str) -> None:
        self.problem_counts[kind] = self.problem_counts.get(kind, 0) + 1
        if len(self.problems) < MAX_PROBLEM_MESSAGES:
            self.problems.append(message)
        elif len(self.problems) == MAX_PROBLEM_MESSAGES:
            self.problems.append("Further problems are counted in "
                                 "problem_counts but not listed.")

    def records(self, *, recovered: bool = True, should_cancel=None):
        """Yield every record, chunk by chunk, in file order. Recovered records
        (signature scans) are included unless `recovered=False`. Resets and
        refills `problems` and `chunk_reports` on each walk."""
        self._reset()
        listed = self.header.chunk_count if self.header.signature_ok else 0
        slots = self.chunk_slots
        for index in range(slots + (1 if (self.size - FILE_HEADER_SIZE)
                                    % CHUNK_SIZE else 0)):
            if should_cancel is not None and should_cancel():
                raise Cancelled("event log parsing was cancelled")
            offset = FILE_HEADER_SIZE + index * CHUNK_SIZE
            buf = self.reader.read_at(offset, CHUNK_SIZE)
            report = ChunkReport(index, offset, "ok", index < listed)
            self.chunk_reports.append(report)
            if len(buf) < CHUNK_SIZE:
                report.status = "short"
                if recovered:
                    yield from self._scan(buf, report, CHUNK_HEADER_SIZE
                                          if buf[:8] == CHUNK_SIGNATURE else 0,
                                          "scan-partial-chunk", {})
                continue
            if buf[:8] != CHUNK_SIGNATURE:
                if buf.count(0) == len(buf):
                    report.status = "empty"
                    if index < listed:
                        self._chunk_problem(report, "the chunk is all zeroes "
                                            "although the header counts it")
                    continue
                report.status = "no-signature"
                self._chunk_problem(report, "the chunk does not start with the "
                                    "ElfChnk signature; it is scanned for "
                                    "records instead")
                if recovered:
                    yield from self._scan(buf, report, 0, "scan-bad-chunk", {})
                continue
            yield from self._walk_chunk(buf, report, recovered)

    def _chunk_problem(self, report: ChunkReport, message: str,
                       kind: str = "chunk") -> None:
        report.problems.append(message)
        self._report(kind, f"Chunk {report.index} (file offset "
                     f"0x{report.offset:X}): {message}.")

    def _record_problem(self, rec: EvtxRecord, message: str) -> None:
        rec.problems.append(message)
        self._report("record", f"Record {rec.record_id} at file offset "
                     f"0x{rec.offset:X}: {message}")

    def _walk_chunk(self, buf: bytes, report: ChunkReport, recovered: bool):
        (report.first_record_number, report.last_record_number,
         report.first_record_id, report.last_record_id) = struct.unpack_from(
            "<QQQQ", buf, 8)
        _hsize, last_off, free_off, records_crc = struct.unpack_from(
            "<IIII", buf, 40)
        report.last_record_offset, report.free_space_offset = last_off, free_off
        header_crc = _U32(buf, 124)[0]
        computed = zlib.crc32(buf[128:512], zlib.crc32(buf[:120])) & 0xFFFFFFFF
        report.header_checksum_ok = header_crc == computed
        if not report.header_checksum_ok:
            self._chunk_problem(report, f"the chunk header checksum does not "
                                f"match (stored 0x{header_crc:08X}, computed "
                                f"0x{computed:08X}); its offsets may be wrong")
        end = free_off
        if not CHUNK_HEADER_SIZE <= free_off <= CHUNK_SIZE:
            self._chunk_problem(report, f"the free-space offset 0x{free_off:X} "
                                "is outside the chunk; the whole chunk is walked")
            end = CHUNK_SIZE
        else:
            computed = zlib.crc32(buf[CHUNK_HEADER_SIZE:free_off]) & 0xFFFFFFFF
            report.records_checksum_ok = records_crc == computed
            if not report.records_checksum_ok:
                self._chunk_problem(report, f"the event-records checksum does "
                                    f"not match (stored 0x{records_crc:08X}, "
                                    f"computed 0x{computed:08X}); a record in "
                                    "it was altered or not completely written")
        found_by = "chunk" if report.listed or not self.header.signature_ok \
            else "unlisted-chunk"
        xml = _ChunkXml(buf)
        live: dict[int, tuple[int, int]] = {}       # record id -> (pos, size)
        pos = CHUNK_HEADER_SIZE
        last_pos = None
        damaged = None
        while pos + RECORD_MIN_SIZE <= end:
            if buf[pos:pos + 4] != RECORD_SIGNATURE:
                if buf.count(0, pos, end) == end - pos:
                    # Seen in archived logs: the free-space offset points to
                    # the chunk's end and zeroes follow the last record.
                    report.notes.append(f"the records end at chunk offset "
                                        f"0x{pos:X}; zeroes fill the space to "
                                        f"the free-space offset 0x{end:X}")
                else:
                    self._chunk_problem(report, f"no record signature at chunk "
                                        f"offset 0x{pos:X}; the rest of the "
                                        "chunk is scanned")
                    damaged = pos
                break
            size = _U32(buf, pos + 4)[0]
            if size < RECORD_MIN_SIZE or pos + size > CHUNK_SIZE or size % 4:
                self._chunk_problem(report, f"the record at chunk offset "
                                    f"0x{pos:X} has an impossible size "
                                    f"({size}); the rest of the chunk is scanned")
                damaged = pos
                break
            copy = _U32(buf, pos + size - 4)[0]
            rec = self._record(xml, buf, report, pos, size, found_by)
            if copy != size:
                self._record_problem(rec, f"its size ({size}) and the copy of "
                                     f"its size ({copy}) differ — it was not "
                                     "completely written or was overwritten; "
                                     "the rest of the chunk is scanned")
                report.records += 1
                yield rec
                damaged = pos + 4
                break
            report.records += 1
            live[rec.record_id] = (pos, size)
            yield rec
            last_pos = pos
            pos += size
        if damaged is None:
            if last_pos is not None and last_pos != last_off:
                self._chunk_problem(report, f"the last record walked is at chunk "
                                    f"offset 0x{last_pos:X} but the header says "
                                    f"0x{last_off:X}", "chunk-last")
            expected = report.last_record_number - report.first_record_number + 1
            if report.header_checksum_ok and 0 < expected <= 0xFFFF and \
                    expected != report.records:
                self._chunk_problem(report, f"the header counts {expected} "
                                    f"records but {report.records} were walked",
                                    "chunk-count")
            if recovered:
                yield from self._scan(buf, report, max(pos, end), "chunk-slack",
                                      live, xml)
        elif recovered:
            yield from self._scan(buf, report, damaged, "scan-after-damage",
                                  live, xml, slack_from=end)

    def _record(self, xml: _ChunkXml, buf: bytes, report: ChunkReport,
                pos: int, size: int, found_by: str,
                announce: bool = True) -> EvtxRecord:
        record_id, written = struct.unpack_from("<QQ", buf, pos + 8)
        problems: list[str] = []
        xml.problems = problems
        xml.strict = found_by in RECOVERED_BY
        doc = None
        try:
            doc, _p = xml.nodes(pos + 24, pos + size - 4, False)
        except (_BadXml, struct.error, IndexError, RecursionError) as exc:
            msg = str(exc) if isinstance(exc, _BadXml) else \
                f"the Binary XML is truncated or malformed ({type(exc).__name__})"
            problems.append(f"The event's Binary XML could not be read: {msg}.")
        rec = EvtxRecord(record_id, written, report.offset + pos, report.index,
                         pos, size, found_by, problems, doc)
        if announce:
            self._announce(rec)
        return rec

    def _announce(self, rec: EvtxRecord) -> None:
        for p in rec.problems:
            self._report("record", f"Record {rec.record_id} at file offset "
                         f"0x{rec.offset:X}: {p}")

    def _scan(self, buf: bytes, report: ChunkReport, start: int, how: str,
              live: dict, xml: _ChunkXml | None = None, slack_from=None):
        """Records found by signature in `buf[start:]`. Each candidate must
        have a size whose trailing copy matches and a written time between
        1990 and 2100 before it is believed. A candidate byte-for-byte equal
        to a live record of this chunk with the same identifier is counted
        (`slack_copies`), not yielded again; one that differs is yielded and
        says so."""
        if xml is None:
            xml = _ChunkXml(buf)
        pos = start
        limit = len(buf)
        while True:
            pos = buf.find(RECORD_SIGNATURE, pos, limit - RECORD_MIN_SIZE + 1)
            if pos < 0:
                return
            size = _U32(buf, pos + 4)[0]
            if size < RECORD_MIN_SIZE or pos + size > limit or size % 4 or \
                    _U32(buf, pos + size - 4)[0] != size or \
                    not _plausible_filetime(_U64(buf, pos + 16)[0]):
                pos += 1
                continue
            found = how
            if slack_from is not None and pos >= slack_from:
                found = "chunk-slack"
            rec = self._record(xml, buf, report, pos, size, found,
                               announce=False)
            if not rec.readable and found == "chunk-slack":
                # Unused space is full of fragments of older records; one
                # whose XML cannot be read is counted, not listed.
                self.problem_counts["slack-unreadable"] = \
                    self.problem_counts.get("slack-unreadable", 0) + 1
                report.problems.append(f"a record-shaped fragment at chunk "
                                       f"offset 0x{pos:X} in unused space "
                                       "could not be read")
                pos += 4
                continue
            twin = live.get(rec.record_id)
            if twin is not None:
                if buf[twin[0]:twin[0] + twin[1]] == buf[pos:pos + size]:
                    report.slack_copies += 1
                    pos += size
                    continue
                self._announce(rec)
                rec.problems.append("A live record in this chunk has the same "
                                    "identifier and different content; this "
                                    "may be an earlier version of it.")
            else:
                self._announce(rec)
            report.recovered += 1
            yield rec
            pos += size


def open_evtx(reader_or_bytes) -> Evtx:
    """An `Evtx` over bytes, or over a reader with `.size` and `.read_at`."""
    if isinstance(reader_or_bytes, (bytes, bytearray, memoryview)):
        return Evtx(_BytesReader(reader_or_bytes))
    return Evtx(reader_or_bytes)


def summary(evtx: Evtx, *, should_cancel=None) -> dict:
    """What the whole log holds, counted per (provider, event id), without
    keeping any record. Walks every record (System section only).

    `count` is live records; `recovered` is records found by signature scan,
    counted apart because unused space often holds copies of live records.
    First/last times are System/TimeCreated (the record's written time when
    that is absent), raw FILETIME beside UTC; recovered records are included
    in them."""
    counts: dict[tuple, list] = {}
    total = recovered = unreadable = 0
    for rec in evtx.records(should_cancel=should_cancel):
        s = rec.system()
        if rec.recovered:
            recovered += 1
        else:
            total += 1
        if not rec.readable:
            unreadable += 1
        key = (s.get("provider_name"), s.get("event_id"))
        entry = counts.get(key)
        t = s.get("time_created_raw") or rec.written_raw
        if entry is None:
            entry = counts[key] = [0, 0, s.get("channel"), t, t]
        entry[1 if rec.recovered else 0] += 1
        if t and (not entry[3] or t < entry[3]):
            entry[3] = t
        if t and (not entry[4] or t > entry[4]):
            entry[4] = t
    rows = []
    for (provider, event_id), (n, rec_n, channel, first, last) in counts.items():
        rows.append({"provider": provider, "event_id": event_id,
                     "channel": channel, "count": n, "recovered": rec_n,
                     "first_raw": first, "first_utc": timeutil.decode(first, "filetime"),
                     "last_raw": last, "last_utc": timeutil.decode(last, "filetime"),
                     "epoch": "filetime",
                     "catalogued": ((provider or "").lower(), event_id) in CATALOGUE})
    rows.sort(key=lambda r: (-r["count"], -r["recovered"], r["provider"] or "",
                             r["event_id"] if r["event_id"] is not None else -1))
    return {"records": total, "recovered": recovered, "unreadable": unreadable,
            "chunks": len(evtx.chunk_reports),
            "chunks_empty": sum(1 for c in evtx.chunk_reports if c.status == "empty"),
            "header": evtx.header.as_dict(), "problems": list(evtx.problems),
            "problem_counts": dict(evtx.problem_counts), "counts": rows}


# ---------------------------------------------------------------------------
# artefact rows: a catalogue of event identifiers an examiner looks for
# ---------------------------------------------------------------------------

LOGON_TYPES = {0: "System", 2: "Interactive", 3: "Network", 4: "Batch",
               5: "Service", 7: "Unlock", 8: "NetworkCleartext",
               9: "NewCredentials", 10: "RemoteInteractive",
               11: "CachedInteractive", 12: "CachedRemoteInteractive",
               13: "CachedUnlock"}

#: NTSTATUS names (MS-ERREF) of the codes 4625 commonly carries.
NTSTATUS = {0x00000000: "STATUS_SUCCESS",
            0xC000005E: "STATUS_NO_LOGON_SERVERS",
            0xC0000064: "STATUS_NO_SUCH_USER",
            0xC000006A: "STATUS_WRONG_PASSWORD",
            0xC000006D: "STATUS_LOGON_FAILURE",
            0xC000006E: "STATUS_ACCOUNT_RESTRICTION",
            0xC000006F: "STATUS_INVALID_LOGON_HOURS",
            0xC0000070: "STATUS_INVALID_WORKSTATION",
            0xC0000071: "STATUS_PASSWORD_EXPIRED",
            0xC0000072: "STATUS_ACCOUNT_DISABLED",
            0xC00000DC: "STATUS_INVALID_SERVER_STATE",
            0xC0000133: "STATUS_TIME_DIFFERENCE_AT_DC",
            0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
            0xC000018C: "STATUS_TRUSTED_DOMAIN_FAILURE",
            0xC0000192: "STATUS_NETLOGON_NOT_STARTED",
            0xC0000193: "STATUS_ACCOUNT_EXPIRED",
            0xC0000224: "STATUS_PASSWORD_MUST_CHANGE",
            0xC0000234: "STATUS_ACCOUNT_LOCKED_OUT",
            0xC0000413: "STATUS_AUTHENTICATION_FIREWALL_FAILED"}

#: Characters kept of one field in a row; longer values are cut and listed
#: in the row's `detail.truncated` with their full length.
FIELD_LIMIT = 2048
FIELD_LIMITS = {"script_block_text": 8192, "task_content": 4096}

_SUBJECT = {"subject_user": "SubjectUserName", "subject_domain": "SubjectDomainName",
            "subject_sid": "SubjectUserSid", "subject_logon_id": "SubjectLogonId"}
_SEC = "microsoft-windows-security-auditing"
_ACCOUNT = dict(_SUBJECT, target_user="TargetUserName",
                target_domain="TargetDomainName", target_sid="TargetSid")


def _entry(artefact, title, summary, fields, channel=""):
    return {"artefact": artefact, "title": title, "summary": summary,
            "fields": fields, "channel": channel}


#: (provider name in lower case, event id) -> what to emit. `fields` maps a
#: row field to the EventData / UserData key it is read from (first present
#: of a tuple wins); `summary` is formatted with those fields ("?" when
#: absent). Add entries here to widen the catalogue.
CATALOGUE: dict[tuple[str, int], dict] = {
    (_SEC, 4624): _entry(
        "evtx_logon", "Logon succeeded (Security 4624)",
        "Security 4624: logon type {logon_type}{logon_type_name} for "
        "{target_domain}\\{target_user} from {source_ip} (workstation "
        "{workstation}, process {process_name})",
        dict(_SUBJECT, target_user="TargetUserName",
             target_domain="TargetDomainName", target_sid="TargetUserSid",
             target_logon_id="TargetLogonId", logon_type="LogonType",
             logon_process="LogonProcessName",
             auth_package="AuthenticationPackageName",
             workstation="WorkstationName", source_ip="IpAddress",
             source_port="IpPort", process_name="ProcessName",
             elevated_token="ElevatedToken",
             linked_logon_id="TargetLinkedLogonId"), "Security"),
    (_SEC, 4625): _entry(
        "evtx_logon_failed", "Logon failed (Security 4625)",
        "Security 4625: logon type {logon_type}{logon_type_name} failed for "
        "{target_domain}\\{target_user} from {source_ip} (workstation "
        "{workstation}); status {status}{status_name}, sub-status "
        "{sub_status}{sub_status_name}",
        dict(_SUBJECT, target_user="TargetUserName",
             target_domain="TargetDomainName", target_sid="TargetUserSid",
             logon_type="LogonType", status="Status", sub_status="SubStatus",
             failure_reason="FailureReason", logon_process="LogonProcessName",
             auth_package="AuthenticationPackageName",
             workstation="WorkstationName", source_ip="IpAddress",
             source_port="IpPort", process_name="ProcessName"), "Security"),
    (_SEC, 4634): _entry(
        "evtx_logoff", "Logoff (Security 4634)",
        "Security 4634: logon session {target_logon_id} of "
        "{target_domain}\\{target_user} (type {logon_type}{logon_type_name}) "
        "ended",
        dict(target_user="TargetUserName", target_domain="TargetDomainName",
             target_sid="TargetUserSid", target_logon_id="TargetLogonId",
             logon_type="LogonType"), "Security"),
    (_SEC, 4647): _entry(
        "evtx_logoff", "User-initiated logoff (Security 4647)",
        "Security 4647: logoff requested by {target_domain}\\{target_user} "
        "(session {target_logon_id})",
        dict(target_user="TargetUserName", target_domain="TargetDomainName",
             target_sid="TargetUserSid", target_logon_id="TargetLogonId"),
        "Security"),
    (_SEC, 4648): _entry(
        "evtx_explicit_credentials", "Logon with explicit credentials "
        "(Security 4648)",
        "Security 4648: {subject_domain}\\{subject_user} used the credentials "
        "of {target_domain}\\{target_user} for {target_server} (process "
        "{process_name}, address {source_ip})",
        dict(_SUBJECT, target_user="TargetUserName",
             target_domain="TargetDomainName", target_server="TargetServerName",
             target_info="TargetInfo", process_name="ProcessName",
             process_id="ProcessId", source_ip="IpAddress",
             source_port="IpPort"), "Security"),
    (_SEC, 4672): _entry(
        "evtx_special_privileges", "Special privileges assigned "
        "(Security 4672)",
        "Security 4672: special privileges assigned to logon "
        "{subject_logon_id} of {subject_domain}\\{subject_user}",
        dict(_SUBJECT, privileges="PrivilegeList"), "Security"),
    (_SEC, 4688): _entry(
        "evtx_process_created", "Process created (Security 4688)",
        "Security 4688: {new_process_name} started by {parent_process_name} "
        "as {subject_domain}\\{subject_user}; command line: {command_line}",
        dict(_SUBJECT, new_process_name="NewProcessName",
             new_process_id="NewProcessId", command_line="CommandLine",
             parent_process_name="ParentProcessName",
             parent_process_id="ProcessId",
             token_elevation_type="TokenElevationType",
             mandatory_label="MandatoryLabel",
             target_user="TargetUserName", target_domain="TargetDomainName"),
        "Security"),
    (_SEC, 4697): _entry(
        "evtx_service_installed", "Service installed (Security 4697)",
        "Security 4697: service {service_name} installed, file "
        "{service_file}, start type {start_type}, account {service_account}",
        dict(_SUBJECT, service_name="ServiceName",
             service_file="ServiceFileName", service_type="ServiceType",
             start_type="ServiceStartType", service_account="ServiceAccount"),
        "Security"),
    ("service control manager", 7045): _entry(
        "evtx_service_installed", "Service installed (System 7045)",
        "System 7045: service {service_name} installed, image {service_file}, "
        "start type {start_type}, account {service_account}",
        dict(service_name="ServiceName", service_file="ImagePath",
             service_type="ServiceType", start_type="StartType",
             service_account="AccountName"), "System"),
    (_SEC, 4698): _entry(
        "evtx_scheduled_task", "Scheduled task created (Security 4698)",
        "Security 4698: task {task_name} created by "
        "{subject_domain}\\{subject_user}; command {task_command} "
        "{task_arguments}",
        dict(_SUBJECT, task_name="TaskName", task_content="TaskContent"),
        "Security"),
    (_SEC, 4702): _entry(
        "evtx_scheduled_task", "Scheduled task updated (Security 4702)",
        "Security 4702: task {task_name} updated by "
        "{subject_domain}\\{subject_user}; command {task_command} "
        "{task_arguments}",
        dict(_SUBJECT, task_name="TaskName", task_content="TaskContentNew"),
        "Security"),
    (_SEC, 4720): _entry(
        "evtx_account_change", "User account created (Security 4720)",
        "Security 4720: account {target_domain}\\{target_user} ({target_sid}) "
        "created by {subject_domain}\\{subject_user}",
        dict(_ACCOUNT, sam_account_name="SamAccountName"), "Security"),
    (_SEC, 4722): _entry(
        "evtx_account_change", "User account enabled (Security 4722)",
        "Security 4722: account {target_domain}\\{target_user} enabled by "
        "{subject_domain}\\{subject_user}", dict(_ACCOUNT), "Security"),
    (_SEC, 4724): _entry(
        "evtx_account_change", "Password reset attempted (Security 4724)",
        "Security 4724: password reset of {target_domain}\\{target_user} "
        "attempted by {subject_domain}\\{subject_user}", dict(_ACCOUNT),
        "Security"),
    (_SEC, 4726): _entry(
        "evtx_account_change", "User account deleted (Security 4726)",
        "Security 4726: account {target_domain}\\{target_user} deleted by "
        "{subject_domain}\\{subject_user}", dict(_ACCOUNT), "Security"),
    (_SEC, 4732): _entry(
        "evtx_account_change", "Member added to a local group "
        "(Security 4732)",
        "Security 4732: {member_name} ({member_sid}) added to group "
        "{target_domain}\\{target_user} by {subject_domain}\\{subject_user}",
        dict(_ACCOUNT, member_name="MemberName", member_sid="MemberSid"),
        "Security"),
    ("microsoft-windows-eventlog", 1102): _entry(
        "evtx_log_cleared", "Audit log cleared (Security 1102)",
        "Security 1102: the Security log was cleared by "
        "{subject_domain}\\{subject_user}",
        dict(_SUBJECT), "Security"),
    ("microsoft-windows-eventlog", 104): _entry(
        "evtx_log_cleared", "Event log cleared (System 104)",
        "System 104: the {cleared_channel} log was cleared by "
        "{subject_domain}\\{subject_user}",
        dict(subject_user="SubjectUserName", subject_domain="SubjectDomainName",
             cleared_channel="Channel", backup_path="BackupPath"), "System"),
    ("eventlog", 6005): _entry(
        "evtx_system_power", "Event log service started (System 6005)",
        "System 6005: the event log service started", {}, "System"),
    ("eventlog", 6006): _entry(
        "evtx_system_power", "Event log service stopped (System 6006)",
        "System 6006: the event log service stopped", {}, "System"),
    ("eventlog", 6008): _entry(
        "evtx_system_power", "Previous shutdown was unexpected (System 6008)",
        "System 6008: the previous shutdown at {local_time} on {local_date} "
        "(local time as recorded, zone not stated) was unexpected",
        dict(local_time="Data_1", local_date="Data_2"), "System"),
    ("microsoft-windows-terminalservices-localsessionmanager", 21): _entry(
        "evtx_rdp_session", "Remote Desktop logon (LocalSessionManager 21)",
        "LocalSessionManager 21: session {session_id} logon of {user} from "
        "{source_address}",
        dict(user="User", session_id="SessionID", source_address="Address"),
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
    ("microsoft-windows-terminalservices-localsessionmanager", 24): _entry(
        "evtx_rdp_session", "Remote Desktop session disconnected "
        "(LocalSessionManager 24)",
        "LocalSessionManager 24: session {session_id} of {user} disconnected "
        "(source {source_address})",
        dict(user="User", session_id="SessionID", source_address="Address"),
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
    ("microsoft-windows-terminalservices-localsessionmanager", 25): _entry(
        "evtx_rdp_session", "Remote Desktop session reconnected "
        "(LocalSessionManager 25)",
        "LocalSessionManager 25: session {session_id} of {user} reconnected "
        "from {source_address}",
        dict(user="User", session_id="SessionID", source_address="Address"),
        "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
    ("microsoft-windows-terminalservices-remoteconnectionmanager", 1149):
        _entry("evtx_rdp_auth", "Remote Desktop user authentication "
               "succeeded (RemoteConnectionManager 1149)",
               "RemoteConnectionManager 1149: network authentication of "
               "{domain}\\{user} from {source_address}",
               dict(user="Param1", domain="Param2", source_address="Param3"),
               "Microsoft-Windows-TerminalServices-RemoteConnectionManager/"
               "Operational"),
    ("microsoft-windows-powershell", 4104): _entry(
        "evtx_powershell_scriptblock", "PowerShell script block logged "
        "(PowerShell 4104)",
        "PowerShell 4104: script block {script_block_id} part {message_number} "
        "of {message_total} ({path}): {script_block_text}",
        dict(message_number="MessageNumber", message_total="MessageTotal",
             script_block_text="ScriptBlockText",
             script_block_id="ScriptBlockId", path="Path"),
        "Microsoft-Windows-PowerShell/Operational"),
    ("microsoft-windows-windows defender", 1116): _entry(
        "evtx_defender_detection", "Defender detected malware or unwanted "
        "software (Defender 1116)",
        "Defender 1116: {threat_name} ({severity}, {category}) detected at "
        "{path} (process {process_name}, user {detection_user})",
        {"threat_name": "Threat Name", "threat_id": "Threat ID",
         "severity": "Severity Name", "category": "Category Name",
         "path": "Path", "process_name": "Process Name",
         "detection_user": "Detection User", "detection_time": "Detection Time",
         "action": "Action Name", "status": "Status Description"},
        "Microsoft-Windows-Windows Defender/Operational"),
    ("microsoft-windows-windows defender", 1117): _entry(
        "evtx_defender_detection", "Defender took action against malware "
        "(Defender 1117)",
        "Defender 1117: action {action} on {threat_name} at {path} "
        "(error {error_code})",
        {"threat_name": "Threat Name", "threat_id": "Threat ID",
         "severity": "Severity Name", "category": "Category Name",
         "path": "Path", "process_name": "Process Name",
         "detection_user": "Detection User", "action": "Action Name",
         "error_code": "Error Code", "error_description": "Error Description"},
        "Microsoft-Windows-Windows Defender/Operational"),
    ("microsoft-windows-sysmon", 1): _entry(
        "evtx_sysmon_process", "Process created (Sysmon 1)",
        "Sysmon 1: {image} started by {parent_image} as {user}; command line: "
        "{command_line}",
        dict(utc_time="UtcTime", process_guid="ProcessGuid",
             process_id="ProcessId", image="Image", command_line="CommandLine",
             current_directory="CurrentDirectory", user="User",
             logon_id="LogonId", integrity_level="IntegrityLevel",
             hashes="Hashes", parent_image="ParentImage",
             parent_process_id="ParentProcessId",
             parent_command_line="ParentCommandLine",
             original_file_name="OriginalFileName"),
        "Microsoft-Windows-Sysmon/Operational"),
    ("microsoft-windows-sysmon", 3): _entry(
        "evtx_sysmon_network", "Network connection (Sysmon 3)",
        "Sysmon 3: {image} {protocol} {source_ip}:{source_port} -> "
        "{destination_ip}:{destination_port} ({destination_hostname}), "
        "initiated {initiated}",
        dict(utc_time="UtcTime", process_id="ProcessId", image="Image",
             user="User", protocol="Protocol", initiated="Initiated",
             source_ip="SourceIp", source_port="SourcePort",
             source_hostname="SourceHostname", destination_ip="DestinationIp",
             destination_port="DestinationPort",
             destination_hostname="DestinationHostname"),
        "Microsoft-Windows-Sysmon/Operational"),
    ("microsoft-windows-sysmon", 11): _entry(
        "evtx_sysmon_file", "File created (Sysmon 11)",
        "Sysmon 11: {image} created {target_filename}",
        dict(utc_time="UtcTime", process_id="ProcessId", image="Image",
             target_filename="TargetFilename",
             creation_utc_time="CreationUtcTime", user="User"),
        "Microsoft-Windows-Sysmon/Operational"),
    ("microsoft-windows-taskscheduler", 106): _entry(
        "evtx_task_scheduler", "Scheduled task registered "
        "(TaskScheduler 106)",
        "TaskScheduler 106: task {task_name} registered by {user_context}",
        dict(task_name="TaskName", user_context="UserContext"),
        "Microsoft-Windows-TaskScheduler/Operational"),
    ("microsoft-windows-taskscheduler", 200): _entry(
        "evtx_task_scheduler", "Scheduled task action started "
        "(TaskScheduler 200)",
        "TaskScheduler 200: task {task_name} started action {action_name}",
        dict(task_name="TaskName", action_name="ActionName",
             task_instance_id="TaskInstanceId", engine_pid="EnginePID"),
        "Microsoft-Windows-TaskScheduler/Operational"),
    ("microsoft-windows-taskscheduler", 201): _entry(
        "evtx_task_scheduler", "Scheduled task action completed "
        "(TaskScheduler 201)",
        "TaskScheduler 201: task {task_name} action {action_name} completed "
        "with result {result_code}",
        dict(task_name="TaskName", action_name="ActionName",
             task_instance_id="TaskInstanceId", result_code="ResultCode",
             engine_pid="EnginePID"),
        "Microsoft-Windows-TaskScheduler/Operational"),
}

_TASK_COMMAND = re.compile(r"<Command>(.*?)</Command>", re.S)
_TASK_ARGS = re.compile(r"<Arguments>(.*?)</Arguments>", re.S)


class _Blank(dict):
    def __missing__(self, key):
        return "?"


def _parse_int(value) -> int | None:
    if value is None:
        return None
    try:
        s = str(value).strip()
        return int(s, 16) if s[:2].lower() == "0x" else int(s)
    except ValueError:
        return None


def _derive(fields: dict) -> dict:
    """Documented names of coded values, and the command a task definition
    names — kept beside the fields they come from, never replacing them."""
    derived: dict = {}
    if "logon_type" in fields:
        lt = _parse_int(fields.get("logon_type"))
        derived["logon_type_name"] = LOGON_TYPES.get(lt) if lt is not None else None
    for key in ("status", "sub_status"):
        if key in fields:
            code = _parse_int(fields.get(key))
            derived[f"{key}_name"] = NTSTATUS.get(code) if code is not None else None
    content = fields.get("task_content")
    if isinstance(content, str):
        derived["task_command"] = "; ".join(
            c.strip() for c in _TASK_COMMAND.findall(content)) or None
        derived["task_arguments"] = "; ".join(
            a.strip() for a in _TASK_ARGS.findall(content)) or None
    return derived


def _one_line(text: str, limit: int = 400) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _iter_dicts(source):
    """(record dict, cheap System dict) pairs from an Evtx, EvtxRecords or
    record dicts — the full dict is only built for catalogued records."""
    items = source.records() if isinstance(source, Evtx) else source
    for item in items:
        if isinstance(item, dict):
            yield item, item
        else:
            yield item, item.system()


def to_rows(evtx_or_records, *, source_path: str, channel_hint: str = "") -> list[dict]:
    """Artefact rows for the catalogued events only (see `CATALOGUE`).

    `channel_hint` names the log when a record carries no Channel of its own
    (the file's name, say); the row records which one was used.

    Unused chunk space often holds byte-for-byte copies of records that are
    live elsewhere in the file. A recovered row whose record identifier,
    event identifier, time and fields equal a live row's is folded into that
    row (`detail.recovered_copies`) instead of being listed twice; a
    recovered row that differs is kept, marked `[recovered]`.
    """
    rows: list[dict] = []
    for item, sysd in _iter_dicts(evtx_or_records):
        provider = (sysd.get("provider_name") or "").lower()
        spec = CATALOGUE.get((provider, sysd.get("event_id")))
        if spec is None:
            continue
        d = item.as_dict() if not isinstance(item, dict) else item
        rows.append(_row(spec, d, source_path, channel_hint))
    live = {_same_event(r): r for r in rows if not r["detail"]["recovered"]}
    out = []
    for r in rows:
        twin = live.get(_same_event(r)) if r["detail"]["recovered"] else None
        if twin is not None:
            twin["detail"]["recovered_copies"].append(
                {"chunk": r["detail"]["chunk"], "offset": r["detail"]["offset"],
                 "found_by": r["detail"]["found_by"]})
            continue
        out.append(r)
    return out


def _same_event(row: dict) -> tuple:
    d = row["detail"]
    return (d["record_id"], d["event_id"], row["at_raw"],
            repr(sorted(d["fields"].items())))


def _row(spec: dict, d: dict, source_path: str, channel_hint: str) -> dict:
    data = d.get("event_data") or {}
    fields: dict = {}
    truncated: dict = {}
    for out_name, keys in spec["fields"].items():
        if isinstance(keys, str):
            keys = (keys,)
        for key in keys:
            if key in data:
                value = data[key]
                limit = FIELD_LIMITS.get(out_name, FIELD_LIMIT)
                if isinstance(value, str) and len(value) > limit:
                    truncated[out_name] = len(value)
                    value = value[:limit]
                fields[out_name] = value
                break
    derived = _derive(fields)
    channel = d.get("channel")
    channel_from = "record"
    if not channel and channel_hint:
        channel, channel_from = channel_hint, "hint"
    elif not channel:
        channel_from = "none"
    at_raw = d.get("time_created_raw")
    time_source = "System/TimeCreated"
    if not at_raw:
        at_raw = d.get("written_raw")
        time_source = "record written time"
    shown = _Blank({k: ("?" if v is None else v) for k, v in fields.items()})
    for k, v in derived.items():
        if k.endswith("_name"):
            shown[k] = f" ({v})" if v else ""
        else:
            shown[k] = "" if v is None else v
    value = _one_line(spec["summary"].format_map(shown))
    if d.get("recovered"):
        value = "[recovered] " + value
    detail = {
        "event_id": d.get("event_id"), "event_qualifiers": d.get("event_qualifiers"),
        "provider": d.get("provider_name"), "channel": channel,
        "channel_from": channel_from, "computer": d.get("computer"),
        "record_id": d.get("record_id"), "event_record_id": d.get("event_record_id"),
        "user_sid": d.get("user_sid"), "process_id": d.get("process_id"),
        "thread_id": d.get("thread_id"), "level": d.get("level"),
        "time_source": time_source,
        "time_created_raw": d.get("time_created_raw"),
        "time_created_utc": d.get("time_created_utc"),
        "written_raw": d.get("written_raw"), "written_utc": d.get("written_utc"),
        "recovered": bool(d.get("recovered")), "found_by": d.get("found_by"),
        "found_how": FOUND_BY.get(d.get("found_by"), ""),
        "chunk": d.get("chunk"), "offset": d.get("offset"),
        "fields": fields, "derived": derived,
        "truncated": truncated, "source": source_path,
        "problems": list(d.get("problems") or []),
        "recovered_copies": [],
    }
    return {"artefact": spec["artefact"],
            "at_utc": timeutil.decode(at_raw, "filetime"),
            "at_raw": at_raw if at_raw else None,
            "at_epoch": "filetime" if at_raw else None,
            "title": spec["title"], "value": value, "detail": detail,
            "row_ref_suffix": f"evtx:{d.get('record_id')}@{d.get('offset')}"}
