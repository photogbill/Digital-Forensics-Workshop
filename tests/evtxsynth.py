"""Builds Windows XML Event Logs (.evtx) byte by byte, from the published
layout (Joachim Metz's EVTX format document, [MS-EVEN6] Binary XML) — never
from the parser under test. Standard library only.

A log is a 4096-byte file header and 64 KiB chunks. Each chunk keeps its own
name table and template table: the first use of an element or attribute
name in a chunk stores it inline, later uses point back at it; the first
record using a template defines it inline, later records point back at the
definition. Records are template instances with typed substitution values.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import dataclass, field

CHUNK = 0x10000
EPOCH_DELTA = 116444736000000000            # 1601 -> 1970 in 100 ns ticks


def filetime(unix_seconds: float, extra_ticks: int = 0) -> int:
    return EPOCH_DELTA + int(unix_seconds) * 10_000_000 + extra_ticks


T0 = filetime(1714980000, 1234567)          # 2024-05-06T07:20:00.1234567Z


# ---------------------------------------------------------------------------
# Binary XML node types (the template side)
# ---------------------------------------------------------------------------

@dataclass
class Sub:
    index: int
    vtype: int
    optional: bool = False


@dataclass
class CharRef:
    value: int


@dataclass
class EntityRef:
    name: str


@dataclass
class CData:
    text: str


@dataclass
class PI:
    target: str
    data: str


@dataclass
class E:
    name: str
    attrs: list = field(default_factory=list)       # [(name, [parts])]
    children: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# typed substitution values: (value type, bytes) or Nested
# ---------------------------------------------------------------------------

def utf16(s: str) -> bytes:
    return s.encode("utf-16-le")


def v_null():
    return (0x00, b"")


def v_str(s: str):
    return (0x01, utf16(s))


def v_ansi(s: str):
    return (0x02, s.encode("cp1252"))


def v_int(vtype: int, value: int):
    fmt = {0x03: "<b", 0x04: "<B", 0x05: "<h", 0x06: "<H", 0x07: "<i",
           0x08: "<I", 0x09: "<q", 0x0A: "<Q", 0x14: "<I", 0x15: "<Q"}[vtype]
    return (vtype, struct.pack(fmt, value))


def v_real32(x: float):
    return (0x0B, struct.pack("<f", x))


def v_real64(x: float):
    return (0x0C, struct.pack("<d", x))


def v_bool(value: int):
    return (0x0D, struct.pack("<I", value))


def v_binary(raw: bytes):
    return (0x0E, raw)


def guid_bytes(text: str) -> bytes:
    return uuid.UUID(text.strip("{}")).bytes_le


def v_guid(text: str):
    return (0x0F, guid_bytes(text))


def v_sizet(value: int, width: int = 8):
    return (0x10, value.to_bytes(width, "little"))


def v_filetime(value: int):
    return (0x11, struct.pack("<Q", value))


def v_systemtime(y, mo, dow, d, h, mi, s, ms):
    return (0x12, struct.pack("<8H", y, mo, dow, d, h, mi, s, ms))


def sid_bytes(text: str) -> bytes:
    parts = text.split("-")
    rev, auth, subs = int(parts[1]), int(parts[2]), [int(p) for p in parts[3:]]
    return (bytes([rev, len(subs)]) + auth.to_bytes(6, "big")
            + b"".join(struct.pack("<I", s) for s in subs))


def v_sid(text: str):
    return (0x13, sid_bytes(text))


def v_str_array(items):
    return (0x81, b"".join(utf16(i) + b"\x00\x00" for i in items))


def v_u16_array(items):
    return (0x86, b"".join(struct.pack("<H", i) for i in items))


@dataclass
class Nested:
    """A Binary XML (0x21) value: a fragment holding a template instance,
    or (direct=True) a fragment holding one element with no dependency
    identifier, as [MS-EVEN6] describes for substitution values."""
    tree: E
    values: list = field(default_factory=list)
    key: str = ""
    direct: bool = False


# ---------------------------------------------------------------------------
# chunk writer
# ---------------------------------------------------------------------------

class ChunkWriter:
    def __init__(self) -> None:
        self.buf = bytearray(512)
        self.names: dict[str, int] = {}
        self.templates: dict[str, tuple[int, int]] = {}
        self.records: list[tuple[int, int, int]] = []    # (offset, size, id)

    @property
    def pos(self) -> int:
        return len(self.buf)

    def _name_ref(self, name: str) -> None:
        off = self.names.get(name)
        if off is None:
            off = self.pos + 4
            self.buf += struct.pack("<I", off)
            self.buf += struct.pack("<IHH", 0, 0, len(name)) + utf16(name) + b"\0\0"
            self.names[name] = off
        else:
            self.buf += struct.pack("<I", off)

    def _text(self, s: str, token: int = 0x05) -> None:
        self.buf += bytes([token, 0x01]) + struct.pack("<H", len(s)) + utf16(s)

    def _part(self, part) -> None:
        if isinstance(part, str):
            self._text(part)
        elif isinstance(part, Sub):
            self.buf += bytes([0x0E if part.optional else 0x0D])
            self.buf += struct.pack("<HB", part.index, part.vtype)
        elif isinstance(part, CharRef):
            self.buf += b"\x08" + struct.pack("<H", part.value)
        elif isinstance(part, EntityRef):
            self.buf += b"\x09"
            self._name_ref(part.name)
        elif isinstance(part, CData):
            self.buf += b"\x07" + struct.pack("<H", len(part.text)) + utf16(part.text)
        elif isinstance(part, PI):
            self.buf += b"\x0a"
            self._name_ref(part.target)
            self.buf += b"\x0b" + struct.pack("<H", len(part.data)) + utf16(part.data)
        elif isinstance(part, E):
            raise TypeError("elements go through element()")
        else:
            raise TypeError(part)

    def element(self, el: E, dep: bool = True) -> None:
        start = self.pos
        self.buf += bytes([0x41 if el.attrs else 0x01])
        if dep:
            self.buf += struct.pack("<H", 0xFFFF)
        size_at = self.pos
        self.buf += b"\0\0\0\0"
        self._name_ref(el.name)
        if el.attrs:
            list_at = self.pos
            self.buf += b"\0\0\0\0"
            for i, (aname, parts) in enumerate(el.attrs):
                self.buf += bytes([0x46 if i < len(el.attrs) - 1 else 0x06])
                self._name_ref(aname)
                for part in parts:
                    self._part(part)
            struct.pack_into("<I", self.buf, list_at, self.pos - list_at - 4)
        if el.children:
            self.buf += b"\x02"
            for child in el.children:
                if isinstance(child, E):
                    self.element(child, dep)
                else:
                    self._part(child)
            self.buf += b"\x04"
        else:
            self.buf += b"\x03"
        struct.pack_into("<I", self.buf, size_at,
                         self.pos - start - (7 if dep else 5))

    def instance(self, key: str, tree: E, values: list,
                 template_guid: str | None = None) -> None:
        self.buf += b"\x0c\x01"
        known = self.templates.get(key)
        if known is None:
            guid = uuid.uuid5(uuid.NAMESPACE_URL, template_guid or key).bytes_le
            tid = struct.unpack_from("<I", guid)[0]
            off = self.pos + 8
            self.buf += struct.pack("<II", tid, off)
            self.buf += struct.pack("<I", 0) + guid
            size_at = self.pos
            self.buf += b"\0\0\0\0"
            frag = self.pos
            self.buf += b"\x0f\x01\x01\x00"
            self.element(tree, dep=True)
            self.buf += b"\x00"
            struct.pack_into("<I", self.buf, size_at, self.pos - frag)
            self.templates[key] = (off, tid)
        else:
            off, tid = known
            self.buf += struct.pack("<II", tid, off)
        self.buf += struct.pack("<I", len(values))
        desc_at = self.pos
        self.buf += bytes(4 * len(values))
        for i, val in enumerate(values):
            start = self.pos
            if isinstance(val, Nested):
                self.buf += b"\x0f\x01\x01\x00"
                if val.direct:
                    self.element(val.tree, dep=False)
                else:
                    self.instance(val.key or repr(val.tree), val.tree, val.values)
                self.buf += b"\x00"
                vtype = 0x21
            else:
                vtype, raw = val
                self.buf += raw
            struct.pack_into("<HBB", self.buf, desc_at + 4 * i,
                             self.pos - start, vtype, 0)

    def record(self, record_id: int, written: int, key: str, tree: E,
               values: list) -> int:
        start = self.pos
        self.buf += b"**\0\0\0\0\0\0" + struct.pack("<QQ", record_id, written)
        self.buf += b"\x0f\x01\x01\x00"
        self.instance(key, tree, values)
        self.buf += b"\x00"
        self.buf += bytes(-(self.pos + 4 - start) % 8)
        size = self.pos + 4 - start
        struct.pack_into("<I", self.buf, start + 4, size)
        self.buf += struct.pack("<I", size)
        self.records.append((start, size, record_id))
        if self.pos > CHUNK:
            raise ValueError("chunk overflow")
        return start

    def finish(self, *, live: int | None = None) -> bytes:
        """The 64 KiB chunk. `live` = how many records the header accounts
        for; records after those sit in the chunk's unused space."""
        recs = self.records if live is None else self.records[:live]
        free = (recs[-1][0] + recs[-1][1]) if recs else 512
        last_off = recs[-1][0] if recs else 0
        first_id = recs[0][2] if recs else 0
        last_id = recs[-1][2] if recs else 0
        data = bytearray(self.buf) + bytes(CHUNK - len(self.buf))
        data[0:8] = b"ElfChnk\x00"
        struct.pack_into("<QQQQ", data, 8, first_id, last_id, first_id, last_id)
        struct.pack_into("<IIII", data, 40, 128, last_off, free,
                         zlib.crc32(bytes(data[512:free])) & 0xFFFFFFFF)
        struct.pack_into("<I", data, 124, crc_chunk_header(data))
        return bytes(data)


def crc_chunk_header(data) -> int:
    return zlib.crc32(bytes(data[128:512]), zlib.crc32(bytes(data[:120]))) & 0xFFFFFFFF


def crc_records(data, free: int) -> int:
    return zlib.crc32(bytes(data[512:free])) & 0xFFFFFFFF


def file_header(*, chunk_count: int, next_record_id: int, flags: int = 0,
                first_chunk: int = 0, last_chunk: int | None = None,
                minor: int = 1) -> bytes:
    if last_chunk is None:
        last_chunk = max(chunk_count - 1, 0)
    head = bytearray(4096)
    head[0:8] = b"ElfFile\x00"
    struct.pack_into("<QQQI", head, 8, first_chunk, last_chunk, next_record_id, 128)
    struct.pack_into("<HHHH", head, 36, minor, 3, 4096, chunk_count)
    struct.pack_into("<I", head, 120, flags)
    struct.pack_into("<I", head, 124, zlib.crc32(bytes(head[:120])) & 0xFFFFFFFF)
    return bytes(head)


def build(chunks: list[bytes], *, flags: int = 0, chunk_count: int | None = None,
          next_record_id: int = 1, **kw) -> bytes:
    count = len(chunks) if chunk_count is None else chunk_count
    return file_header(chunk_count=count, next_record_id=next_record_id,
                       flags=flags, **kw) + b"".join(chunks)


# ---------------------------------------------------------------------------
# events: a System section in the Windows layout plus EventData / UserData
# ---------------------------------------------------------------------------

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
SECURITY_GUID = "{54849625-5478-4994-A5BA-3E3B0328C30D}"


def system_element() -> E:
    o = True
    return E("System", [], [
        E("Provider", [("Name", [Sub(0, 0x01, o)]), ("Guid", [Sub(1, 0x0F, o)])]),
        E("EventID", [("Qualifiers", [Sub(2, 0x06, o)])], [Sub(3, 0x06, o)]),
        E("Version", [], [Sub(4, 0x04, o)]),
        E("Level", [], [Sub(5, 0x04, o)]),
        E("Task", [], [Sub(6, 0x06, o)]),
        E("Opcode", [], [Sub(7, 0x04, o)]),
        E("Keywords", [], [Sub(8, 0x15, o)]),
        E("TimeCreated", [("SystemTime", [Sub(9, 0x11, o)])]),
        E("EventRecordID", [], [Sub(10, 0x0A, o)]),
        E("Correlation", [("ActivityID", [Sub(11, 0x0F, o)])]),
        E("Execution", [("ProcessID", [Sub(12, 0x08, o)]),
                        ("ThreadID", [Sub(13, 0x08, o)])]),
        E("Channel", [], [Sub(14, 0x01, o)]),
        E("Computer", [], [Sub(15, 0x01, o)]),
        E("Security", [("UserID", [Sub(16, 0x13, o)])]),
    ])


N_SYSTEM = 17


@dataclass
class Event:
    provider: str
    event_id: int
    record_id: int
    time: int = T0
    channel: str = "Security"
    computer: str = "WS01.corp.example"
    guid: str | None = SECURITY_GUID
    qualifiers: int | None = None
    version: int = 0
    level: int = 0
    task: int = 12544
    opcode: int = 0
    keywords: int = 0x8020000000000000
    activity: str | None = None
    pid: int = 636
    tid: int = 700
    user_sid: str | None = None
    data: list = field(default_factory=list)      # [(name or None, value)]
    userdata: E | None = None                     # tree; subs index from N_SYSTEM
    userdata_values: list = field(default_factory=list)
    written: int | None = None
    event_record_id: int | None = None


def _system_values(ev: Event) -> list:
    return [v_str(ev.provider),
            v_guid(ev.guid) if ev.guid else v_null(),
            v_int(0x06, ev.qualifiers) if ev.qualifiers is not None else v_null(),
            v_int(0x06, ev.event_id), v_int(0x04, ev.version),
            v_int(0x04, ev.level), v_int(0x06, ev.task), v_int(0x04, ev.opcode),
            v_int(0x15, ev.keywords), v_filetime(ev.time),
            v_int(0x0A, ev.event_record_id if ev.event_record_id is not None
                  else ev.record_id),
            v_guid(ev.activity) if ev.activity else v_null(),
            v_int(0x08, ev.pid), v_int(0x08, ev.tid), v_str(ev.channel),
            v_str(ev.computer),
            v_sid(ev.user_sid) if ev.user_sid else v_null()]


def event_template(ev: Event) -> tuple[str, E, list]:
    """(template key, tree, values) for an event: same shape, same key."""
    values = _system_values(ev)
    children = [system_element()]
    if ev.userdata is not None:
        children.append(E("UserData", [], [ev.userdata]))
        values += ev.userdata_values
        key = f"ud:{ev.userdata!r}"
    else:
        datas = []
        for i, (name, val) in enumerate(ev.data):
            vtype = 0x21 if isinstance(val, Nested) else val[0]
            attrs = [("Name", [name])] if name is not None else []
            datas.append(E("Data", attrs, [Sub(N_SYSTEM + i, vtype)]))
            values.append(val)
        children.append(E("EventData", [], datas))
        key = "ed:" + "|".join(f"{n}/{0x21 if isinstance(v, Nested) else v[0]}"
                               for n, v in ev.data)
    tree = E("Event", [("xmlns", [NS])], children)
    return key, tree, values


def add_event(chunk: ChunkWriter, ev: Event) -> int:
    key, tree, values = event_template(ev)
    return chunk.record(ev.record_id, ev.written if ev.written is not None
                        else ev.time, key, tree, values)


def chunk_of(events: list[Event], *, live: int | None = None) -> bytes:
    c = ChunkWriter()
    for ev in events:
        add_event(c, ev)
    return c.finish(live=live)


def logon_4624(record_id: int, *, user="alice", domain="CORP", logon_type=10,
               ip="10.0.0.5", workstation="WS07", time=T0) -> Event:
    return Event("Microsoft-Windows-Security-Auditing", 4624, record_id,
                 time=time, data=[
                     ("SubjectUserSid", v_sid("S-1-5-18")),
                     ("SubjectUserName", v_str("WS01$")),
                     ("SubjectDomainName", v_str("CORP")),
                     ("SubjectLogonId", v_int(0x15, 0x3E7)),
                     ("TargetUserSid", v_sid("S-1-5-21-1-2-3-1104")),
                     ("TargetUserName", v_str(user)),
                     ("TargetDomainName", v_str(domain)),
                     ("TargetLogonId", v_int(0x15, 0x1A2B3C)),
                     ("LogonType", v_int(0x08, logon_type)),
                     ("LogonProcessName", v_str("User32 ")),
                     ("AuthenticationPackageName", v_str("Negotiate")),
                     ("WorkstationName", v_str(workstation)),
                     ("ProcessName", v_str("C:\\Windows\\System32\\svchost.exe")),
                     ("IpAddress", v_str(ip)),
                     ("IpPort", v_str("0"))])
