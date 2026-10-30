"""Shell links built from [MS-SHLLINK] (and libfwsi's shell-item notes) for
the shelllink and jumplist suites. Standard library only; writes nothing."""

from __future__ import annotations

import struct
import uuid

LNK_CLSID = uuid.UUID("00021401-0000-0000-c000-000000000046").bytes_le
MY_COMPUTER = "20d04fe0-3aea-1069-a2d8-08002b30309d"
DOCUMENTS_KF = "fdd39ad0-238f-46af-adb4-6c85480369c7"
T_CREATE = 132223104000000000      # 2020-01-01T00:00:00Z
T_ACCESS = 132223104123456780
T_WRITE = 132223140000000000       # 2020-01-01T01:00:00Z
MAC = 0x000C29AABBCC
#: a version-1 UUID timestamp (100 ns since 1582-10-15) = 2021-05-31T04:00:00Z
UUID_TICKS = 132669072000000000 + 5748192000000000


def u16(v):
    return struct.pack("<H", v)


def u32(v):
    return struct.pack("<I", v)


def guid(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def droid_v1(ticks: int = UUID_TICKS, node: int = MAC, clock: int = 0x1234) -> bytes:
    """A version-1 (time-based) UUID as Windows stores a GUID."""
    value = uuid.UUID(fields=(ticks & 0xFFFFFFFF, (ticks >> 32) & 0xFFFF,
                              ((ticks >> 48) & 0x0FFF) | 0x1000,
                              ((clock >> 8) & 0x3F) | 0x80, clock & 0xFF, node))
    return value.bytes_le


def dos(y, mo, d, h=0, mi=0, s=0) -> int:
    """An MS-DOS date (low 16 bits) and time (high 16 bits)."""
    date = ((y - 1980) << 9) | (mo << 5) | d
    time = (h << 11) | (mi << 5) | (s // 2)
    return date | (time << 16)


# -- shell items ---------------------------------------------------------------

def _item(body: bytes) -> bytes:
    return u16(len(body) + 2) + body


def item_root(clsid: str = MY_COMPUTER, sort: int = 0x50) -> bytes:
    return _item(bytes([0x1F, sort]) + guid(clsid))


def item_volume(name: str = "C:\\") -> bytes:
    return _item(bytes([0x2F]) + name.encode("ascii").ljust(20, b"\0") + b"\0\0")


def item_file(short: str, long_name: str, *, mft=(0, 0), size=0,
              modified=0, created=0, accessed=0, directory=False,
              ext_version=9, unicode_primary=False,
              terminate_primary=True) -> bytes:
    """A file-entry shell item with a 0xBEEF0004 extension (version 9 or 8)."""
    t = (0x31 if directory else 0x32) | (0x04 if unicode_primary else 0)
    attrs = 0x10 if directory else 0x20
    head = bytes([t, 0]) + u32(size) + u32(modified) + u16(attrs)
    if unicode_primary:
        primary = short.encode("utf-16-le") + (b"\0\0" if terminate_primary else b"")
    else:
        primary = short.encode("ascii") + b"\0"
        if (2 + len(head) + len(primary)) % 2:
            primary += b"\0"
    ext_at = 2 + len(head) + len(primary)
    name_off = 46 if ext_version >= 9 else 42
    ref = mft[0] | (mft[1] << 48)
    ext = (u16(0) + u16(ext_version) + u32(0xBEEF0004) + u32(created) +
           u32(accessed) + u16(name_off) + u16(0) + struct.pack("<Q", ref) +
           struct.pack("<Q", 0) + u16(0) +
           (u32(0) if ext_version >= 9 else b"") + u32(0) +
           long_name.encode("utf-16-le") + b"\0\0" + u16(ext_at))
    ext = u16(len(ext)) + ext[2:]
    return _item(head + primary + ext)


def id_list(*items: bytes) -> bytes:
    body = b"".join(items) + b"\0\0"
    return u16(len(body)) + body


# -- LinkInfo -----------------------------------------------------------------

def link_info_local(base: str, *, serial=0x1234ABCD, label="SYSTEM",
                    drive_type=3, suffix="", unicode_base: str | None = None) -> bytes:
    hdr = 0x24 if unicode_base is not None else 0x1C
    volume = u32(0) + u32(drive_type) + u32(serial) + u32(0x10) + \
        label.encode("ascii") + b"\0"
    volume = u32(len(volume)) + volume[4:]
    base_b = base.encode("ascii") + b"\0"
    suffix_b = suffix.encode("ascii") + b"\0"
    vol_off = hdr
    base_off = vol_off + len(volume)
    suffix_off = base_off + len(base_b)
    tail = volume + base_b + suffix_b
    extra = b""
    if unicode_base is not None:
        u_base_off = suffix_off + len(suffix_b)
        u_base = unicode_base.encode("utf-16-le") + b"\0\0"
        u_suffix_off = u_base_off + len(u_base)
        tail += u_base + suffix.encode("utf-16-le") + b"\0\0"
        extra = u32(u_base_off) + u32(u_suffix_off)
    head = u32(hdr) + u32(1) + u32(vol_off) + u32(base_off) + u32(0) + \
        u32(suffix_off) + extra
    body = head + tail
    return u32(len(body) + 4) + body


def link_info_network(share: str, suffix: str, device: str = "Z:") -> bytes:
    hdr = 0x1C
    net = u32(0) + u32(3) + u32(0x14) + u32(0) + u32(0x00020000)
    name_b = share.encode("ascii") + b"\0"
    dev_b = device.encode("ascii") + b"\0"
    net = net[:12] + u32(0x14 + len(name_b)) + net[16:] + name_b + dev_b
    net = u32(len(net)) + net[4:]
    suffix_b = suffix.encode("ascii") + b"\0"
    net_off = hdr
    suffix_off = net_off + len(net)
    head = u32(hdr) + u32(2) + u32(0) + u32(0) + u32(net_off) + u32(suffix_off)
    body = head + net + suffix_b
    return u32(len(body) + 4) + body


# -- extra data ---------------------------------------------------------------

def tracker(machine="WORKSTATION7", droid_file: bytes | None = None,
            droid_volume: bytes | None = None) -> bytes:
    df = droid_file if droid_file is not None else droid_v1()
    dv = droid_volume if droid_volume is not None else \
        uuid.UUID("9a3e1d2c-0b4f-4c55-8e21-77aa66bb55cc").bytes_le
    return (u32(0x60) + u32(0xA0000003) + u32(0x58) + u32(0) +
            machine.encode("ascii").ljust(16, b"\0") + dv + df + dv + df)


def known_folder(clsid: str = DOCUMENTS_KF, offset: int = 0) -> bytes:
    return u32(0x1C) + u32(0xA000000B) + guid(clsid) + u32(offset)


def special_folder(csidl: int = 0x25, offset: int = 0) -> bytes:
    return u32(0x10) + u32(0xA0000005) + u32(csidl) + u32(offset)


def environment(path: str) -> bytes:
    return (u32(0x314) + u32(0xA0000001) +
            path.encode("ascii").ljust(260, b"\0") +
            path.encode("utf-16-le").ljust(520, b"\0"))


def property_store(values: list) -> bytes:
    """One `1SPS` storage, integer ids. values: [(id, vt, raw_value_bytes)]."""
    fmt = guid("b725f130-47ef-101a-a5f1-02608c9eebac")
    body = b""
    for pid, vt, raw in values:
        v = u32(pid) + b"\0" + u16(vt) + u16(0) + raw
        body += u32(len(v) + 4) + v
    body += u32(0)
    storage = b"1SPS" + fmt + body
    storage = u32(len(storage) + 4) + storage
    store = storage + u32(0)
    return u32(len(store) + 8) + u32(0xA0000009) + store


def vt_lpwstr(text: str) -> bytes:
    raw = text.encode("utf-16-le") + b"\0\0"
    return u32(len(raw) // 2) + raw


def vista_id_list(*items: bytes) -> bytes:
    body = b"".join(items) + b"\0\0"
    return u32(len(body) + 8) + u32(0xA000000C) + body


# -- the file -------------------------------------------------------------------

def build_lnk(*, ids: bytes | None = None, link_info: bytes | None = None,
              strings: dict | None = None, extra: list | None = None,
              unicode=True, attrs=0x20, size=4096, times=(T_CREATE, T_ACCESS, T_WRITE),
              icon=0, show=1, hotkey=0, terminal=True, extra_flags=0) -> bytes:
    strings = strings or {}
    flags = 0
    if ids is not None:
        flags |= 0x01
    if link_info is not None:
        flags |= 0x02
    for bit, key in ((0x04, "name"), (0x08, "relative_path"),
                     (0x10, "working_dir"), (0x20, "arguments"),
                     (0x40, "icon_location")):
        if key in strings:
            flags |= bit
    if unicode:
        flags |= 0x80
    flags |= extra_flags
    header = (u32(0x4C) + LNK_CLSID + u32(flags) + u32(attrs) +
              struct.pack("<QQQ", *times) + u32(size) + struct.pack("<i", icon) +
              u32(show) + u16(hotkey) + u16(0) + u32(0) + u32(0))
    out = header + (ids or b"") + (link_info or b"")
    for key in ("name", "relative_path", "working_dir", "arguments",
                "icon_location"):
        if key in strings:
            value = strings[key]
            if isinstance(value, tuple):            # (declared count, text)
                count, value = value
            else:
                count = len(value)
            raw = value.encode("utf-16-le") if unicode else value.encode("cp1252")
            out += u16(count) + raw
    for block in extra or []:
        out += block
    if terminal:
        out += u32(0)
    return out


def sample_lnk() -> bytes:
    """A complete local-file link: ID list, LinkInfo, strings, tracker, …"""
    ids = id_list(
        item_root(),
        item_volume("C:\\"),
        item_file("Users", "Users", mft=(375, 1), directory=True,
                  modified=dos(2020, 1, 1, 10, 0, 0), created=dos(2019, 7, 14, 2, 37, 6),
                  accessed=dos(2020, 1, 1, 10, 0, 0)),
        item_file("REPORT~1.DOC", "report final.docx", mft=(91234, 7), size=4096,
                  modified=dos(2020, 1, 1, 1, 0, 0), created=dos(2020, 1, 1, 0, 0, 0),
                  accessed=dos(2020, 1, 1, 1, 0, 0)))
    li = link_info_local("C:\\Users\\report final.docx", serial=0x1234ABCD,
                         label="SYSTEM", unicode_base="C:\\Users\\report final.docx")
    store = property_store([(10, 0x1F, vt_lpwstr("report final.docx")),
                            (15, 0x40, struct.pack("<Q", T_WRITE)),
                            (12, 0x13, u32(4096))])
    return build_lnk(ids=ids, link_info=li,
                     strings={"relative_path": "..\\report final.docx",
                              "working_dir": "C:\\Users",
                              "arguments": "/safe"},
                     extra=[environment("%USERPROFILE%\\report final.docx"),
                            special_folder(0x25), known_folder(),
                            store, tracker()],
                     hotkey=0x0641)
