# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows registry hives (regf) built byte by byte for the test suite.

Written from the published layout (Joachim Metz, "Windows NT Registry File
(REGF) format"; Maxim Suhanov, "Windows registry file format
specification"), NOT from any parser: the 4096-byte base block with its XOR
checksum, 4096-byte-multiple hive bins, and cells whose 32-bit size is
negative when allocated. Key nodes (`nk`), values (`vk`, inline when four
bytes or fewer, `db` big data above 16 344 bytes), subkey lists (`lf`, `lh`,
`li`, and `ri` over leaves), one shared `sk`. A key or value marked
`deleted=True` is laid out like any other but left OUT of its parent's lists
and its cells are marked free — which is exactly what Windows leaves behind.

The artefact helpers at the bottom (UserAssist records, ShimCache blobs,
shell items, SAM F values, …) are built from the same public descriptions.
"""

from __future__ import annotations

import struct
import uuid

T0 = 132_000_000_000_000_000          # a FILETIME: 2019-04-15T…Z
HOUR = 36_000_000_000                 # one hour in FILETIME ticks
HBIN = 4096
SEGMENT = 16344

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY = 0, 1, 2, 3
REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ = 4, 5, 6, 7
REG_QWORD = 11


# -- value data --------------------------------------------------------------

def sz(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\x00\x00"


def multi_sz(items) -> bytes:
    return b"".join(sz(i) for i in items) + b"\x00\x00"


def dword(n: int) -> bytes:
    return struct.pack("<I", n & 0xFFFFFFFF)


def dword_be(n: int) -> bytes:
    return struct.pack(">I", n)


def qword(n: int) -> bytes:
    return struct.pack("<Q", n)


def systemtime(y, mo, d, h=0, mi=0, s=0, ms=0, dow=0) -> bytes:
    return struct.pack("<8H", y, mo, dow, d, h, mi, s, ms)


def guid_le(text: str) -> bytes:
    return uuid.UUID(text.strip("{}")).bytes_le


# -- the tree ----------------------------------------------------------------

class V:
    def __init__(self, name, vtype, data, *, utf16_name=False, deleted=False):
        self.name, self.type, self.data = name, vtype, bytes(data)
        self.utf16_name = utf16_name
        self.deleted = deleted


class K:
    def __init__(self, name, *, written=T0, class_name=None, utf16=False,
                 deleted=False, list_kind=None):
        self.name = name
        self.written = written
        self.class_name = class_name
        self.utf16 = utf16
        self.deleted = deleted
        self.list_kind = list_kind
        self.subkeys: list[K] = []
        self.values: list[V] = []

    def key(self, name, **kw) -> "K":
        child = K(name, **kw)
        self.subkeys.append(child)
        return child

    def path(self, path: str, **kw) -> "K":
        """The key at `path` under this one, created as needed (the last
        component takes `kw`)."""
        node = self
        parts = [p for p in path.split("\\") if p]
        for i, part in enumerate(parts):
            found = next((c for c in node.subkeys
                          if c.name.lower() == part.lower() and not c.deleted),
                         None)
            if found is None:
                found = node.key(part, **(kw if i == len(parts) - 1 else {}))
            node = found
        return node

    def value(self, name, vtype, data, **kw) -> "K":
        self.values.append(V(name, vtype, data, **kw))
        return self

    def sz(self, name, text, **kw) -> "K":
        return self.value(name, REG_SZ, sz(text), **kw)

    def dword(self, name, n, **kw) -> "K":
        return self.value(name, REG_DWORD, dword(n), **kw)

    def binary(self, name, data, **kw) -> "K":
        return self.value(name, REG_BINARY, data, **kw)


def _name_bytes(name: str, utf16: bool) -> tuple[bytes, bool]:
    if not utf16:
        try:
            return name.encode("latin-1"), True
        except UnicodeEncodeError:
            pass
    return name.encode("utf-16-le"), False


def lh_hash(name: str) -> int:
    h = 0
    for ch in name.upper():
        h = (h * 37 + ord(ch)) & 0xFFFFFFFF
    return h


def _cell_size(payload_len: int) -> int:
    n = payload_len + 4
    return max(8, n + (-n % 8))


class _Alloc:
    """Places cells in hive bins; a bin's unused tail becomes one free cell."""

    def __init__(self) -> None:
        self.bins: list[list[int]] = []      # [start, size, used]

    def cell(self, payload_len: int) -> int:
        size = _cell_size(payload_len)
        if self.bins:
            b = self.bins[-1]
            if b[2] + size <= b[1]:
                off = b[0] + b[2]
                b[2] += size
                return off
        start = self.bins[-1][0] + self.bins[-1][1] if self.bins else 0
        bsize = max(HBIN, -(-(size + 32) // HBIN) * HBIN)
        self.bins.append([start, bsize, 32 + size])
        return start + 32

    @property
    def total(self) -> int:
        return self.bins[-1][0] + self.bins[-1][1] if self.bins else 0


OWNER_SD = (bytes([1, 0]) + struct.pack("<H", 0x8000)
            + struct.pack("<IIII", 20, 0, 0, 0)
            + bytes([1, 2, 0, 0, 0, 0, 0, 5]) + struct.pack("<II", 32, 544))


class HiveBuilder:
    """`HiveBuilder().root` is the root key; `build()` returns the bytes and
    fills `offsets` (key path -> nk offset) and `value_offsets`
    ((key path, value name) -> vk offset) for tests that damage cells."""

    def __init__(self, root_name="ROOT", *, minor=5, list_kind="lh",
                 ri_chunk=2) -> None:
        self.root = K(root_name)
        self.minor = minor
        self.list_kind = list_kind
        self.ri_chunk = ri_chunk
        self.offsets: dict = {}
        self.value_offsets: dict = {}
        self.data_offsets: dict = {}

    def build(self, *, primary=7, secondary=7, written=T0,
              file_name="\\??\\C:\\Windows\\System32\\config\\TEST",
              file_type=0) -> bytes:
        alloc = _Alloc()
        cells: list = []                     # (offset, payload, free)
        sk_off = alloc.cell(20 + len(OWNER_SD))
        nkeys = [0]
        plan: dict = {}

        def visit(k: K, path: str) -> None:
            nkeys[0] += 1
            nb, comp = _name_bytes(k.name, k.utf16)
            p = {"nk": alloc.cell(0x4C + len(nb)), "nb": nb, "comp": comp,
                 "values": []}
            plan[id(k)] = p
            self.offsets[path] = p["nk"]
            if k.class_name:
                cb = k.class_name.encode("utf-16-le")
                p["class"] = (alloc.cell(len(cb)), cb)
            for v in k.values:
                vb, vcomp = _name_bytes(v.name, v.utf16_name)
                vp = {"v": v, "vk": alloc.cell(0x14 + len(vb)), "nb": vb,
                      "comp": vcomp}
                self.value_offsets[(path, v.name)] = vp["vk"]
                n = len(v.data)
                if n > SEGMENT and self.minor >= 4:
                    nseg = -(-n // SEGMENT)
                    vp["db"] = alloc.cell(8)
                    vp["seglist"] = alloc.cell(4 * nseg)
                    vp["segs"] = [alloc.cell(min(SEGMENT, n - i * SEGMENT))
                                  for i in range(nseg)]
                    self.data_offsets[(path, v.name)] = vp["db"]
                elif n > 4:
                    vp["data"] = alloc.cell(n)
                    self.data_offsets[(path, v.name)] = vp["data"]
                p["values"].append(vp)
            live_values = [vp for vp in p["values"] if not vp["v"].deleted]
            if live_values:
                p["vlist"] = alloc.cell(4 * len(live_values))
            live = sorted((c for c in k.subkeys if not c.deleted),
                          key=lambda c: c.name.upper())
            kind = k.list_kind or self.list_kind
            if live:
                if kind == "ri":
                    chunks = [live[i:i + self.ri_chunk]
                              for i in range(0, len(live), self.ri_chunk)]
                    p["ri"] = alloc.cell(4 + 4 * len(chunks))
                    p["leaves"] = [(alloc.cell(4 + 4 * len(c)), c)
                                   for c in chunks]
                else:
                    step = 4 if kind == "li" else 8
                    p["list"] = (alloc.cell(4 + step * len(live)), kind, live)
            for c in k.subkeys:
                visit(c, (path + "\\" if path else "") + c.name)

        visit(self.root, "")

        def render(k: K, parent_off: int) -> None:
            p = plan[id(k)]
            live = sorted((c for c in k.subkeys if not c.deleted),
                          key=lambda c: c.name.upper())
            if "ri" in p:
                list_off = p["ri"]
                cells.append((p["ri"], b"ri" + struct.pack("<H", len(p["leaves"]))
                              + b"".join(struct.pack("<I", off)
                                         for off, _c in p["leaves"]), k.deleted))
                for off, chunk in p["leaves"]:
                    cells.append((off, b"li" + struct.pack("<H", len(chunk))
                                  + b"".join(struct.pack("<I", plan[id(c)]["nk"])
                                             for c in chunk), k.deleted))
            elif "list" in p:
                list_off, kind, kids = p["list"]
                body = bytearray(kind.encode() + struct.pack("<H", len(kids)))
                for c in kids:
                    body += struct.pack("<I", plan[id(c)]["nk"])
                    if kind == "lf":
                        body += (c.name.encode("latin-1", "replace") + b"\0" * 4)[:4]
                    elif kind == "lh":
                        body += struct.pack("<I", lh_hash(c.name))
                cells.append((list_off, bytes(body), k.deleted))
            else:
                list_off = 0xFFFFFFFF
            live_values = [vp for vp in p["values"] if not vp["v"].deleted]
            vlist = p.get("vlist", 0xFFFFFFFF)
            if live_values:
                cells.append((vlist, b"".join(struct.pack("<I", vp["vk"])
                                              for vp in live_values), k.deleted))
            for vp in p["values"]:
                v = vp["v"]
                free = v.deleted or k.deleted
                n = len(v.data)
                if n <= 4:
                    size_field = n | 0x80000000
                    data_field = struct.unpack("<I", (v.data + b"\0" * 4)[:4])[0]
                elif "db" in vp:
                    size_field, data_field = n, vp["db"]
                    cells.append((vp["db"], b"db" + struct.pack(
                        "<HI", len(vp["segs"]), vp["seglist"]), free))
                    cells.append((vp["seglist"], b"".join(
                        struct.pack("<I", s) for s in vp["segs"]), free))
                    for i, s in enumerate(vp["segs"]):
                        cells.append((s, v.data[i * SEGMENT:(i + 1) * SEGMENT],
                                      free))
                else:
                    size_field, data_field = n, vp["data"]
                    cells.append((vp["data"], v.data, free))
                cells.append((vp["vk"], b"vk" + struct.pack(
                    "<HIIIHH", len(vp["nb"]), size_field, data_field, v.type,
                    1 if vp["comp"] else 0, 0) + vp["nb"], free))
            flags = 0x20 if p["comp"] else 0
            if k is self.root:
                flags |= 0x0C
            cls_off, cls_len = 0xFFFFFFFF, 0
            if "class" in p:
                cls_off, cb = p["class"]
                cls_len = len(cb)
                cells.append((cls_off, cb, k.deleted))
            nk = (b"nk" + struct.pack(
                "<HQIIIIIIIIIIIIIIIHH", flags, k.written, 0, parent_off,
                len(live), 0, list_off, 0xFFFFFFFF, len(live_values), vlist,
                sk_off, cls_off, 0, 0, 0, 0, 0, len(p["nb"]), cls_len)
                + p["nb"])
            cells.append((p["nk"], nk, k.deleted))
            for c in k.subkeys:
                render(c, p["nk"])

        render(self.root, 0xFFFFFFFF)
        cells.append((sk_off, b"sk\0\0" + struct.pack(
            "<IIII", sk_off, sk_off, nkeys[0], len(OWNER_SD)) + OWNER_SD, False))

        body = bytearray(alloc.total)
        for start, size, used in alloc.bins:
            body[start:start + 32] = (b"hbin" + struct.pack("<II", start, size)
                                      + bytes(8) + struct.pack("<Q", written)
                                      + bytes(4))
            if used < size:
                struct.pack_into("<i", body, start + used, size - used)
        for off, payload, free in cells:
            size = _cell_size(len(payload))
            struct.pack_into("<i", body, off, size if free else -size)
            body[off + 4:off + 4 + len(payload)] = payload
        base = bytearray(4096)
        fname = file_name[-31:].encode("utf-16-le")   # Windows keeps the tail
        base[0:4] = b"regf"
        struct.pack_into("<IIQIIIIIII", base, 4, primary, secondary, written,
                         1, self.minor, file_type, 1, plan[id(self.root)]["nk"],
                         len(body), 1)
        base[0x30:0x30 + len(fname)] = fname
        struct.pack_into("<I", base, 0x1FC, checksum(base))
        return bytes(base) + bytes(body)


def checksum(block) -> int:
    x = 0
    for (w,) in struct.iter_unpack("<I", bytes(block[:508])):
        x ^= w
    return 0xFFFFFFFE if x == 0xFFFFFFFF else (1 if x == 0 else x)


def resign(data: bytes) -> bytes:
    """Recompute the base block checksum after a test edits the header."""
    out = bytearray(data)
    struct.pack_into("<I", out, 0x1FC, checksum(out))
    return bytes(out)


# -- artefact payloads ---------------------------------------------------------

def rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def userassist72(runs, focus_count, focus_ms, last_run) -> bytes:
    """Windows 7+ record: 0 session, 4 run count, 8 focus count, 12 focus
    time (ms), 60 last execution FILETIME; 72 bytes."""
    out = bytearray(72)
    struct.pack_into("<IIII", out, 0, 0, runs, focus_count, focus_ms)
    struct.pack_into("<Q", out, 60, last_run)
    return bytes(out)


def userassist16(runs, last_run) -> bytes:
    return struct.pack("<IIQ", 1, runs, last_run)


def mru_list_ex(order) -> bytes:
    return b"".join(struct.pack("<I", n) for n in order) + b"\xff\xff\xff\xff"


def shim_win10(entries, header=0x34) -> bytes:
    """[(path, last-modified FILETIME, data bytes)] in the '10ts' layout."""
    out = bytearray(header)
    struct.pack_into("<I", out, 0, header)
    for path, mod, blob in entries:
        pb = path.encode("utf-16-le")
        body = (struct.pack("<H", len(pb)) + pb + struct.pack("<Q", mod)
                + struct.pack("<I", len(blob)) + blob)
        out += b"10ts" + struct.pack("<II", 0x1234, len(body)) + body
    return bytes(out)


def shim_win81(entries) -> bytes:
    """[(path, insert flags, last-modified)]: header 0x80, '10ts' entries
    with an (empty) package name and the two flag dwords."""
    out = bytearray(0x80)
    for path, flags, mod in entries:
        pb = path.encode("utf-16-le")
        body = (struct.pack("<H", len(pb)) + pb + struct.pack("<H", 0)
                + struct.pack("<II", flags, 0) + struct.pack("<Q", mod)
                + struct.pack("<I", 0))
        out += b"10ts" + struct.pack("<II", 0, len(body)) + body
    return bytes(out)


def shim_win7_64(entries) -> bytes:
    """[(path, last-modified, insert flags)]: 0xBADC0FEE header of 0x80,
    48-byte entries, paths after the table."""
    n = len(entries)
    table = bytearray(0x80)
    struct.pack_into("<II", table, 0, 0xBADC0FEE, n)
    strings = bytearray()
    base = 0x80 + 48 * n
    rows = bytearray()
    for path, mod, flags in entries:
        pb = path.encode("utf-16-le")
        rows += struct.pack("<HHIQQIIQQ", len(pb), len(pb) + 2, 0,
                            base + len(strings), mod, flags, 0, 0, 0)
        strings += pb + b"\0\0"
    return bytes(table + rows + strings)


def dos_datetime(y, mo, d, h, mi, s) -> int:
    date = ((y - 1980) << 9) | (mo << 5) | d
    time = (h << 11) | (mi << 5) | (s // 2)
    return date | (time << 16)


def item_root(guid: str, sort=0x50) -> bytes:
    return struct.pack("<HBB", 20, 0x1F, sort) + guid_le(guid)


def item_volume(letter: str) -> bytes:
    name = (letter + ":\\").encode("ascii")
    body = bytes([0x2F]) + name + bytes(20 - len(name))
    return struct.pack("<H", 2 + len(body)) + body


def item_file(name: str, *, directory=True, modified=0, created=0,
              accessed=0, mft=(0, 0), short=None) -> bytes:
    """A file-entry item (class 0x31/0x32) with a version-9 0xBEEF0004
    extension carrying the long name."""
    short = (short or name.upper()[:12]).encode("ascii") + b"\0"
    if len(short) % 2:
        short += b"\0"
    long_name = name.encode("utf-16-le") + b"\0\0"
    ext = bytearray()
    ext += struct.pack("<HHI", 0, 9, 0xBEEF0004)
    ext += struct.pack("<II", created, accessed)
    ext += struct.pack("<HH", 0x2E, 0)
    ext += struct.pack("<Q", mft[0] | (mft[1] << 48)) + bytes(8)
    ext += struct.pack("<H", 0) + bytes(4) + bytes(4)
    ext += long_name + struct.pack("<H", 0x14)
    struct.pack_into("<H", ext, 0, len(ext))
    body = (bytes([0x31 if directory else 0x32, 0]) + struct.pack("<I", 0)
            + struct.pack("<I", modified)
            + struct.pack("<H", 0x10 if directory else 0x20) + short + ext)
    return struct.pack("<H", 2 + len(body)) + body


def item_property_view(name: str, signature=0x3B93AFBB) -> bytes:
    """A class-0x00 'users property view' item: signature at 6, then a
    Serialized Property Storage ([MS-PROPSTORE]) holding
    PKEY_ItemNameDisplay ({B725F130-…}/10) as VT_LPWSTR."""
    text = name.encode("utf-16-le") + b"\0\0"
    prop = (struct.pack("<I", 10) + b"\0" + struct.pack("<HH", 0x1F, 0)
            + struct.pack("<I", len(name) + 1) + text)
    prop = struct.pack("<I", 4 + len(prop)) + prop
    storage = (b"1SPS" + guid_le("{B725F130-47EF-101A-A5F1-02608C9EEBAC}")
               + prop + struct.pack("<I", 0))
    storage = struct.pack("<I", 4 + len(storage)) + storage
    store = struct.pack("<I", 4 + len(storage)) + storage + struct.pack("<I", 0)
    body = bytes([0x00, 0x00]) + struct.pack("<HI", len(store), signature) + store
    return struct.pack("<H", 2 + len(body)) + body


def pidl(*items: bytes) -> bytes:
    return b"".join(items) + b"\0\0"


def sam_f(*, last_logon=0, pw_set=0, expires=0x7FFFFFFFFFFFFFFF, failed=0,
          rid=1000, acb=0x10, bad=0, logons=0) -> bytes:
    out = bytearray(80)
    struct.pack_into("<QQQQQ", out, 8, last_logon, 0, pw_set, expires, failed)
    struct.pack_into("<I", out, 0x30, rid)
    struct.pack_into("<H", out, 0x38, acb)
    struct.pack_into("<HHHH", out, 0x3C, 0, 0, bad, logons)
    return bytes(out)


def sam_v(username: str, full_name: str = "") -> bytes:
    data = bytearray()
    header = bytearray(0xCC)
    for slot, text in ((1, username), (2, full_name)):
        tb = text.encode("utf-16-le")
        struct.pack_into("<III", header, slot * 12, len(data), len(tb), 0)
        data += tb + bytes(-len(tb) % 4)
    return bytes(header + data)


# -- transaction logs (new format) -------------------------------------------

def marvin32(data: bytes, seed: int = 0x82EF4D887A4E55C5) -> int:
    """Marvin32 as published by Microsoft; 64-bit result (high << 32 | low)."""
    m = 0xFFFFFFFF

    def rotl(x, n):
        return ((x << n) | (x >> (32 - n))) & m

    lo, hi = seed & m, seed >> 32
    data = bytes(data)
    words = len(data) // 4
    for i in range(words):
        lo = (lo + struct.unpack_from("<I", data, 4 * i)[0]) & m
        hi ^= lo; lo = (rotl(lo, 20) + hi) & m; hi = rotl(hi, 9) ^ lo
        lo = (rotl(lo, 27) + hi) & m; hi = rotl(hi, 19)
    tail = data[4 * words:] + b"\x80"
    lo = (lo + int.from_bytes(tail, "little")) & m
    for _ in range(2):
        hi ^= lo; lo = (rotl(lo, 20) + hi) & m; hi = rotl(hi, 9) ^ lo
        lo = (rotl(lo, 27) + hi) & m; hi = rotl(hi, 19)
    return (hi << 32) | lo


def new_format_log(old: bytes, new: bytes, *, base_seq: int, first_seq: int,
                   entries: int = 2) -> bytes:
    """A .LOG1/.LOG2 in the new format whose 'HvLE' entries carry every
    4096-byte page of `new`'s hive bins that differs from `old`'s: a
    512-byte base block (file type 6), then entries, each a 40-byte header
    (signature, size, flags, sequence, hive-bins size, page count, two
    Marvin32 hashes), the page references and the pages, padded to 512."""
    pages = [off for off in range(0, len(new) - 4096, 4096)
             if new[4096 + off:8192 + off] != old[4096 + off:8192 + off]]
    per = max(1, -(-len(pages) // entries))
    groups = [pages[i:i + per] for i in range(0, len(pages), per)]
    base = bytearray(new[:512])
    struct.pack_into("<II", base, 4, base_seq, base_seq)
    struct.pack_into("<I", base, 0x1C, 6)
    struct.pack_into("<I", base, 0x1FC, checksum(base))
    out = bytearray(base)
    hbins = len(new) - 4096
    for i, group in enumerate(groups):
        refs = b"".join(struct.pack("<II", off, 4096) for off in group)
        body = refs + b"".join(new[4096 + off:8192 + off] for off in group)
        size = 40 + len(body)
        size += -size % 512
        body += bytes(size - 40 - len(body))
        head = b"HvLE" + struct.pack("<IIIII", size, 0, first_seq + i, hbins,
                                     len(group))
        h1 = marvin32(body)
        h2 = marvin32(head + struct.pack("<Q", h1))
        out += head + struct.pack("<QQ", h1, h2) + body
    return bytes(out)
