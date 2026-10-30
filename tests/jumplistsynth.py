"""Compound files ([MS-CFB]), DestList streams and custom-destination files,
built from the published layouts for the jumplist suite. Standard library
only; writes nothing to disk."""

from __future__ import annotations

import math
import struct

import shelllinksynth as ls

FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
NOSTREAM = 0xFFFFFFFF
CUTOFF = 4096
MINI = 64


def _dir_entry(name: str, kind: int, left=NOSTREAM, right=NOSTREAM,
               child=NOSTREAM, start=ENDOFCHAIN, size=0) -> bytes:
    raw = name.encode("utf-16-le") + b"\0\0" if name else b""
    out = raw.ljust(64, b"\0") + struct.pack("<HBB", len(raw), kind, 1)
    out += struct.pack("<III", left, right, child) + bytes(16)
    out += struct.pack("<IQQIQ", 0, 0, 0, start, size)
    return out


def build_cfb(streams, *, version=3, storage=None, unlinked=(),
              free_blobs=(), free_mini_blobs=(), min_fat_sectors=0):
    """Return (bytes, layout). `streams` and the storage's members are
    [(name, data)]; `unlinked` entries get chains and directory slots but no
    tree link; `free_*_blobs` sit in sectors the FAT/MiniFAT mark free."""
    ss = 512 if version == 3 else 4096
    per_fat = ss // 4
    # directory entries: (name, kind, data, children-indices)
    entries = [{"name": "Root Entry", "kind": 5, "data": b""}]
    top = []
    for name, data in streams:
        top.append(len(entries))
        entries.append({"name": name, "kind": 2, "data": data})
    if storage:
        sname, members = storage
        sidx = len(entries)
        top.append(sidx)
        entries.append({"name": sname, "kind": 1, "data": b""})
        kids = []
        for name, data in members:
            kids.append(len(entries))
            entries.append({"name": name, "kind": 2, "data": data})
        entries[sidx]["kids"] = kids
    loose = []
    for name, data in unlinked:
        loose.append(len(entries))
        entries.append({"name": name, "kind": 2, "data": data})
    for e in entries:
        e.setdefault("left", NOSTREAM)
        e.setdefault("right", NOSTREAM)
        e.setdefault("child", NOSTREAM)
    entries[0]["child"] = top[0] if top else NOSTREAM
    for a, b in zip(top, top[1:]):
        entries[a]["right"] = b
    for e in entries:
        kids = e.get("kids") or []
        if kids:
            e["child"] = kids[0]
            for a, b in zip(kids, kids[1:]):
                entries[a]["right"] = b

    # mini stream
    mini_data = b""
    minifat = []
    for e in entries[1:]:
        if e["kind"] == 2 and 0 < len(e["data"]) < CUTOFF:
            n = math.ceil(len(e["data"]) / MINI)
            first = len(minifat)
            minifat.extend(range(first + 1, first + n))
            minifat.append(ENDOFCHAIN)
            e["start"], e["mini"] = first, True
            mini_data += e["data"].ljust(n * MINI, b"\0")
    free_mini = []
    for blob in free_mini_blobs:
        n = math.ceil(len(blob) / MINI)
        free_mini.append((len(minifat), len(minifat) + n - 1))
        minifat.extend([FREESECT] * n)
        mini_data += blob.ljust(n * MINI, b"\0")

    dir_bytes_len = len(entries) * 128
    n_dir = math.ceil(dir_bytes_len / ss)
    n_minifat = math.ceil(len(minifat) * 4 / ss) if minifat else 0
    n_mini_sectors = math.ceil(len(mini_data) / ss) if mini_data else 0
    large = [e for e in entries[1:] if e["kind"] == 2 and len(e["data"]) >= CUTOFF]
    n_large = sum(math.ceil(len(e["data"]) / ss) for e in large)
    n_free = sum(math.ceil(len(b) / ss) for b in free_blobs)
    others = n_dir + n_minifat + n_mini_sectors + n_large + n_free

    n_fat = max(1, min_fat_sectors)
    while True:
        n_difat = max(0, math.ceil((n_fat - 109) / (per_fat - 1)))
        total = n_fat + n_difat + others
        if n_fat * per_fat >= total:
            break
        n_fat += 1

    fat = [FREESECT] * (n_fat * per_fat)
    sectors: list[bytes] = []

    def alloc(n, mark=None):
        first = len(sectors)
        for i in range(n):
            sectors.append(b"")
            if mark is not None:
                fat[first + i] = mark
            else:
                fat[first + i] = first + i + 1 if i + 1 < n else ENDOFCHAIN
        return first

    fat_first = alloc(n_fat, FATSECT)
    difat_first = alloc(n_difat, DIFSECT) if n_difat else ENDOFCHAIN
    dir_first = alloc(n_dir)
    minifat_first = alloc(n_minifat) if n_minifat else ENDOFCHAIN
    mini_first = alloc(n_mini_sectors) if n_mini_sectors else ENDOFCHAIN
    layout = {"sector_size": ss, "fat_first": fat_first, "dir_first": dir_first,
              "minifat_first": minifat_first, "mini_first": mini_first,
              "streams": {}, "free": [], "free_mini": free_mini,
              "n_fat": n_fat, "n_difat": n_difat}
    for e in large:
        n = math.ceil(len(e["data"]) / ss)
        e["start"] = alloc(n)
        layout["streams"][e["name"]] = e["start"]
        for i in range(n):
            sectors[e["start"] + i] = e["data"][i * ss:(i + 1) * ss]
    for blob in free_blobs:
        n = math.ceil(len(blob) / ss)
        first = alloc(n, FREESECT)
        layout["free"].append(first)
        for i in range(n):
            sectors[first + i] = blob[i * ss:(i + 1) * ss]
    for e in entries[1:]:
        if e.get("mini"):
            layout["streams"][e["name"]] = ("mini", e["start"])

    # fill metadata sectors
    fat_raw = struct.pack(f"<{len(fat)}I", *fat)
    for i in range(n_fat):
        sectors[fat_first + i] = fat_raw[i * ss:(i + 1) * ss]
    fat_ids = list(range(fat_first, fat_first + n_fat))
    rest = fat_ids[109:]
    for d in range(n_difat):
        chunk = rest[d * (per_fat - 1):(d + 1) * (per_fat - 1)]
        chunk += [FREESECT] * (per_fat - 1 - len(chunk))
        nxt = difat_first + d + 1 if d + 1 < n_difat else ENDOFCHAIN
        sectors[difat_first + d] = struct.pack(f"<{per_fat}I", *chunk, nxt)
    root = entries[0]
    root["start"] = mini_first if mini_data else ENDOFCHAIN
    dir_raw = b""
    for e in entries:
        size = len(mini_data) if e["kind"] == 5 else len(e["data"])
        dir_raw += _dir_entry(e["name"], e["kind"], e["left"], e["right"],
                              e["child"], e.get("start", ENDOFCHAIN), size)
    dir_raw = dir_raw.ljust(n_dir * ss, b"\0")
    # padding entries must read as unallocated with no links
    pad = _dir_entry("", 0)
    dir_raw = dir_raw[:len(entries) * 128] + pad * ((n_dir * ss) // 128 - len(entries))
    for i in range(n_dir):
        sectors[dir_first + i] = dir_raw[i * ss:(i + 1) * ss]
    if n_minifat:
        mf = struct.pack(f"<{len(minifat)}I", *minifat).ljust(n_minifat * ss, b"\xff")
        for i in range(n_minifat):
            sectors[minifat_first + i] = mf[i * ss:(i + 1) * ss]
    if n_mini_sectors:
        md = mini_data.ljust(n_mini_sectors * ss, b"\0")
        for i in range(n_mini_sectors):
            sectors[mini_first + i] = md[i * ss:(i + 1) * ss]

    difat_head = fat_ids[:109] + [FREESECT] * (109 - min(109, n_fat))
    header = (bytes.fromhex("d0cf11e0a1b11ae1") + bytes(16) +
              struct.pack("<HHHHH", 0x3E, version, 0xFFFE, 9 if ss == 512 else 12, 6) +
              bytes(6) +
              struct.pack("<IIIIIIIII", n_dir if version == 4 else 0, n_fat,
                          dir_first, 0, CUTOFF, minifat_first, n_minifat,
                          difat_first, n_difat) +
              struct.pack("<109I", *difat_head))
    header = header.ljust(ss, b"\0")
    body = b"".join(s.ljust(ss, b"\0") for s in sectors)
    layout["entries"] = [e["name"] for e in entries]
    layout["unlinked"] = loose
    return header + body, layout


# -- DestList -----------------------------------------------------------------

def destlist_entry(version: int, number: int, path: str, *, time=ls.T_WRITE,
                   pin=-1, count=1, host="WORKSTATION7", droid_file=None,
                   store: bytes = b"") -> bytes:
    df = droid_file if droid_file is not None else ls.droid_v1()
    dv = ls.guid("9a3e1d2c-0b4f-4c55-8e21-77aa66bb55cc")
    out = (struct.pack("<Q", 0x1122334455667788) + dv + df + dv + df +
           host.encode("ascii").ljust(16, b"\0") +
           struct.pack("<IIfQi", number, 0, 1.0, time, pin))
    if version != 1:
        out += struct.pack("<IIQ", 0xFFFFFFFF, count, 0)
    out += struct.pack("<H", len(path)) + path.encode("utf-16-le")
    if version != 1:
        out += struct.pack("<I", len(store)) + store
    return out


def destlist(version: int, entries: list[bytes], *, declared=None,
             pinned=0, last=None) -> bytes:
    n = len(entries) if declared is None else declared
    head = struct.pack("<IIifIIII", version, n, pinned, 2.0,
                       last if last is not None else n, 0, n + 1, 0)
    return head + b"".join(entries)


def property_store_blob(text: str) -> bytes:
    """A serialized property store (no extra-data header) for DestList."""
    block = ls.property_store([(10, 0x1F, ls.vt_lpwstr(text))])
    return block[8:]


# -- customDestinations -------------------------------------------------------

def custom_category(kind: int, *, name: str = "", links=(), ident=2) -> bytes:
    out = struct.pack("<I", kind)
    if kind == 0:
        out += struct.pack("<H", len(name)) + name.encode("utf-16-le")
        out += struct.pack("<I", len(links))
    elif kind == 1:
        out += struct.pack("<I", ident)
    elif kind == 2:
        out += struct.pack("<I", len(links))
    for link in links:
        out += ls.LNK_CLSID + link
    return out + struct.pack("<I", 0xBABFFBAB)


def custom_file(categories: list[bytes]) -> bytes:
    return struct.pack("<III", 2, len(categories), 0) + b"".join(categories)
