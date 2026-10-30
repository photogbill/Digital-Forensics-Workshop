# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows jump lists: `*.automaticDestinations-ms` and `*.customDestinations-ms`.

Since Windows 7 the taskbar keeps, per application, a list of the items
opened through it. The application is named only by an AppID — the file
name's hex prefix, a CRC-64 of the application's path — which a small table
here turns into a name for the well-known ones; any other stays the hex id.

**automaticDestinations** are OLE Compound Files ([MS-CFB]). The reader here
is written from that specification and needs nothing outside the standard
library: header (versions 3 and 4, 512- and 4096-byte sectors), the FAT
from the header's DIFAT and any DIFAT sectors, the MiniFAT and the mini
stream for streams under the 4 096-byte cutoff, and the directory, walked as
the red-black tree it is from the root's child. Chains are followed with a
loop guard and every sector number is bounds-checked; a broken chain is
reported with the stream it belongs to. Each hex-numbered stream is a shell
link (parsed by `shelllink`); the `DestList` stream (versions 1 — Windows 7
and 8 — and 3/4 — Windows 10 and 11, per libyal's "Jump lists format" and
the layout real files show) gives, per entry, the entry number that names
its stream, the NetBIOS host name, the droids (NTFS object identifiers) of
the target and its volume, the entry's FILETIME (libyal: "last modification
time" of the entry), the pin status, and for version 2+ an integer counter
libyal labels "access count?". The DestList holds no MFT reference of its
own: the target's MFT entry and sequence come from the joined shortcut's
last shell item (its 0xBEEF0004 block) and are labelled with that source.
DestList entries are joined to their streams; a stream with no entry, an
entry with no stream, and directory entries not linked from the root are
all reported.

**Deleted entries.** Two places can still hold a removed entry's shortcut,
and both are searched and flagged: directory entries that exist in the
directory array but are not linked from the root ("unlinked"), read from the
start sector they record; and free sectors / free mini-stream sectors that
still begin with a shell-link header ("carved"). Either may have been partly
overwritten since; anything read from them says how it was found, and a
carved shortcut is read from contiguous free space, so a link that was
fragmented will show damage in its own `problems`. Unallocated directory
slots that still hold a name are listed by name; their content is not read.

**customDestinations** are not compound files: a header, then categories,
each a list of shell links prefixed by the shell-link class identifier and
closed by the footer 0xBABFFBAB. Categories are read where their structure
holds; where it does not, the remainder is split on the shell-link signature
and every byte range that was not read as a link or a category structure is
reported as skipped, with its offset and length.

**What a value means is not decided here.** "DestList entry 7, time X,
pinned, count 3" is a measurement of what the taskbar stored; whether a
person opened the file then is the examiner's question. The FILETIMEs are
UTC and kept raw beside decoded.

**Not read.** The DestList header's floating-point field and the per-entry
float at offset 96 are kept raw (as numbers) without interpretation; the
version 2+ per-entry property store is decoded only as far as
`shelllink.parse_property_store` goes; compound-file timestamps on storages
are kept raw; non-shell-link objects in a custom destinations file are
skipped and reported, not decoded.
"""

from __future__ import annotations

import re
import struct

from . import shelllink, timeutil
from .errors import FileSystemError

MAX_INPUT = 256 << 20
CFB_SIGNATURE = bytes.fromhex("d0cf11e0a1b11ae1")
MAXREGSECT = 0xFFFFFFFA
DIFSECT = 0xFFFFFFFC
FATSECT = 0xFFFFFFFD
ENDOFCHAIN = 0xFFFFFFFE
FREESECT = 0xFFFFFFFF
NOSTREAM = 0xFFFFFFFF
OBJECT_TYPES = {0: "unallocated", 1: "storage", 2: "stream", 5: "root"}
CUSTOM_FOOTER = 0xBABFFBAB
_HEX_NAME = re.compile(r"^[0-9a-fA-F]{1,16}$")

#: well-known AppIDs (community-compiled lists; the hex id is always kept)
APP_IDS = {
    "1b4dd67f29cb1962": "Windows Explorer (Windows 7)",
    "f01b4d95cf55d32a": "Windows Explorer (Windows 8.1 and later)",
    "5f7b5f1e01b83767": "Quick Access",
    "7e4dca80246863e3": "Control Panel",
    "9b9cdc69c1c24e2b": "Notepad (64-bit)",
    "918e0ecb43d17e23": "Notepad (32-bit)",
    "bc0c37e84e063727": "Command Prompt (cmd.exe, 32-bit)",
    "9f5c7755804b850a": "Windows Script Host (wscript.exe, 64-bit)",
    "1bc392b8e104a00e": "Remote Desktop Connection",
    "74d7f43c1561fc1e": "Windows Media Player",
    "12dc1ea8e34b5a6": "Microsoft Paint (Windows 7)",
    "28c8b86deab549a1": "Internet Explorer 8 / 9",
    "9d1f905ce5044aee": "Microsoft Edge (legacy)",
    "ccba5a5986c77e43": "Microsoft Edge (Chromium)",
    "5d696d521de238c3": "Google Chrome",
    "6824f4a902c78fbd": "Mozilla Firefox",
    "adecfb853d77462a": "Microsoft Word 2007",
    "a7bd71699cd38d1c": "Microsoft Word 2010 (32-bit)",
    "fb3b0dbfee58fac8": "Microsoft Word 2016 (64-bit)",
    "9839aec31243a928": "Microsoft Excel 2010 (32-bit)",
    "b8ab77100df80ab2": "Microsoft Excel (64-bit)",
    "f5ac5390b9115fdb": "Microsoft PowerPoint 2007",
    "d00655d2aa12ff6d": "Microsoft PowerPoint 2016 (64-bit)",
    "290532160612e071": "WinRAR (64-bit)",
    "9fda41b86ddcf1db": "VLC media player",
    "ee462c3b81abb6f6": "Adobe Reader X",
}
KNOWN_CATEGORIES = {1: "Frequent", 2: "Recent"}


def app_id_from_name(file_name: str | None) -> tuple[str | None, str | None]:
    """(AppID, application name or None) from a jump-list file name."""
    if not file_name:
        return None, None
    base = file_name.replace("\\", "/").rsplit("/", 1)[-1]
    stem = base.split(".", 1)[0]
    if not _HEX_NAME.match(stem):
        return None, None
    app = stem.lower()
    return app, APP_IDS.get(app) or APP_IDS.get(app.lstrip("0"))


def _filetime(raw: int) -> dict:
    return {"raw": raw, "epoch": "filetime",
            "utc": timeutil.decode(raw, "filetime")}


# ---------------------------------------------------------------------------
# Compound File Binary ([MS-CFB])
# ---------------------------------------------------------------------------

class DirEntry:
    __slots__ = ("index", "name", "type", "color", "left", "right", "child",
                 "clsid", "state", "created", "modified", "start", "size",
                 "path", "linked", "size_high_ignored")

    def as_dict(self) -> dict:
        return {"index": self.index, "name": self.name,
                "type": OBJECT_TYPES.get(self.type, f"0x{self.type:02X}"),
                "start": self.start, "size": self.size, "path": self.path,
                "linked": self.linked, "created_raw": self.created,
                "modified_raw": self.modified}


class CompoundFile:
    """A read-only OLE compound file, from bytes or a reader."""

    def __init__(self, source) -> None:
        data = shelllink._as_bytes(source, MAX_INPUT, "compound file")
        self.data = data
        self.problems: list[str] = []
        if len(data) < 512 or data[:8] != CFB_SIGNATURE:
            raise FileSystemError(
                "This is not an OLE compound file: it does not begin with the "
                "compound-file signature D0 CF 11 E0 A1 B1 1A E1.")
        (minor, major, order, shift, mini_shift) = struct.unpack_from(
            "<HHHHH", data, 24)
        (n_dir, n_fat, first_dir, _txn, cutoff, first_mini, n_mini,
         first_difat, n_difat) = struct.unpack_from("<IIIIIIIII", data, 40)
        if order != 0xFFFE:
            raise FileSystemError(
                f"The compound file's byte-order mark is 0x{order:04X}, not "
                "0xFFFE; the header is damaged.")
        if major not in (3, 4):
            raise FileSystemError(
                f"Compound file major version {major} is neither 3 nor 4; "
                "this reader does not guess at other layouts.")
        if shift not in (9, 12):
            raise FileSystemError(
                f"The compound file declares 2^{shift}-byte sectors; only "
                "512 and 4096 exist.")
        if (major, shift) not in ((3, 9), (4, 12)):
            self.problems.append(
                f"Version {major} with {1 << shift}-byte sectors is not the "
                "documented pairing; the declared sector size was used.")
        self.version = major
        self.minor_version = minor
        self.sector_size = 1 << shift
        self.mini_sector_size = 1 << mini_shift
        self.cutoff = cutoff
        if cutoff != 4096:
            self.problems.append(f"The mini-stream cutoff is {cutoff}, not 4096; "
                                 "the declared value was used.")
        self.n_sectors = max(0, (len(data) - self.sector_size) // self.sector_size)
        if (len(data) - self.sector_size) % self.sector_size:
            self.n_sectors += 1
            self.problems.append(
                f"The file is {len(data):,} bytes, not a whole number of "
                f"{self.sector_size}-byte sectors; the last sector is short.")
        self.fat = self._load_fat(n_fat, first_difat, n_difat)
        dir_bytes = self._chain_bytes(first_dir, self.fat, "the directory")
        self.entries = self._load_entries(dir_bytes)
        if not self.entries or self.entries[0].type != 5:
            raise FileSystemError(
                "The compound file's first directory entry is not the root "
                "entry; the directory is damaged and cannot be read.")
        root = self.entries[0]
        self.minifat = []
        if first_mini not in (ENDOFCHAIN, FREESECT) and n_mini:
            mf = self._chain_bytes(first_mini, self.fat, "the MiniFAT")
            self.minifat = list(struct.unpack_from(f"<{len(mf) // 4}I", mf))
        self.ministream_chain = self._chain(root.start, self.fat, "the mini stream")
        self.ministream = b"".join(self._sector(s) for s in self.ministream_chain)
        if len(self.ministream) < root.size:
            self.problems.append(
                f"The mini stream should be {root.size:,} bytes but its chain "
                f"holds {len(self.ministream):,}; small streams past that "
                "point cannot be read.")
        self.ministream = self.ministream[:root.size]
        self._walk()

    # -- sectors and chains -------------------------------------------------
    def _sector(self, n: int) -> bytes:
        off = (n + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    def _load_fat(self, n_fat: int, first_difat: int, n_difat: int) -> list:
        locations = list(struct.unpack_from("<109I", self.data, 76))
        s = first_difat
        seen = set()
        per = self.sector_size // 4 - 1
        while s not in (ENDOFCHAIN, FREESECT):
            if len(seen) >= max(n_difat, 1) + 1:
                self.problems.append(
                    f"The DIFAT chain is longer than the {n_difat} sector(s) the "
                    "header declares; the extra sectors were not followed.")
                break
            if s > MAXREGSECT or s >= self.n_sectors or s in seen:
                self.problems.append(f"The DIFAT chain breaks at sector {s}; "
                                     "FAT sectors listed after it are lost.")
                break
            seen.add(s)
            sec = self._sector(s)
            vals = struct.unpack_from(f"<{per + 1}I", sec.ljust(self.sector_size, b"\xff"))
            locations.extend(vals[:per])
            s = vals[per]
        fat_sectors = [x for x in locations if x <= MAXREGSECT][:n_fat]
        if len(fat_sectors) < n_fat:
            self.problems.append(f"The header declares {n_fat} FAT sectors but "
                                 f"only {len(fat_sectors)} are listed.")
        fat = []
        for s in fat_sectors:
            if s >= self.n_sectors:
                self.problems.append(f"FAT sector {s} lies beyond the end of the "
                                     "file; its entries are unknown.")
                fat.extend([FREESECT] * (self.sector_size // 4))
                continue
            sec = self._sector(s).ljust(self.sector_size, b"\xff")
            fat.extend(struct.unpack_from(f"<{self.sector_size // 4}I", sec))
        return fat

    def _chain(self, start: int, table: list, what: str,
               problems: list | None = None) -> list:
        problems = self.problems if problems is None else problems
        chain = []
        seen = set()
        s = start
        limit = len(table)
        while s != ENDOFCHAIN:
            if s == FREESECT and not chain:
                break                               # an empty stream
            if s > MAXREGSECT or s >= limit or s in seen:
                why = ("loops back on itself" if s in seen else
                       "points outside the allocation table" if s <= MAXREGSECT
                       else f"meets the special value 0x{s:08X}")
                problems.append(f"The sector chain of {what} {why} after "
                                f"{len(chain)} sector(s); it was cut there.")
                break
            seen.add(s)
            chain.append(s)
            s = table[s]
        return chain

    def _chain_bytes(self, start: int, table: list, what: str,
                     problems: list | None = None) -> bytes:
        return b"".join(self._sector(s)
                        for s in self._chain(start, table, what, problems))

    def _load_entries(self, raw: bytes) -> list:
        entries = []
        for i in range(len(raw) // 128):
            b = raw[i * 128:(i + 1) * 128]
            e = DirEntry()
            name_len = struct.unpack_from("<H", b, 64)[0]
            if name_len > 64 or name_len % 2:
                name_len = 0 if name_len > 64 else name_len - 1
            e.index = i
            e.name = shelllink._utf16(b[:max(0, name_len - 2)])
            e.type, e.color = b[66], b[67]
            e.left, e.right, e.child = struct.unpack_from("<III", b, 68)
            e.clsid = shelllink.guid_str(b[80:96])
            e.state = struct.unpack_from("<I", b, 96)[0]
            e.created, e.modified = struct.unpack_from("<QQ", b, 100)
            e.start = struct.unpack_from("<I", b, 116)[0]
            size = struct.unpack_from("<Q", b, 120)[0]
            e.size_high_ignored = False
            if self.version == 3 and size >> 32:
                e.size_high_ignored = True
                size &= 0xFFFFFFFF
                if b[66] in (1, 2, 5):
                    self.problems.append(
                        f"Directory entry {i} has non-zero high 32 bits in its "
                        "size; a version 3 file only uses the low 32 (MS-CFB), "
                        "so they were ignored.")
            e.size = size
            e.path = None
            e.linked = False
            entries.append(e)
        return entries

    def _walk(self) -> None:
        root = self.entries[0]
        root.linked = True
        root.path = ""
        stack = [(root.child, "")]
        seen = {0}
        while stack:
            idx, parent = stack.pop()
            if idx == NOSTREAM:
                continue
            if idx >= len(self.entries):
                self.problems.append(f"A directory link points at entry {idx}, "
                                     "beyond the directory; it was ignored.")
                continue
            if idx in seen:
                self.problems.append(f"Directory entry {idx} is linked twice "
                                     "(a loop); the second link was ignored.")
                continue
            seen.add(idx)
            e = self.entries[idx]
            e.linked = True
            e.path = f"{parent}/{e.name}" if parent else e.name
            stack.append((e.left, parent))
            stack.append((e.right, parent))
            if e.type == 1:
                stack.append((e.child, e.path))

    # -- streams ---------------------------------------------------------------
    def streams(self) -> list:
        """Linked stream entries, in directory order."""
        return [e for e in self.entries if e.linked and e.type == 2]

    def unallocated_names(self) -> list:
        """Unallocated directory slots that still hold a name."""
        return [e for e in self.entries[1:] if e.type == 0 and e.name]

    def unlinked(self) -> list:
        """Stream/storage entries present in the directory array but not
        reachable from the root."""
        return [e for e in self.entries[1:] if not e.linked and e.type in (1, 2)]

    def find(self, path: str):
        for e in self.entries:
            if e.linked and e.path == path:
                return e
        return None

    def read(self, entry, problems: list | None = None) -> bytes:
        """A stream's bytes; a short or broken chain is reported."""
        problems = self.problems if problems is None else problems
        if entry.size == 0:
            return b""
        what = f"stream '{entry.name}'"
        if entry.type != 5 and entry.size < self.cutoff:
            chain = self._chain(entry.start, self.minifat, what + " (mini)",
                                problems)
            ms = self.mini_sector_size
            data = b"".join(self.ministream[s * ms:(s + 1) * ms] for s in chain)
        else:
            data = self._chain_bytes(entry.start, self.fat, what, problems)
        if len(data) < entry.size:
            problems.append(f"The {what} should be {entry.size:,} bytes but "
                            f"only {len(data):,} could be read.")
        return data[:entry.size]

    def free_regions(self) -> list:
        """Runs of free sectors and free mini sectors: (kind, first, last, bytes)."""
        out = []
        for kind, table, read, size in (
                ("sector", self.fat, self._sector, self.sector_size),
                ("mini-sector", self.minifat,
                 lambda s: self.ministream[s * self.mini_sector_size:
                                           (s + 1) * self.mini_sector_size],
                 self.mini_sector_size)):
            limit = self.n_sectors if kind == "sector" else \
                len(self.ministream) // max(1, size)
            run = []
            for s in range(min(len(table), limit) + 1):
                free = s < min(len(table), limit) and table[s] == FREESECT
                if free:
                    run.append(s)
                elif run:
                    out.append((kind, run[0], run[-1],
                                b"".join(read(x) for x in run)))
                    run = []
        return out

    def summary(self) -> dict:
        return {"version": self.version, "sector_size": self.sector_size,
                "mini_sector_size": self.mini_sector_size,
                "entries": len(self.entries),
                "streams": [{"name": e.name, "path": e.path, "size": e.size}
                            for e in self.streams()]}


# ---------------------------------------------------------------------------
# DestList
# ---------------------------------------------------------------------------

def _hostname(raw: bytes) -> str:
    if raw[:1] != b"\x00" and raw[1:2] == b"\x00" and raw[2:3] != b"\x00" \
            and raw[3:4] == b"\x00":
        return shelllink._utf16z(raw, 0)[0]
    return shelllink._ansiz(raw, 0)[0]


def parse_destlist(data: bytes) -> dict:
    """The DestList stream: header and entries (versions 1 and 2+)."""
    problems: list[str] = []
    if len(data) == 0:
        return {"header": None, "entries": [], "problems": [],
                "empty": True}
    if len(data) < 32:
        return {"header": None, "entries": [], "empty": False,
                "problems": [f"The DestList stream is {len(data)} bytes, "
                             "shorter than its 32-byte header."]}
    version, n_entries, n_pinned = struct.unpack_from("<IIi", data, 0)
    header = {"version": version, "entries_declared": n_entries,
              "pinned_declared": n_pinned,
              "float_at_12": struct.unpack_from("<f", data, 12)[0],
              "last_entry_number": struct.unpack_from("<I", data, 16)[0],
              "unknown_20": struct.unpack_from("<I", data, 20)[0],
              "last_revision": struct.unpack_from("<I", data, 24)[0],
              "unknown_28": struct.unpack_from("<I", data, 28)[0]}
    if version not in (1, 2, 3, 4):
        problems.append(f"DestList version {version} is not documented; it "
                        "was read with the version 2+ layout.")
    path_at = 112 if version == 1 else 128
    entries = []
    pos = 32
    while pos < len(data):
        if version == 1 and len(entries) >= n_entries:
            break
        remaining = len(data) - pos
        if remaining < path_at + 2:
            if any(data[pos:]):
                problems.append(f"{remaining} bytes at offset {pos} are too "
                                "short for a DestList entry; they were not read.")
            break
        chars = struct.unpack_from("<H", data, pos + path_at)[0]
        end = pos + path_at + 2 + 2 * chars
        if end > len(data):
            problems.append(f"The DestList entry at offset {pos} declares a "
                            f"{chars}-character path that runs past the end "
                            "of the stream; entries from there are not read.")
            break
        b = data[pos:end]
        entry = {
            "offset": pos, "position": len(entries),
            "hash_or_checksum": struct.unpack_from("<Q", b, 0)[0],
            "droid_volume": shelllink.droid_info(b[8:24]),
            "droid_file": shelllink.droid_info(b[24:40]),
            "birth_droid_volume": shelllink.droid_info(b[40:56]),
            "birth_droid_file": shelllink.droid_info(b[56:72]),
            "hostname": _hostname(b[72:88]),
            "entry_number": struct.unpack_from("<I", b, 88)[0],
            "unknown_92": struct.unpack_from("<I", b, 92)[0],
            "float_at_96": struct.unpack_from("<f", b, 96)[0],
            "last_modified": _filetime(struct.unpack_from("<Q", b, 100)[0]),
            "pin_status": struct.unpack_from("<i", b, 108)[0],
            "path": shelllink._utf16(b[path_at + 2:]),
        }
        entry["pinned"] = entry["pin_status"] >= 0
        if version != 1:
            entry["unknown_112"] = struct.unpack_from("<I", b, 112)[0]
            entry["access_count"] = struct.unpack_from("<I", b, 116)[0]
            entry["unknown_120"] = struct.unpack_from("<Q", b, 120)[0]
            if end + 4 > len(data):
                problems.append(f"The DestList entry at offset {pos} is missing "
                                "its trailing 4-byte size field; entries from "
                                "there are not read.")
                entries.append(entry)
                break
            tail = struct.unpack_from("<I", data, end)[0]
            end += 4
            if tail:
                if end + tail > len(data):
                    problems.append(f"DestList entry {entry['entry_number']} "
                                    f"declares a {tail}-byte property store "
                                    "that runs past the end of the stream.")
                    entries.append(entry)
                    break
                ps_problems: list[str] = []
                entry["property_store"] = shelllink.parse_property_store(
                    data[end:end + tail], ps_problems)
                problems.extend(f"DestList entry {entry['entry_number']}: {p}"
                                for p in ps_problems)
                end += tail
        else:
            entry["access_count"] = None
        entries.append(entry)
        pos = end
    if version == 1 and len(entries) < n_entries:
        problems.append(f"The header declares {n_entries} entries; "
                        f"{len(entries)} were read.")
    return {"header": header, "entries": entries, "problems": problems,
            "empty": False}


# ---------------------------------------------------------------------------
# automaticDestinations
# ---------------------------------------------------------------------------

def _lnk_summary(lnk: dict) -> dict:
    tr = lnk.get("tracker") or {}
    return {"target_path": lnk.get("target_path"),
            "target_path_source": lnk.get("target_path_source"),
            "arguments": lnk["strings"].get("arguments"),
            "target_times": {k: {"raw": v["raw"], "utc": v["utc"]}
                             for k, v in lnk["header"]["times"].items()},
            "target_size": lnk["header"]["file_size"],
            "target_mft": lnk.get("target_mft"),
            "machine_id": tr.get("machine_id"),
            "volume": (lnk.get("link_info") or {}).get("volume"),
            "problems": list(lnk.get("problems", []))}


def _try_lnk(data: bytes) -> tuple[dict | None, str | None]:
    try:
        return shelllink.parse_lnk(data), None
    except FileSystemError as exc:
        return None, str(exc)


def parse_automatic(source, *, file_name: str | None = None) -> dict:
    """An automaticDestinations-ms file: DestList joined to its shortcuts."""
    cf = CompoundFile(source)
    problems = list(cf.problems)
    app_id, app_name = app_id_from_name(file_name)
    dl_entry = cf.find("DestList")
    if dl_entry is None:
        problems.append("There is no DestList stream; shortcuts are listed "
                        "without entry times or pin status.")
        destlist = {"header": None, "entries": [], "problems": [], "empty": True}
    else:
        destlist = parse_destlist(cf.read(dl_entry, problems))
        problems.extend(destlist["problems"])

    lnk_streams = {}
    other_streams = []
    for e in cf.streams():
        if e.name == "DestList":
            continue
        if _HEX_NAME.match(e.name) and "/" not in e.path:
            lnk_streams[int(e.name, 16)] = e
        else:
            other_streams.append(e.name)

    entries = []
    used = set()
    for d in destlist["entries"]:
        number = d["entry_number"]
        row = {"entry_number": number, "stream": None, "destlist": d,
               "lnk": None, "lnk_error": None}
        stream = lnk_streams.get(number)
        if stream is None:
            problems.append(f"DestList entry {number} has no stream named "
                            f"'{number:x}'.")
        else:
            used.add(number)
            row["stream"] = stream.name
            s_problems: list[str] = []
            lnk, err = _try_lnk(cf.read(stream, s_problems))
            problems.extend(s_problems)
            row["lnk"] = _lnk_summary(lnk) if lnk else None
            row["lnk_error"] = err
        entries.append(row)

    orphans = []
    for number, stream in sorted(lnk_streams.items()):
        if number in used:
            continue
        lnk, err = _try_lnk(cf.read(stream, problems))
        orphans.append({"stream": stream.name, "entry_number": number,
                        "lnk": _lnk_summary(lnk) if lnk else None,
                        "lnk_error": err,
                        "how": "stream linked in the directory but absent "
                               "from DestList"})

    recovered = []
    for e in cf.unlinked():
        rec_problems: list[str] = []
        lnk = err = None
        if e.type == 2:
            lnk, err = _try_lnk(cf.read(e, rec_problems))
        recovered.append({
            "name": e.name, "directory_index": e.index, "size": e.size,
            "recovered": True,
            "how": ("directory entry present in the directory array but not "
                    "linked from the root; content read from the start sector "
                    "it records and may since have been overwritten"),
            "lnk": _lnk_summary(lnk) if lnk else None, "lnk_error": err,
            "problems": rec_problems})
    recovered.extend(_carve_free(cf))
    remnant_names = [{"directory_index": e.index, "name": e.name,
                      "start": e.start, "size": e.size,
                      "how": "unallocated directory entry that still holds a "
                             "name; its content was not read"}
                     for e in cf.unallocated_names()]

    return {"format": "automaticDestinations", "app_id": app_id,
            "app_name": app_name, "cfb": cf.summary(),
            "destlist_header": destlist["header"],
            "destlist_empty": destlist.get("empty", False),
            "entries": entries, "orphan_streams": orphans,
            "other_streams": other_streams, "recovered": recovered,
            "unallocated_names": remnant_names, "problems": problems}


def _carve_free(cf: CompoundFile) -> list:
    found = []
    for kind, first, last, blob in cf.free_regions():
        pos = blob.find(shelllink.LNK_SIGNATURE)
        while pos >= 0:
            lnk, err = _try_lnk(blob[pos:])
            found.append({
                "recovered": True, "free_kind": kind,
                "free_first": first, "free_last": last, "offset_in_run": pos,
                "how": (f"shell-link signature found in free {kind}s "
                        f"{first}–{last} (contiguous run, offset {pos}); the "
                        "link was read from contiguous free space"),
                "lnk": _lnk_summary(lnk) if lnk else None, "lnk_error": err})
            nxt = pos + max(1, (lnk or {}).get("consumed", 1))
            pos = blob.find(shelllink.LNK_SIGNATURE, nxt)
    return found


# ---------------------------------------------------------------------------
# customDestinations
# ---------------------------------------------------------------------------

def parse_custom(source, *, file_name: str | None = None) -> dict:
    """A customDestinations-ms file: categories of shortcuts."""
    data = shelllink._as_bytes(source, MAX_INPUT, "jump list")
    app_id, app_name = app_id_from_name(file_name)
    problems: list[str] = []
    if len(data) < 12:
        raise FileSystemError("This custom jump list is shorter than its "
                              "12-byte header; there is nothing to read.")
    version, n_cat, _unk = struct.unpack_from("<III", data, 0)
    if version != 2:
        problems.append(f"Custom destinations version {version} is not the "
                        "documented 2; the layout was read anyway.")
    categories, links, skipped = [], [], []
    pos = 12
    structured = True
    resume = pos
    for ci in range(n_cat):
        start = pos
        try:
            ctype = struct.unpack_from("<I", data, pos)[0]
            pos += 4
            cat = {"index": ci, "type": ctype, "offset": start, "name": None,
                   "entries": 0}
            count = 0
            if ctype == 0:
                nchars = struct.unpack_from("<H", data, pos)[0]
                cat["name"] = shelllink._utf16(data[pos + 2:pos + 2 + 2 * nchars])
                pos += 2 + 2 * nchars
                count = struct.unpack_from("<I", data, pos)[0]
                pos += 4
            elif ctype == 1:
                ident = struct.unpack_from("<I", data, pos)[0]
                pos += 4
                cat["name"] = KNOWN_CATEGORIES.get(ident, f"known category {ident}")
            elif ctype == 2:
                cat["name"] = "Tasks"
                count = struct.unpack_from("<I", data, pos)[0]
                pos += 4
            else:
                raise ValueError(f"category type {ctype} is not documented")
            for _ in range(count):
                if data[pos:pos + 16] != shelllink.LNK_CLSID_BYTES:
                    raise ValueError("an entry that is not a shell link")
                lnk, err = _try_lnk(data[pos + 16:])
                if lnk is None:
                    raise ValueError(f"a shell link that does not parse ({err})")
                links.append({"category": cat["name"], "category_index": ci,
                              "offset": pos + 16, "how": "category structure",
                              "consumed": lnk["consumed"],
                              "lnk": _lnk_summary(lnk)})
                pos += 16 + lnk["consumed"]
                cat["entries"] += 1
            footer = struct.unpack_from("<I", data, pos)[0]
            if footer != CUSTOM_FOOTER:
                raise ValueError(f"footer 0x{footer:08X} instead of 0xBABFFBAB")
            pos += 4
            categories.append(cat)
        except (struct.error, ValueError) as exc:
            problems.append(f"Category {ci} at offset {start} could not be read "
                            f"as structured ({exc}); the rest of the file was "
                            "split on the shell-link signature.")
            structured = False
            resume = start
            break
    if structured and pos < len(data):
        skipped.append({"offset": pos, "length": len(data) - pos,
                        "why": "after the last declared category"})
    if not structured:
        links_before = {l["offset"] for l in links}
        hit = data.find(shelllink.LNK_SIGNATURE, resume)
        last_end = resume
        while hit >= 0:
            if hit in links_before:
                done = next(l for l in links if l["offset"] == hit)
                last_end = max(last_end, hit + done["consumed"])
                hit = data.find(shelllink.LNK_SIGNATURE, last_end)
                continue
            lnk, err = _try_lnk(data[hit:])
            if lnk is None:
                hit = data.find(shelllink.LNK_SIGNATURE, hit + 1)
                continue
            if hit > last_end:
                skipped.append({"offset": last_end, "length": hit - last_end,
                                "why": "between links, not read as structure"})
            links.append({"category": None, "category_index": None,
                          "offset": hit, "how": "signature scan",
                          "consumed": lnk["consumed"],
                          "lnk": _lnk_summary(lnk)})
            last_end = hit + lnk["consumed"]
            hit = data.find(shelllink.LNK_SIGNATURE, last_end)
        if last_end < len(data):
            skipped.append({"offset": last_end, "length": len(data) - last_end,
                            "why": "after the last link found"})
        if version != 2 and not links:
            raise FileSystemError(
                "This is not a custom destinations jump list: its header "
                f"version is {version}, not 2, and it holds no shell link.")
    return {"format": "customDestinations", "app_id": app_id,
            "app_name": app_name, "version": version,
            "categories_declared": n_cat, "categories": categories,
            "links": links, "skipped": skipped, "problems": problems}


def parse_jumplist(source, *, file_name: str | None = None) -> dict:
    """Either kind, told apart by content (the compound-file signature)."""
    data = shelllink._as_bytes(source, MAX_INPUT, "jump list")
    if data[:8] == CFB_SIGNATURE:
        return parse_automatic(data, file_name=file_name)
    return parse_custom(data, file_name=file_name)


# ---------------------------------------------------------------------------
# rows
# ---------------------------------------------------------------------------

def _app_label(parsed: dict) -> str:
    return parsed.get("app_name") or parsed.get("app_id") or "unknown application"


def _target(lnk: dict | None, fallback: str | None = None) -> str:
    if lnk and lnk.get("target_path"):
        return lnk["target_path"]
    return fallback or "(no target path recorded)"


def to_rows(parsed: dict, *, source_path: str) -> list[dict]:
    """`jumplist-entry` rows: one per DestList entry (timed), per stream
    without an entry, per recovered link, and per custom-destination link."""
    app = _app_label(parsed)
    base = {"app_id": parsed.get("app_id"), "app_name": parsed.get("app_name"),
            "source": source_path, "format": parsed.get("format")}
    rows = []
    if parsed.get("format") == "automaticDestinations":
        for i, e in enumerate(parsed["entries"]):
            d = e["destlist"]
            path = d["path"] or _target(e["lnk"])
            t = d["last_modified"]
            pin = (f"pinned (position {d['pin_status']})" if d["pinned"]
                   else "not pinned")
            count = d.get("access_count")
            rows.append({
                "artefact": "jumplist-entry",
                "at_utc": t["utc"], "at_raw": t["raw"], "at_epoch": "filetime",
                "title": f"{app}: {path}",
                "value": (f"Jump list ({app}) DestList entry {e['entry_number']} "
                          f"records {path}, entry time {t['utc'] or 'none'}, "
                          f"{pin}" + (f", counter {count}" if count is not None
                                      else "")),
                "detail": dict(base, entry_number=e["entry_number"], path=path,
                               pinned=d["pinned"], pin_status=d["pin_status"],
                               access_count=count, hostname=d["hostname"],
                               droid_file_mac=d["droid_file"].get("mac"),
                               stream=e["stream"], lnk=e["lnk"],
                               lnk_error=e["lnk_error"], recovered=False),
                "row_ref_suffix": f"destlist:{i}:{e['entry_number']}",
            })
        for o in parsed["orphan_streams"]:
            target = _target(o["lnk"])
            rows.append({
                "artefact": "jumplist-entry", "at_utc": None, "at_raw": None,
                "at_epoch": None, "title": f"{app}: {target}",
                "value": (f"Jump list ({app}) stream {o['stream']} records "
                          f"{target} but has no DestList entry"),
                "detail": dict(base, stream=o["stream"], lnk=o["lnk"],
                               lnk_error=o["lnk_error"], recovered=False,
                               how=o["how"]),
                "row_ref_suffix": f"stream:{o['stream']}",
            })
        for i, r in enumerate(parsed["recovered"]):
            target = _target(r.get("lnk"))
            rows.append({
                "artefact": "jumplist-entry", "at_utc": None, "at_raw": None,
                "at_epoch": None, "title": f"{app} (recovered): {target}",
                "value": (f"Jump list ({app}) holds a recovered shortcut to "
                          f"{target} — {r['how']}"),
                "detail": dict(base, recovered=True, how=r["how"],
                               lnk=r.get("lnk"), lnk_error=r.get("lnk_error")),
                "row_ref_suffix": f"recovered:{i}",
            })
    else:
        for i, link in enumerate(parsed.get("links", [])):
            target = _target(link["lnk"])
            cat = link["category"] or "unknown category"
            rows.append({
                "artefact": "jumplist-entry", "at_utc": None, "at_raw": None,
                "at_epoch": None, "title": f"{app}: {target}",
                "value": (f"Custom jump list ({app}), {cat}, lists {target}"),
                "detail": dict(base, category=link["category"],
                               offset=link["offset"], how=link["how"],
                               lnk=link["lnk"], recovered=False),
                "row_ref_suffix": f"custom:{i}",
            })
    return rows
