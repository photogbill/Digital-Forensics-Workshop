# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows registry hives (regf), read from the bytes — and the artefacts in them.

A hive file (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT, UsrClass.dat,
Amcache.hve) is parsed here structure by structure, from the layout published
in Joachim Metz's "Windows NT Registry File (REGF) format" (libyal) and Maxim
Suhanov's "Windows registry file format specification": the 4096-byte base
block, the hive bins, and the cells inside them — key nodes (`nk`), values
(`vk`), subkey lists (`lf`, `lh`, `li`, `ri`), big-data records (`db`) and
security records (`sk`). Nothing asks Windows what a key holds, so the hive
can come from any image, any export, any operating system.

**What is checked, and what happens to damage.** The base block's signature
is required (no `regf`, no hive: `FileSystemError`); its checksum is
recomputed and a mismatch reported. Every cell offset is bounds-checked
against the file and against the hive bin that should contain it; a cell
that is out of range, mis-sized, of the wrong kind, or marked free while an
allocated record points at it becomes a line in `hive.problems` and the walk
goes on around it. A loop in the key tree (a list that points back at an
ancestor) is detected and reported, never followed.

**A dirty hive is said to be dirty.** When the base block's primary and
secondary sequence numbers differ, Windows had begun writing the hive and
had not finished — the newest changes are in the transaction logs
(`.LOG1`/`.LOG2`) and are NOT in this file. Opened alone, the hive is read
as it is on disk and the condition is the first line of `hive.problems`:
the newest data may be missing and a key may be half-written. Opened with
its logs (`open_hive(..., logs={...})`), new-format logs (Windows 8.1 and
later, `HvLE` entries) are replayed IN MEMORY: an entry is used only if
both of its Marvin32 hashes check and its sequence number continues the
one before; a log older than the hive is left out, with the reason. The
first line of `problems` then says which logs and which sequence numbers
were applied, and `hive.recovery` keeps the original base block. Nothing
is written — not the hive, not a log, not a recovered copy.

**Values.** REG_SZ / REG_EXPAND_SZ (UTF-16LE, cut at the first NUL),
REG_MULTI_SZ, REG_DWORD (both byte orders), REG_QWORD, REG_LINK; REG_BINARY,
REG_NONE, the resource-list types and every unknown type (device-property
types such as 0xFFFF0010 included) are kept as their raw bytes — never
guessed at. Inline data (four bytes or fewer, held in the value record) and
big data (`db`, for values over 16 344 bytes in hive version 1.4 and later)
are both read.

**Deleted keys and values** are looked for in FREE cells (`recover_deleted`):
a key or value record still intact in space Windows has released. Each one
is flagged `deleted=True`, `recovered_from="free cell"`. A key record in a
free cell may be an OLDER COPY of a key that still exists — Windows rewrites
a key's record when it grows — so each recovered key says whether a live key
exists at the same path. That is a measurement; what it means is the
examiner's call.

**The artefact extractors** (`to_rows`) read the well-known locations in each
kind of hive and report what they hold: USB devices, ShimCache, services,
network interfaces and profiles, installed programs, autoruns, UserAssist,
RecentDocs and the other MRU lists, ShellBags, SAM accounts, Amcache file
entries. A missing key yields no rows, not an error. Every row is a
MEASUREMENT with its key path and that key's last-written time. Each row
says which time it carries (`detail["time_basis"]`):

* `entry` — a timestamp stored IN the item (UserAssist's last-run FILETIME,
  a ShimCache entry's recorded modification time, a USB device property);
* `key` — the last-written time of a key that holds this item alone (a
  service, an uninstall entry, a USBSTOR instance, a ShellBag node);
* `key-mru-0` — a list key's last-written time, given only to the entry its
  MRU order names most recent; the other entries carry no time, because the
  key's time is when the LIST last changed, not when each entry was added;
* `none` — no time belongs to this item; the key's time is still in detail.

**Local times are never presented as UTC.** NetworkList's DateCreated /
DateLastConnected are SYSTEMTIME structures in the machine's local time, and
shell items carry DOS date-times with no zone; both are kept in `detail`,
labelled, and never put in `at_utc`.

**What this does NOT read.** Old-format transaction logs (Windows XP to 8,
`DIRT` sector bitmaps) are recognised and NOT replayed. Volatile keys
(CurrentControlSet, HARDWARE) exist only in a running system's memory, not
in a hive file; `find()` resolves a leading `CurrentControlSet` through
`Select\\Current`, and the `control-set` row records how. SECURITY hive
contents (LSA secrets, cached credentials) are not decoded, and no password
hash is extracted from SAM. ShimCache before Windows 7 (XP, Vista/2008) is
identified, not decoded. Shell items are decoded for the common types (root
and known folders, volumes, file entries with their 0xBEEF0004 long name,
network locations, control-panel items, and Windows 10 property-view items
through their [MS-PROPSTORE] property store); rarer types (MTP devices,
URIs, compressed-folder items) are named by type only, and unknown known-
folder GUIDs are shown as GUIDs. Amcache: `InventoryApplicationFile` and the
older `Root\\File` layout are read; `InventoryApplication` (programs) and the
driver inventories are not.
"""

from __future__ import annotations

import bisect
import codecs
import logging
import re
import struct
import uuid
from dataclasses import dataclass

from . import timeutil
from .errors import FileSystemError

log = logging.getLogger(__name__)

HEADER_SIZE = 4096
BIN_HEADER = 32
NO_OFFSET = 0xFFFFFFFF
BIG_DATA_SEGMENT = 16344
MAX_HIVE = (4 << 30) + HEADER_SIZE        # hive bins size is a 32-bit field
READ_CHUNK = 16 << 20
MAX_PROBLEMS = 500
MAX_DEPTH = 512                           # deeper than any real hive

REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY = 0, 1, 2, 3
REG_DWORD, REG_DWORD_BIG_ENDIAN, REG_LINK, REG_MULTI_SZ = 4, 5, 6, 7
REG_RESOURCE_LIST, REG_FULL_RESOURCE_DESCRIPTOR = 8, 9
REG_RESOURCE_REQUIREMENTS_LIST, REG_QWORD = 10, 11

REG_TYPES = {
    REG_NONE: "REG_NONE", REG_SZ: "REG_SZ", REG_EXPAND_SZ: "REG_EXPAND_SZ",
    REG_BINARY: "REG_BINARY", REG_DWORD: "REG_DWORD",
    REG_DWORD_BIG_ENDIAN: "REG_DWORD_BIG_ENDIAN", REG_LINK: "REG_LINK",
    REG_MULTI_SZ: "REG_MULTI_SZ", REG_RESOURCE_LIST: "REG_RESOURCE_LIST",
    REG_FULL_RESOURCE_DESCRIPTOR: "REG_FULL_RESOURCE_DESCRIPTOR",
    REG_RESOURCE_REQUIREMENTS_LIST: "REG_RESOURCE_REQUIREMENTS_LIST",
    REG_QWORD: "REG_QWORD",
}

FILE_TYPES = {0: "primary hive", 1: "transaction log (old format)",
              2: "transaction log (old format, alternate)",
              6: "transaction log (new format)"}

KEY_FLAGS = {0x0001: "VOLATILE", 0x0002: "HIVE_EXIT", 0x0004: "HIVE_ENTRY",
             0x0008: "NO_DELETE", 0x0010: "SYM_LINK", 0x0020: "COMP_NAME",
             0x0040: "PREDEF_HANDLE", 0x0080: "VIRTUAL_SOURCE",
             0x0100: "VIRTUAL_TARGET", 0x0200: "VIRTUAL_STORE"}
KEY_COMP_NAME = 0x0020
VALUE_COMP_NAME = 0x0001

KINDS = ("SYSTEM", "SOFTWARE", "SAM", "SECURITY", "NTUSER", "USRCLASS",
         "AMCACHE", "unknown")

_U32 = struct.Struct("<I")
_I32 = struct.Struct("<i")
_U16 = struct.Struct("<H")
_U64 = struct.Struct("<Q")


def _utf16(raw: bytes) -> str:
    """UTF-16LE that may hold unpaired surrogates — kept as escapes, never
    silently replaced (the ntfs.py rule)."""
    raw = bytes(raw)
    if len(raw) % 2:
        raw = raw[:-1]
    text = raw.decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _utf16z(raw: bytes) -> str:
    """UTF-16LE cut at the first NUL character."""
    raw = bytes(raw)
    for i in range(0, len(raw) - 1, 2):
        if raw[i] == 0 and raw[i + 1] == 0:
            return _utf16(raw[:i])
    return _utf16(raw)


def _asciiz(raw: bytes) -> str:
    raw = bytes(raw)
    cut = raw.find(b"\x00")
    return (raw if cut < 0 else raw[:cut]).decode("latin-1")


def _guid(raw: bytes) -> str:
    return "{" + str(uuid.UUID(bytes_le=bytes(raw[:16]))).upper() + "}"


def _filetime_pair(raw: int | None) -> dict:
    return {"raw": raw, "utc": timeutil.decode(raw, "filetime") if raw else None}


# ---------------------------------------------------------------------------
# base block
# ---------------------------------------------------------------------------

def base_block_checksum(block: bytes) -> int:
    """XOR of the first 127 little-endian dwords, with 0 and 0xFFFFFFFF
    remapped (0 -> 1, 0xFFFFFFFF -> 0xFFFFFFFE), as the format defines."""
    value = 0
    for (word,) in struct.iter_unpack("<I", bytes(block[:508])):
        value ^= word
    if value == 0xFFFFFFFF:
        return 0xFFFFFFFE
    if value == 0:
        return 1
    return value


@dataclass(frozen=True)
class BaseBlock:
    primary_sequence: int
    secondary_sequence: int
    last_written_raw: int
    major: int
    minor: int
    file_type: int
    file_format: int
    root_offset: int
    hbins_size: int
    clustering: int
    file_name: str
    flags: int
    checksum_stored: int
    checksum_computed: int

    @property
    def dirty(self) -> bool:
        return self.primary_sequence != self.secondary_sequence

    @property
    def checksum_ok(self) -> bool:
        return self.checksum_stored == self.checksum_computed

    @property
    def last_written(self) -> str | None:
        return timeutil.decode(self.last_written_raw, "filetime")

    def as_dict(self) -> dict:
        return {"primary_sequence": self.primary_sequence,
                "secondary_sequence": self.secondary_sequence,
                "dirty": self.dirty,
                "last_written_raw": self.last_written_raw,
                "last_written_utc": self.last_written,
                "version": f"{self.major}.{self.minor}",
                "file_type": self.file_type,
                "file_type_name": FILE_TYPES.get(self.file_type, "unknown"),
                "file_format": self.file_format,
                "root_offset": self.root_offset,
                "hbins_size": self.hbins_size,
                "file_name": self.file_name, "flags": self.flags,
                "checksum_stored": f"0x{self.checksum_stored:08X}",
                "checksum_computed": f"0x{self.checksum_computed:08X}",
                "checksum_ok": self.checksum_ok}


def parse_base_block(data: bytes, name: str = "") -> BaseBlock:
    label = f"'{name}'" if name else "This file"
    if len(data) < 512 or bytes(data[:4]) != b"regf":
        raise FileSystemError(
            f"{label} is not a Windows registry hive: it does not begin with "
            "the 'regf' signature. Check that the right file was selected — a "
            "hive is a file such as SYSTEM, SOFTWARE, NTUSER.DAT or "
            "UsrClass.dat, without an extension.")
    (primary, secondary, written, major, minor, ftype, fformat, root,
     hbins, clustering) = struct.unpack_from("<IIQIIIIIII", data, 4)
    fname = _utf16z(data[0x30:0x70])
    flags = _U32.unpack_from(data, 0x90)[0]
    stored = _U32.unpack_from(data, 0x1FC)[0]
    return BaseBlock(primary, secondary, written, major, minor, ftype, fformat,
                     root, hbins, clustering, fname, flags, stored,
                     base_block_checksum(data))


# ---------------------------------------------------------------------------
# value data
# ---------------------------------------------------------------------------

def decode_data(vtype: int, raw: bytes):
    """(decoded data, problem or None). Types this does not interpret come
    back as their raw bytes."""
    raw = bytes(raw)
    if vtype in (REG_SZ, REG_EXPAND_SZ):
        note = "odd byte length for a UTF-16 string" if len(raw) % 2 else None
        return _utf16z(raw), note
    if vtype == REG_LINK:
        return _utf16(raw).rstrip("\x00"), None
    if vtype == REG_MULTI_SZ:
        text = _utf16(raw)
        parts = text.split("\x00")
        while parts and parts[-1] == "":
            parts.pop()
        return parts, None
    if vtype == REG_DWORD:
        if len(raw) < 4:
            return None, f"REG_DWORD holds {len(raw)} bytes, not 4"
        return _U32.unpack_from(raw)[0], None
    if vtype == REG_DWORD_BIG_ENDIAN:
        if len(raw) < 4:
            return None, f"REG_DWORD_BIG_ENDIAN holds {len(raw)} bytes, not 4"
        return struct.unpack_from(">I", raw)[0], None
    if vtype == REG_QWORD:
        if len(raw) < 8:
            return None, f"REG_QWORD holds {len(raw)} bytes, not 8"
        return _U64.unpack_from(raw)[0], None
    return raw, None


class Value:
    """One value record. `raw` is the data exactly as stored; `data` is it
    decoded by type (bytes for types not interpreted)."""

    __slots__ = ("hive", "offset", "name", "type", "raw", "data_size",
                 "inline", "flags", "problems", "deleted", "recovered_from",
                 "_decoded")

    def __init__(self, hive, offset, name, vtype, raw, data_size, inline,
                 flags, problems, deleted=False, recovered_from=None):
        self.hive = hive
        self.offset = offset
        self.name = name
        self.type = vtype
        self.raw = raw
        self.data_size = data_size
        self.inline = inline
        self.flags = flags
        self.problems = problems
        self.deleted = deleted
        self.recovered_from = recovered_from
        self._decoded = None

    @property
    def type_name(self) -> str:
        if self.type in REG_TYPES:
            return REG_TYPES[self.type]
        if self.type & 0xFFFF0000 == 0xFFFF0000:
            return f"DEVPROP_TYPE 0x{self.type & 0xFFFF:04X}"
        return f"0x{self.type:08X}"

    @property
    def data(self):
        if self._decoded is None:
            data, problem = decode_data(self.type, self.raw)
            if problem and problem not in self.problems:
                self.problems.append(problem)
            self._decoded = (data,)
        return self._decoded[0]

    def as_dict(self) -> dict:
        return {"name": self.name, "type": self.type,
                "type_name": self.type_name, "data": _jsonable(self.data),
                "data_size": self.data_size, "inline": self.inline,
                "offset": self.offset, "problems": list(self.problems),
                "deleted": self.deleted, "recovered_from": self.recovered_from}

    def __repr__(self) -> str:
        return f"<Value {self.name!r} {self.type_name}>"


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------

class Key:
    """One key node. Children are read when asked for and cached."""

    __slots__ = ("hive", "offset", "name", "flags", "last_written_raw",
                 "access_bits", "parent_offset", "subkey_count",
                 "volatile_subkey_count", "subkey_list_offset", "value_count",
                 "value_list_offset", "security_offset", "class_offset",
                 "class_length", "path", "deleted", "recovered_from",
                 "live_twin", "_subkeys", "_values")

    def __init__(self, hive, offset, cell, path, deleted=False,
                 recovered_from=None):
        (self.flags, self.last_written_raw, self.access_bits,
         self.parent_offset, self.subkey_count, self.volatile_subkey_count,
         self.subkey_list_offset, _vol_list, self.value_count,
         self.value_list_offset, self.security_offset,
         self.class_offset) = struct.unpack_from("<HQIIIIIIIIII", cell, 2)
        name_len, self.class_length = struct.unpack_from("<HH", cell, 0x48)
        raw_name = cell[0x4C:0x4C + name_len]
        if 0x4C + name_len > len(cell) and not deleted:
            hive._problem(f"key at cell 0x{offset:X}: its name runs past the "
                          "end of its cell; the name is cut short")
        if self.flags & KEY_COMP_NAME:
            self.name = bytes(raw_name).decode("latin-1")
        else:
            self.name = _utf16(raw_name)
        self.hive = hive
        self.offset = offset
        self.path = path if path is not None else self.name
        self.deleted = deleted
        self.recovered_from = recovered_from
        self.live_twin = None
        self._subkeys = None
        self._values = None

    # -- facts ------------------------------------------------------------
    @property
    def last_written(self) -> str | None:
        return timeutil.decode(self.last_written_raw, "filetime")

    @property
    def flag_names(self) -> list[str]:
        return [n for bit, n in KEY_FLAGS.items() if self.flags & bit]

    @property
    def class_name(self) -> str | None:
        if self.class_offset == NO_OFFSET or not self.class_length:
            return None
        cell = self.hive._cell(self.class_offset, "class name",
                               allow_free=self.deleted)
        if cell is None:
            return None
        if len(cell) < self.class_length:
            self.hive._problem(f"key '{self.path}': class name cell is shorter "
                               "than the length the key records")
        return _utf16(cell[:self.class_length])

    def security(self) -> dict | None:
        return self.hive._security(self.security_offset)

    # -- children ---------------------------------------------------------
    def subkeys(self) -> list["Key"]:
        if self._subkeys is None:
            out = []
            if self.subkey_count and self.subkey_list_offset != NO_OFFSET:
                prefix = self.path + "\\" if self.path else ""
                for off in self.hive._subkey_offsets(self.subkey_list_offset,
                                                     self.path,
                                                     allow_free=self.deleted):
                    child = self.hive._key(off, None, allow_free=self.deleted,
                                           deleted=self.deleted,
                                           recovered_from=self.recovered_from,
                                           quiet=self.deleted)
                    if child is None:
                        continue
                    child.path = prefix + child.name
                    if child.parent_offset != self.offset and not self.deleted:
                        self.hive._problem(
                            f"key '{child.path}' records parent cell "
                            f"0x{child.parent_offset:X} but is listed under "
                            f"cell 0x{self.offset:X}")
                    out.append(child)
                if len(out) != self.subkey_count and not self.deleted:
                    self.hive._problem(
                        f"key '{self.path or '(root)'}' records "
                        f"{self.subkey_count} subkeys; {len(out)} could be read")
            self._subkeys = out
        return list(self._subkeys)

    def subkey(self, name: str) -> "Key | None":
        want = name.casefold()
        for child in self.subkeys():
            if child.name.casefold() == want:
                return child
        return None

    def values(self) -> list[Value]:
        if self._values is None:
            out = []
            if self.value_count and self.value_list_offset != NO_OFFSET:
                cell = self.hive._cell(self.value_list_offset,
                                       f"value list of '{self.path}'",
                                       allow_free=self.deleted,
                                       quiet=self.deleted)
                if cell is not None:
                    count = self.value_count
                    if len(cell) < 4 * count:
                        if not self.deleted:
                            self.hive._problem(
                                f"key '{self.path}': its value list holds "
                                f"room for {len(cell) // 4} of {count} values")
                        count = len(cell) // 4
                    for i in range(count):
                        off = _U32.unpack_from(cell, 4 * i)[0]
                        value = self.hive._value(off, self.path,
                                                 allow_free=self.deleted,
                                                 quiet=self.deleted)
                        if value is not None:
                            if self.deleted:
                                value.deleted = True
                                value.recovered_from = \
                                    "value list of a key in a free cell"
                            out.append(value)
            self._values = out
        return list(self._values)

    def value(self, name: str) -> Value | None:
        want = "" if name in ("", "(default)", "@") else name.casefold()
        for v in self.values():
            if v.name.casefold() == want:
                return v
        return None

    def as_dict(self) -> dict:
        return {"name": self.name, "path": self.path, "offset": self.offset,
                "last_written_raw": self.last_written_raw,
                "last_written_utc": self.last_written,
                "flags": self.flag_names, "subkey_count": self.subkey_count,
                "value_count": self.value_count, "class_name": self.class_name,
                "deleted": self.deleted, "recovered_from": self.recovered_from}

    def __repr__(self) -> str:
        return f"<Key {self.path or '(root)'!r}>"


# ---------------------------------------------------------------------------
# the hive
# ---------------------------------------------------------------------------

class Hive:
    """A hive read from its bytes. `problems` lists, in plain sentences,
    every piece of damage that was read around."""

    def __init__(self, data: bytes, name: str = "", *,
                 recovery: dict | None = None) -> None:
        self.name = name
        self._data = data
        self.problems: list[str] = []
        self._problem_overflow = 0
        self._seen_problems: set = set()
        self.size = len(data)
        self.recovery = recovery
        self.header = parse_base_block(data, name)
        h = self.header
        if recovery and recovery.get("applied"):
            o = recovery["original_base_block"]
            self._problem(
                "TRANSACTION LOGS APPLIED (in memory; no file was changed): "
                f"the hive file was dirty (primary sequence "
                f"{o['primary_sequence']}, secondary "
                f"{o['secondary_sequence']}), and {recovery['entries']} log "
                f"entries (sequence {recovery['first_sequence']}–"
                f"{recovery['last_sequence']}) from "
                f"{', '.join(recovery['logs_used'])} were replayed over it. "
                "What is read here is the reconstructed hive.")
        elif h.dirty:
            self._problem(
                "DIRTY HIVE: the base block's primary sequence number "
                f"({h.primary_sequence}) differs from its secondary sequence "
                f"number ({h.secondary_sequence}). Windows had begun writing "
                "this hive and had not finished; the newest changes are in "
                "its transaction logs (.LOG1/.LOG2), which were NOT applied. "
                "Recent data may be missing and keys may be half-written."
                + (f" Logs were supplied but not used: {recovery['reason']}"
                   if recovery else ""))
        if not h.checksum_ok:
            self._problem(f"base block checksum is 0x{h.checksum_stored:08X}; "
                          f"recomputed 0x{h.checksum_computed:08X}")
        if h.file_type != 0:
            self._problem(
                f"base block file type is {h.file_type} "
                f"({FILE_TYPES.get(h.file_type, 'unknown')}), not a primary "
                "hive")
        if h.major != 1 or not 2 <= h.minor <= 6:
            self._problem(f"format version {h.major}.{h.minor} is not one this "
                          "reader knows (1.2 to 1.6); read anyway")
        self._bins: list[tuple[int, int]] = []
        self._bin_starts: list[int] = []
        self._walk_bins()
        self.root_offset = h.root_offset
        self._key_count = None
        root = self._key(h.root_offset, "")
        if root is None:
            kind = FILE_TYPES.get(h.file_type, "")
            hint = (" The base block says this is a " + kind + "; open the "
                    "primary hive file instead.") if h.file_type else ""
            raise FileSystemError(
                f"{self._label()}: the root key (cell 0x{h.root_offset:X}) "
                "could not be read, so nothing in the hive can be reached."
                + hint)
        root.path = ""
        self.root = root

    # -- plumbing ---------------------------------------------------------
    def _label(self) -> str:
        return f"Hive '{self.name}'" if self.name else "This hive"

    def _problem(self, text: str) -> None:
        if text in self._seen_problems:
            return
        self._seen_problems.add(text)
        if len(self.problems) >= MAX_PROBLEMS:
            self._problem_overflow += 1
            return
        log.debug("registry %s: %s", self.name or "<hive>", text)
        self.problems.append(text)

    @property
    def all_problems(self) -> list[str]:
        if self._problem_overflow:
            return self.problems + [f"... and {self._problem_overflow} more "
                                    "problems not listed"]
        return list(self.problems)

    def _walk_bins(self) -> None:
        data, h = self._data, self.header
        end = HEADER_SIZE + h.hbins_size
        if end > len(data):
            self._problem(
                f"the base block says the hive bins occupy {h.hbins_size} "
                f"bytes, but the file holds only {len(data) - HEADER_SIZE} "
                "after the base block: the file is truncated")
            end = len(data)
        pos = HEADER_SIZE
        while pos + BIN_HEADER <= end:
            ok = bytes(data[pos:pos + 4]) == b"hbin"
            rel, size = struct.unpack_from("<II", data, pos + 4) if ok \
                else (0, 0)
            if ok and (size < 4096 or size % 4096 or pos + size > len(data)):
                self._problem(f"hive bin at file offset 0x{pos:X} has an "
                              f"impossible size ({size})")
                ok = False
            if not ok:
                nxt = self._resync(pos + 4096, end)
                if nxt is None:
                    self._problem(
                        f"no hive bin at file offset 0x{pos:X} or anywhere "
                        "after it: cells from there to the end are not read")
                    break
                self._problem(
                    f"file offsets 0x{pos:X}-0x{nxt - 1:X} hold no valid hive "
                    "bin (overwritten or zeroed); cells there cannot be read. "
                    f"Reading resumed at the next valid bin (0x{nxt:X}).")
                pos = nxt
                continue
            if rel != pos - HEADER_SIZE:
                self._problem(f"hive bin at file offset 0x{pos:X} records its "
                              f"own offset as 0x{rel:X}")
            self._bins.append((pos - HEADER_SIZE, pos - HEADER_SIZE + size))
            self._bin_starts.append(pos - HEADER_SIZE)
            pos += size

    def _resync(self, pos: int, end: int) -> int | None:
        """The next 4096-aligned 'hbin' whose recorded offset matches where
        it sits — the next bin that can be trusted after damage."""
        data = self._data
        while pos + BIN_HEADER <= end:
            if bytes(data[pos:pos + 4]) == b"hbin":
                rel, size = struct.unpack_from("<II", data, pos + 4)
                if rel == pos - HEADER_SIZE and size >= 4096 and \
                        size % 4096 == 0 and pos + size <= len(data):
                    return pos
            pos += 4096
        return None

    def _bin_for(self, off: int) -> tuple[int, int] | None:
        i = bisect.bisect_right(self._bin_starts, off) - 1
        if i < 0:
            return None
        start, end = self._bins[i]
        return (start, end) if start <= off < end else None

    def _cell(self, off: int, what: str, *, allow_free: bool = False,
              quiet: bool = False) -> bytes | None:
        """The data of the cell at hive-bins offset `off`, or None (with a
        problem recorded unless `quiet`)."""
        def bad(reason: str):
            if not quiet:
                self._problem(f"{what}: cell 0x{off:X} {reason}")
            return None
        if off == NO_OFFSET or off < 0:
            return bad("is not a cell offset")
        if off % 8:
            return bad("is not 8-byte aligned")
        pos = HEADER_SIZE + off
        if pos + 4 > len(self._data):
            return bad("lies beyond the end of the file")
        span = self._bin_for(off)
        if span is None:
            return bad("is not inside any hive bin")
        if off < span[0] + BIN_HEADER:
            return bad("points into a hive bin header")
        size = _I32.unpack_from(self._data, pos)[0]
        free = size > 0
        size = abs(size)
        if size < 8 or size % 8:
            return bad(f"has an impossible size ({size})")
        if off + size > span[1]:
            return bad("runs past the end of its hive bin")
        if free and not allow_free and not quiet:
            self._problem(f"{what}: cell 0x{off:X} is marked FREE but is "
                          "referenced by an allocated record; its contents "
                          "were read and may be stale")
        return bytes(self._data[pos + 4:pos + size])

    def _key(self, off: int, path: str | None, *, allow_free=False,
             deleted=False, recovered_from=None, quiet=False) -> Key | None:
        cell = self._cell(off, "key", allow_free=allow_free, quiet=quiet)
        if cell is None:
            return None
        if cell[:2] != b"nk" or len(cell) < 0x4C:
            if not quiet:
                self._problem(f"key: cell 0x{off:X} is not a key node "
                              f"(signature {cell[:2]!r})")
            return None
        return Key(self, off, cell, path, deleted, recovered_from)

    def _subkey_offsets(self, off: int, where: str, depth: int = 0, *,
                        allow_free=False) -> list[int]:
        what = f"subkey list of '{where or '(root)'}'"
        cell = self._cell(off, what, allow_free=allow_free, quiet=allow_free)
        if cell is None or len(cell) < 4:
            return []
        sig = cell[:2]
        count = _U16.unpack_from(cell, 2)[0]
        if sig in (b"lf", b"lh"):
            step = 8
        elif sig == b"li":
            step = 4
        elif sig == b"ri":
            if depth:
                self._problem(f"{what}: an 'ri' list inside an 'ri' list at "
                              f"cell 0x{off:X}; not followed")
                return []
            out = []
            for i in range(min(count, (len(cell) - 4) // 4)):
                sub = _U32.unpack_from(cell, 4 + 4 * i)[0]
                out += self._subkey_offsets(sub, where, depth + 1,
                                            allow_free=allow_free)
            return out
        else:
            self._problem(f"{what}: cell 0x{off:X} has unknown list "
                          f"signature {sig!r}")
            return []
        room = (len(cell) - 4) // step
        if room < count:
            self._problem(f"{what}: list at cell 0x{off:X} records {count} "
                          f"entries but has room for {room}")
            count = room
        return [_U32.unpack_from(cell, 4 + step * i)[0] for i in range(count)]

    def _value(self, off: int, where: str, *, allow_free=False,
               quiet=False) -> Value | None:
        what = f"value of '{where or '(root)'}'"
        cell = self._cell(off, what, allow_free=allow_free, quiet=quiet)
        if cell is None:
            return None
        if cell[:2] != b"vk" or len(cell) < 0x14:
            if not quiet:
                self._problem(f"{what}: cell 0x{off:X} is not a value record "
                              f"(signature {cell[:2]!r})")
            return None
        name_len, size_raw, data_off, vtype, flags = struct.unpack_from(
            "<HIIIH", cell, 2)
        raw_name = cell[0x14:0x14 + name_len]
        name = bytes(raw_name).decode("latin-1") if flags & VALUE_COMP_NAME \
            else _utf16(raw_name)
        problems: list[str] = []
        if 0x14 + name_len > len(cell):
            problems.append("value name runs past the end of its cell")
        inline = bool(size_raw & 0x80000000)
        size = size_raw & 0x7FFFFFFF
        if inline:
            if size > 4:
                problems.append(f"inline data claims {size} bytes; 4 kept")
                size = 4
            raw = struct.pack("<I", data_off)[:size]
        elif size == 0:
            raw = b""
        else:
            raw = self._value_data(data_off, size, problems, where, name,
                                   allow_free, quiet)
        if not quiet:
            for p in problems:
                self._problem(f"value '{name or '(default)'}' of "
                              f"'{where or '(root)'}': {p}")
        return Value(self, off, name, vtype, raw, size, inline, flags,
                     problems)

    def _value_data(self, off, size, problems, where, name, allow_free,
                    quiet=False):
        what = f"data of value '{name or '(default)'}' of '{where or '(root)'}'"
        cell = self._cell(off, what, allow_free=allow_free, quiet=quiet)
        if cell is None:
            problems.append("data cell could not be read")
            return b""
        if size > BIG_DATA_SEGMENT and cell[:2] == b"db" and len(cell) >= 8 \
                and len(cell) < size:
            count, list_off = struct.unpack_from("<HI", cell, 2)
            seglist = self._cell(list_off, what + " (segment list)",
                                 allow_free=allow_free, quiet=quiet)
            if seglist is None:
                problems.append("big-data segment list could not be read")
                return b""
            if len(seglist) < 4 * count:
                problems.append("big-data segment list is shorter than its "
                                "segment count")
                count = len(seglist) // 4
            out = bytearray()
            for i in range(count):
                seg = self._cell(_U32.unpack_from(seglist, 4 * i)[0],
                                 what + f" (segment {i})",
                                 allow_free=allow_free, quiet=quiet)
                if seg is None:
                    problems.append(f"big-data segment {i} could not be read")
                    break
                out += seg[:min(BIG_DATA_SEGMENT, size - len(out))]
                if len(out) >= size:
                    break
            if len(out) < size:
                problems.append(f"big data holds {len(out)} of {size} bytes")
            return bytes(out[:size])
        if len(cell) < size:
            problems.append(f"data cell holds {len(cell)} of {size} bytes")
        return cell[:size]

    def _security(self, off: int) -> dict | None:
        if off == NO_OFFSET:
            return None
        cell = self._cell(off, "security record", quiet=True)
        if cell is None or cell[:2] != b"sk" or len(cell) < 20:
            return None
        flink, blink, refs, sd_size = struct.unpack_from("<IIII", cell, 4)
        sd = cell[20:20 + sd_size]
        out = {"offset": off, "reference_count": refs,
               "descriptor_size": sd_size, "owner_sid": None,
               "group_sid": None}
        if len(sd) >= 20:
            owner, group = struct.unpack_from("<II", sd, 4)
            out["owner_sid"] = _sid(sd, owner)
            out["group_sid"] = _sid(sd, group)
        return out

    # -- public -----------------------------------------------------------
    def key_at(self, offset: int) -> Key | None:
        return self._key(offset, None)

    def control_set(self) -> tuple[str | None, str]:
        """The control set `Select\\Current` names, and how it was found."""
        select = self.root.subkey("Select")
        if select is not None:
            cur = select.value("Current")
            if cur is not None and isinstance(cur.data, int):
                name = f"ControlSet{cur.data:03d}"
                if self.root.subkey(name) is not None:
                    return name, f"Select\\Current = {cur.data}"
                return None, (f"Select\\Current = {cur.data}, but {name} is "
                              "not in the hive")
        for k in self.root.subkeys():
            if k.name.lower().startswith("controlset"):
                return k.name, ("Select\\Current not readable; the first "
                                "control set present was used")
        return None, "no control set in this hive"

    def find(self, path: str) -> Key | None:
        """The key at `path` (backslash-separated, case-insensitive, relative
        to the root). A leading `CurrentControlSet` — which exists only in a
        running system's memory — is resolved through `Select\\Current`."""
        parts = [p for p in path.replace("/", "\\").split("\\") if p]
        if parts and parts[0].casefold() == self.root.name.casefold() and \
                self.root.subkey(parts[0]) is None:
            parts = parts[1:]
        if parts and parts[0].casefold() == "currentcontrolset":
            ccs, _how = self.control_set()
            if ccs is None:
                return None
            parts[0] = ccs
        key = self.root
        for part in parts:
            key = key.subkey(part)
            if key is None:
                return None
        return key

    def walk(self, start: Key | None = None):
        """Every key under `start` (the root by default), depth first,
        `start` included. A cell reached twice is reported and not re-entered."""
        start = start or self.root
        seen = {start.offset}
        stack = [(start, 0)]
        while stack:
            key, depth = stack.pop()
            yield key
            if depth >= MAX_DEPTH:
                self._problem(f"key '{key.path}' is nested over {MAX_DEPTH} "
                              "deep; not descended")
                continue
            children = key.subkeys()
            for child in reversed(children):
                if child.offset in seen:
                    self._problem(f"key cell 0x{child.offset:X} "
                                  f"('{child.path}') is reached twice — a loop "
                                  "or a shared list; not re-entered")
                    continue
                seen.add(child.offset)
                stack.append((child, depth + 1))

    def key_count(self) -> int:
        if self._key_count is None:
            self._key_count = sum(1 for _ in self.walk())
        return self._key_count

    def cells(self):
        """(offset, size, allocated) for every cell in every indexed bin."""
        data = self._data
        for start, end in self._bins:
            off = start + BIN_HEADER
            while off + 4 <= end:
                size = _I32.unpack_from(data, HEADER_SIZE + off)[0]
                length = abs(size)
                if length < 8 or length % 8 or off + length > end:
                    self._problem(f"cell at 0x{off:X} has an impossible size "
                                  f"({size}); the rest of its hive bin was not "
                                  "walked")
                    break
                yield off, length, size < 0
                off += length

    def recover_deleted(self) -> dict:
        """Key and value records found intact in FREE cells.

        Returns {"keys": [Key], "values": [(Value, parent_path or None)]}.
        Every item has `deleted=True` and `recovered_from="free cell"`."""
        paths = {}
        for key in self.walk():
            paths[key.offset] = key.path
        live_paths = {p.casefold() for p in paths.values()}
        keys, values, claimed = [], [], set()
        for off, length, allocated in self.cells():
            if allocated:
                continue
            for sub in range(off, off + length - 8, 8):
                sig = bytes(self._data[HEADER_SIZE + sub + 4:
                                       HEADER_SIZE + sub + 6])
                if sig not in (b"nk", b"vk") or sub in claimed:
                    continue
                inner = abs(_I32.unpack_from(self._data, HEADER_SIZE + sub)[0])
                if inner < 8 or sub + inner > off + length:
                    continue
                if sig == b"nk":
                    key = self._key(sub, None, allow_free=True, deleted=True,
                                    recovered_from="free cell", quiet=True)
                    if key is None or not _plausible_key(key):
                        continue
                    parent = paths.get(key.parent_offset)
                    if parent is None:
                        parent = self._deleted_parent_path(key.parent_offset)
                    key.path = (parent + "\\" if parent else "") + key.name \
                        if parent is not None else "?\\" + key.name
                    keys.append(key)
                    claimed.add(sub)
                else:
                    value = self._value(sub, "deleted value", allow_free=True,
                                        quiet=True)
                    if value is None or not _plausible_value(value) or \
                            (not value.name and not value.raw):
                        continue
                    value.deleted = True
                    value.recovered_from = "free cell"
                    values.append(value)
                    claimed.add(sub)
        parent_of = {}
        for key in keys:
            key.recovered_from = "free cell"
            key.live_twin = key.path.casefold() in live_paths
            try:
                for v in key.values():
                    parent_of[v.offset] = key.path
            except (struct.error, ValueError):
                self._problem(f"deleted key '{key.path}': its value list "
                              "could not be read")
        return {"keys": keys,
                "values": [(v, parent_of.get(v.offset)) for v in values]}

    def _deleted_parent_path(self, off: int) -> str | None:
        names = []
        seen = set()
        while off not in seen and len(names) < 64:
            seen.add(off)
            key = self._key(off, None, allow_free=True, quiet=True)
            if key is None:
                return None
            if off == self.root_offset:
                return "\\".join(reversed(names))
            names.append(key.name)
            off = key.parent_offset
        return None

    def as_dict(self) -> dict:
        return {"name": self.name, "size": self.size,
                "header": self.header.as_dict(),
                "root_name": self.root.name,
                "problems": self.all_problems}


def _plausible_key(key: Key) -> bool:
    if not key.name or len(key.name) > 512:
        return False
    if any(ord(ch) < 0x20 for ch in key.name):
        return False
    raw = key.last_written_raw
    return 0 < raw < 0x0300000000000000      # before roughly year 2600


def _plausible_value(value: Value) -> bool:
    if value.type > 0xFFFF and value.type & 0xFFFF0000 != 0xFFFF0000:
        return False
    if len(value.name) > 16383 or any(ord(ch) < 0x20 for ch in value.name):
        return False
    return True


def _sid(sd: bytes, off: int) -> str | None:
    if not off or off + 8 > len(sd):
        return None
    rev, count = sd[off], sd[off + 1]
    if rev != 1 or count > 15 or off + 8 + 4 * count > len(sd):
        return None
    auth = int.from_bytes(sd[off + 2:off + 8], "big")
    subs = struct.unpack_from(f"<{count}I", sd, off + 8)
    return "S-1-" + str(auth) + "".join(f"-{s}" for s in subs)


def _read_all(source, name: str) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        return bytes(source)
    size = getattr(source, "size", None)
    if size is None or not hasattr(source, "read_at"):
        raise TypeError("open_hive needs bytes, or a reader with .size and "
                        ".read_at(offset, length)")
    label = f"'{name}'" if name else "The hive"
    if size > MAX_HIVE:
        raise FileSystemError(
            f"{label} is {size} bytes — larger than any registry hive can be "
            "(the format's size fields stop at 4 GiB). It is probably not a "
            "hive, or the wrong region was selected.")
    out = bytearray()
    while len(out) < size:
        chunk = source.read_at(len(out), min(READ_CHUNK, size - len(out)))
        if not chunk:
            break
        out += chunk
    return bytes(out)


def open_hive(reader_or_bytes, name: str = "", *, logs=None) -> Hive:
    """Parse a hive from bytes or from a reader (`.size`, `.read_at`).

    `logs` — the hive's transaction logs, as {name: bytes-or-reader} or a
    list — are replayed IN MEMORY when the hive is dirty (new-format logs,
    Windows 8.1 and later); the result says exactly what was applied
    (`hive.recovery`). Nothing is written anywhere.

    Raises `FileSystemError` when the bytes are not a hive or its root key
    cannot be read; everything else that is wrong is in `hive.problems`."""
    data = _read_all(reader_or_bytes, name)
    if len(data) < HEADER_SIZE:
        parse_base_block(data, name)       # raises if it is not even regf
        raise FileSystemError(
            f"{'Hive ' + repr(name) if name else 'This hive'} is only "
            f"{len(data)} bytes; a hive's base block alone is 4096. The file "
            "is truncated.")
    recovery = None
    if logs:
        if isinstance(logs, dict):
            named = list(logs.items())
        else:
            named = [(f"log {i + 1}", src) for i, src in enumerate(logs)]
        data, recovery = replay_logs(data, [(n, _read_all(src, n))
                                            for n, src in named])
    return Hive(data, name, recovery=recovery)


# ---------------------------------------------------------------------------
# transaction logs (new format, 'HvLE')
# ---------------------------------------------------------------------------

MARVIN_SEED = 0x82EF4D887A4E55C5
_M32 = 0xFFFFFFFF


def _rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _M32


def marvin32(data: bytes, seed: int = MARVIN_SEED) -> int:
    """Marvin32 (Microsoft's published keyed hash), the 64-bit form the
    registry stores in each log entry: (high << 32) | low."""
    data = bytes(data)
    lo, hi = seed & _M32, seed >> 32

    def block(lo, hi):
        hi ^= lo
        lo = (_rotl(lo, 20) + hi) & _M32
        hi = _rotl(hi, 9) ^ lo
        lo = (_rotl(lo, 27) + hi) & _M32
        hi = _rotl(hi, 19)
        return lo, hi

    full = len(data) - len(data) % 4
    for (word,) in struct.iter_unpack("<I", data[:full]):
        lo = (lo + word) & _M32
        lo, hi = block(lo, hi)
    tail = data[full:]
    final = 0x80
    if len(tail) == 1:
        final = 0x8000 | tail[0]
    elif len(tail) == 2:
        final = 0x800000 | _U16.unpack(tail)[0]
    elif len(tail) == 3:
        final = 0x80000000 | (tail[2] << 16) | _U16.unpack(tail[:2])[0]
    lo = (lo + final) & _M32
    lo, hi = block(lo, hi)
    lo, hi = block(lo, hi)
    return (hi << 32) | lo


def log_entries(raw: bytes) -> tuple[dict, list[dict], list[str]]:
    """(log base block, valid consecutive 'HvLE' entries, problems) of one
    new-format log file. Reading stops at the first entry whose signature,
    size, either Marvin32 hash or sequence continuity fails — which is how
    the end of the valid part of a reused log is recognised."""
    problems: list[str] = []
    if len(raw) < 512 or raw[:4] != b"regf":
        return {}, [], ["does not begin with a 'regf' base block"]
    p, s, = struct.unpack_from("<II", raw, 4)
    ftype = _U32.unpack_from(raw, 0x1C)[0]
    base = {"primary_sequence": p, "secondary_sequence": s,
            "file_type": ftype,
            "checksum_ok": _U32.unpack_from(raw, 0x1FC)[0] ==
            base_block_checksum(raw)}
    if not base["checksum_ok"]:
        problems.append("log base block checksum does not match")
    if ftype != 6 and raw[512:516] != b"HvLE":
        problems.append(f"file type {ftype}: an old-format (pre-Windows 8.1) "
                        "log, which this version does not replay")
        return base, [], problems
    entries: list[dict] = []
    pos = 512
    while pos + 40 <= len(raw) and raw[pos:pos + 4] == b"HvLE":
        size, flags, seq, hbins, count = struct.unpack_from("<IIIII", raw,
                                                            pos + 4)
        h1, h2 = struct.unpack_from("<QQ", raw, pos + 24)
        if size < 40 or size % 512 or pos + size > len(raw) or \
                40 + 8 * count > size:
            problems.append(f"log entry at byte {pos} has an impossible size")
            break
        if marvin32(raw[pos:pos + 32]) != h2 or \
                marvin32(raw[pos + 40:pos + size]) != h1:
            problems.append(f"log entry at byte {pos} (sequence {seq}) fails "
                            "its hash check; entries from there are not used")
            break
        if entries and seq != entries[-1]["sequence"] + 1:
            break
        pages, dpos = [], pos + 40 + 8 * count
        for i in range(count):
            off, psize = struct.unpack_from("<II", raw, pos + 40 + 8 * i)
            pages.append((off, raw[dpos:dpos + psize]))
            dpos += psize
        if dpos > pos + size:
            problems.append(f"log entry {seq}: its pages run past the entry")
            break
        entries.append({"sequence": seq, "flags": flags, "hbins_size": hbins,
                        "pages": pages, "offset": pos})
        pos += size
    return base, entries, problems


def replay_logs(data: bytes, logs: list) -> tuple[bytes, dict]:
    """Replay new-format transaction logs over a dirty hive, in memory.

    A log is applicable when its base block's sequence number is at least
    the hive's secondary sequence number; applicable logs are taken in
    ascending order and their entries applied while sequence numbers stay
    consecutive. Each entry's dirty pages overwrite the hive bins at the
    offsets it names. In the reconstructed copy the base block takes the
    last entry's hive-bins size and its secondary sequence number is set
    equal to the primary; the original base block is kept in the report."""
    original = parse_base_block(data)
    report = {"applied": False, "logs_used": [], "entries": 0,
              "first_sequence": None, "last_sequence": None,
              "original_base_block": original.as_dict(), "log_problems": {}}
    if not original.dirty:
        report["reason"] = "the hive is not dirty; nothing to replay"
        return data, report
    candidates = []
    for lname, raw in logs:
        base, entries, problems = log_entries(raw)
        if problems:
            report["log_problems"][lname] = problems
        if not entries:
            continue
        if base.get("primary_sequence", 0) < original.secondary_sequence:
            report["log_problems"].setdefault(lname, []).append(
                f"its sequence ({base['primary_sequence']}) is older than the "
                f"hive's ({original.secondary_sequence}): already in the hive")
            continue
        candidates.append((base["primary_sequence"], lname, entries))
    candidates.sort(key=lambda c: c[0])
    out = bytearray(data)
    expected = None
    hbins = original.hbins_size
    for _seq, lname, entries in candidates:
        used = False
        for e in entries:
            if e["sequence"] < original.secondary_sequence:
                continue
            if expected is not None and e["sequence"] != expected:
                break
            for off, page in e["pages"]:
                at = HEADER_SIZE + off
                if at + len(page) > len(out):
                    out += bytes(at + len(page) - len(out))
                out[at:at + len(page)] = page
            hbins = e["hbins_size"]
            expected = e["sequence"] + 1
            report["entries"] += 1
            if report["first_sequence"] is None:
                report["first_sequence"] = e["sequence"]
            report["last_sequence"] = e["sequence"]
            used = True
        if used:
            report["logs_used"].append(lname)
    if not report["entries"]:
        report["reason"] = "no log held entries that continue the hive"
        return data, report
    report["applied"] = True
    if HEADER_SIZE + hbins > len(out):
        out += bytes(HEADER_SIZE + hbins - len(out))
    struct.pack_into("<I", out, 8, original.primary_sequence)
    struct.pack_into("<I", out, 0x28, hbins)
    struct.pack_into("<I", out, 0x1FC, base_block_checksum(out))
    return bytes(out), report


# ---------------------------------------------------------------------------
# hive kind
# ---------------------------------------------------------------------------

_NAME_KINDS = (("ntuser", "NTUSER"), ("usrclass", "USRCLASS"),
               ("amcache", "AMCACHE"), ("software", "SOFTWARE"),
               ("system", "SYSTEM"), ("security", "SECURITY"), ("sam", "SAM"))


def hive_kind(hive: Hive, file_name: str = "") -> str:
    """SYSTEM | SOFTWARE | SAM | SECURITY | NTUSER | USRCLASS | AMCACHE |
    unknown — by what the root key holds first, by file name second."""
    names = {k.name.casefold() for k in hive.root.subkeys()}
    if "select" in names and any(n.startswith("controlset") for n in names):
        return "SYSTEM"
    if "sam" in names:
        sam = hive.root.subkey("SAM")
        if sam is not None and sam.subkey("Domains") is not None:
            return "SAM"
    if "policy" in names and ({"rxact", "cache", "sam"} & names or
                              len(names) <= 6):
        return "SECURITY"
    if "root" in names:
        root = hive.root.subkey("Root")
        sub = {k.name.casefold() for k in root.subkeys()} if root else set()
        if sub & {"inventoryapplicationfile", "file", "programs",
                  "inventoryapplication", "inventorydriverbinary"}:
            return "AMCACHE"
    if "software" in names and names & {"control panel", "environment",
                                        "appevents", "console", "keyboard layout"}:
        return "NTUSER"
    if "local settings" in names or ("clsid" in names and
                                     any(n.startswith(".") for n in names)
                                     and "microsoft" not in names):
        return "USRCLASS"
    if "microsoft" in names and names & {"classes", "clients", "policies",
                                         "registeredapplications"}:
        return "SOFTWARE"
    for candidate in (file_name, hive.name, hive.header.file_name):
        base = (candidate or "").replace("/", "\\").rsplit("\\", 1)[-1]
        stem = base.casefold().split(".")[0]
        for prefix, kind in _NAME_KINDS:
            if stem == prefix or (prefix in ("ntuser", "usrclass", "amcache")
                                  and stem.startswith(prefix)):
                return kind
    return "unknown"


# ---------------------------------------------------------------------------
# small decoders used by the extractors
# ---------------------------------------------------------------------------

def systemtime(raw: bytes) -> dict | None:
    """A 16-byte SYSTEMTIME, decoded WITHOUT a zone (it records none)."""
    if raw is None or len(raw) < 16:
        return None
    y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", raw)
    out = {"raw_hex": bytes(raw[:16]).hex(), "zone": "local time of the "
           "recording machine; zone not recorded", "value": None}
    if 1601 <= y <= 30827 and 1 <= mo <= 12 and 1 <= d <= 31 and h < 24 \
            and mi < 60 and s < 60 and ms < 1000:
        out["value"] = (f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}"
                        f".{ms:03d}")
    return out


def dos_datetime(raw: int) -> dict | None:
    """A 4-byte DOS date-time as shell items store it (date in the low
    16 bits, time in the high 16). Decoded WITHOUT a zone."""
    if not raw:
        return None
    date, time = raw & 0xFFFF, raw >> 16
    day, month, year = date & 0x1F, (date >> 5) & 0x0F, 1980 + (date >> 9)
    sec, minute, hour = (time & 0x1F) * 2, (time >> 5) & 0x3F, time >> 11
    value = None
    if 1 <= day <= 31 and 1 <= month <= 12 and hour < 24 and minute < 60 \
            and sec < 60:
        value = (f"{year:04d}-{month:02d}-{day:02d}T{hour:02d}:{minute:02d}:"
                 f"{sec:02d}")
    return {"raw": raw, "value": value,
            "zone": "DOS date-time; zone not recorded in the item"}


def mru_list_ex(raw) -> list[int]:
    """MRUListEx: little-endian dwords, most recent first, ended by
    0xFFFFFFFF."""
    if not isinstance(raw, (bytes, bytearray)):
        return []
    out = []
    for i in range(0, len(raw) - 3, 4):
        n = _U32.unpack_from(raw, i)[0]
        if n == 0xFFFFFFFF:
            break
        out.append(n)
    return out


# -- shell items ------------------------------------------------------------

ROOT_FOLDERS = {
    "{20D04FE0-3AEA-1069-A2D8-08002B30309D}": "My Computer",
    "{59031A47-3F72-44A7-89C5-5595FE6B30EE}": "Users Files",
    "{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}": "Network",
    "{208D2C60-3AEA-1069-A2D7-08002B30309D}": "My Network Places",
    "{645FF040-5081-101B-9F08-00AA002F954E}": "Recycle Bin",
    "{031E4825-7B94-4DC3-B131-E946B44C8DD5}": "Libraries",
    "{450D8FBA-AD25-11D0-98A8-0800361B1103}": "My Documents",
    "{26EE0668-A00A-44D7-9371-BEB064C98683}": "Control Panel",
    "{21EC2020-3AEA-1069-A2DD-08002B30309D}": "Control Panel Items",
    "{4234D49B-0245-4DF3-B780-3893943456E1}": "Applications",
    "{679F85CB-0220-4080-B29B-5540CC05AAB6}": "Quick access",
    "{F874310E-B6B7-47DC-BC84-B9E6B38F5903}": "Home",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{D3162B92-9365-467A-956B-92703ACA08AF}": "Documents",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
    "{A8CDFF1C-4878-43BE-B5FD-F8091C1C60D0}": "Documents",
    "{088E3905-0323-4B02-9826-5D99428E115F}": "Downloads",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
    "{24AD3AD4-A569-4530-98E1-AB02F9417AA8}": "Pictures",
    "{3ADD1653-EB32-4CB0-BBD7-DFA0ABB5ACCA}": "Pictures",
    "{3DFDF296-DBEC-4FB4-81D1-6A3438BCF4DE}": "Music",
    "{1CF1260C-4DD0-4EBB-811F-33C572699FDE}": "Music",
    "{F86FA3AB-70D2-4FC7-9C99-FCBF05467F3A}": "Videos",
    "{A0953C92-50DC-43BF-BE83-3742FED03C9C}": "Videos",
    "{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}": "3D Objects",
    "{018D5C66-4533-4307-9B53-224DE2ED1FE6}": "OneDrive",
    "{9343812E-1C37-4A49-A12E-4B2D810D956B}": "Search Home",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "User profile folder",
    "{E31EA727-12ED-4702-820C-4B6445F28E1A}": "Dropbox",
    "{4A8FCD9F-623C-4283-96F0-10F41846A98A}": "Box Sync",
    "{BB06C0E4-D293-4F75-8A90-CB05B6477EEE}": "System (Control Panel)",
}

#: Control-panel category items (class 0x01, signature 0x39DE2184).
CONTROL_PANEL_CATEGORIES = {
    0: "All Control Panel Items", 1: "Appearance and Personalization",
    2: "Hardware and Sound", 3: "Network and Internet",
    4: "Sound, Speech and Audio Devices", 5: "System and Security",
    6: "Clock, Language, and Region", 7: "Ease of Access", 8: "Programs",
    9: "User Accounts", 10: "Security Center", 11: "Mobile PC"}

KNOWN_FOLDERS = {
    "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}": "System32",
    "{D65231B0-B2F1-4857-A4CE-A8E7C6EA7D27}": "SysWOW64",
    "{F38BF404-1D43-42F2-9305-67DE0B28FC23}": "Windows",
    "{6D809377-6AF0-444B-8957-A3773F02200E}": "Program Files",
    "{7C5A40EF-A0FB-4BFC-874A-C0F2E0B9FA8E}": "Program Files (x86)",
    "{905E63B6-C1BF-494E-B29C-65B732D3D21A}": "Program Files",
    "{F7F1ED05-9F6D-47A2-AAAE-29D317C6F066}": "Common Files",
    "{6365D5A7-0F0D-45E5-87F6-0DA56B6A4F7D}": "Common Files",
    "{DE974D24-D9C6-4D3E-BF91-F4455120B917}": "Common Files (x86)",
    "{0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8}": "Common Start Menu Programs",
    "{A77F5D77-2E2B-44C3-A6A2-ABA601054A51}": "Start Menu Programs",
    "{9E3995AB-1F9C-4F13-B827-48B24B6C7174}": "User Pinned",
    "{374DE290-123F-4565-9164-39C4925E467B}": "Downloads",
    "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}": "Documents",
    "{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}": "Desktop",
    "{F1B32785-6FBA-4FCF-9D55-7B8E7F157091}": "LocalAppData",
    "{3EB685DB-65F9-4CF6-A03A-E3EF65729F3D}": "RoamingAppData",
    "{62AB5D82-FDC1-4DC3-A9DD-070D1D495D97}": "ProgramData",
    "{5E6C858F-0E22-4760-9AFE-EA3317B67173}": "User profile",
}

_BEEF0004 = b"\x04\x00\xef\xbe"


def _beef0004(item: bytes, start: int) -> dict:
    """The 0xBEEF0004 file-entry extension block, if present after `start`."""
    i = item.find(_BEEF0004, start)
    if i < 4:
        return {}
    b = i - 4                                 # block starts with size, version
    size, version = struct.unpack_from("<HH", item, b)
    end = min(len(item), b + size)
    out: dict = {"extension_version": version}
    if b + 16 <= end:
        out["created"] = dos_datetime(_U32.unpack_from(item, b + 8)[0])
        out["accessed"] = dos_datetime(_U32.unpack_from(item, b + 12)[0])
    if version >= 7 and b + 28 <= end:
        ref = _U64.unpack_from(item, b + 20)[0]
        if ref:
            out["mft_record"] = ref & 0xFFFFFFFFFFFF
            out["mft_sequence"] = ref >> 48
    name_at = {3: 20, 7: 38, 8: 42}.get(version, 46 if version >= 9 else None)
    if name_at is not None and b + name_at < end:
        long_name = _utf16z(item[b + name_at:end])
        if long_name and all(ch >= " " for ch in long_name):
            out["long_name"] = long_name
    return out


#: [MS-PROPSTORE] property keys that name an item, in order of preference.
NAME_PROPERTIES = ("{B725F130-47EF-101A-A5F1-02608C9EEBAC}/10",   # ItemNameDisplay
                   "{28636AA6-953D-11D2-B5D6-00C04FD918D0}/30",   # ParsingPath
                   "{B725F130-47EF-101A-A5F1-02608C9EEBAC}/2",    # ItemFolderNameDisplay
                   "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}/AutolistCacheKey")
NAMED_FORMAT = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}"
_VT_FIXED = {0x02: "<h", 0x03: "<i", 0x0B: "<H", 0x10: "<b", 0x11: "<B",
             0x12: "<H", 0x13: "<I", 0x14: "<q", 0x15: "<Q", 0x16: "<i",
             0x17: "<I"}


def _typed_value(raw: bytes):
    """A TypedPropertyValue ([MS-OLEPS] 2.15) — the common scalar types;
    anything else is returned as hex."""
    if len(raw) < 4:
        return None
    vt = _U16.unpack_from(raw)[0]
    body = raw[4:]
    if vt in (0x1F, 0x08) and len(body) >= 4:          # LPWSTR, BSTR
        n = _U32.unpack_from(body)[0]
        width = 2 * n if vt == 0x1F else n
        return _utf16z(body[4:4 + width])
    if vt == 0x1E and len(body) >= 4:                    # LPSTR
        n = _U32.unpack_from(body)[0]
        return _asciiz(body[4:4 + n])
    if vt in _VT_FIXED and len(body) >= struct.calcsize(_VT_FIXED[vt]):
        return struct.unpack_from(_VT_FIXED[vt], body)[0]
    if vt == 0x40 and len(body) >= 8:                    # FILETIME
        return _filetime_pair(_U64.unpack_from(body)[0])
    if vt == 0x48 and len(body) >= 16:                   # CLSID
        return _guid(body[:16])
    if vt == 0:
        return None
    return {"vt": f"0x{vt:04X}", "hex": bytes(body[:64]).hex()}


def property_store(data: bytes) -> dict:
    """Every Serialized Property Storage ('1SPS', [MS-PROPSTORE] 2.2) found
    in `data`, flattened to {"{FMTID}/id-or-name": value}."""
    data = bytes(data)
    out: dict = {}
    pos = 0
    while True:
        i = data.find(b"1SPS", pos)
        if i < 0:
            break
        pos = i + 4
        if i < 4:
            continue
        start = i - 4
        size = _U32.unpack_from(data, start)[0]
        end = start + size
        if size < 24 or end > len(data):
            continue
        fmtid = _guid(data[i + 4:i + 20])
        p = i + 20
        while p + 9 <= end:
            vsize = _U32.unpack_from(data, p)[0]
            if vsize == 0 or p + vsize > end or vsize < 9:
                break
            if fmtid == NAMED_FORMAT:
                nsize = _U32.unpack_from(data, p + 4)[0]
                pid = _utf16z(data[p + 9:p + 9 + nsize])
                vstart = p + 9 + nsize
            else:
                pid = _U32.unpack_from(data, p + 4)[0]
                vstart = p + 9
            out[f"{fmtid}/{pid}"] = _typed_value(data[vstart:p + vsize])
            p += vsize
        pos = max(pos, end)
    return out


def shell_item(item: bytes) -> dict:
    """One shell item (its bytes, starting with the 2-byte size). Returns a
    dict with at least `class_type`, `kind` and `name` (None if unread)."""
    item = bytes(item)
    if len(item) < 3:
        return {"class_type": None, "kind": "truncated", "name": None}
    ctype = item[2]
    out: dict = {"class_type": f"0x{ctype:02X}", "size": len(item),
                 "name": None}
    sig = _U32.unpack_from(item, 6)[0] if len(item) >= 10 else None
    try:
        if ctype == 0x1F and sig == 0xF5A6B710 and len(item) >= 14:
            inner = item[10:10 + _U16.unpack_from(item, 10)[0]]
            sub = shell_item(inner)
            out.update(kind="root folder (embedded " + str(sub.get("kind"))
                       + ")", name=sub.get("name"), embedded=sub)
        elif sig in (0x23A3DFD5, 0x3B93AFBB, 0x23FEBBEE, 0x07192006,
                     0x10312005, 0x4C644C51) or (
                ctype in (0x00, 0x1F) and b"1SPS" in item[:64]):
            props = property_store(item)
            name = next((props[k] for k in NAME_PROPERTIES
                         if isinstance(props.get(k), str) and props[k]), None)
            out.update(kind="property view" + (f" (signature 0x{sig:08X})"
                                                if sig is not None else ""),
                       name=name, properties=props)
            if name is None:
                out["problem"] = ("property-view item: no display-name "
                                  "property found")
        elif ctype == 0x1F and len(item) >= 20:
            guid = _guid(item[4:20])
            out.update(kind="root folder", guid=guid,
                       name=ROOT_FOLDERS.get(guid, guid))
        elif ctype == 0x2E and len(item) >= 20:
            guid = _guid(item[4:20])
            out.update(kind="shell folder", guid=guid,
                       name=ROOT_FOLDERS.get(guid, guid))
        elif 0x20 <= ctype <= 0x2F:
            out["kind"] = "volume"
            if ctype & 0x01:
                out["name"] = _asciiz(item[3:3 + 20]) or None
        elif 0x30 <= ctype <= 0x3F and len(item) >= 14:
            out["kind"] = "directory" if ctype & 0x01 else (
                "file" if ctype & 0x02 else "file entry")
            out["file_size"] = _U32.unpack_from(item, 4)[0]
            out["modified"] = dos_datetime(_U32.unpack_from(item, 8)[0])
            out["attributes"] = _U16.unpack_from(item, 12)[0]
            if ctype & 0x04:
                short = _utf16z(item[14:])
                after = 14 + 2 * len(short) + 2
            else:
                short = _asciiz(item[14:])
                after = 14 + len(short) + 1
                after += after % 2
            out["short_name"] = short
            ext = _beef0004(item, after)
            out.update({k: v for k, v in ext.items()})
            out["name"] = ext.get("long_name") or short or None
        elif ctype & 0x70 == 0x40 and len(item) > 5:
            location = _asciiz(item[5:])
            out.update(kind="network location", name=location or None,
                       network_flags=item[4])
            if item[4] & 0x80:
                out["description"] = _asciiz(item[5 + len(location) + 1:])
        elif ctype == 0x01 and sig is not None and \
                _U32.unpack_from(item, 4)[0] == 0x39DE2184 and len(item) >= 12:
            cat = _U32.unpack_from(item, 8)[0]
            out.update(kind="control panel category", category=cat,
                       name=CONTROL_PANEL_CATEGORIES.get(cat,
                                                         f"category {cat}"))
        elif ctype == 0x71 and len(item) >= 30:
            guid = _guid(item[14:30])
            out.update(kind="control panel item", guid=guid,
                       name=ROOT_FOLDERS.get(guid, guid))
        elif ctype == 0x74 and item[6:10] == b"CFSF" and len(item) > 26:
            out["kind"] = "delegate folder"
            inner = item[10:]
            sub = shell_item(inner[:_U16.unpack_from(inner, 0)[0]]) \
                if len(inner) >= 2 else {}
            ext = _beef0004(item, 10)
            out["short_name"] = sub.get("short_name")
            out["modified"] = sub.get("modified")
            out.update({k: v for k, v in ext.items()})
            out["name"] = ext.get("long_name") or sub.get("short_name")
        elif ctype in (0x61, 0x60):
            out["kind"] = "URI"
            m = re.search(rb"(?:[\x20-\x7e]\x00){4,}", item[4:])
            if m:
                out["name"] = _utf16(m.group(0))
        else:
            out["kind"] = f"unparsed item type 0x{ctype:02X}"
            ext = _beef0004(item, 3)
            if ext.get("long_name"):
                out.update(ext)
                out["name"] = ext["long_name"]
    except (struct.error, ValueError, IndexError) as exc:
        out["problem"] = f"shell item could not be fully read: {exc}"
    return out


def shell_item_list(data: bytes, start: int = 0) -> tuple[list[dict], list]:
    """An ITEMIDLIST: shell items one after another, ended by a zero size."""
    items, problems = [], []
    pos = start
    data = bytes(data)
    while pos + 2 <= len(data):
        size = _U16.unpack_from(data, pos)[0]
        if size == 0:
            break
        if size < 3 or pos + size > len(data):
            problems.append(f"shell item at byte {pos} claims {size} bytes; "
                            "the list is cut there")
            break
        items.append(shell_item(data[pos:pos + size]))
        pos += size
    return items, problems


def join_shell_path(names: list[str | None]) -> str:
    out = ""
    for n in names:
        n = n if n is not None else "?"
        if not out:
            out = n
        elif out.endswith("\\"):
            out += n
        else:
            out += "\\" + n
    return out


# -- ShimCache ---------------------------------------------------------------

SHIMCACHE_NOTE = (
    "An entry records that Windows' application-compatibility layer examined "
    "this path. On Windows 10 and 11 that happens for files that were never "
    "run (an Explorer listing is enough), so presence in ShimCache is NOT "
    "proof of execution. The time is the file's own last-modified time as "
    "recorded when the entry was made — not a time of execution. Position 0 "
    "is the most recently added or updated entry.")
SHIMCACHE_FLAG_NOTE = (
    "insert_flags are recorded as read. Published research (Mandiant, 2012) "
    "reports bit 0x00000002 being set on Windows 7/8 when the entry was added "
    "by process creation; the flag is a measurement, not a verdict.")


def parse_shimcache(data: bytes) -> dict:
    """{"format", "entries": [...], "problems": [...]} from an
    AppCompatCache value's bytes."""
    data = bytes(data)
    out = {"format": "unknown", "entries": [], "problems": []}
    if len(data) < 8:
        out["problems"].append(f"AppCompatCache holds {len(data)} bytes; too "
                               "short to read")
        return out
    first = _U32.unpack_from(data, 0)[0]
    if first in (0x30, 0x34) and data[first:first + 4] == b"10ts":
        out["format"] = "Windows 10/11"
        _shim_ts(data, first, b"10ts", False, out)
    elif len(data) >= 0x84 and data[0x80:0x84] in (b"00ts", b"10ts"):
        magic = data[0x80:0x84]
        out["format"] = "Windows 8.1" if magic == b"10ts" else "Windows 8.0"
        _shim_ts(data, 0x80, magic, True, out)
    elif first == 0xBADC0FEE:
        out["format"] = "Windows 7 / Server 2008 R2"
        _shim_win7(data, out)
    elif first == 0xBADC0FFE:
        out["format"] = "Windows Vista / Server 2008"
        out["problems"].append("Vista/Server 2008 ShimCache is identified but "
                               "not decoded by this version")
    elif first == 0xDEADBEEF:
        out["format"] = "Windows XP"
        out["problems"].append("Windows XP ShimCache is identified but not "
                               "decoded by this version")
    else:
        out["problems"].append(f"unrecognised AppCompatCache header "
                               f"0x{first:08X}")
    return out


def _shim_ts(data, pos, magic, win8, out):
    n = 0
    while pos + 12 <= len(data):
        if data[pos:pos + 4] != magic:
            out["problems"].append(f"entry {n}: expected signature {magic!r} "
                                   f"at byte {pos}; parsing stopped")
            break
        entry_size = _U32.unpack_from(data, pos + 8)[0]
        end = pos + 12 + entry_size
        if end > len(data):
            out["problems"].append(f"entry {n} runs past the end of the value; "
                                   "parsing stopped")
            break
        body = data[pos + 12:end]
        try:
            p = 0
            plen = _U16.unpack_from(body, p)[0]
            p += 2
            path = _utf16(body[p:p + plen])
            p += plen
            entry = {"position": n, "path": path}
            if "\t" in path:
                entry["entry_kind"] = ("packaged (Store) app: the path field "
                                       "holds a tab-separated package "
                                       "identity, not a file path")
            if win8:
                if magic == b"10ts":
                    pk = _U16.unpack_from(body, p)[0]
                    entry["package"] = _utf16(body[p + 2:p + 2 + pk]) or None
                    p += 2 + pk
                entry["insert_flags"] = _U32.unpack_from(body, p)[0]
                entry["shim_flags"] = _U32.unpack_from(body, p + 4)[0]
                p += 8
            entry["last_modified_raw"] = _U64.unpack_from(body, p)[0]
            p += 8
            dsize = _U32.unpack_from(body, p)[0]
            p += 4
            blob = body[p:p + dsize]
            entry["data_size"] = dsize
            entry["data_head_hex"] = blob[:32].hex()
            out["entries"].append(entry)
        except struct.error:
            out["problems"].append(f"entry {n} is shorter than its fields")
        pos = end
        n += 1


def _shim_win7(data, out):
    count = _U32.unpack_from(data, 4)[0]
    if 0x80 + 32 * count > len(data):
        out["problems"].append(f"header records {count} entries; the value is "
                               "too short for them")
        count = (len(data) - 0x80) // 32
    wide = True
    if count:
        plen, maxlen, pad = struct.unpack_from("<HHI", data, 0x80)
        poff = _U64.unpack_from(data, 0x88)[0] if 0x80 + 48 <= len(data) else 0
        wide = (pad == 0 and maxlen >= plen and
                0x80 + 48 * count <= poff < len(data))
    out["format"] += " (64-bit)" if wide else " (32-bit)"
    step = 48 if wide else 32
    for n in range(count):
        base = 0x80 + step * n
        try:
            if wide:
                plen, _mx, _pad, poff, mod, ins, shim, dsize, _doff = \
                    struct.unpack_from("<HHIQQIIQQ", data, base)
            else:
                plen, _mx, poff, mod, ins, shim, dsize, _doff = \
                    struct.unpack_from("<HHIQIIII", data, base)
        except struct.error:
            out["problems"].append(f"entry {n} lies past the end of the value")
            break
        if poff + plen > len(data):
            out["problems"].append(f"entry {n}: its path lies outside the value")
            continue
        out["entries"].append({
            "position": n, "path": _utf16(data[poff:poff + plen]),
            "last_modified_raw": mod, "insert_flags": ins, "shim_flags": shim,
            "data_size": dsize})


# ---------------------------------------------------------------------------
# artefact rows
# ---------------------------------------------------------------------------

def _jsonable(obj):
    if isinstance(obj, (bytes, bytearray, memoryview)):
        return bytes(obj).hex()
    if isinstance(obj, dict):
        return {str(k): _jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_jsonable(v) for v in obj]
    return obj


class _Rows:
    def __init__(self, hive: Hive, source_path: str) -> None:
        self.hive = hive
        self.source_path = source_path
        self.rows: list[dict] = []
        self._refs: dict = {}

    def step(self, label: str, fn, *args) -> None:
        """Run one extractor; a failure costs that extractor's remaining rows,
        never the others', and is reported."""
        try:
            fn(*args)
        except (struct.error, ValueError, IndexError, KeyError, TypeError,
                AttributeError, UnicodeError) as exc:
            self.hive._problem(f"{label}: extraction stopped early "
                               f"({type(exc).__name__}: {exc}); rows found "
                               "before that point are kept")
            log.debug("registry extractor %r failed", label, exc_info=True)

    def add(self, artefact: str, ref: str, *, key: Key | None, title: str,
            value: str, at_raw=None, at_epoch=None, time_basis="none",
            **detail) -> None:
        if not at_raw or at_epoch is None:
            at_raw, at_epoch = None, None
        at_utc = timeutil.decode(at_raw, at_epoch) if at_epoch else None
        d = {}
        if key is not None:
            d["key_path"] = key.path
            d["key_last_written_raw"] = key.last_written_raw
            d["key_last_written_utc"] = key.last_written
        d["time_basis"] = time_basis
        d.update(detail)
        suffix = f"{artefact}:{ref}"
        n = self._refs.get(suffix, 0) + 1
        self._refs[suffix] = n
        if n > 1:
            suffix = f"{suffix}#{n}"
        self.rows.append({"artefact": artefact, "at_utc": at_utc,
                          "at_raw": at_raw, "at_epoch": at_epoch,
                          "title": title, "value": _oneline(value),
                          "detail": _jsonable(d), "row_ref_suffix": suffix})


def _oneline(text) -> str:
    text = "" if text is None else str(text)
    text = " ".join(text.split())
    return text if len(text) <= 400 else text[:397] + "..."


def _val(key: Key | None, name: str):
    if key is None:
        return None
    v = key.value(name)
    return None if v is None else v.data


def _sval(key: Key | None, name: str) -> str | None:
    data = _val(key, name)
    if isinstance(data, list):
        return "; ".join(data)
    return data if isinstance(data, str) else None


def _ival(key: Key | None, name: str) -> int | None:
    data = _val(key, name)
    return data if isinstance(data, int) else None


def _signed32(n: int | None) -> int | None:
    if n is None:
        return None
    return n - (1 << 32) if n & 0x80000000 else n


def _values_dict(key: Key, limit: int = 64) -> dict:
    out = {}
    for v in key.values()[:limit]:
        data = v.data
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data[:256]).hex()
        out[v.name or "(default)"] = data
    return out


# -- SYSTEM ------------------------------------------------------------------

START_TYPES = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual",
               4: "Disabled"}
SERVICE_TYPES = {0x1: "kernel driver", 0x2: "file system driver",
                 0x4: "adapter", 0x8: "recognizer driver",
                 0x10: "own process", 0x20: "shared process",
                 0x50: "user service (own process)",
                 0x60: "user service (shared process)",
                 0x110: "own process, interactive",
                 0x120: "shared process, interactive"}
DEVICE_PROPERTIES = "{83da6326-97a6-4088-9453-a1923f573b29}"
DEVICE_TIMES = (("0064", "first install"), ("0065", "install"),
                ("0066", "last arrival"), ("0067", "last removal"))


def _device_times(instance: Key) -> dict:
    """The DEVPKEY FILETIMEs under Properties\\{83da6326-…}\\0064..0067."""
    props = instance.subkey("Properties")
    group = props.subkey(DEVICE_PROPERTIES) if props else None
    out = {}
    if group is None:
        return out
    for pid, label in DEVICE_TIMES:
        k = group.subkey(pid)
        if k is None:
            continue
        v = k.value("")
        if v is None:                         # Windows 7: ...\0065\00000000\Data
            sub = k.subkey("00000000")
            v = sub.value("Data") if sub else None
        if v is None or not isinstance(v.raw, bytes) or len(v.raw) < 8:
            continue
        raw = _U64.unpack_from(v.raw)[0]
        out[label] = {"raw": raw, "utc": timeutil.decode(raw, "filetime"),
                      "property": pid, "key_path": k.path}
    return out


def _system_rows(hive: Hive, rows: _Rows) -> None:
    select = hive.root.subkey("Select")
    ccs, how = hive.control_set()
    if select is not None:
        rows.add("control-set", "select", key=select,
                 title="Control set selection",
                 value=f"Current control set: {ccs or 'unknown'} ({how})",
                 time_basis="key", at_raw=select.last_written_raw,
                 at_epoch="filetime", current=_ival(select, "Current"),
                 default=_ival(select, "Default"),
                 failed=_ival(select, "Failed"),
                 last_known_good=_ival(select, "LastKnownGood"),
                 resolved=ccs, basis=how)
    if ccs is None:
        return
    cs = hive.root.subkey(ccs)

    k = hive.find(f"{ccs}\\Control\\ComputerName\\ComputerName")
    name = _sval(k, "ComputerName")
    if name is not None:
        tcp = hive.find(f"{ccs}\\Services\\Tcpip\\Parameters")
        rows.add("computer-name", "computer-name", key=k,
                 title="Computer name", value=name, time_basis="none",
                 computer_name=name, control_set=ccs,
                 tcpip_hostname=_sval(tcp, "Hostname"),
                 tcpip_domain=_sval(tcp, "Domain"))

    k = hive.find(f"{ccs}\\Control\\TimeZoneInformation")
    if k is not None:
        tz = _sval(k, "TimeZoneKeyName") or _sval(k, "StandardName") or "?"
        bias = _signed32(_ival(k, "Bias"))
        active = _signed32(_ival(k, "ActiveTimeBias"))
        rows.add("timezone", "timezone", key=k, title="Time zone setting",
                 value=f"{tz} (Bias {bias} min, ActiveTimeBias {active} min)",
                 time_basis="none", time_zone_key_name=_sval(k, "TimeZoneKeyName"),
                 standard_name=_sval(k, "StandardName"),
                 daylight_name=_sval(k, "DaylightName"),
                 bias_minutes=bias, active_time_bias_minutes=active,
                 standard_bias_minutes=_signed32(_ival(k, "StandardBias")),
                 daylight_bias_minutes=_signed32(_ival(k, "DaylightBias")),
                 dynamic_daylight_time_disabled=_ival(
                     k, "DynamicDaylightTimeDisabled"),
                 note="Bias is minutes added to local time to get UTC "
                      "(UTC = local + Bias).")

    rows.step("USB devices", _usb_rows, hive, ccs, rows)
    rows.step("MountedDevices", _mounted_device_rows, hive, rows)
    for csk in hive.root.subkeys():
        if csk.name.lower().startswith("controlset"):
            rows.step(f"ShimCache in {csk.name}", _shimcache_rows, hive, csk,
                      csk.name == ccs, rows)
    rows.step("services", _service_rows, hive, cs, rows)
    rows.step("network interfaces", _interface_rows, hive, ccs, rows)


def _usb_rows(hive: Hive, ccs: str, rows: _Rows) -> None:
    usbstor = hive.find(f"{ccs}\\Enum\\USBSTOR")
    for dev in usbstor.subkeys() if usbstor else []:
        parts = dict(p.split("_", 1) for p in dev.name.split("&")
                     if "_" in p)
        dtype = dev.name.split("&", 1)[0]
        for inst in dev.subkeys():
            serial = inst.name
            generated = len(serial) > 1 and serial[1] == "&"
            times = _device_times(inst)
            friendly = _sval(inst, "FriendlyName")
            ref = f"{dev.name}\\{serial}"
            rows.add("usbstor-device", ref, key=inst,
                     title="USB storage device (USBSTOR)",
                     value=f"{friendly or dev.name} — serial {serial}",
                     at_raw=inst.last_written_raw, at_epoch="filetime",
                     time_basis="key", device_class=dev.name,
                     device_type=dtype, vendor=parts.get("Ven"),
                     product=parts.get("Prod"), revision=parts.get("Rev"),
                     serial=serial, serial_is_windows_generated=generated,
                     serial_note=("the second character is '&': Windows made "
                                  "this instance ID because the device reported "
                                  "no unique serial number") if generated
                     else None,
                     friendly_name=friendly,
                     container_id=_sval(inst, "ContainerID"),
                     hardware_id=_val(inst, "HardwareID"),
                     times=times, control_set=ccs)
            for label, t in times.items():
                rows.add("usbstor-time", f"{ref}:{t['property']}", key=inst,
                         title=f"USB storage device {label} time "
                               f"(property {t['property']})",
                         value=f"{friendly or dev.name} — serial {serial}",
                         at_raw=t["raw"], at_epoch="filetime",
                         time_basis="entry", event=label, serial=serial,
                         device_class=dev.name,
                         property_key_path=t["key_path"])
    usb = hive.find(f"{ccs}\\Enum\\USB")
    for dev in usb.subkeys() if usb else []:
        m = re.match(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", dev.name)
        for inst in dev.subkeys():
            times = _device_times(inst)
            desc = _sval(inst, "FriendlyName") or _sval(inst, "DeviceDesc")
            if desc and desc.startswith("@") and ";" in desc:
                desc = desc.rsplit(";", 1)[-1]
            ref = f"{dev.name}\\{inst.name}"
            rows.add("usb-device", ref, key=inst, title="USB device (Enum\\USB)",
                     value=f"{dev.name} — {inst.name}"
                           + (f" — {desc}" if desc else ""),
                     at_raw=inst.last_written_raw, at_epoch="filetime",
                     time_basis="key", device_id=dev.name,
                     vid=m.group(1).upper() if m else None,
                     pid=m.group(2).upper() if m else None,
                     instance=inst.name, description=desc,
                     service=_sval(inst, "Service"),
                     location=_sval(inst, "LocationInformation"),
                     parent_id_prefix=_sval(inst, "ParentIdPrefix"),
                     container_id=_sval(inst, "ContainerID"),
                     times=times, control_set=ccs)
            for label, t in times.items():
                rows.add("usb-time", f"{ref}:{t['property']}", key=inst,
                         title=f"USB device {label} time "
                               f"(property {t['property']})",
                         value=f"{dev.name} — {inst.name}",
                         at_raw=t["raw"], at_epoch="filetime",
                         time_basis="entry", event=label,
                         property_key_path=t["key_path"])


def decode_mounted_device(raw: bytes) -> dict:
    raw = bytes(raw)
    if len(raw) == 12:
        sig, off = struct.unpack("<IQ", raw)
        return {"form": "MBR partition", "disk_signature": f"{sig:08X}",
                "partition_offset": off,
                "text": f"MBR disk {sig:08X}, partition at byte {off}"}
    if len(raw) == 24 and raw[:8] == b"DMIO:ID:":
        g = _guid(raw[8:24])
        return {"form": "GPT partition", "partition_guid": g,
                "text": f"GPT partition {g}"}
    if len(raw) >= 8 and len(raw) % 2 == 0 and raw[1] == 0:
        text = _utf16(raw).rstrip("\x00")
        out = {"form": "device path", "text": text}
        parts = text.split("#")
        if len(parts) >= 3:
            out["device_class"] = parts[1]
            out["instance"] = parts[2]
        return out
    return {"form": "unrecognised", "text": raw.hex()}


def _mounted_device_rows(hive: Hive, rows: _Rows) -> None:
    k = hive.root.subkey("MountedDevices")
    for v in k.values() if k else []:
        info = decode_mounted_device(v.raw)
        rows.add("mounted-device", v.name, key=k, title="Mounted device",
                 value=f"{v.name} → {info['text']}", time_basis="none",
                 name=v.name, **info)


def _shimcache_rows(hive: Hive, cs: Key, current: bool, rows: _Rows) -> None:
    k = cs.subkey("Control")
    k = k.subkey("Session Manager") if k else None
    k = k.subkey("AppCompatCache") if k else None
    v = k.value("AppCompatCache") if k else None
    if v is None or not isinstance(v.raw, bytes):
        return
    parsed = parse_shimcache(v.raw)
    for p in parsed["problems"]:
        hive._problem(f"ShimCache in {cs.name}: {p}")
    for e in parsed["entries"]:
        detail = dict(e)
        detail.pop("last_modified_raw", None)
        rows.add("shimcache", f"{cs.name}:{e['position']}", key=k,
                 title="ShimCache entry (file last-modified time as recorded)",
                 value=e["path"], at_raw=e["last_modified_raw"],
                 at_epoch="filetime", time_basis="entry",
                 format=parsed["format"], control_set=cs.name,
                 current_control_set=current,
                 last_modified_raw=e["last_modified_raw"],
                 last_modified_utc=timeutil.decode(e["last_modified_raw"],
                                                   "filetime"),
                 note=SHIMCACHE_NOTE,
                 flag_note=SHIMCACHE_FLAG_NOTE if "insert_flags" in e
                 else None, **detail)


def _service_rows(hive: Hive, cs: Key | None, rows: _Rows) -> None:
    services = cs.subkey("Services") if cs else None
    for svc in services.subkeys() if services else []:
        image = _sval(svc, "ImagePath")
        start = _ival(svc, "Start")
        stype = _ival(svc, "Type")
        if image is None and start is None and stype is None:
            continue
        params = svc.subkey("Parameters")
        rows.add("service", svc.name, key=svc, title="Service",
                 value=f"{svc.name}: {image or '(no ImagePath)'} — start "
                       f"{START_TYPES.get(start, start)}",
                 at_raw=svc.last_written_raw, at_epoch="filetime",
                 time_basis="key", name=svc.name,
                 display_name=_sval(svc, "DisplayName"), image_path=image,
                 start=start, start_name=START_TYPES.get(start),
                 type=stype, type_name=SERVICE_TYPES.get(stype),
                 delayed_autostart=_ival(svc, "DelayedAutostart"),
                 object_name=_sval(svc, "ObjectName"),
                 service_dll=_sval(params, "ServiceDll"),
                 description=_sval(svc, "Description"))


def _interface_rows(hive: Hive, ccs: str, rows: _Rows) -> None:
    root = hive.find(f"{ccs}\\Services\\Tcpip\\Parameters\\Interfaces")
    stack = [(k, 0) for k in (root.subkeys() if root else [])]
    while stack:
        k, depth = stack.pop(0)
        if depth < 2:
            stack += [(c, depth + 1) for c in k.subkeys()]
        if not k.values():
            continue
        dhcp_ip = _sval(k, "DhcpIPAddress")
        static = _val(k, "IPAddress")
        lease = _ival(k, "LeaseObtainedTime")
        ips = [dhcp_ip] if dhcp_ip and dhcp_ip != "0.0.0.0" else []
        if isinstance(static, list):
            ips += [ip for ip in static if ip and ip != "0.0.0.0"]
        if lease:
            at, epoch, basis = lease, "unix_s", "entry"
        else:
            at, epoch, basis = k.last_written_raw, "filetime", "key"
        rel = k.path[len(root.path) + 1:]
        rows.add("network-interface", rel, key=k,
                 title="Network interface (TCP/IP)"
                       + (" — DHCP lease obtained" if lease else ""),
                 value=f"{rel}: {', '.join(ips) or 'no address recorded'}",
                 at_raw=at, at_epoch=epoch, time_basis=basis,
                 interface=rel, enable_dhcp=_ival(k, "EnableDHCP"),
                 dhcp_ip_address=dhcp_ip,
                 dhcp_subnet_mask=_sval(k, "DhcpSubnetMask"),
                 dhcp_server=_sval(k, "DhcpServer"),
                 dhcp_domain=_sval(k, "DhcpDomain"),
                 dhcp_default_gateway=_val(k, "DhcpDefaultGateway"),
                 dhcp_name_server=_sval(k, "DhcpNameServer"),
                 ip_address=static, default_gateway=_val(k, "DefaultGateway"),
                 name_server=_sval(k, "NameServer"), domain=_sval(k, "Domain"),
                 lease_obtained=_time_dict(lease, "unix_s"),
                 lease_terminates=_time_dict(_ival(k, "LeaseTerminatesTime"),
                                             "unix_s"))


def _time_dict(raw, epoch):
    if not raw:
        return None
    return {"raw": raw, "epoch": epoch, "utc": timeutil.decode(raw, epoch)}


# -- SOFTWARE ----------------------------------------------------------------

NETWORK_CATEGORY = {0: "Public", 1: "Private", 2: "Domain"}
NETWORK_NAME_TYPE = {0x06: "wired", 0x17: "broadband (3G/4G)",
                     0x47: "wireless", 0xF3: "mobile broadband"}


def _os_rows(hive: Hive, rows: _Rows) -> None:
    cv = hive.find("Microsoft\\Windows NT\\CurrentVersion")
    if cv is not None and cv.values():
        product = _sval(cv, "ProductName")
        build = _sval(cv, "CurrentBuild") or _sval(cv, "CurrentBuildNumber")
        itime = _val(cv, "InstallTime")
        idate = _ival(cv, "InstallDate")
        if isinstance(itime, int) and itime:
            at, epoch = itime, "filetime"
        else:
            at, epoch = idate, "unix_s"
        rows.add("os-version", "os", key=cv,
                 title="Operating system (InstallTime/InstallDate)",
                 value=f"{product or '?'} build {build or '?'}"
                       + (f" ({_sval(cv, 'DisplayVersion')})"
                          if _sval(cv, "DisplayVersion") else ""),
                 at_raw=at, at_epoch=epoch, time_basis="entry",
                 product_name=product, edition_id=_sval(cv, "EditionID"),
                 display_version=_sval(cv, "DisplayVersion"),
                 release_id=_sval(cv, "ReleaseId"), current_build=build,
                 ubr=_ival(cv, "UBR"),
                 current_version=_sval(cv, "CurrentVersion"),
                 major_version=_ival(cv, "CurrentMajorVersionNumber"),
                 build_lab=_sval(cv, "BuildLabEx") or _sval(cv, "BuildLab"),
                 registered_owner=_sval(cv, "RegisteredOwner"),
                 registered_organization=_sval(cv, "RegisteredOrganization"),
                 system_root=_sval(cv, "SystemRoot"),
                 install_date=_time_dict(idate, "unix_s"),
                 install_time=_time_dict(itime if isinstance(itime, int)
                                         else None, "filetime"),
                 note=("Feature updates on Windows 10/11 rewrite "
                       "InstallDate/InstallTime: the value records the most "
                       "recent installation of the OS image, which need not be "
                       "the first. Windows 11 (build 22000 and later) still "
                       "writes 'Windows 10' in ProductName."))


def _uninstall_rows(hive: Hive, rows: _Rows) -> None:
    for path in ("Microsoft\\Windows\\CurrentVersion\\Uninstall",
                 "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"):
        un = hive.find(path)
        for app in un.subkeys() if un else []:
            name = _sval(app, "DisplayName")
            rows.add("installed-program", app.path, key=app,
                     title="Installed program (Uninstall entry)",
                     value=name or app.name, at_raw=app.last_written_raw,
                     at_epoch="filetime", time_basis="key",
                     display_name=name, entry=app.name,
                     display_version=_sval(app, "DisplayVersion"),
                     publisher=_sval(app, "Publisher"),
                     install_date_text=_sval(app, "InstallDate"),
                     install_location=_sval(app, "InstallLocation"),
                     install_source=_sval(app, "InstallSource"),
                     uninstall_string=_sval(app, "UninstallString"),
                     wow6432=path.startswith("WOW6432Node"))


def _software_run_rows(hive: Hive, rows: _Rows) -> None:
    _run_rows(hive, rows, (
        "Microsoft\\Windows\\CurrentVersion\\Run",
        "Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
        "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"))


def _networklist_rows(hive: Hive, rows: _Rows) -> None:
    nl = hive.find("Microsoft\\Windows NT\\CurrentVersion\\NetworkList")
    sigs: dict = {}
    for kind in ("Managed", "Unmanaged"):
        sk = nl.subkey("Signatures") if nl else None
        sk = sk.subkey(kind) if sk else None
        for s in sk.subkeys() if sk else []:
            guid = (_sval(s, "ProfileGuid") or "").upper()
            mac = _val(s, "DefaultGatewayMac")
            sigs.setdefault(guid, []).append({
                "signature_key": s.path, "managed": kind == "Managed",
                "description": _sval(s, "Description"),
                "dns_suffix": _sval(s, "DnsSuffix"),
                "first_network": _sval(s, "FirstNetwork"),
                "default_gateway_mac": "-".join(f"{b:02X}" for b in mac)
                if isinstance(mac, bytes) else None})
    profiles = nl.subkey("Profiles") if nl else None
    for p in profiles.subkeys() if profiles else []:
        name = _sval(p, "ProfileName")
        created = systemtime(_val(p, "DateCreated")
                             if isinstance(_val(p, "DateCreated"), bytes)
                             else None)
        last = systemtime(_val(p, "DateLastConnected")
                          if isinstance(_val(p, "DateLastConnected"), bytes)
                          else None)
        ntype = _ival(p, "NameType")
        rows.add("network-profile", p.name, key=p,
                 title="Network profile (NetworkList)",
                 value=f"{name or p.name}"
                       + (f" — last connected {last['value']} LOCAL TIME"
                          if last and last["value"] else ""),
                 at_raw=p.last_written_raw, at_epoch="filetime",
                 time_basis="key", profile_guid=p.name, profile_name=name,
                 description=_sval(p, "Description"),
                 category=NETWORK_CATEGORY.get(_ival(p, "Category")),
                 name_type=ntype, name_type_name=NETWORK_NAME_TYPE.get(ntype),
                 managed=_ival(p, "Managed"),
                 date_created_local=created,
                 date_last_connected_local=last,
                 signatures=sigs.get(p.name.upper(), []),
                 time_note=("DateCreated and DateLastConnected are SYSTEMTIME "
                            "values in the machine's LOCAL time with no zone "
                            "recorded; they are not UTC. at_utc carries the "
                            "profile key's last-written time."))


def _profilelist_rows(hive: Hive, rows: _Rows) -> None:
    pl = hive.find("Microsoft\\Windows NT\\CurrentVersion\\ProfileList")
    for p in pl.subkeys() if pl else []:
        path = _sval(p, "ProfileImagePath")
        load = _split_filetime(p, "LocalProfileLoadTime")
        unload = _split_filetime(p, "LocalProfileUnloadTime")
        rows.add("user-profile", p.name, key=p, title="User profile (ProfileList)",
                 value=f"{p.name} → {path or '?'}",
                 at_raw=p.last_written_raw, at_epoch="filetime",
                 time_basis="key", sid=p.name, profile_image_path=path,
                 flags=_ival(p, "Flags"), state=_ival(p, "State"),
                 local_profile_load_time=_filetime_pair(load) if load else None,
                 local_profile_unload_time=_filetime_pair(unload)
                 if unload else None)
        for label, raw in (("load", load), ("unload", unload)):
            if raw:
                rows.add("user-profile-time", f"{p.name}:{label}", key=p,
                         title=f"User profile local {label} time",
                         value=f"{p.name} → {path or '?'}", at_raw=raw,
                         at_epoch="filetime", time_basis="entry", sid=p.name,
                         event=label)


def _software_rows(hive: Hive, rows: _Rows) -> None:
    for label, fn in (("OS version", _os_rows),
                      ("installed programs", _uninstall_rows),
                      ("Run keys", _software_run_rows),
                      ("NetworkList", _networklist_rows),
                      ("ProfileList", _profilelist_rows)):
        rows.step(label, fn, hive, rows)


def _split_filetime(key: Key, stem: str) -> int | None:
    hi, lo = _ival(key, stem + "High"), _ival(key, stem + "Low")
    if hi is None or lo is None:
        return None
    return (hi << 32) | lo or None


def _run_rows(hive: Hive, rows: _Rows, paths) -> None:
    for path in paths:
        k = hive.find(path)
        for v in k.values() if k else []:
            data = v.data
            if isinstance(data, list):
                data = "; ".join(data)
            if isinstance(data, (bytes, bytearray)):
                data = bytes(data).hex()
            rows.add("autorun", f"{path}:{v.name}", key=k,
                     title=f"Autorun ({path.rsplit(chr(92), 1)[-1]})",
                     value=f"{v.name or '(default)'}: {data}",
                     time_basis="none", name=v.name, command=data,
                     location=path)


# -- NTUSER ------------------------------------------------------------------

EXPLORER = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
USERASSIST_GUIDS = {
    "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}": "executables",
    "{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}": "shortcuts",
    "{75048700-EF1F-11D0-9888-006097DEACF9}": "executables (XP)",
    "{5E6AB780-7743-11CF-A12B-00AA004AE837}": "Internet Explorer toolbar (XP)",
}


def decode_userassist(raw: bytes) -> dict | None:
    """The Windows 7+ 72-byte record, or the XP 16-byte one."""
    raw = bytes(raw)
    if len(raw) == 72:
        _sess, runs, focus, focus_ms = struct.unpack_from("<IIII", raw, 0)
        last = _U64.unpack_from(raw, 60)[0]
        return {"format": "Windows 7+ (72 bytes)", "run_count": runs,
                "focus_count": focus, "focus_time_ms": focus_ms,
                "last_run_raw": last}
    if len(raw) == 16:
        _sess, runs = struct.unpack_from("<II", raw, 0)
        last = _U64.unpack_from(raw, 8)[0]
        return {"format": "Windows XP (16 bytes)", "run_count": runs,
                "run_count_note": "XP counters start at 5; the raw count is "
                                  "shown", "last_run_raw": last}
    return None


def _ntuser_run_rows(hive: Hive, rows: _Rows) -> None:
    _run_rows(hive, rows, (
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"))


def _userassist_rows(hive: Hive, rows: _Rows) -> None:
    ua = hive.find(EXPLORER + "\\UserAssist")
    for g in ua.subkeys() if ua else []:
        count = g.subkey("Count")
        for v in count.values() if count else []:
            name = codecs.decode(v.name, "rot_13")
            rec = decode_userassist(v.raw) if isinstance(v.raw, bytes) else None
            folder = None
            m = re.match(r"(\{[0-9A-Fa-f-]{36}\})", name)
            if m:
                folder = KNOWN_FOLDERS.get(m.group(1).upper())
            last = rec.get("last_run_raw") if rec else None
            rows.add("userassist", f"{g.name}:{v.name}", key=count,
                     title="UserAssist entry (last run time as recorded)",
                     value=(f"{name} — {rec['run_count']} runs" if rec
                            else name),
                     at_raw=last, at_epoch="filetime", time_basis="entry",
                     name=name, name_rot13=v.name, guid=g.name,
                     guid_meaning=USERASSIST_GUIDS.get(g.name.upper()),
                     known_folder=folder,
                     record=({k: val for k, val in rec.items()
                              if k != "last_run_raw"} if rec else None),
                     last_run_raw=last,
                     last_run_utc=timeutil.decode(last, "filetime")
                     if last else None,
                     data_size=len(v.raw) if isinstance(v.raw, bytes) else None,
                     note=None if rec else "record is not 16 or 72 bytes; "
                                           "not decoded")


def _recentdocs_rows(hive: Hive, rows: _Rows) -> None:
    rd = hive.find(EXPLORER + "\\RecentDocs")
    if rd is not None:
        for k in [rd] + rd.subkeys():
            _mru_ex_rows(rows, k, "recentdocs", "RecentDocs entry",
                         _recentdoc_name)


def _typed_rows(hive: Hive, rows: _Rows) -> None:
    tp = hive.find(EXPLORER + "\\TypedPaths")
    _url_n_rows(rows, tp, "typed-path", "Typed path (Explorer address bar)")
    tu = hive.find("Software\\Microsoft\\Internet Explorer\\TypedURLs")
    tt = hive.find("Software\\Microsoft\\Internet Explorer\\TypedURLsTime")
    _url_n_rows(rows, tu, "typed-url", "Typed URL (Internet Explorer / Edge "
                "legacy)", times=tt)


def _runmru_rows(hive: Hive, rows: _Rows) -> None:
    rm = hive.find(EXPLORER + "\\RunMRU")
    if rm is not None:
        order = _sval(rm, "MRUList") or ""
        for v in rm.values():
            if v.name.casefold() == "mrulist" or not isinstance(v.data, str):
                continue
            pos = order.find(v.name) if len(v.name) == 1 else -1
            command = v.data[:-2] if v.data.endswith("\\1") else v.data
            first = pos == 0
            rows.add("runmru", v.name, key=rm, title="Run dialog entry (RunMRU)",
                     value=command,
                     at_raw=rm.last_written_raw if first else None,
                     at_epoch="filetime" if first else None,
                     time_basis="key-mru-0" if first else "none",
                     command=command, letter=v.name,
                     mru_position=pos if pos >= 0 else None)


def _wordwheel_rows(hive: Hive, rows: _Rows) -> None:
    ww = hive.find(EXPLORER + "\\WordWheelQuery")
    if ww is not None:
        for k in [ww] + ww.subkeys():
            _mru_ex_rows(rows, k, "wordwheelquery",
                         "Explorer search term (WordWheelQuery)",
                         lambda raw: (_utf16z(raw), {}))


def _comdlg32_rows(hive: Hive, rows: _Rows) -> None:
    dlg = hive.find(EXPLORER + "\\ComDlg32")
    if dlg is not None:
        osp = dlg.subkey("OpenSavePidlMRU")
        for k in ([osp] + osp.subkeys()) if osp else []:
            _mru_ex_rows(rows, k, "opensave-mru",
                         "Open/Save dialog entry (OpenSavePidlMRU)",
                         _pidl_name)
        lv = dlg.subkey("LastVisitedPidlMRU")
        if lv is not None:
            _mru_ex_rows(rows, lv, "lastvisited-mru",
                         "Program and folder last used in an Open/Save dialog "
                         "(LastVisitedPidlMRU)", _lastvisited_name)
        for legacy, art in (("OpenSaveMRU", "opensave-mru"),
                            ("LastVisitedMRU", "lastvisited-mru")):
            lk = dlg.subkey(legacy)
            for k in ([lk] + lk.subkeys()) if lk else []:
                _mru_list_rows(rows, k, art, f"Open/Save dialog ({legacy})")


def _ntuser_shellbag_rows(hive: Hive, rows: _Rows) -> None:
    for path in ("Software\\Microsoft\\Windows\\Shell\\BagMRU",
                 "Software\\Microsoft\\Windows\\ShellNoRoam\\BagMRU"):
        bag = hive.find(path)
        if bag is not None:
            _shellbag_rows(hive, bag, rows)


def _ntuser_rows(hive: Hive, rows: _Rows) -> None:
    for label, fn in (("Run keys", _ntuser_run_rows),
                      ("UserAssist", _userassist_rows),
                      ("RecentDocs", _recentdocs_rows),
                      ("TypedPaths/TypedURLs", _typed_rows),
                      ("RunMRU", _runmru_rows),
                      ("WordWheelQuery", _wordwheel_rows),
                      ("ComDlg32", _comdlg32_rows),
                      ("ShellBags", _ntuser_shellbag_rows)):
        rows.step(label, fn, hive, rows)


def _recentdoc_name(raw: bytes):
    name = _utf16z(raw)
    extra = {}
    after = 2 * len(name) + 2
    if after + 2 < len(raw):
        items, _p = shell_item_list(raw, after)
        if items:
            extra["shell_item_short_name"] = items[0].get("short_name")
    return name, extra


def _pidl_name(raw: bytes):
    items, problems = shell_item_list(raw)
    path = join_shell_path([i.get("name") for i in items])
    return path, {"shell_items": [_item_summary(i) for i in items],
                  "shell_item_problems": problems}


def _lastvisited_name(raw: bytes):
    exe = _utf16z(raw)
    after = 2 * len(exe) + 2
    items, problems = shell_item_list(raw, after)
    path = join_shell_path([i.get("name") for i in items])
    return f"{exe} → {path}", {"program": exe, "folder": path,
                               "shell_item_problems": problems}


def _item_summary(item: dict) -> dict:
    return {k: item.get(k) for k in ("class_type", "kind", "name",
                                     "short_name", "guid", "mft_record",
                                     "mft_sequence") if item.get(k) is not None}


def _mru_ex_rows(rows: _Rows, key: Key, artefact: str, title: str,
                 decode) -> None:
    order = mru_list_ex(_val(key, "MRUListEx"))
    position = {n: i for i, n in enumerate(order)}
    for v in key.values():
        if not v.name.isdigit() or not isinstance(v.raw, bytes):
            continue
        n = int(v.name)
        try:
            text, extra = decode(v.raw)
        except (struct.error, ValueError, IndexError) as exc:
            text, extra = v.raw[:64].hex(), {"problem": str(exc)}
        pos = position.get(n)
        first = pos == 0
        rows.add(artefact, f"{key.path}:{v.name}", key=key, title=title,
                 value=text, at_raw=key.last_written_raw if first else None,
                 at_epoch="filetime" if first else None,
                 time_basis="key-mru-0" if first else "none",
                 entry=text, value_name=v.name, mru_position=pos,
                 list_key=key.name, **extra)


def _mru_list_rows(rows: _Rows, key: Key, artefact: str, title: str) -> None:
    order = _sval(key, "MRUList") or ""
    for v in key.values():
        if v.name.casefold() == "mrulist":
            continue
        text = v.data if isinstance(v.data, str) else (
            " → ".join(p for p in _utf16(v.raw).split("\x00") if p)
            if isinstance(v.raw, bytes) else "")
        pos = order.find(v.name) if len(v.name) == 1 else -1
        first = pos == 0
        rows.add(artefact, f"{key.path}:{v.name}", key=key, title=title,
                 value=text, at_raw=key.last_written_raw if first else None,
                 at_epoch="filetime" if first else None,
                 time_basis="key-mru-0" if first else "none", entry=text,
                 value_name=v.name, mru_position=pos if pos >= 0 else None)


def _url_n_rows(rows: _Rows, key: Key | None, artefact: str, title: str,
                times: Key | None = None) -> None:
    if key is None:
        return
    for v in key.values():
        m = re.fullmatch(r"url(\d+)", v.name, re.I)
        if not m or not isinstance(v.data, str):
            continue
        n = int(m.group(1))
        tv = times.value(v.name) if times is not None else None
        traw = _U64.unpack_from(tv.raw)[0] if tv is not None and \
            isinstance(tv.raw, bytes) and len(tv.raw) >= 8 else None
        if traw:
            at, epoch, basis = traw, "filetime", "entry"
        elif n == 1:
            at, epoch, basis = key.last_written_raw, "filetime", "key-mru-0"
        else:
            at, epoch, basis = None, None, "none"
        rows.add(artefact, v.name, key=key, title=title, value=v.data,
                 at_raw=at, at_epoch=epoch, time_basis=basis, entry=v.data,
                 value_name=v.name, order=n,
                 order_note="url1 is the most recent entry",
                 typed_time=_filetime_pair(traw) if traw else None)


# -- ShellBags ----------------------------------------------------------------

def _shellbag_rows(hive: Hive, bagmru: Key, rows: _Rows) -> None:
    seen = {bagmru.offset}
    stack = [(bagmru, [], 0)]
    while stack:
        node, names, depth = stack.pop()
        order = mru_list_ex(_val(node, "MRUListEx"))
        position = {n: i for i, n in enumerate(order)}
        for v in node.values():
            if not v.name.isdigit() or not isinstance(v.raw, bytes):
                continue
            item = shell_item(v.raw[:_U16.unpack_from(v.raw)[0]]
                              if len(v.raw) >= 2 else v.raw)
            if "problem" in item:
                hive._problem(f"ShellBag '{node.path}\\{v.name}': "
                              f"{item['problem']}")
            here = names + [item.get("name")]
            path = join_shell_path(here)
            child = node.subkey(v.name)
            subject = child if child is not None else node
            basis = "key" if child is not None else "none"
            rows.add("shellbag", f"{node.path}\\{v.name}", key=subject,
                     title="ShellBag folder (BagMRU)", value=path,
                     at_raw=subject.last_written_raw if child else None,
                     at_epoch="filetime" if child else None,
                     time_basis=basis, path=path, depth=depth,
                     mru_position=position.get(int(v.name)),
                     node_slot=_ival(child, "NodeSlot") if child else None,
                     parent_key_path=node.path,
                     parent_key_last_written_utc=node.last_written,
                     item=_jsonable({k: val for k, val in item.items()
                                     if k != "size"}),
                     time_note="at_utc is the last-written time of this "
                               "folder's BagMRU key; DOS date-times in the "
                               "item carry no zone and are not UTC.")
            if child is not None and child.offset not in seen and \
                    depth < MAX_DEPTH:
                seen.add(child.offset)
                stack.append((child, here, depth + 1))


# -- SAM ----------------------------------------------------------------------

ACB_FLAGS = {0x0001: "disabled", 0x0002: "home directory required",
             0x0004: "password not required", 0x0010: "normal account",
             0x0200: "password does not expire", 0x0400: "auto-locked"}


def decode_sam_f(raw: bytes) -> dict | None:
    raw = bytes(raw)
    if len(raw) < 0x44:
        return None
    last_logon, _logoff, pw_set, expires, failed = struct.unpack_from(
        "<QQQQQ", raw, 8)
    rid = _U32.unpack_from(raw, 0x30)[0]
    acb = _U16.unpack_from(raw, 0x38)[0]
    country, codepage, bad, logons = struct.unpack_from("<HHHH", raw, 0x3C)
    return {"last_logon_raw": last_logon, "password_last_set_raw": pw_set,
            "account_expires_raw": expires, "last_failed_logon_raw": failed,
            "rid": rid, "acb_flags": acb,
            "acb_flag_names": [n for b, n in ACB_FLAGS.items() if acb & b],
            "country_code": country, "code_page": codepage,
            "failed_logon_count": bad, "logon_count": logons}


def decode_sam_v_names(raw: bytes) -> dict:
    raw = bytes(raw)
    out = {}
    for label, at in (("username", 0x0C), ("full_name", 0x18),
                      ("comment", 0x24)):
        if len(raw) < at + 8:
            break
        off, length = struct.unpack_from("<II", raw, at)
        start = 0xCC + off
        if length and start + length <= len(raw):
            out[label] = _utf16(raw[start:start + length])
    return out


def _sam_rows(hive: Hive, rows: _Rows) -> None:
    users = hive.find("SAM\\Domains\\Account\\Users")
    if users is None:
        return
    names_by_rid = {}
    names = users.subkey("Names")
    for n in names.subkeys() if names else []:
        v = n.value("")
        if v is not None:
            names_by_rid[v.type] = n
    for u in users.subkeys():
        if u.name.casefold() == "names":
            continue
        try:
            rid = int(u.name, 16)
        except ValueError:
            continue
        fv = u.value("F")
        vv = u.value("V")
        f = decode_sam_f(fv.raw) if fv is not None and \
            isinstance(fv.raw, bytes) else None
        vnames = decode_sam_v_names(vv.raw) if vv is not None and \
            isinstance(vv.raw, bytes) else {}
        nk = names_by_rid.get(rid)
        name = nk.name if nk is not None else vnames.get("username")
        times = {}
        if f:
            for label, field in (("last logon", "last_logon_raw"),
                                 ("password last set", "password_last_set_raw"),
                                 ("last failed logon", "last_failed_logon_raw"),
                                 ("account expires", "account_expires_raw")):
                raw = f[field]
                if raw and raw != 0x7FFFFFFFFFFFFFFF:
                    times[label] = _filetime_pair(raw)
        rows.add("sam-user", u.name, key=u, title="Local user account (SAM)",
                 value=f"{name or '?'} (RID {rid})"
                       + (f", {f['logon_count']} logons" if f else ""),
                 at_raw=u.last_written_raw, at_epoch="filetime",
                 time_basis="key", rid=rid, username=name,
                 username_from="Names subkey" if nk is not None
                 else ("V value" if name else None),
                 v_value_names=vnames, names_key_last_written_utc=(
                     nk.last_written if nk is not None else None),
                 f=({k: v for k, v in f.items() if not k.endswith("_raw")}
                    if f else None), times=times,
                 account_never_expires=bool(
                     f and f["account_expires_raw"] in (0, 0x7FFFFFFFFFFFFFFF)),
                 f_note=None if f else "F value missing or too short")
        for label, t in times.items():
            rows.add("sam-user-time", f"{u.name}:{label}", key=u,
                     title=f"Local user account {label} (SAM F value)",
                     value=f"{name or '?'} (RID {rid})", at_raw=t["raw"],
                     at_epoch="filetime", time_basis="entry", rid=rid,
                     username=name, event=label)


# -- Amcache ------------------------------------------------------------------

AMCACHE_NOTE = ("An Amcache entry records that Windows inventoried this file "
                "(its path, hash and PE details). It is not by itself proof "
                "that the file was executed.")


def _amcache_rows(hive: Hive, rows: _Rows) -> None:
    inv = hive.find("Root\\InventoryApplicationFile")
    for e in inv.subkeys() if inv else []:
        path = _sval(e, "LowerCaseLongPath")
        file_id = _sval(e, "FileId")
        sha1 = file_id[4:] if file_id and file_id.startswith("0000") and \
            len(file_id) == 44 else file_id
        size_raw = _val(e, "Size")
        size = size_raw if isinstance(size_raw, int) else None
        if isinstance(size_raw, str):           # early builds: REG_SZ "0x7fac0"
            try:
                size = int(size_raw, 0)
            except ValueError:
                size = None
        rows.add("amcache-file", e.name, key=e,
                 title="Amcache file entry (InventoryApplicationFile)",
                 value=f"{path or e.name}" + (f" sha1 {sha1}" if sha1 else ""),
                 at_raw=e.last_written_raw, at_epoch="filetime",
                 time_basis="key", format="InventoryApplicationFile",
                 path=path, sha1=sha1, file_id_raw=file_id, size=size,
                 size_as_stored=size_raw if isinstance(size_raw, str) else None,
                 long_path_hash=_sval(e, "LongPathHash"),
                 link_date_text=_sval(e, "LinkDate"), name=_sval(e, "Name"),
                 publisher=_sval(e, "Publisher"), version=_sval(e, "Version"),
                 product_name=_sval(e, "ProductName"),
                 product_version=_sval(e, "ProductVersion"),
                 program_id=_sval(e, "ProgramId"),
                 binary_type=_sval(e, "BinaryType"),
                 is_os_component=_ival(e, "IsOsComponent"),
                 link_date_note="LinkDate is the PE header's link time as "
                                "text, written by Windows without a zone",
                 note=AMCACHE_NOTE)
    old = hive.find("Root\\File")
    for vol in old.subkeys() if old else []:
        for e in vol.subkeys():
            path = _sval(e, "15")
            sha = _sval(e, "101")
            sha1 = sha[4:] if sha and sha.startswith("0000") and \
                len(sha) == 44 else sha
            mod = _val(e, "11")
            mod2 = _val(e, "17")
            created = _val(e, "12")
            link = _ival(e, "f")
            rows.add("amcache-file", f"{vol.name}\\{e.name}", key=e,
                     title="Amcache file entry (Root\\File, older format)",
                     value=f"{path or e.name}" + (f" sha1 {sha1}" if sha1
                                                  else ""),
                     at_raw=e.last_written_raw, at_epoch="filetime",
                     time_basis="key", format="File (pre-2017)",
                     path=path, sha1=sha1, size=_ival(e, "6"),
                     volume_guid=vol.name, file_reference=e.name,
                     product_name=_sval(e, "0"), company=_sval(e, "1"),
                     file_version=_sval(e, "5"),
                     last_modified=_filetime_pair(mod)
                     if isinstance(mod, int) else None,
                     last_modified_2=_filetime_pair(mod2)
                     if isinstance(mod2, int) else None,
                     created=_filetime_pair(created)
                     if isinstance(created, int) else None,
                     link_time=_time_dict(link, "unix_s"), note=AMCACHE_NOTE)


# -- dispatch -----------------------------------------------------------------

EXTRACTORS = {"SYSTEM": _system_rows, "SOFTWARE": _software_rows,
              "NTUSER": _ntuser_rows, "SAM": _sam_rows,
              "AMCACHE": _amcache_rows}


def _usrclass_rows(hive: Hive, rows: _Rows) -> None:
    for path in ("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
                 "Wow6432Node\\Local Settings\\Software\\Microsoft\\Windows\\"
                 "Shell\\BagMRU"):
        bag = hive.find(path)
        if bag is not None:
            rows.step("ShellBags", _shellbag_rows, hive, bag, rows)


EXTRACTORS["USRCLASS"] = _usrclass_rows


def to_rows(hive: Hive, *, source_path: str, deleted: bool = True) -> list[dict]:
    """Artefact rows for the engine's `artefacts` table.

    One `registry-hive` row describes the hive itself (its kind, its
    base-block time, whether it is dirty, its problems); the extractor for
    the hive's kind adds the rest; with `deleted`, key and value records
    recovered from free cells follow as `registry-deleted-key` /
    `registry-deleted-value`."""
    base = source_path.replace("/", "\\").rsplit("\\", 1)[-1]
    kind = hive_kind(hive, base)
    rows = _Rows(hive, source_path)
    extractor = EXTRACTORS.get(kind)
    if extractor is not None:
        rows.step(f"{kind} extractors", extractor, hive, rows)
    if deleted:
        try:
            found = hive.recover_deleted()
        except (struct.error, ValueError, IndexError) as exc:
            hive._problem(f"deleted-record recovery stopped: {exc}")
            found = {"keys": [], "values": []}
        for k in found["keys"]:
            rows.add("registry-deleted-key", f"0x{k.offset:X}", key=k,
                     title="Deleted key record (recovered from a free cell)",
                     value=k.path, at_raw=k.last_written_raw,
                     at_epoch="filetime", time_basis="key", deleted=True,
                     recovered_from=k.recovered_from, cell_offset=k.offset,
                     live_key_at_same_path=k.live_twin,
                     live_key_note=("a live key exists at this path: this "
                                    "record may be an older copy of it that "
                                    "Windows replaced when the key grew")
                     if k.live_twin else None,
                     values=_values_dict(k) if k._values else {},
                     value_count_recorded=k.value_count)
        for v, parent in found["values"]:
            data = v.data
            if isinstance(data, list):
                data = "; ".join(data)
            shown = bytes(data[:64]).hex() if isinstance(data, (bytes,
                                                                bytearray)) \
                else data
            rows.add("registry-deleted-value", f"0x{v.offset:X}", key=None,
                     title="Deleted value record (recovered from a free cell)",
                     value=f"{parent or '?'} : {v.name or '(default)'} = "
                           f"{shown}", time_basis="none", deleted=True,
                     recovered_from=v.recovered_from, cell_offset=v.offset,
                     parent_key_path=parent, name=v.name,
                     type_name=v.type_name, data=data,
                     value_problems=list(v.problems))
    h = hive.header
    hive_row = {
        "artefact": "registry-hive", "at_raw": h.last_written_raw or None,
        "at_epoch": "filetime" if h.last_written_raw else None,
        "at_utc": h.last_written, "title": f"Registry hive ({kind})",
        "value": _oneline(f"{kind} hive, base block last written "
                          f"{h.last_written or 'not recorded'}"
                          + (" — DIRTY: transaction logs not applied"
                             if h.dirty else "")
                          + (f" — transaction logs applied in memory "
                             f"({hive.recovery['entries']} entries)"
                             if hive.recovery and hive.recovery["applied"]
                             else "")),
        "detail": _jsonable({"kind": kind, "header": h.as_dict(),
                             "transaction_logs": hive.recovery,
                             "root_name": hive.root.name,
                             "rows": len(rows.rows),
                             "time_basis": "entry",
                             "problems": hive.all_problems}),
        "row_ref_suffix": "registry-hive"}
    log.debug("registry %s: %s hive, %d rows", source_path, kind,
              len(rows.rows))
    return [hive_row] + rows.rows
