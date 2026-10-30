# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""FAT12, FAT16, FAT32 and exFAT from the bytes: boot sectors, FATs, directories.

Nothing here mounts anything. The volume is a byte stream (a partition in an
image, an SD card, a thumb drive) and every structure is parsed from it, so a
deleted entry, a damaged chain or a disagreement between two copies of the
same structure is visible exactly as it is on the media. Written from
Microsoft's published "FAT: General Overview of On-Disk Format" (fatgen103)
and the "exFAT File System Specification" (2019).

**Which FAT it is.** FAT12, FAT16 and FAT32 are told apart the way the
Microsoft specification says, and only that way: by the COUNT OF CLUSTERS
(< 4085 is FAT12, < 65525 is FAT16, otherwise FAT32). The "FAT16   " text in
the boot sector is informational and is only compared. exFAT is recognised by
its "EXFAT   " name at offset 3.

**What is checked, and what is done with damage.** The boot sector is checked
against its backup (FAT32: the sector `BkBootSec` names, normally 6; exFAT:
the 11-sector boot region against the checksum sector after it, and the main
region against the backup region at sector 12). Every copy of the FAT is
compared with the one in use. FSInfo's free-cluster count (FAT32) and
exFAT's PercentInUse are REPORTED beside a count made from the FAT or the
allocation bitmap — they are hints Windows does not always keep current, and
are never trusted. Long-name entries are checked against their 8.3 entry's
checksum and against each other; exFAT entry sets against their SetChecksum
and NameHash. A cluster chain is followed with loop detection, against the
volume's cluster range, and against the size the directory entry claims;
two live files claiming one cluster (cross-linked) are reported on both. A
disagreement is reported beside the result (`problems`), never repaired; a
boot sector that is not one raises `FileSystemError`.

**Timestamps are kept raw and labelled with what they are.** A FAT
directory entry's times are the LOCAL wall-clock time of whatever machine
wrote them, with no zone recorded — epoch `fat-local` (and `fat-local-date`
for the last-access date, which has no time). They are decoded to a naive
ISO string and are NEVER presented as UTC: a row's `at_utc` is None for them.
Placing them on a UTC timeline needs the writing device's zone, which only
the examiner can supply. exFAT adds a UtcOffset field per timestamp; where
its valid bit is set the value is decoded to true UTC (`exfat-utc`), and
where it is not, the value is local (`exfat-local`) and treated as FAT's.
These epochs are defined here (`EPOCHS`), not in `timeutil`.

**Deleted is a state of the entry, not a verdict on the data.** FAT marks a
deleted entry by overwriting the first byte of its 8.3 name with 0xE5; that
character is gone and is shown as "_" (`name_note` says so). A deleted
long-name run keeps its text — only its sequence byte is overwritten — so a
deleted file's long name is usually whole; and because the long-name
checksum is a one-to-one function of the 8.3 name's first byte, that byte is
INFERRED from the checksum (`short_name_inferred`, labelled an inference).
FAT zeroes a deleted file's chain, so its content can only be read on the
standard assumption that it was CONTIGUOUS from its first cluster
(`recovery_basis = "contiguous-assumption"`). For exFAT a deleted entry set
has its InUse bits cleared; a set flagged NoFatChain was contiguous by
definition, and a FAT-chained one is read through the FAT if a chain of
exactly the right length is still there, else contiguously. `recoverable`
then MEASURES how many of those clusters the FAT (exFAT: the allocation
bitmap) now marks allocated — the difference between "recovered" and "these
bytes are probably someone else's". It is a measurement, not a verdict: a
fragmented deleted file can read wrong past its first fragment with every
cluster free.

**Deleted directories are walked** when their first cluster is unallocated
and still holds directory entries (FAT: a "." entry pointing at itself);
what is found inside is flagged `in_deleted_dir`. A deleted FAT directory's
chain is gone, so only its FIRST cluster is walked.

**Slots after the end-of-directory marker are read too.** The specification
says every slot after the first 0x00 is unused, so drivers and fsck stop
there — which is also where a hand-edited directory can hide entries. Any
non-zero bytes there are reported, and entries found there are listed with
`past_end_marker` set. Two live entries with one name in a folder, and
names holding characters the file system forbids, are reported; `name` is
always kept as stored, but `path` escapes control characters and "/" and
brackets "", "." and ".." (`path_piece`), so a path can never be read as a
separator or a reference to a parent folder.

"Deleted" here is the entry's own mark (0xE5, or exFAT's InUse bit), never
an inference from the allocation of the cluster that holds it. The Sleuth
Kit, for one, also calls an entry unallocated when its directory cluster
is free in the bitmap, so the two can disagree on damaged volumes.

**What is NOT read.** 8.3 names are decoded as code page 437 — the OEM code
page of the machine that wrote a non-ASCII 8.3 name is not recorded
anywhere. TexFAT transaction state, exFAT vendor extension entries
(0xE0/0xE1, e.g. Windows CE ACLs) and OS/2 extended attributes are not
interpreted. On FAT32 some Windows versions clear the high 16 bits of a
deleted file's first cluster; where that may have happened the entry says
so, and the low half is all there is. Slack and unallocated space are
`carve.py`'s business; BitLocker To Go and other encrypted volumes are not
FAT on the media and are refused by the boot-sector check.
"""

from __future__ import annotations

import struct
import sys
from array import array
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import timeutil
from .errors import Cancelled, FileSystemError

CHUNK = 1 << 20
SLOT = 32

#: The epochs this module's timestamps are labelled with. A raw value is
#: (date << 16) | time, exactly as the 16-bit fields sit on disk.
EPOCH_FAT_LOCAL = "fat-local"
EPOCH_FAT_LOCAL_DATE = "fat-local-date"
EPOCH_EXFAT_UTC = "exfat-utc"
EPOCH_EXFAT_LOCAL = "exfat-local"
EPOCHS = {
    EPOCH_FAT_LOCAL: (
        "FAT date and time, (date << 16) | time: two-second resolution (a "
        "creation time adds a 10 ms count). LOCAL time of the writing "
        "machine, no zone recorded — not UTC."),
    EPOCH_FAT_LOCAL_DATE: (
        "FAT last-access DATE only (16 bits): local, no time of day, no zone."),
    EPOCH_EXFAT_UTC: (
        "exFAT timestamp (same 32-bit layout as FAT) whose UtcOffset field "
        "is valid, decoded to true UTC."),
    EPOCH_EXFAT_LOCAL: (
        "exFAT timestamp whose UtcOffset field is not valid: local time of "
        "the writing machine, no zone — not UTC."),
}

ATTRIBUTES = {0x01: "read-only", 0x02: "hidden", 0x04: "system",
              0x08: "volume-label", 0x10: "directory", 0x20: "archive"}
ATTR_LFN = 0x0F
ATTR_VOLUME = 0x08
ATTR_DIR = 0x10

FIRST_DELETED_CHAR = "_"
PAST_END_NOTE = (
    "Found AFTER its directory's end-of-directory marker: by the "
    "specification that slot is unused, so file system drivers and fsck do "
    "not list this entry.")
DELETED_NAME_NOTE = (
    "The first character of the 8.3 name was overwritten by the deletion "
    "mark (0xE5) and is shown as '_'.")

#: Bytes the FAT specification forbids in an 8.3 name (besides < 0x20).
_SFN_ILLEGAL = frozenset(b'"*+,./:;<=>?[\\]|')
#: Characters long names (VFAT and exFAT) may not hold (besides < U+0020).
_NAME_ILLEGAL = frozenset('"*/:<>?\\|')

EOC = {"FAT12": 0xFF8, "FAT16": 0xFFF8, "FAT32": 0x0FFFFFF8,
       "exFAT": 0xFFFFFFF8}
BAD = {"FAT12": 0xFF7, "FAT16": 0xFFF7, "FAT32": 0x0FFFFFF7,
       "exFAT": 0xFFFFFFF7}

#: A FAT directory holds at most 65 536 entries; exFAT's at most 256 MiB.
MAX_FAT_DIR = 65536 * SLOT
MAX_EXFAT_DIR = 256 << 20

# exFAT entry types (InUse bit set; clear it for the deleted form)
X_BITMAP, X_UPCASE, X_LABEL, X_FILE = 0x81, 0x82, 0x83, 0x85
X_GUID, X_PADDING, X_ACT = 0xA0, 0xA1, 0xA2
X_STREAM, X_NAME, X_VENDOR, X_VENDOR_ALLOC = 0xC0, 0xC1, 0xE0, 0xE1
_X_KNOWN = {X_BITMAP, X_UPCASE, X_LABEL, X_FILE, X_GUID, X_PADDING, X_ACT,
            X_STREAM, X_NAME, X_VENDOR, X_VENDOR_ALLOC}


def _utf16(raw: bytes) -> str:
    """UTF-16LE, unpaired surrogates kept as `\\udXXX` escapes (as ntfs.py)."""
    text = bytes(raw).decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


# ---------------------------------------------------------------------------
# checksums (each as its specification gives it)
# ---------------------------------------------------------------------------

def lfn_checksum(name11: bytes) -> int:
    """The 8-bit checksum a long-name entry carries of its 8.3 name."""
    s = 0
    for b in name11[:11]:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def first_byte_for_checksum(rest10: bytes, checksum: int) -> int:
    """The one first byte that gives `checksum` with these last 10 bytes.

    The rotate-and-add step is a bijection on the running sum, so exactly
    one value of the first byte produces any given checksum."""
    for b in range(256):
        if lfn_checksum(bytes([b]) + rest10) == checksum:
            return b
    raise AssertionError("unreachable: the checksum is a bijection")


def exfat_boot_checksum(region: bytes) -> int:
    """32-bit checksum of the first 11 sectors of an exFAT boot region,
    skipping VolumeFlags (106, 107) and PercentInUse (112)."""
    s = 0
    for i, b in enumerate(region):
        if i in (106, 107, 112):
            continue
        s = (((s & 1) << 31) + (s >> 1) + b) & 0xFFFFFFFF
    return s


def exfat_table_checksum(data: bytes) -> int:
    s = 0
    for b in data:
        s = (((s & 1) << 31) + (s >> 1) + b) & 0xFFFFFFFF
    return s


def exfat_set_checksum(entry_set: bytes) -> int:
    """16-bit SetChecksum over a whole entry set, skipping bytes 2-3."""
    s = 0
    for i, b in enumerate(entry_set):
        if i in (2, 3):
            continue
        s = (((s & 1) << 15) + (s >> 1) + b) & 0xFFFF
    return s


def exfat_name_hash(name: str, upcase: dict) -> int:
    s = 0
    units = name.encode("utf-16-le", "surrogatepass")
    for i in range(0, len(units), 2):
        u = units[i] | units[i + 1] << 8
        u = upcase.get(u, u)
        for b in (u & 0xFF, u >> 8):
            s = (((s & 1) << 15) + (s >> 1) + b) & 0xFFFF
    return s


def parse_upcase(data: bytes) -> dict:
    """An exFAT up-case table (compressed or not) → {code unit: upper}.
    0xFFFF followed by N means the next N code units map to themselves."""
    table, code, i = {}, 0, 0
    n = len(data) // 2
    vals = struct.unpack_from(f"<{n}H", data)
    while i < n:
        v = vals[i]
        if v == 0xFFFF and i + 1 < n:
            code += vals[i + 1]
            i += 2
            continue
        if v != code:
            table[code] = v
        code += 1
        i += 1
    return table


# ---------------------------------------------------------------------------
# timestamps
# ---------------------------------------------------------------------------

def _dos_datetime(raw: int, fine: int = 0) -> datetime | None:
    date, tm = raw >> 16 & 0xFFFF, raw & 0xFFFF
    if date == 0 or not 0 <= fine <= 199:
        return None
    try:
        dt = datetime(1980 + (date >> 9), date >> 5 & 0xF, date & 0x1F,
                      tm >> 11, tm >> 5 & 0x3F, (tm & 0x1F) * 2)
    except ValueError:
        return None
    return dt + timedelta(milliseconds=10 * fine)


def decode_fat_local(raw, fine: int = 0) -> str | None:
    """(date << 16) | time → naive ISO local time, or None (zero/invalid).
    No zone is attached because none was recorded."""
    if raw is None:
        return None
    dt = _dos_datetime(int(raw), fine)
    return None if dt is None else dt.isoformat(timespec="microseconds")


def decode_fat_date(raw) -> str | None:
    """A 16-bit FAT date → "YYYY-MM-DD", or None."""
    if not raw:
        return None
    dt = _dos_datetime(int(raw) << 16)
    return None if dt is None else dt.date().isoformat()


def utc_offset_minutes(offset_byte: int) -> int | None:
    """exFAT UtcOffset: bit 7 valid, bits 0-6 signed 15-minute steps."""
    if not offset_byte & 0x80:
        return None
    v = offset_byte & 0x7F
    if v & 0x40:
        v -= 0x80
    return v * 15


@dataclass(frozen=True)
class FatTime:
    """One timestamp: the raw value, the epoch that names it, the decoding.

    `value` is a naive ISO string for the local epochs and a `Z`-suffixed
    UTC string for `exfat-utc`. `fine_10ms` is the 10-millisecond count
    (0-199) creation and modification times carry; `offset_raw` is exFAT's
    UtcOffset byte, `utc_offset_minutes` its meaning when valid."""
    raw: int
    epoch: str
    value: str | None
    fine_10ms: int = 0
    offset_raw: int | None = None
    utc_offset_minutes: int | None = None

    @property
    def is_utc(self) -> bool:
        return self.epoch == EPOCH_EXFAT_UTC and self.value is not None

    def as_dict(self) -> dict:
        d = {"raw": self.raw, "epoch": self.epoch, "value": self.value}
        if self.fine_10ms:
            d["fine_10ms"] = self.fine_10ms
        if self.offset_raw is not None:
            d["offset_raw"] = self.offset_raw
            d["utc_offset_minutes"] = self.utc_offset_minutes
        return d


def fat_time(date: int, time_: int, fine: int = 0) -> FatTime:
    raw = (date << 16) | time_
    return FatTime(raw, EPOCH_FAT_LOCAL, decode_fat_local(raw, fine), fine)


def fat_date(date: int) -> FatTime:
    return FatTime(date, EPOCH_FAT_LOCAL_DATE, decode_fat_date(date))


def exfat_time(raw: int, fine: int, offset_byte: int) -> FatTime:
    minutes = utc_offset_minutes(offset_byte)
    local = _dos_datetime(raw, fine)
    if minutes is None:
        return FatTime(raw, EPOCH_EXFAT_LOCAL,
                       None if local is None else
                       local.isoformat(timespec="microseconds"),
                       fine, offset_byte, None)
    value = None
    if local is not None:
        value = timeutil.iso(local.replace(tzinfo=timeutil.UTC)
                             - timedelta(minutes=minutes))
    return FatTime(raw, EPOCH_EXFAT_UTC, value, fine, offset_byte, minutes)


# ---------------------------------------------------------------------------
# the entry
# ---------------------------------------------------------------------------

@dataclass
class FatEntry:
    """One file or folder as its directory entry (or exFAT entry set) says.

    `chain` is a run list, [(first cluster, count), ...]; `recovery_basis`
    says where it came from: "fat-chain" (followed through the FAT),
    "contiguous-nofatchain" (exFAT says the clusters are contiguous),
    "contiguous-assumption" (the chain is gone; contiguous from the first
    cluster is ASSUMED), "fat-chain-left-after-deletion" (exFAT: the FAT
    still holds a chain of exactly the right length), or "none"."""
    fs: str
    path: str
    name: str
    short_name: str
    long_name: str
    is_dir: bool
    deleted: bool
    size: int
    first_cluster: int
    attributes: int
    created: FatTime | None
    modified: FatTime | None
    accessed: FatTime | None
    dir_entry_offset: int
    set_offset: int
    slots: int
    in_deleted_dir: bool = False
    past_end_marker: bool = False
    name_note: str = ""
    short_name_inferred: str = ""
    chain: list = field(default_factory=list)
    recovery_basis: str = "none"
    recoverable: dict | None = None
    problems: list = field(default_factory=list)
    valid_data_length: int | None = None
    no_fat_chain: bool | None = None
    parent_dir_cluster: int = field(default=0, repr=False, compare=False)

    @property
    def attribute_names(self) -> list[str]:
        names = [n for b, n in ATTRIBUTES.items() if self.attributes & b]
        if self.fs == "exFAT":           # exFAT reserves 0x08; no labels
            names = [n for n in names if n != "volume-label"]
        return names

    @property
    def clusters(self) -> int:
        return sum(n for _s, n in self.chain)

    def as_dict(self) -> dict:
        d = {k: getattr(self, k) for k in (
            "fs", "path", "name", "short_name", "long_name", "is_dir",
            "deleted", "in_deleted_dir", "past_end_marker", "size",
            "first_cluster",
            "attributes", "dir_entry_offset", "set_offset", "slots",
            "name_note", "short_name_inferred", "recovery_basis",
            "recoverable", "valid_data_length", "no_fat_chain")}
        d["attribute_names"] = self.attribute_names
        d["chain"] = [list(r) for r in self.chain]
        d["problems"] = list(self.problems)
        for k in ("created", "modified", "accessed"):
            t = getattr(self, k)
            d[k] = None if t is None else t.as_dict()
        return d


class _DirData:
    """A directory's bytes and where each cluster of them lies in the volume."""

    def __init__(self, data: bytes, unit: int, bases: list) -> None:
        self.data, self.unit, self.bases = data, unit, bases

    def offset(self, pos: int) -> int:
        return self.bases[pos // self.unit] + pos % self.unit

    def slots(self):
        d = self.data
        for pos in range(0, len(d) - SLOT + 1, SLOT):
            yield pos, d[pos:pos + SLOT]


def path_piece(name: str) -> str:
    """A name as it is shown in a path: control characters and '/' escaped
    as \\xNN, and '', '.' and '..' bracketed, so a stored name can never
    read as a separator or a reference to a parent folder. `name` itself is
    always kept exactly as stored."""
    special = {"": "[no name]", ".": "[.]", "..": "[..]"}
    if name in special:
        return special[name]
    return "".join(f"\\x{ord(c):02x}" if ord(c) < 0x20 or c == "/" else c
                   for c in name)


def _join(parent: str, name: str) -> str:
    piece = path_piece(name)
    return f"{parent}/{piece}" if parent else piece


def _past_end_report(dd: _DirData, pos: int, where: str) -> str:
    nz = sum(1 for x in dd.data[pos:] if x)
    return (f"{nz} non-zero byte(s) follow the end-of-directory marker in "
            f"{where} (at volume offset {dd.offset(pos)}). By the "
            "specification those slots are unused and drivers do not read "
            "them; they are parsed here, and entries found are flagged "
            "past_end_marker.")


# ---------------------------------------------------------------------------
# FAT12/16/32 boot sector
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FatBoot:
    fat_type: str
    oem: str
    bytes_per_sector: int
    sectors_per_cluster: int
    reserved_sectors: int
    num_fats: int
    root_entries: int
    total_sectors: int
    media: int
    fat_sectors: int
    hidden_sectors: int
    cluster_count: int
    first_data_sector: int
    root_dir_sector: int
    root_dir_sectors: int
    root_cluster: int
    fsinfo_sector: int
    backup_boot_sector: int
    ext_flags: int
    fs_version: int
    boot_signature: int
    serial: int | None
    label: str
    fs_type_text: str
    source: str
    problems: tuple

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def size(self) -> int:
        return self.total_sectors * self.bytes_per_sector


def _power_of_two(n: int) -> bool:
    return n > 0 and not n & (n - 1)


def parse_fat_boot(data: bytes, source: str = "primary") -> FatBoot:
    """A FAT12/16/32 boot sector; raises FileSystemError if it is not one."""
    if len(data) < 512:
        raise FileSystemError(f"The {source} boot sector is shorter than 512 "
                              "bytes; the volume is truncated.")
    (bps, spc, rsvd, nfats, root_ent, tot16, media, fatsz16, _spt, _heads,
     hidden, tot32) = struct.unpack_from("<HBHBHHBHHHII", data, 11)
    what = f"The {source} sector is not a FAT boot sector"
    if bps not in (512, 1024, 2048, 4096):
        raise FileSystemError(f"{what}: {bps} bytes per sector is not a FAT "
                              "value.")
    if not _power_of_two(spc) or spc > 128:
        raise FileSystemError(f"{what}: {spc} sectors per cluster is not a "
                              "power of two up to 128.")
    if rsvd == 0 or nfats == 0:
        raise FileSystemError(f"{what}: it declares {rsvd} reserved sectors "
                              f"and {nfats} FATs.")
    problems = []
    fatsz32 = struct.unpack_from("<I", data, 36)[0]
    fatsz = fatsz16 or fatsz32
    total = tot16 or tot32
    if fatsz == 0 or total == 0:
        raise FileSystemError(f"{what}: it declares a FAT of {fatsz} sectors "
                              f"in a volume of {total} sectors.")
    root_secs = (root_ent * 32 + bps - 1) // bps
    first_data = rsvd + nfats * fatsz + root_secs
    if first_data >= total:
        raise FileSystemError(f"{what}: its reserved area, FATs and root "
                              f"directory ({first_data} sectors) fill the "
                              f"whole {total}-sector volume.")
    count = (total - first_data) // spc
    by_count = ("FAT12" if count < 4085 else
                "FAT16" if count < 65525 else "FAT32")
    layout32 = fatsz16 == 0
    fat_type = by_count
    if layout32 and by_count != "FAT32":
        fat_type = "FAT32"
        problems.append(
            f"The boot sector is laid out for FAT32, but {count:,} clusters "
            f"make it {by_count} by the Microsoft rule (FAT32 needs 65,525 "
            "or more); Windows would not mount it. It is read as FAT32, as "
            "its layout says.")
    elif not layout32 and by_count == "FAT32":
        fat_type = "FAT16"
        problems.append(
            f"{count:,} clusters make this FAT32 by the Microsoft rule, but "
            "its boot sector is laid out for FAT12/16; it is read as FAT16 "
            "and clusters past 65,524 cannot be reached.")
    if data[0] not in (0xEB, 0xE9):
        problems.append(f"The jump instruction is 0x{data[0]:02X}, not the "
                        "0xEB or 0xE9 a FAT boot sector starts with.")
    if data[510:512] != b"\x55\xaa":
        problems.append("The boot sector has no 55 AA end marker.")
    if media != 0xF0 and media < 0xF8:
        problems.append(f"Media byte 0x{media:02X} is not a FAT value.")
    root_cluster = fsinfo = backup = ext_flags = fs_ver = 0
    if fat_type == "FAT32":
        ext_flags, fs_ver, root_cluster, fsinfo, backup = struct.unpack_from(
            "<HHIHH", data, 40)
        sig_at, serial_at, label_at, type_at = 66, 67, 71, 82
        if root_ent:
            problems.append(f"A FAT32 boot sector declares {root_ent} root "
                            "entries; it should be 0.")
        if fs_ver:
            problems.append(f"FAT32 version {fs_ver >> 8}.{fs_ver & 0xFF} "
                            "is not 0.0, the only version defined.")
    else:
        sig_at, serial_at, label_at, type_at = 38, 39, 43, 54
    bootsig = data[sig_at]
    serial = (struct.unpack_from("<I", data, serial_at)[0]
              if bootsig in (0x28, 0x29) else None)
    label = type_text = ""
    if bootsig == 0x29:
        label = data[label_at:label_at + 11].decode("cp437").rstrip(" ")
        type_text = data[type_at:type_at + 8].decode("cp437").rstrip(" ")
        if type_text.startswith("FAT") and type_text not in ("FAT", fat_type):
            problems.append(f"The informational type text says "
                            f"'{type_text}'; the cluster count makes it "
                            f"{fat_type}, and the cluster count decides.")
    return FatBoot(fat_type, data[3:11].decode("cp437"), bps, spc, rsvd, nfats,
                   root_ent, total, media, fatsz, hidden, count, first_data,
                   rsvd + nfats * fatsz, root_secs, root_cluster, fsinfo,
                   backup, ext_flags, fs_ver, bootsig, serial, label,
                   type_text, source, tuple(problems))


def _serial_text(serial: int | None) -> str:
    if serial is None:
        return ""
    return f"{serial >> 16 & 0xFFFF:04X}-{serial & 0xFFFF:04X}"


def _diff(a: bytes, b: bytes) -> tuple[int, int]:
    """(bytes that differ, first differing offset or -1)."""
    n, first = abs(len(a) - len(b)), -1
    for pos in range(0, min(len(a), len(b)), 4096):
        x, y = a[pos:pos + 4096], b[pos:pos + 4096]
        if x == y:
            continue
        for i, (p, q) in enumerate(zip(x, y)):
            if p != q:
                n += 1
                if first < 0:
                    first = pos + i
    return n, first


# ---------------------------------------------------------------------------
# the volume (FAT12/16/32); ExfatVolume below overrides what differs
# ---------------------------------------------------------------------------

class FatVolume:
    """A FAT12/16/32 volume presented by `reader` (read_at + size), read-only.

    Use `open_fat(reader)`, which also recognises exFAT."""

    fs_type = "FAT"
    _alloc_source = "FAT"

    def __init__(self, reader, boot: FatBoot, problems: list | None = None):
        self.reader = reader
        self.boot = boot
        self.fs_type = boot.fat_type
        self.problems: list[str] = list(problems or [])
        self.problems.extend(boot.problems)
        self.bytes_per_sector = boot.bytes_per_sector
        self.cluster_size = boot.cluster_size
        self.cluster_count = boot.cluster_count
        self.max_cluster = boot.cluster_count + 1
        self._data_offset = boot.first_data_sector * boot.bytes_per_sector
        self.orphan_names: list[dict] = []
        self.deleted_labels: list[str] = []
        self.label_dir: str | None = None
        self.fsinfo: dict | None = None
        if boot.size > reader.size:
            self.problems.append(
                f"The boot sector describes {boot.size:,} bytes but only "
                f"{reader.size:,} are present: the image or partition is "
                "truncated, and clusters beyond it cannot be read.")
        self._walk_problems_seen: set = set()
        self._check_backup_boot()
        self._load_fat()
        self._read_fsinfo()
        self._reset_walk()
        self._scan_labels()
        self._fsinfo_problem()

    # -- structures read at open ----------------------------------------------
    def _check_backup_boot(self) -> None:
        b = self.boot
        if b.fat_type != "FAT32":
            return
        if b.backup_boot_sector in (0, 0xFFFF):
            self.problems.append("The FAT32 boot sector names no backup boot "
                                 "sector; there is nothing to compare it "
                                 "with.")
            return
        bps = b.bytes_per_sector
        if b.source != "primary":
            return
        primary = self.reader.read_at(0, bps)
        backup = self.reader.read_at(b.backup_boot_sector * bps, bps)
        if primary != backup:
            n, first = _diff(primary, backup)
            self.problems.append(
                f"The backup boot sector (sector {b.backup_boot_sector}) "
                f"differs from the primary in {n} byte(s), first at offset "
                f"{first}. The primary is the one used.")

    def _fat_bytes_needed(self) -> int:
        n = self.max_cluster + 1
        return {"FAT12": (n * 3 + 1) // 2 + 1, "FAT16": n * 2}.get(
            self.fs_type, n * 4)

    def _load_fat(self) -> None:
        b = self.boot
        bps = b.bytes_per_sector
        fat_bytes = b.fat_sectors * bps
        need = self._fat_bytes_needed()
        if need > fat_bytes:
            bits = {"FAT12": 12, "FAT16": 16}.get(self.fs_type, 32)
            self.problems.append(
                f"The FAT ({fat_bytes:,} bytes) is too small for "
                f"{self.cluster_count:,} clusters; entries past cluster "
                f"{fat_bytes * 8 // bits - 1:,} do not exist.")
        length = min(need, fat_bytes)
        self.mirroring = not (self.fs_type == "FAT32" and b.ext_flags & 0x80)
        self.active_fat = 0 if self.mirroring else b.ext_flags & 0x0F
        if self.active_fat >= b.num_fats:
            self.problems.append(f"ExtFlags names FAT {self.active_fat} as "
                                 f"active but there are {b.num_fats}; FAT 0 "
                                 "is used.")
            self.active_fat = 0
        base = b.reserved_sectors * bps
        self._fat = self.reader.read_at(base + self.active_fat * fat_bytes,
                                        length)
        if len(self._fat) < length:
            self.problems.append("The FAT is cut short by the end of the "
                                 "image; clusters past it read as missing.")
        for i in range(b.num_fats):
            if i == self.active_fat:
                continue
            other = self.reader.read_at(base + i * fat_bytes, length)
            if other == self._fat:
                continue
            n, first = _diff(self._fat, other)
            what = (f"FAT copy {i + 1} differs from copy "
                    f"{self.active_fat + 1} (the one used) in {n} byte(s), "
                    f"first at byte {first} of the FAT")
            if self.mirroring:
                self.problems.append(what + ".")
            else:
                self.problems.append(what + "; mirroring is disabled on this "
                                     "volume, so copies may differ by design.")
        self._fat_get = self._make_fat_get()
        f0, f1 = self._fat_get(0), self._fat_get(1)
        if f0 is not None and f0 & 0xFF != b.media:
            self.problems.append(f"FAT[0] carries media byte 0x{f0 & 0xFF:02X}"
                                 f", the boot sector 0x{b.media:02X}.")
        self.clean_shutdown = self.hard_error = None
        if f1 is not None and self.fs_type in ("FAT16", "FAT32"):
            clean, ok = ((0x8000, 0x4000) if self.fs_type == "FAT16"
                         else (0x08000000, 0x04000000))
            self.clean_shutdown = bool(f1 & clean)
            self.hard_error = not f1 & ok

    def _make_fat_get(self):
        fat, kind = self._fat, self.fs_type
        if kind == "FAT12":
            def get(n):
                off = n + (n >> 1)
                if n < 0 or off + 2 > len(fat):
                    return None
                v = fat[off] | fat[off + 1] << 8
                return v >> 4 if n & 1 else v & 0xFFF
        elif kind == "FAT16":
            def get(n):
                if n < 0 or 2 * n + 2 > len(fat):
                    return None
                return fat[2 * n] | fat[2 * n + 1] << 8
        else:
            mask = 0x0FFFFFFF if kind == "FAT32" else 0xFFFFFFFF

            def get(n):
                if n < 0 or 4 * n + 4 > len(fat):
                    return None
                return int.from_bytes(fat[4 * n:4 * n + 4], "little") & mask
        return get

    def _read_fsinfo(self) -> None:
        b = self.boot
        if b.fat_type != "FAT32" or b.fsinfo_sector in (0, 0xFFFF):
            return
        raw = self.reader.read_at(b.fsinfo_sector * b.bytes_per_sector, 512)
        if len(raw) < 512:
            return
        lead, = struct.unpack_from("<I", raw, 0)
        struc, free, nxt = struct.unpack_from("<III", raw, 484)
        trail, = struct.unpack_from("<I", raw, 508)
        ok = lead == 0x41615252 and struc == 0x61417272 and \
            trail == 0xAA550000
        self.fsinfo = {"sector": b.fsinfo_sector, "signatures_ok": ok,
                       "free_count": None if free == 0xFFFFFFFF else free,
                       "next_free": None if nxt == 0xFFFFFFFF else nxt}
        if not ok:
            self.problems.append(f"The FSInfo sector ({b.fsinfo_sector}) does "
                                 "not carry its signatures; its counts are "
                                 "not used.")

    # -- clusters --------------------------------------------------------------
    def cluster_offset(self, cluster: int) -> int:
        return self._data_offset + (cluster - 2) * self.cluster_size

    def is_allocated(self, cluster: int) -> bool:
        """What the FAT says now: a non-zero entry is allocated."""
        v = self._fat_get(cluster)
        return v is not None and v != 0

    def _eoc(self, v: int) -> bool:
        return v >= EOC[self.fs_type]

    def follow_chain(self, first: int, *, limit: int | None = None):
        """The chain from `first` → ([(start, count)], problems)."""
        runs: list = []
        problems: list[str] = []
        if not 2 <= first <= self.max_cluster:
            return runs, [f"The first cluster {first} is outside the "
                          f"volume's clusters (2-{self.max_cluster})."]
        seen = set()
        cur = first
        bad = BAD[self.fs_type]
        while True:
            if cur in seen:
                problems.append(f"The chain loops back to cluster {cur}; it "
                                "is cut there.")
                break
            seen.add(cur)
            if runs and runs[-1][0] + runs[-1][1] == cur:
                runs[-1][1] += 1
            else:
                runs.append([cur, 1])
            if limit is not None and len(seen) >= limit:
                problems.append(f"The chain is longer than {limit:,} "
                                "clusters, the most this structure may "
                                "have; the rest is not followed.")
                break
            nxt = self._fat_get(cur)
            if nxt is None:
                problems.append(f"Cluster {cur} has no entry in the FAT "
                                "that was read; the chain stops there.")
                break
            if self._eoc(nxt):
                break
            if nxt == 0:
                problems.append(f"The FAT marks cluster {cur} free although "
                                "it is in this chain; the chain stops "
                                "there.")
                break
            if nxt == bad:
                problems.append(f"The chain reaches a cluster marked BAD "
                                f"after cluster {cur}.")
                break
            if not 2 <= nxt <= self.max_cluster:
                problems.append(f"Cluster {cur} points to {nxt:#x}, which is "
                                "not a cluster of this volume; the chain "
                                "stops there.")
                break
            cur = nxt
        return [tuple(r) for r in runs], problems

    def _clip(self, first: int, count: int, problems: list) -> list:
        """A contiguous run, cut at the volume's last cluster."""
        if count <= 0 or not 2 <= first <= self.max_cluster:
            return []
        last = first + count - 1
        if last > self.max_cluster:
            problems.append(f"Read contiguously, the data would run "
                            f"{last - self.max_cluster} cluster(s) past the "
                            "volume's last cluster.")
            count = self.max_cluster - first + 1
        return [(first, count)]

    def measure_allocation(self, runs, wanted: int) -> dict:
        """How many of these clusters are marked allocated now."""
        total = now = 0
        for s, n in runs:
            total += n
            for c in range(s, s + n):
                now += self.is_allocated(c)
        return {"clusters": wanted, "in_volume": total, "now_allocated": now,
                "measured_against": self._alloc_source}

    # -- the walk ---------------------------------------------------------------
    def _reset_walk(self) -> None:
        nbytes = (self.max_cluster + 8) // 8 + 1
        self._claimed = bytearray(nbytes)
        self._owners: list = []
        self._dirs_seen: dict = {}
        self.orphan_names = []

    def _vol_problem(self, msg: str) -> None:
        if msg not in self._walk_problems_seen:
            self._walk_problems_seen.add(msg)
            self.problems.append(msg)

    def _claim(self, e: FatEntry) -> None:
        """Record a live entry's clusters; report clusters already claimed."""
        conflicts: dict = {}
        claimed = self._claimed
        for s, n in e.chain:
            for c in range(s, s + n):
                byte, bit = c >> 3, 1 << (c & 7)
                if claimed[byte] & bit:
                    owner = self._owner_of(c)
                    key = id(owner) if owner is not None else None
                    if key not in conflicts:
                        conflicts[key] = [owner, c, 0]
                    conflicts[key][2] += 1
                else:
                    claimed[byte] |= bit
        for owner, c, n in conflicts.values():
            who = owner.path if owner is not None else "another entry"
            e.problems.append(f"Cross-linked: {n} cluster(s) of this chain, "
                              f"first {c}, are also in the chain of {who}.")
            if owner is not None:
                owner.problems.append(f"Cross-linked: {n} cluster(s), first "
                                      f"{c}, are also in the chain of "
                                      f"{e.path}.")
        self._owners.append(e)

    def _owner_of(self, cluster: int):
        for o in self._owners:
            for s, n in o.chain:
                if s <= cluster < s + n:
                    return o
        return None

    def entries(self, *, should_cancel=None):
        """Every entry, live and deleted, depth first in on-disk order.

        `.` and `..` and volume-label entries are not yielded. A cross-link is
        recorded on BOTH entries; the one met first gets its note when the
        second is met, possibly after it was yielded (`to_rows` collects all
        entries before building rows)."""
        self._reset_walk()
        stack = [iter(self._root_listing())]
        while stack:
            if should_cancel is not None and should_cancel():
                raise Cancelled("FAT directory walking was cancelled")
            try:
                e = next(stack[-1])
            except StopIteration:
                stack.pop()
                continue
            kids = self._open_subdir(e) if e.is_dir else None
            yield e
            if kids:
                stack.append(iter(kids))

    def _read_runs(self, runs, max_bytes: int) -> _DirData:
        cs = self.cluster_size
        parts, bases, got = [], [], 0
        for s, n in runs:
            n = min(n, (max_bytes - got) // cs)
            if n <= 0:
                break
            data = self.reader.read_at(self.cluster_offset(s), n * cs)
            if len(data) < n * cs:
                data += bytes(n * cs - len(data))
            parts.append(data)
            bases.extend(self.cluster_offset(s + i) for i in range(n))
            got += n * cs
        return _DirData(b"".join(parts), cs, bases)

    def _root_listing(self) -> list:
        b = self.boot
        if self.fs_type == "FAT32":
            runs, probs = self.follow_chain(b.root_cluster,
                                            limit=MAX_FAT_DIR // self.cluster_size)
            for p in probs:
                self._vol_problem(f"Root directory chain: {p}")
            self._dirs_seen[b.root_cluster] = "the root directory"
            dd = self._read_runs(runs, MAX_FAT_DIR)
            for s, n in runs:
                self._claim_dir_runs(s, n)
        else:
            off = b.root_dir_sector * b.bytes_per_sector
            length = b.root_entries * SLOT
            data = self.reader.read_at(off, length)
            if len(data) < length:
                self._vol_problem("The root directory is cut short by the "
                                  "end of the image.")
            dd = _DirData(data, max(1, length), [off])
        return self._parse_dir(dd, path="", in_deleted=False, owner=None,
                               my_cluster=0 if self.fs_type != "FAT32"
                               else b.root_cluster, parent_cluster=None)

    def _claim_dir_runs(self, s: int, n: int) -> None:
        for c in range(s, s + n):
            self._claimed[c >> 3] |= 1 << (c & 7)

    def _open_subdir(self, e: FatEntry) -> list | None:
        """Read a directory entry's listing, or say why it is not read."""
        if not e.chain:
            if not e.deleted and e.first_cluster == 0:
                e.problems.append("A directory with no first cluster.")
            return None
        first = e.first_cluster
        if first in self._dirs_seen:
            e.problems.append(f"Its first cluster {first} is already walked "
                              f"as {self._dirs_seen[first]}; not walked "
                              "again.")
            return None
        if e.recovery_basis == "contiguous-assumption":
            if self.is_allocated(first):
                e.problems.append(
                    f"Its first cluster {first} is now allocated (to this "
                    "directory under another name, or to something else); "
                    "it is not walked as this deleted directory.")
                return None
            runs = [(first, 1)]
        else:
            runs = e.chain
        self._dirs_seen[first] = e.path
        dd = self._read_runs(runs, MAX_FAT_DIR)
        if e.recovery_basis == "contiguous-assumption":
            head = dd.data[:SLOT * 2]
            dot_cluster = self._sfn_cluster(head[:SLOT]) if len(head) >= SLOT \
                else -1
            if head[:11] != b".          " or dot_cluster != first:
                e.problems.append(f"Its first cluster {first} no longer "
                                  "holds this directory's '.' entry; it is "
                                  "not walked.")
                return None
        parent = self._parent_cluster(e)
        return self._parse_dir(dd, path=e.path,
                               in_deleted=e.in_deleted_dir or e.deleted,
                               owner=e, my_cluster=first,
                               parent_cluster=parent,
                               partial=e.recovery_basis ==
                               "contiguous-assumption",
                               hidden=e.past_end_marker)

    def _check_names(self, listing: list, upper) -> None:
        """Names no driver writes, and two live entries with one name."""
        seen: dict = {}
        for e in listing:
            bad = sorted({c for c in e.long_name if ord(c) < 0x20 or c in
                          _NAME_ILLEGAL})
            if bad:
                escaped = any(ord(c) < 0x20 or c == "/" for c in bad)
                e.problems.append(
                    "The name holds characters the file system forbids ("
                    + ", ".join(f"U+{ord(c):04X}" for c in bad)
                    + "); `name` keeps it as stored"
                    + ("; the path shows them escaped as \\xNN."
                       if escaped else "."))
            if e.name in ("", ".", ".."):
                e.problems.append(
                    f"The name '{e.name}' is not one a driver writes; the "
                    f"path shows it as '{path_piece(e.name)}' so it cannot "
                    "be read as a reference to a folder.")
            if e.deleted or e.past_end_marker:
                continue
            keys = {upper(e.name)}
            if e.short_name:
                keys.add("8.3:" + e.short_name.upper())
            for k in keys:
                if k in seen:
                    other = seen[k]
                    e.problems.append(
                        f"Another live entry in this folder has the same "
                        f"name ('{other.name}', directory entry at volume "
                        f"offset {other.dir_entry_offset}).")
                    break
            for k in keys:
                seen.setdefault(k, e)

    def _parent_cluster(self, e: FatEntry) -> int:
        return e.parent_dir_cluster

    def _sfn_cluster(self, raw: bytes) -> int:
        lo = struct.unpack_from("<H", raw, 26)[0]
        hi = struct.unpack_from("<H", raw, 20)[0] if self.fs_type == "FAT32" \
            else 0
        return hi << 16 | lo

    # -- FAT directory parsing ----------------------------------------------------
    def _parse_dir(self, dd: _DirData, *, path: str, in_deleted: bool, owner,
                   my_cluster: int, parent_cluster, partial: bool = False,
                   hidden: bool = False):
        report = (owner.problems.append if owner is not None
                  else self._vol_problem)
        where = f"'{path}'" if path else "the root directory"
        out: list = []
        pending: list = []          # long-name slots waiting for their 8.3
        garbage = 0
        ended = past_end = False
        for pos, raw in dd.slots():
            first = raw[0]
            if first == 0x00:
                self._flush_orphans(pending, path)
                pending = []
                if past_end:
                    continue
                ended = True
                if not any(dd.data[pos:]):
                    break
                report(_past_end_report(dd, pos, where))
                past_end = True
                continue
            attr = raw[11]
            off = dd.offset(pos)
            if attr & 0x3F == ATTR_LFN and first != 0x00:
                pending.append((off, raw))
                continue
            deleted = first == 0xE5
            name11 = raw[:11]
            if name11 in (b".          ", b"..         "):
                self._flush_orphans(pending, path)
                pending = []
                self._check_dot(raw, name11, my_cluster, parent_cluster,
                                report, where)
                continue
            if attr & ATTR_VOLUME and not attr & ATTR_DIR:
                self._flush_orphans(pending, path)    # labels: _scan_labels
                pending = []
                continue
            if not self._valid_sfn(raw, deleted):
                self._flush_orphans(pending, path)
                pending = []
                if past_end:
                    continue
                garbage += 1
                if partial:
                    report(f"The slot at volume offset {off} does not parse "
                           "as a directory entry; the rest of this deleted "
                           "directory is not read.")
                    break
                continue
            lfn, lfn_off, lfn_slots, inferred, notes = self._match_lfn(
                pending, raw, deleted, path)
            pending = []
            out.append(self._make_entry(raw, off, path, deleted, in_deleted,
                                        lfn, lfn_off, lfn_slots, inferred,
                                        notes, my_cluster,
                                        hidden or past_end))
        self._flush_orphans(pending, path)
        self._check_names(out, str.upper)
        if garbage:
            report(f"{garbage} slot(s) in {where} do not parse as directory "
                   "entries and are skipped.")
        if partial and not ended:
            report("This deleted directory's entries fill its first cluster; "
                   "its chain is gone, so any further clusters are not "
                   "walked.")
        return out

    def _check_dot(self, raw, name11, my_cluster, parent_cluster, report,
                   where) -> None:
        got = self._sfn_cluster(raw)
        if name11[:2] == b". ":
            if got != my_cluster:
                report(f"The '.' entry of {where} points to cluster {got}, "
                       f"not to the directory itself ({my_cluster}).")
        elif parent_cluster is not None and got != parent_cluster:
            report(f"The '..' entry of {where} points to cluster {got}; its "
                   f"parent is at cluster {parent_cluster} (0 = root).")

    def _valid_sfn(self, raw: bytes, deleted: bool) -> bool:
        attr = raw[11]
        if attr & 0xC0:
            return False
        name = raw[:11]
        start = 1 if deleted or name[0] == 0x05 else 0
        if not deleted and name[0] == 0x20:
            return False
        for b in name[start:]:
            if b < 0x20 or b in _SFN_ILLEGAL:
                return False
        return True

    @staticmethod
    def _short_text(name11: bytes, ntres: int, *, label: bool = False,
                    deleted: bool = False) -> str:
        raw = bytearray(name11)
        if raw[0] == 0x05 and not deleted:
            raw[0] = 0xE5
        text = bytes(raw).decode("cp437")
        if deleted:
            text = FIRST_DELETED_CHAR + text[1:]
        if label:
            return text.rstrip(" ")
        base, ext = text[:8].rstrip(" "), text[8:11].rstrip(" ")
        if ntres & 0x08:
            base = base.lower()
        if ntres & 0x10:
            ext = ext.lower()
        return f"{base}.{ext}" if ext else base

    @staticmethod
    def _lfn_text(slots: list) -> str:
        """Long-name slots in name order (ord 1 first) → the name."""
        units = bytearray()
        for _off, raw in slots:
            units += raw[1:11] + raw[14:26] + raw[28:32]
        end = len(units)
        for i in range(0, len(units), 2):
            if units[i] == 0 and units[i + 1] == 0:
                end = i
                break
        return _utf16(bytes(units[:end]))

    @staticmethod
    def _has_terminator(raw: bytes) -> bool:
        u = raw[1:11] + raw[14:26] + raw[28:32]
        return any(u[i] == 0 and u[i + 1] == 0 for i in range(0, 26, 2))

    def _match_lfn(self, pending, sfn_raw, deleted, path):
        """Pick the long-name slots that belong to this 8.3 entry.

        Returns (long name, offset of its first slot, slots used, inferred
        8.3 first character, problems). Slots that do not belong are
        recorded as orphans."""
        notes: list[str] = []
        if not pending:
            return "", None, 0, "", notes
        taken: list = []
        i = len(pending) - 1
        if not deleted:
            want = 1
            while i >= 0:
                off, raw = pending[i]
                if raw[0] == 0xE5 or raw[0] & 0x3F != want:
                    break
                taken.append(pending[i])
                i -= 1
                if raw[0] & 0x40:
                    break
                want += 1
            if taken and not taken[-1][1][0] & 0x40:
                notes.append("The long-name entries before this entry lack "
                             "the 'last' (0x40) mark on their final entry; "
                             "the name may be incomplete.")
        else:
            chk = None
            while i >= 0:
                off, raw = pending[i]
                if raw[0] != 0xE5 or (chk is not None and raw[13] != chk):
                    break
                chk = raw[13]
                taken.append(pending[i])
                i -= 1
                if self._has_terminator(raw) or len(taken) == 20:
                    break
        leftover = pending[:i + 1]
        if leftover:
            self._flush_orphans(leftover, path)
        if not taken:
            return "", None, 0, "", notes
        sums = {raw[13] for _o, raw in taken}
        text = self._lfn_text(taken)
        inferred = ""
        if len(sums) > 1:
            notes.append("Its long-name entries disagree on their checksum; "
                         "they are treated as orphaned and the 8.3 name is "
                         f"used. Their text: '{text}'.")
            self._flush_orphans(list(reversed(taken)), path, recorded=False)
            return "", None, 0, "", notes
        chk = sums.pop()
        if not deleted:
            expected = lfn_checksum(sfn_raw[:11])
            if chk != expected:
                notes.append(
                    f"LFN checksum mismatch: the long-name entries carry "
                    f"0x{chk:02X}, the 8.3 name gives 0x{expected:02X}. By the "
                    "FAT specification they are orphaned, and the 8.3 name is "
                    f"used. Their text: '{text}'.")
                self._flush_orphans(list(reversed(taken)), path,
                                    recorded=False)
                return "", None, 0, "", notes
        else:
            b = first_byte_for_checksum(sfn_raw[1:11], chk)
            if b < 0x21 or b in _SFN_ILLEGAL or 0x61 <= b <= 0x7A or b == 0xE5:
                notes.append(
                    "The deleted long-name entries before this deleted entry "
                    f"would need its first byte to be 0x{b:02X}, which no 8.3 "
                    "name has; they are treated as orphaned. Their text: "
                    f"'{text}'.")
                self._flush_orphans(list(reversed(taken)), path,
                                    recorded=False)
                return "", None, 0, "", notes
            inferred = self._short_text(bytes([b]) + sfn_raw[1:11],
                                        sfn_raw[12])
        return text, taken[-1][0], len(taken), inferred, notes

    def _flush_orphans(self, slots, path, *, recorded: bool = True) -> None:
        """Long-name slots that belong to no 8.3 entry (in physical order)."""
        if not slots:
            return
        groups, cur = [], [slots[0]]
        for prev, s in zip(slots, slots[1:]):
            same = s[1][13] == prev[1][13] and \
                (s[1][0] == 0xE5) == (prev[1][0] == 0xE5)
            if same and not (s[1][0] != 0xE5 and s[1][0] & 0x40):
                cur.append(s)
            else:
                groups.append(cur)
                cur = [s]
        groups.append(cur)
        for g in groups:
            self.orphan_names.append({
                "directory": path, "dir_entry_offset": g[0][0],
                "slots": len(g), "deleted": g[0][1][0] == 0xE5,
                "checksum": g[0][1][13],
                "text": self._lfn_text(list(reversed(g))),
                "reported_on_entry": not recorded})

    def _make_entry(self, raw, off, path, deleted, in_deleted, lfn, lfn_off,
                    lfn_slots, inferred, notes, my_cluster,
                    past_end=False) -> FatEntry:
        (attr, ntres, tenth, ctime, cdate, adate, hi, mtime, mdate, lo,
         size) = struct.unpack_from("<BBBHHHHHHHI", raw, 11)
        short = self._short_text(raw[:11], ntres, deleted=deleted)
        first = (hi << 16 | lo) if self.fs_type == "FAT32" else lo
        name = lfn or short
        e = FatEntry(
            fs=self.fs_type, path=_join(path, name),
            name=name, short_name=short, long_name=lfn,
            is_dir=bool(attr & ATTR_DIR), deleted=deleted,
            size=size, first_cluster=first, attributes=attr,
            created=fat_time(cdate, ctime, tenth),
            modified=fat_time(mdate, mtime), accessed=fat_date(adate),
            dir_entry_offset=off,
            set_offset=lfn_off if lfn_off is not None else off,
            slots=lfn_slots + 1, in_deleted_dir=in_deleted,
            past_end_marker=past_end, problems=list(notes))
        if past_end:
            e.problems.insert(0, PAST_END_NOTE)
        e.parent_dir_cluster = my_cluster if self.fs_type != "FAT32" or \
            my_cluster != self.boot.root_cluster else 0
        if deleted:
            e.name_note = DELETED_NAME_NOTE
            e.short_name_inferred = inferred
            if inferred:
                e.name_note += (" The first character is INFERRED as '"
                                f"{inferred[0]}' from the long-name "
                                "checksum.")
            if self.fs_type == "FAT32" and hi == 0 and \
                    self.max_cluster > 0xFFFF:
                e.problems.append(
                    "On FAT32 some Windows versions clear the high 16 bits of "
                    "a deleted entry's first cluster; this entry's are zero, "
                    "so its first cluster may be the low half only.")
        self._settle_chain(e)
        return e

    def _settle_chain(self, e: FatEntry) -> None:
        cs = self.cluster_size
        need = -(-e.size // cs)
        first = e.first_cluster
        if first == 0:
            if e.size:
                e.problems.append(f"The size is {e.size:,} bytes but no first "
                                  "cluster is recorded.")
            return
        if not 2 <= first <= self.max_cluster:
            e.problems.append(f"The first cluster {first} is outside the "
                              f"volume's clusters (2-{self.max_cluster}).")
            return
        if e.deleted or not self.is_allocated(first):
            if not e.deleted:
                e.problems.append(
                    f"The FAT marks its first cluster {first} free: its chain "
                    "is gone, and contiguous clusters are assumed.")
            want = 1 if e.is_dir else need
            e.chain = self._clip(first, want, e.problems)
            e.recovery_basis = "contiguous-assumption"
            e.recoverable = self.measure_allocation(e.chain, want)
            return
        limit = MAX_FAT_DIR // cs if e.is_dir else None
        e.chain, probs = self.follow_chain(first, limit=limit)
        e.problems.extend(probs)
        e.recovery_basis = "fat-chain"
        got = e.clusters
        if not e.is_dir and got != need:
            if got < need:
                e.problems.append(f"Chain shorter than size: {got} cluster(s) "
                                  f"for {e.size:,} bytes, which need {need}.")
            else:
                e.problems.append(f"Chain longer than size: {got} cluster(s) "
                                  f"for {e.size:,} bytes, which need {need}.")
        if not (e.in_deleted_dir or e.past_end_marker):
            self._claim(e)

    # -- reading -----------------------------------------------------------------
    def read_file(self, entry: FatEntry, offset: int = 0,
                  length: int | None = None) -> bytes:
        """Content bytes of a file, within its size.

        Follows `entry.chain` — the FAT chain, or for a deleted file the
        contiguous assumption its `recovery_basis` names. A read stops where
        the chain or the image stops; it is never padded. On exFAT, bytes
        past the valid-data length read as zero, as the file system returns
        them."""
        if entry.is_dir:
            raise FileSystemError(f"'{entry.path}' is a folder; its content "
                                  "is directory entries, which entries() "
                                  "lists.")
        size = entry.size
        if offset < 0:
            raise ValueError("offset must not be negative")
        if length is None:
            length = size - offset
        length = max(0, min(length, size - offset))
        if length == 0:
            return b""
        cs = self.cluster_size
        out = bytearray()
        pos = offset
        end = offset + length
        logical = 0
        for s, n in entry.chain:
            r_start, r_end = logical * cs, (logical + n) * cs
            logical += n
            if r_end <= pos:
                continue
            if r_start >= end:
                break
            a, b = max(pos, r_start), min(end, r_end)
            data = self.reader.read_at(self.cluster_offset(s) + (a - r_start),
                                       b - a)
            out += data
            pos = a + len(data)
            if len(data) < b - a or pos >= end:
                break
        vdl = entry.valid_data_length
        if vdl is not None and vdl < offset + len(out):
            cut = max(0, vdl - offset)
            out[cut:] = bytes(len(out) - cut)
        return bytes(out)

    def iter_file(self, entry: FatEntry, chunk: int = CHUNK):
        pos = 0
        while pos < entry.size:
            piece = self.read_file(entry, pos, chunk)
            if not piece:
                break
            yield piece
            pos += len(piece)

    # -- volume metadata -----------------------------------------------------------
    def used_clusters(self) -> int:
        """Clusters the FAT marks non-free, counted from the FAT itself."""
        if getattr(self, "_used", None) is None:
            self._used = self._count_used()
        return self._used

    def _count_used(self) -> int:
        top = self.max_cluster + 1
        if self.fs_type == "FAT12":
            return sum(1 for c in range(2, top) if self._fat_get(c))
        code = "H" if self.fs_type == "FAT16" else "I"
        width = 2 if code == "H" else 4
        arr = array(code)
        arr.frombytes(self._fat[:(len(self._fat) // width) * width])
        if sys.byteorder != "little":
            arr.byteswap()
        arr = arr[2:top]
        if self.fs_type == "FAT32":
            return sum(1 for v in arr if v & 0x0FFFFFFF)
        return len(arr) - arr.count(0)

    def _scan_labels(self) -> None:
        """Volume-label entries in the root directory (live and deleted)."""
        b = self.boot
        if self.fs_type == "FAT32":
            runs, _p = self.follow_chain(b.root_cluster,
                                         limit=MAX_FAT_DIR // self.cluster_size)
            data = self._read_runs(runs, MAX_FAT_DIR).data
        else:
            data = self.reader.read_at(b.root_dir_sector * b.bytes_per_sector,
                                       b.root_entries * SLOT)
        for pos in range(0, len(data) - SLOT + 1, SLOT):
            raw = data[pos:pos + SLOT]
            if raw[0] == 0:
                break
            attr = raw[11]
            if attr & 0x3F == ATTR_LFN or not attr & ATTR_VOLUME or \
                    attr & ATTR_DIR:
                continue
            deleted = raw[0] == 0xE5
            text = self._short_text(raw[:11], 0, label=True, deleted=deleted)
            if deleted:
                self.deleted_labels.append(text)
            elif self.label_dir is None:
                self.label_dir = text

    def info(self) -> dict:
        """Volume facts, each as the structure it came from says it."""
        b = self.boot
        used = self.used_clusters()
        return {
            "fs_type": self.fs_type, "oem": b.oem,
            "label": self.label_dir if self.label_dir is not None else b.label,
            "label_boot": b.label, "label_dir": self.label_dir,
            "deleted_labels": list(self.deleted_labels),
            "serial": _serial_text(b.serial), "serial_raw": b.serial,
            "bytes_per_sector": b.bytes_per_sector,
            "sectors_per_cluster": b.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "total_clusters": self.cluster_count, "used_clusters": used,
            "free_clusters": self.cluster_count - used,
            "fsinfo": self.fsinfo, "num_fats": b.num_fats,
            "active_fat": self.active_fat, "mirroring": self.mirroring,
            "clean_shutdown": self.clean_shutdown,
            "hard_error": self.hard_error,
            "volume_size": b.size, "image_size": self.reader.size,
            "boot_source": b.source, "fs_type_text": b.fs_type_text,
            "problems": list(self.problems)}

    def _fsinfo_problem(self) -> None:
        if self.fsinfo and self.fsinfo["signatures_ok"] and \
                self.fsinfo["free_count"] is not None:
            counted = self.cluster_count - self.used_clusters()
            if counted != self.fsinfo["free_count"]:
                self._vol_problem(
                    f"FSInfo says {self.fsinfo['free_count']:,} free "
                    f"clusters; the FAT has {counted:,}. FSInfo is a hint "
                    "Windows does not always keep current; the FAT count "
                    "is the measurement.")


# ---------------------------------------------------------------------------
# exFAT
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ExfatBoot:
    partition_offset: int
    volume_length: int
    fat_offset: int
    fat_length: int
    cluster_heap_offset: int
    cluster_count: int
    root_cluster: int
    serial: int
    revision: int
    volume_flags: int
    bytes_per_sector: int
    sectors_per_cluster: int
    num_fats: int
    drive_select: int
    percent_in_use: int
    source: str
    problems: tuple

    @property
    def cluster_size(self) -> int:
        return self.bytes_per_sector * self.sectors_per_cluster

    @property
    def size(self) -> int:
        return self.volume_length * self.bytes_per_sector


def parse_exfat_boot(data: bytes, source: str = "main") -> ExfatBoot:
    """An exFAT main (or backup) boot sector; FileSystemError if not one."""
    if len(data) < 512 or data[3:11] != b"EXFAT   ":
        raise FileSystemError(f"The {source} boot sector does not carry the "
                              "exFAT signature at offset 3.")
    (part, vol_len, fat_off, fat_len, heap, count, root, serial, rev, flags,
     bpss, spcs, nfats, drive, pct) = struct.unpack_from(
        "<QQIIIIIIHHBBBBB", data, 64)
    what = f"The {source} exFAT boot sector is not usable"
    if not 9 <= bpss <= 12:
        raise FileSystemError(f"{what}: a sector size of 2^{bpss} bytes is "
                              "not an exFAT value (2^9-2^12).")
    if spcs > 25 - bpss:
        raise FileSystemError(f"{what}: clusters of 2^{bpss + spcs} bytes "
                              "exceed the 32 MiB exFAT allows.")
    if nfats not in (1, 2):
        raise FileSystemError(f"{what}: it declares {nfats} FATs.")
    if fat_off < 24 or fat_len == 0 or heap < fat_off + fat_len * nfats \
            or count == 0:
        raise FileSystemError(f"{what}: its FAT (sector {fat_off}, "
                              f"{fat_len} sectors) and cluster heap (sector "
                              f"{heap}, {count} clusters) do not fit "
                              "together.")
    if not 2 <= root <= count + 1:
        raise FileSystemError(f"{what}: the root directory is placed at "
                              f"cluster {root}, outside 2-{count + 1}.")
    problems = []
    if any(data[11:64]):
        problems.append("The 53 bytes after the name, which exFAT requires "
                        "to be zero, are not.")
    if data[0:3] != b"\xeb\x76\x90":
        problems.append(f"The jump instruction is {data[0:3].hex()}, not "
                        "EB 76 90.")
    if data[510:512] != b"\x55\xaa":
        problems.append("The boot sector has no 55 AA end marker.")
    if rev >> 8 != 1:
        problems.append(f"File system revision {rev >> 8}.{rev & 0xFF:02d} is "
                        "not 1.x, the version this reader is written for.")
    if pct > 100 and pct != 0xFF:
        problems.append(f"PercentInUse is {pct}, which is not a percentage.")
    if count > (vol_len - heap) >> spcs:
        problems.append(f"{count:,} clusters do not fit between the cluster "
                        f"heap and the volume's end.")
    if fat_len * (1 << bpss) < (count + 2) * 4:
        problems.append("The FAT is too small for the cluster count.")
    return ExfatBoot(part, vol_len, fat_off, fat_len, heap, count, root,
                     serial, rev, flags, 1 << bpss, 1 << spcs, nfats, drive,
                     pct, source, tuple(problems))


class ExfatVolume(FatVolume):
    """An exFAT volume presented by `reader`, read-only. Use `open_fat`."""

    _alloc_source = "allocation bitmap"

    def __init__(self, reader, *, boot_at: int = 0,
                 problems: list | None = None) -> None:
        self.reader = reader
        self.fs_type = "exFAT"
        self.problems = list(problems or [])
        head = reader.read_at(boot_at, 512)
        source = "main" if boot_at == 0 else "backup"
        self.boot = boot = parse_exfat_boot(head, source)
        self.problems.extend(boot.problems)
        self.bytes_per_sector = bps = boot.bytes_per_sector
        self.cluster_size = boot.cluster_size
        self.cluster_count = boot.cluster_count
        self.max_cluster = boot.cluster_count + 1
        self._data_offset = boot.cluster_heap_offset * bps
        self.orphan_names, self.deleted_labels = [], []
        self.label_dir = None
        self._walk_problems_seen: set = set()
        self.volume_guid = None
        self.fsinfo = None
        self.clean_shutdown = not boot.volume_flags & 0x2
        self.hard_error = bool(boot.volume_flags & 0x4)
        if boot.size > reader.size:
            self.problems.append(
                f"The boot sector describes {boot.size:,} bytes but only "
                f"{reader.size:,} are present: the image or partition is "
                "truncated, and clusters beyond it cannot be read.")
        self._check_boot_regions(boot_at)
        self.mirroring = False
        self.active_fat = boot.volume_flags & 1 if boot.num_fats == 2 else 0
        need = (self.max_cluster + 1) * 4
        fat_bytes = boot.fat_length * bps
        self._fat = reader.read_at(
            boot.fat_offset * bps + self.active_fat * fat_bytes,
            min(need, fat_bytes))
        self._fat_get = self._make_fat_get()
        self._bitmap = b""
        self._upcase: dict | None = None
        self._reset_walk()
        self._load_root_metadata()

    def _check_boot_regions(self, boot_at: int) -> None:
        bps = self.bytes_per_sector
        main = self.reader.read_at(0, 12 * bps)
        backup = self.reader.read_at(12 * bps, 12 * bps)
        for name, region in (("main", main), ("backup", backup)):
            if len(region) < 12 * bps:
                self.problems.append(f"The {name} boot region is cut short "
                                     "by the end of the image.")
                continue
            want = exfat_boot_checksum(region[:11 * bps])
            words = struct.unpack_from(f"<{bps // 4}I", region, 11 * bps)
            wrong = [(k, w) for k, w in enumerate(words) if w != want]
            if wrong:
                k, w = wrong[0]
                self.problems.append(
                    f"The {name} boot region's checksum sector does not "
                    f"match its 11 sectors: computed 0x{want:08X}; "
                    f"{len(wrong)} of its {len(words)} copies differ, the "
                    f"first (word {k}) holding 0x{w:08X}.")
            for s in range(1, 9):
                if region[s * bps + bps - 4:s * bps + bps] != \
                        b"\x00\x00\x55\xaa":
                    self.problems.append(
                        f"Extended boot sector {s} of the {name} boot region "
                        "lacks its AA550000 signature.")
                    break
        if len(main) == len(backup) == 12 * bps:
            a, b = bytearray(main), bytearray(backup)
            for buf in (a, b):
                buf[106:108] = b"\0\0"
                buf[112] = 0
            if a != b:
                n, first = _diff(bytes(a), bytes(b))
                self.problems.append(
                    f"The backup boot region (sectors 12-23) differs from "
                    f"the main one in {n} byte(s), first at offset {first} "
                    "(VolumeFlags and PercentInUse, which only the main "
                    "region keeps current, excluded).")
        if boot_at:
            self.problems.append("The main boot sector could not be read; "
                                 "the BACKUP boot sector (sector 12) was "
                                 "used.")

    def cluster_offset(self, cluster: int) -> int:
        return self._data_offset + (cluster - 2) * self.cluster_size

    def is_allocated(self, cluster: int) -> bool:
        """What the allocation bitmap says now."""
        i = cluster - 2
        if i < 0 or (i >> 3) >= len(self._bitmap):
            return False
        return bool(self._bitmap[i >> 3] >> (i & 7) & 1)

    def _count_used(self) -> int:
        bm = self._bitmap[:(self.cluster_count + 7) // 8]
        n = int.from_bytes(bm, "little")
        n &= (1 << self.cluster_count) - 1
        return n.bit_count()

    def _read_meta_stream(self, first: int, length: int, what: str) -> bytes:
        runs, probs = self.follow_chain(first)
        got = sum(n for _s, n in runs) * self.cluster_size
        if probs or got < length:
            for p in probs:
                self.problems.append(f"{what}: {p}")
            runs = self._clip(first, -(-length // self.cluster_size),
                              self.problems)
            self.problems.append(f"{what} is read as contiguous clusters "
                                 "from its first cluster.")
        return self._read_runs(runs, max(length, 0) + self.cluster_size
                               ).data[:length]

    def _root_runs(self):
        runs, probs = self.follow_chain(self.boot.root_cluster,
                                        limit=MAX_EXFAT_DIR // self.cluster_size)
        return runs, probs

    def _load_root_metadata(self) -> None:
        runs, probs = self._root_runs()
        for p in probs:
            self.problems.append(f"Root directory chain: {p}")
        dd = self._read_runs(runs, MAX_EXFAT_DIR)
        bitmaps, upcase = [], None
        for pos, raw in dd.slots():
            t = raw[0]
            if t == 0:
                break
            if t == X_BITMAP:
                bitmaps.append(raw)
            elif t == X_UPCASE and upcase is None:
                upcase = raw
            elif t & 0x7F == X_LABEL & 0x7F:
                text = _utf16(raw[2:2 + min(raw[1], 11) * 2])
                if not t & 0x80:
                    self.deleted_labels.append(text)
                elif self.label_dir is None:
                    self.label_dir = text
            elif t == X_GUID and self.volume_guid is None:
                self.volume_guid = raw[6:22].hex()
        if not bitmaps:
            self.problems.append("The root directory holds no allocation "
                                 "bitmap entry; allocation cannot be "
                                 "measured.")
        else:
            pick = bitmaps[0]
            if self.boot.num_fats == 2 and len(bitmaps) > 1:
                pick = next((r for r in bitmaps if r[1] & 1 == self.active_fat),
                            bitmaps[0])
            first, length = struct.unpack_from("<IQ", pick, 20)
            need = (self.cluster_count + 7) // 8
            if length < need:
                self.problems.append(f"The allocation bitmap is {length:,} "
                                     f"bytes; {need:,} are needed.")
            self._bitmap = self._read_meta_stream(first, min(length, 1 << 30),
                                                  "The allocation bitmap")
        if upcase is None:
            self.problems.append("The root directory holds no up-case table "
                                 "entry; file-name hashes are not checked.")
        else:
            chk, = struct.unpack_from("<I", upcase, 4)
            first, length = struct.unpack_from("<IQ", upcase, 20)
            data = self._read_meta_stream(first, min(length, 1 << 20),
                                          "The up-case table")
            if exfat_table_checksum(data) != chk:
                self.problems.append("The up-case table does not match its "
                                     "checksum; file-name hashes are not "
                                     "checked.")
            else:
                self._upcase = parse_upcase(data)

    def _root_listing(self) -> list:
        runs, probs = self._root_runs()
        for p in probs:
            self._vol_problem(f"Root directory chain: {p}")
        self._dirs_seen[self.boot.root_cluster] = "the root directory"
        free = 0
        for s, n in runs:
            self._claim_dir_runs(s, n)
            free += sum(1 for c in range(s, s + n) if not self.is_allocated(c))
        if free and self._bitmap:
            self._vol_problem(f"{free} cluster(s) of the root directory's "
                              "chain are marked free in the allocation "
                              "bitmap.")
        dd = self._read_runs(runs, MAX_EXFAT_DIR)
        return self._parse_xdir(dd, path="", in_deleted=False, owner=None,
                                root=True)

    def _open_subdir(self, e: FatEntry) -> list | None:
        if not e.chain:
            return None
        first = e.first_cluster
        if first in self._dirs_seen:
            e.problems.append(f"Its first cluster {first} is already walked "
                              f"as {self._dirs_seen[first]}; not walked "
                              "again.")
            return None
        deleted_like = e.deleted or e.recovery_basis == "contiguous-assumption"
        if deleted_like and e.recoverable and e.recoverable["now_allocated"]:
            e.problems.append(
                f"{e.recoverable['now_allocated']} of its clusters are now "
                "allocated to something else; it is not walked as this "
                "deleted directory.")
            return None
        self._dirs_seen[first] = e.path
        dd = self._read_runs(e.chain, min(e.size or MAX_EXFAT_DIR,
                                          MAX_EXFAT_DIR))
        if e.size:
            dd.data = dd.data[:e.size]
        if deleted_like and not self._looks_like_xdir(dd.data):
            e.problems.append(f"Its first cluster {first} no longer holds "
                              "directory entries; it is not walked.")
            return None
        return self._parse_xdir(dd, path=e.path,
                                in_deleted=e.in_deleted_dir or e.deleted,
                                owner=e, root=False, partial=deleted_like,
                                hidden=e.past_end_marker)

    @staticmethod
    def _looks_like_xdir(data: bytes) -> bool:
        if len(data) < 64:
            return False
        t = data[0]
        if t == 0:
            return not any(data[:SLOT])
        return t & 0x7F == X_FILE & 0x7F and data[SLOT] & 0x7F == X_STREAM & 0x7F

    # -- exFAT directory parsing ----------------------------------------------------
    def _parse_xdir(self, dd: _DirData, *, path: str, in_deleted: bool, owner,
                    root: bool, partial: bool = False,
                    hidden: bool = False) -> list:
        report = (owner.problems.append if owner is not None
                  else self._vol_problem)
        where = f"'{path}'" if path else "the root directory"
        data = dd.data
        n = len(data) // SLOT
        out: list = []
        stray: list = []
        i = 0
        past_end = False

        def flush_stray():
            if not stray:
                return
            text = _utf16(b"".join(r[2:32] for _o, r in stray)).rstrip("\0")
            self.orphan_names.append({
                "directory": path, "dir_entry_offset": stray[0][0],
                "slots": len(stray), "deleted": not stray[0][1][0] & 0x80,
                "checksum": None, "text": text, "reported_on_entry": False})
            stray.clear()

        while i < n:
            pos = i * SLOT
            raw = data[pos:pos + SLOT]
            t = raw[0]
            if t == 0x00:
                flush_stray()
                if not past_end:
                    if not any(data[pos:]):
                        break
                    report(_past_end_report(dd, pos, where))
                    past_end = True
                i += 1
                continue
            in_use = bool(t & 0x80)
            full = t | 0x80
            if full not in _X_KNOWN:
                if past_end:
                    i += 1
                    continue
                if partial:
                    report(f"The slot at volume offset {dd.offset(pos)} is "
                           f"not a known entry type (0x{t:02X}); the rest of "
                           "this deleted directory is not read.")
                    break
                if in_use and not t & 0x20:
                    report(f"An unknown critical entry type 0x{t:02X} at "
                           f"volume offset {dd.offset(pos)}; skipped.")
                i += 1
                continue
            if full == X_NAME and not in_use:
                stray.append((dd.offset(pos), raw))
                i += 1
                continue
            flush_stray()
            if full == X_FILE:
                e, used = self._entry_set(dd, i, n, path, in_deleted,
                                          report if not past_end else
                                          (lambda _m: None),
                                          hidden or past_end)
                if e is not None:
                    out.append(e)
                i += max(1, used)
                continue
            if full in (X_STREAM, X_NAME, X_VENDOR, X_VENDOR_ALLOC) \
                    and in_use and not past_end:
                report(f"A secondary entry (0x{t:02X}) at volume offset "
                       f"{dd.offset(pos)} belongs to no entry set.")
            i += 1
        flush_stray()
        up = self._upcase
        if up is None:
            self._check_names(out, str.upper)
        else:
            self._check_names(out, lambda t: "".join(
                chr(up.get(ord(c), ord(c))) if ord(c) < 0x10000 else c
                for c in t))
        return out

    def _entry_set(self, dd, i, n, path, in_deleted, report,
                   past_end=False):
        """Parse the File entry set starting at slot i → (entry, slots used)."""
        data = dd.data
        primary = data[i * SLOT:(i + 1) * SLOT]
        deleted = not primary[0] & 0x80
        off = dd.offset(i * SLOT)
        sec = primary[1]
        problems: list[str] = []
        if not 2 <= sec <= 18:
            problems.append(f"The entry set declares {sec} secondary "
                            "entries; a file has 2 to 18.")
        slots = [primary]
        for k in range(1, sec + 1):
            if i + k >= n:
                problems.append("The entry set runs past the directory's "
                                "end.")
                break
            raw = data[(i + k) * SLOT:(i + k + 1) * SLOT]
            t = raw[0]
            if not t & 0x40 or bool(t & 0x80) != (not deleted):
                problems.append(
                    f"Secondary {k} of {sec} is "
                    f"{'a primary' if not t & 0x40 else 'in use' if deleted else 'not in use'}"
                    f" (0x{t:02X}); the set "
                    + ("was partly overwritten by later entries."
                       if deleted else "is broken there."))
                break
            slots.append(raw)
        if len(slots) < 2 or slots[1][0] | 0x80 != X_STREAM:
            what = "deleted " if deleted else ""
            if not deleted:
                report(f"A {what}file entry at volume offset {off} has no "
                       "stream extension entry after it; skipped.")
            return None, len(slots)
        stream = slots[1]
        flags, name_len, name_hash = stream[1], stream[3], \
            struct.unpack_from("<H", stream, 4)[0]
        vdl, = struct.unpack_from("<Q", stream, 8)
        first, size = struct.unpack_from("<IQ", stream, 20)
        names = [r for r in slots[2:] if r[0] | 0x80 == X_NAME]
        text = _utf16(b"".join(r[2:32] for r in names))
        name = text[:name_len]
        if len(text) < name_len:
            problems.append(f"The name should be {name_len} characters; "
                            f"only {len(text)} are present.")
        complete = len(slots) == sec + 1
        if complete:
            blob = bytearray(b"".join(slots))
            if deleted:
                for k in range(0, len(blob), SLOT):
                    blob[k] |= 0x80
            stored, = struct.unpack_from("<H", primary, 2)
            got = exfat_set_checksum(bytes(blob))
            if got != stored:
                problems.append(f"Entry set checksum mismatch: stored "
                                f"0x{stored:04X}, computed 0x{got:04X}.")
        if self._upcase is not None and len(name) == name_len:
            h = exfat_name_hash(name, self._upcase)
            if h != name_hash:
                problems.append(f"Name hash mismatch: stored 0x{name_hash:04X}"
                                f", computed 0x{h:04X} for '{name}'.")
        attrs, = struct.unpack_from("<H", primary, 4)
        ct, mt, at = struct.unpack_from("<III", primary, 8)
        c10, m10, co, mo, ao = primary[20:25]
        e = FatEntry(
            fs="exFAT", path=_join(path, name), name=name,
            short_name="", long_name=name, is_dir=bool(attrs & ATTR_DIR),
            deleted=deleted, size=size, first_cluster=first,
            attributes=attrs, created=exfat_time(ct, c10, co),
            modified=exfat_time(mt, m10, mo), accessed=exfat_time(at, 0, ao),
            dir_entry_offset=off, set_offset=off, slots=len(slots),
            in_deleted_dir=in_deleted, past_end_marker=past_end,
            problems=problems, valid_data_length=vdl,
            no_fat_chain=bool(flags & 0x2))
        if past_end:
            problems.insert(0, PAST_END_NOTE)
        if vdl > size:
            problems.append(f"Valid data length {vdl:,} exceeds the data "
                            f"length {size:,}.")
        if not flags & 0x1 and (first or size):
            problems.append("AllocationPossible is clear but a first cluster "
                            "or size is recorded.")
        self._settle_xchain(e)
        return e, len(slots)

    def _settle_xchain(self, e: FatEntry) -> None:
        cs = self.cluster_size
        need = -(-e.size // cs)
        first = e.first_cluster
        if first == 0 or need == 0:
            if e.size and first == 0:
                e.problems.append(f"The size is {e.size:,} bytes but no first "
                                  "cluster is recorded.")
            return
        if not 2 <= first <= self.max_cluster:
            e.problems.append(f"The first cluster {first} is outside the "
                              f"volume's clusters (2-{self.max_cluster}).")
            return
        if e.is_dir and e.size % cs:
            e.problems.append(f"A directory of {e.size:,} bytes is not a "
                              "whole number of clusters.")
        orphaned = e.deleted or e.in_deleted_dir or e.past_end_marker
        if e.no_fat_chain:
            e.chain = self._clip(first, need, e.problems)
            e.recovery_basis = "contiguous-nofatchain"
        elif e.deleted:
            runs, probs = self.follow_chain(first, limit=need + 1)
            if not probs and sum(n for _s, n in runs) == need:
                e.chain = runs
                e.recovery_basis = "fat-chain-left-after-deletion"
            else:
                e.chain = self._clip(first, need, e.problems)
                e.recovery_basis = "contiguous-assumption"
        else:
            limit = MAX_EXFAT_DIR // cs if e.is_dir else None
            e.chain, probs = self.follow_chain(first, limit=limit)
            e.problems.extend(probs)
            e.recovery_basis = "fat-chain"
            got = e.clusters
            if got < need:
                e.problems.append(f"Chain shorter than size: {got} cluster(s) "
                                  f"for {e.size:,} bytes, which need {need}.")
            elif got > need:
                e.problems.append(f"Chain longer than size: {got} cluster(s) "
                                  f"for {e.size:,} bytes, which need {need}.")
        if orphaned:
            e.recoverable = self.measure_allocation(e.chain, need)
            return
        free = sum(1 for s, n in e.chain for c in range(s, s + n)
                   if not self.is_allocated(c))
        if free:
            e.problems.append(f"{free} of its {e.clusters} cluster(s) are "
                              "marked free in the allocation bitmap.")
        self._claim(e)

    def info(self) -> dict:
        b = self.boot
        used = self.used_clusters()
        return {
            "fs_type": "exFAT", "oem": "EXFAT", "label": self.label_dir or "",
            "label_boot": None, "label_dir": self.label_dir,
            "deleted_labels": list(self.deleted_labels),
            "serial": _serial_text(b.serial), "serial_raw": b.serial,
            "volume_guid": self.volume_guid,
            "bytes_per_sector": b.bytes_per_sector,
            "sectors_per_cluster": b.sectors_per_cluster,
            "cluster_size": self.cluster_size,
            "total_clusters": self.cluster_count, "used_clusters": used,
            "free_clusters": self.cluster_count - used,
            "percent_in_use_reported": (None if b.percent_in_use == 0xFF
                                        else b.percent_in_use),
            "percent_in_use_counted": round(100 * used / self.cluster_count),
            "num_fats": b.num_fats, "active_fat": self.active_fat,
            "volume_dirty": not self.clean_shutdown,
            "media_failure": self.hard_error,
            "revision": f"{b.revision >> 8}.{b.revision & 0xFF:02d}",
            "partition_offset_reported": b.partition_offset,
            "volume_size": b.size, "image_size": self.reader.size,
            "boot_source": b.source, "problems": list(self.problems)}


# ---------------------------------------------------------------------------
# opening
# ---------------------------------------------------------------------------

def open_fat(reader) -> FatVolume:
    """The FAT12/16/32 or exFAT volume `reader` presents.

    Raises FileSystemError, with a sentence saying why, when neither the
    first sector nor a backup boot sector (FAT32 sector 6, exFAT sector 12)
    is a FAT or exFAT boot sector."""
    if reader.size < 512:
        raise FileSystemError("The volume is smaller than one sector; there "
                              "is no boot sector to read.")
    head = reader.read_at(0, 512)
    try:
        if head[3:11] == b"EXFAT   ":
            return ExfatVolume(reader)
        boot = parse_fat_boot(head, "primary")
    except FileSystemError as exc:
        for bps in (512, 1024, 2048, 4096):
            sec = reader.read_at(12 * bps, 512)
            if len(sec) == 512 and sec[3:11] == b"EXFAT   " and \
                    sec[108] == bps.bit_length() - 1:
                try:
                    return ExfatVolume(reader, boot_at=12 * bps)
                except FileSystemError:
                    pass
            if head[3:11] == b"EXFAT   ":
                continue
            sec = reader.read_at(6 * bps, 512)
            try:
                backup = parse_fat_boot(sec, "backup")
            except FileSystemError:
                continue
            if backup.fat_type == "FAT32" and backup.bytes_per_sector == bps \
                    and backup.backup_boot_sector == 6:
                return FatVolume(reader, backup, [
                    f"The primary boot sector could not be read ({exc}) The "
                    "BACKUP boot sector (sector 6) was used."])
        if not any(head):
            raise FileSystemError("The first sector is all zeroes and no "
                                  "backup boot sector was found: this is not "
                                  "a FAT or exFAT volume, or its start is "
                                  "wiped.") from None
        raise FileSystemError(f"This is neither a FAT nor an exFAT volume: "
                              f"{exc}") from None
    return FatVolume(reader, boot)


# ---------------------------------------------------------------------------
# artefact rows
# ---------------------------------------------------------------------------

def _when(t: FatTime | None) -> str:
    if t is None or t.value is None:
        return "no time recorded"
    text = t.value.replace("T", " ").replace("Z", "").replace(".000000", "")
    return text + (" UTC" if t.is_utc else " local (no zone recorded)")


def _entry_row(e: FatEntry) -> dict:
    kind = "exfat-entry" if e.fs == "exFAT" else "fat-entry"
    m = e.modified
    state = "deleted " if e.deleted else ""
    if e.in_deleted_dir and not e.deleted:
        state = "in deleted folder: "
    if e.past_end_marker:
        state = "past end-of-directory marker: " + state
    what = "folder" if e.is_dir else "file"
    value = f"{state}{what} {e.path}"
    if not e.is_dir:
        value += f" · {e.size:,} bytes"
    value += f" · modified {_when(m)}"
    detail = {"fs": e.fs, "name": e.name, "is_dir": e.is_dir,
              "deleted": e.deleted, "size": e.size,
              "first_cluster": e.first_cluster,
              "attributes": e.attribute_names,
              "dir_entry_offset": e.dir_entry_offset}
    if e.short_name and e.short_name != e.name:
        detail["short_name"] = e.short_name
    for k in ("created", "modified", "accessed"):
        t = getattr(e, k)
        if t is not None and (t.raw or t.value):
            detail[k] = t.as_dict()
    if e.in_deleted_dir:
        detail["in_deleted_dir"] = True
    if e.past_end_marker:
        detail["past_end_marker"] = True
    if e.deleted:
        detail["found_as"] = ("FAT directory entry marked 0xE5"
                              if e.fs != "exFAT" else
                              "exFAT entry set with InUse clear")
    if e.name_note:
        detail["name_note"] = e.name_note
    if e.short_name_inferred:
        detail["short_name_inferred"] = e.short_name_inferred
    if e.recovery_basis not in ("fat-chain", "none"):
        detail["recovery_basis"] = e.recovery_basis
    if e.recoverable is not None:
        detail["recoverable"] = e.recoverable
    if len(e.chain) > 1:
        detail["fragments"] = len(e.chain)
    if e.valid_data_length is not None and e.valid_data_length != e.size:
        detail["valid_data_length"] = e.valid_data_length
    if e.problems:
        detail["problems"] = list(e.problems)
    return {"artefact": kind,
            "at_utc": m.value if m is not None and m.is_utc else None,
            "at_raw": m.raw if m is not None and m.raw else None,
            "at_epoch": m.epoch if m is not None and m.raw else None,
            "title": e.path, "value": value, "detail": detail,
            "row_ref_suffix": f"{'x' if e.fs == 'exFAT' else 'f'}"
                              f"{e.dir_entry_offset}"}


def to_rows(vol_or_entries, *, source_path: str) -> list[dict]:
    """One row per entry (`fat-entry` / `exfat-entry`), plus — when given a
    volume — one `fat-volume` / `exfat-volume` row carrying the volume's
    facts and problems, so a damaged boot sector or FAT is not lost from the
    corpus. A FAT time is local with no zone, so `at_utc` is None for it and
    the raw value and its epoch are given instead."""
    vol = vol_or_entries if isinstance(vol_or_entries, FatVolume) else None
    entries = list(vol.entries() if vol is not None else vol_or_entries)
    rows = [_entry_row(e) for e in entries]
    seen: dict = {}
    for r in rows:
        k = r["row_ref_suffix"]
        if k in seen:
            seen[k] += 1
            r["row_ref_suffix"] = f"{k}#{seen[k]}"
        else:
            seen[k] = 0
    if vol is not None:
        info = vol.info()
        kind = "exfat-volume" if vol.fs_type == "exFAT" else "fat-volume"
        deleted = sum(1 for e in entries if e.deleted)
        orphans = vol.orphan_names
        info["entries"] = len(entries)
        info["deleted_entries"] = deleted
        info["orphan_names"] = orphans[:200]
        info["orphan_names_total"] = len(orphans)
        info["source_path"] = source_path
        label = f" '{info['label']}'" if info.get("label") else ""
        rows.append({
            "artefact": kind, "at_utc": None, "at_raw": None,
            "at_epoch": None, "title": f"{vol.fs_type} volume{label}",
            "value": (f"{vol.fs_type}{label} serial {info['serial']} · "
                      f"{len(entries):,} entries, {deleted:,} deleted · "
                      f"{len(info['problems'])} problem(s)"),
            "detail": info, "row_ref_suffix": "volume"})
    return rows
