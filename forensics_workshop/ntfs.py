# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""NTFS from the bytes: boot sector, $MFT records, attributes, data runs, $Bitmap.

Nothing here mounts anything or asks an operating system what a file is. The
volume is a byte stream (a partition in an image) and every structure is
parsed from it, so what a deleted, damaged or hidden record says is visible
exactly as it is on the disk.

**What the parser checks, and what it does with damage.** Every record's
update sequence array is applied and CHECKED — a mismatch at a sector's end
is the signature of a torn write or corruption, and is reported on the
record rather than silently patched over. Attribute lengths, value offsets
and data runs are bounds-checked; a record that fails one is kept with a
problem named, because a damaged record is itself evidence. A structure that
cannot be read at all raises `FileSystemError`.

**Content that is not plain is refused, not returned.** A compressed (LZNT1)
or EFS-encrypted stream stored on disk is not the file's content, and
returning it as though it were would put garbage in a report looking like a
recovered file. Such a stream is described — sizes, runs, flags — and its
content is refused with the reason.

**Deleted is a state of the record, not a verdict on the data.** A record
whose in-use flag is clear may still hold its name, its timestamps and its
run list; the clusters those runs point to may since have been given to
another file. `count_allocated` measures that against `$Bitmap`, so a
recovery can say how many of a deleted file's clusters are now in use by
something else — the difference between "recovered" and "these bytes are
probably someone else's".

**Paths are rebuilt from `$FILE_NAME` parent references, and each step is
checked against the parent's sequence number.** A deleted file whose parent
folder's record has since been reused would otherwise be shown inside a
folder it was never in. NTFS increments a record's sequence number when it
is freed, so a parent that is itself deleted (but not reused) still
matches; one that has been reused does not, and the path says so.

**Timestomp indicators are measurements, never conclusions.** Each one names
the comparison made and the ordinary operations that produce the same
pattern (copy tools, archives, restores). What it means is the examiner's
call, recorded in the findings store — never here.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

from . import timeutil
from .errors import Cancelled, FileSystemError

CHUNK = 1 << 20
ROOT = 5
EXTEND = 11

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM",
}

NAMESPACES = {0: "POSIX", 1: "Win32", 2: "DOS", 3: "Win32+DOS"}

#: Which $FILE_NAME to show when a record has several: the long name first.
NAMESPACE_PREFERENCE = {1: 0, 3: 0, 0: 1, 2: 2}

SYSTEM_FILES = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume",
                4: "$AttrDef", 5: ".", 6: "$Bitmap", 7: "$Boot",
                8: "$BadClus", 9: "$Secure", 10: "$UpCase", 11: "$Extend"}

FLAG_IN_USE = 0x0001
FLAG_DIRECTORY = 0x0002

ATTR_COMPRESSED = 0x0001
ATTR_ENCRYPTED = 0x4000
ATTR_SPARSE = 0x8000

FILE_ATTRIBUTES = {
    0x1: "read-only", 0x2: "hidden", 0x4: "system", 0x20: "archive",
    0x40: "device", 0x80: "normal", 0x100: "temporary", 0x200: "sparse",
    0x400: "reparse-point", 0x800: "compressed", 0x1000: "offline",
    0x2000: "not-content-indexed", 0x4000: "encrypted",
    0x10000000: "directory", 0x20000000: "index-view"}

COMPRESSED_REFUSAL = (
    "This stream is NTFS-compressed (LZNT1). What is on disk is compressed "
    "data, not the file's content, and this version does not decompress it; "
    "returning it would put garbage in a report looking like a recovered "
    "file. Its sizes and runs are recorded.")
ENCRYPTED_REFUSAL = (
    "This stream is EFS-encrypted. What is on disk is ciphertext; without the "
    "user's key it is not the file's content. Decryption is out of scope.")

INDICATORS = {
    "si-created-before-fn-created": (
        "$STANDARD_INFORMATION creation time is earlier than $FILE_NAME "
        "creation time.",
        "Copy and archive tools that preserve creation times (robocopy, "
        "7-Zip, installers), and restores from backup, set "
        "$STANDARD_INFORMATION and leave $FILE_NAME at the time of the copy."),
    "si-whole-seconds": (
        "All four $STANDARD_INFORMATION timestamps are whole seconds, while "
        "at least one $FILE_NAME timestamp is not.",
        "Files that came from FAT or exFAT media, or from an archive storing "
        "2-second DOS times, can carry whole-second times legitimately."),
    "si-changed-before-created": (
        "$STANDARD_INFORMATION's entry-changed time is earlier than its "
        "creation time — the file system sets the changed time itself on "
        "every metadata change.",
        "The system clock being set backwards between the file's creation "
        "and a later change produces the same pattern."),
}


def _utf16(raw: bytes) -> str:
    """UTF-16LE as NTFS stores it — which permits unpaired surrogates. Those
    are kept as `\\udXXX` escapes rather than replaced, so a name is never
    silently altered on its way into a report."""
    text = bytes(raw).decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def split_reference(ref: int) -> tuple[int, int]:
    """A 64-bit file reference → (record number, sequence number)."""
    return ref & 0xFFFFFFFFFFFF, ref >> 48


def next_sequence(seq: int) -> int:
    """What a record's sequence becomes when NTFS frees it (0 stays 0)."""
    if seq == 0:
        return 0
    return 1 if seq == 0xFFFF else seq + 1


# ---------------------------------------------------------------------------
# boot sector
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BootSector:
    oem: str
    bytes_per_sector: int
    sectors_per_cluster: int
    cluster_size: int
    total_sectors: int
    mft_lcn: int
    mftmirr_lcn: int
    record_size: int
    index_block_size: int
    serial: int
    source: str
    problems: tuple

    @property
    def size(self) -> int:
        return self.total_sectors * self.bytes_per_sector

    @property
    def total_clusters(self) -> int:
        return self.total_sectors // self.sectors_per_cluster

    @property
    def serial_short(self) -> str:
        low = self.serial & 0xFFFFFFFF
        return f"{low >> 16:04X}-{low & 0xFFFF:04X}"

    def as_dict(self) -> dict:
        return {"oem": self.oem, "bytes_per_sector": self.bytes_per_sector,
                "sectors_per_cluster": self.sectors_per_cluster,
                "cluster_size": self.cluster_size,
                "total_sectors": self.total_sectors,
                "total_clusters": self.total_clusters, "size": self.size,
                "mft_lcn": self.mft_lcn, "mftmirr_lcn": self.mftmirr_lcn,
                "record_size": self.record_size,
                "index_block_size": self.index_block_size,
                "serial": f"{self.serial:016X}",
                "serial_short": self.serial_short, "source": self.source,
                "problems": list(self.problems)}


def _size_field(raw: int, cluster: int) -> int:
    """Clusters-per-record/index fields: positive = clusters, negative = 2^-n bytes."""
    return (1 << -raw) if raw < 0 else raw * cluster


def parse_boot_sector(data: bytes, source: str = "primary") -> BootSector:
    if len(data) < 512 or data[3:11] != b"NTFS    ":
        raise FileSystemError(f"The {source} boot sector does not carry the "
                              "NTFS signature at offset 3.")
    bps = struct.unpack_from("<H", data, 0x0B)[0]
    raw_spc = data[0x0D]
    spc = (1 << (256 - raw_spc)) if raw_spc > 0x80 else raw_spc
    problems = []
    if bps not in (512, 1024, 2048, 4096):
        raise FileSystemError(f"{bps} bytes per sector is not an NTFS value.")
    if spc <= 0 or spc & (spc - 1):
        raise FileSystemError(f"{spc} sectors per cluster is not a power of two.")
    cluster = bps * spc
    total_sectors, mft_lcn, mirr_lcn = struct.unpack_from("<QQQ", data, 0x28)
    rec_raw = struct.unpack_from("<b", data, 0x40)[0]
    idx_raw = struct.unpack_from("<b", data, 0x44)[0]
    record_size = _size_field(rec_raw, cluster)
    index_size = _size_field(idx_raw, cluster)
    if record_size not in (512, 1024, 2048, 4096) or record_size % bps:
        raise FileSystemError(f"An MFT record size of {record_size} bytes is "
                              "not plausible.")
    serial = struct.unpack_from("<Q", data, 0x48)[0]
    if data[510:512] != b"\x55\xaa":
        problems.append("The boot sector has no 55 AA end marker.")
    if mft_lcn * spc >= total_sectors:
        raise FileSystemError(f"$MFT is placed at cluster {mft_lcn}, beyond "
                              "the volume's end.")
    return BootSector(data[3:11].decode("ascii"), bps, spc, cluster,
                      total_sectors, mft_lcn, mirr_lcn, record_size,
                      index_size, serial, source, tuple(problems))


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass
class Attribute:
    type: int
    name: str
    flags: int
    id: int
    resident: bool
    record: int
    value: bytes = b""
    start_vcn: int = 0
    last_vcn: int = 0
    runs: list = field(default_factory=list)
    alloc_size: int = 0
    data_size: int = 0
    init_size: int = 0
    compression_unit: int = 0


@dataclass(frozen=True)
class StandardInfo:
    created: int
    modified: int
    changed: int
    accessed: int
    attributes: int
    owner_id: int | None
    security_id: int | None
    usn: int | None


@dataclass(frozen=True)
class FileName:
    parent_record: int
    parent_sequence: int
    created: int
    modified: int
    changed: int
    accessed: int
    alloc_size: int
    real_size: int
    flags: int
    namespace: int
    name: str

    @property
    def namespace_name(self) -> str:
        return NAMESPACES.get(self.namespace, f"unknown ({self.namespace})")


@dataclass
class Stream:
    name: str
    resident: bool
    flags: int
    data_size: int
    alloc_size: int
    init_size: int
    runs: list
    value: bytes
    compression_unit: int
    pieces: int

    @property
    def compressed(self) -> bool:
        return bool(self.flags & ATTR_COMPRESSED)

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & ATTR_ENCRYPTED)

    @property
    def sparse(self) -> bool:
        return bool(self.flags & ATTR_SPARSE)

    def runs_as_list(self) -> list:
        return [[v, l, n] for v, l, n in self.runs]


@dataclass
class MftEntry:
    record: int
    signature: str
    sequence: int
    lsn: int
    flags: int
    link_count: int
    base_record: int
    base_sequence: int
    used_size: int
    stored_number: int | None
    fixup_ok: bool
    attributes: list
    problems: list
    si: StandardInfo | None = None
    names: list = field(default_factory=list)
    streams: list = field(default_factory=list)
    has_attribute_list: bool = False
    other_types: list = field(default_factory=list)

    @property
    def in_use(self) -> bool:
        return bool(self.flags & FLAG_IN_USE)

    @property
    def is_dir(self) -> bool:
        return bool(self.flags & FLAG_DIRECTORY)

    @property
    def is_extension(self) -> bool:
        """An extension record points at its base. $MFT's own extensions
        point at record 0, so the SEQUENCE half is what tells them apart
        from a base record, whose reference field is entirely zero."""
        return self.base_record != 0 or self.base_sequence != 0

    def preferred_name(self) -> FileName | None:
        if not self.names:
            return None
        return min(self.names, key=lambda n: NAMESPACE_PREFERENCE.get(n.namespace, 3))

    def stream(self, name: str = "") -> Stream | None:
        for s in self.streams:
            if s.name == name:
                return s
        return None

    def ads(self) -> list:
        return [s for s in self.streams if s.name]

    def indicators(self) -> list[str]:
        return timestomp_indicators(self)


def apply_fixups(raw: bytes, sector_size: int) -> tuple[bytes, list[str], bool]:
    """Apply an MFT record's update sequence array, checking every sector.

    Returns (bytes, problems, every sector checked out)."""
    buf = bytearray(raw)
    problems: list[str] = []
    ok = True
    usa_off, usa_count = struct.unpack_from("<HH", buf, 4)
    if usa_count < 1 or usa_off + usa_count * 2 > len(buf):
        problems.append(f"Update sequence array at {usa_off} with {usa_count} "
                        "entries does not fit the record; fixups not applied.")
        return bytes(buf), problems, False
    if (usa_count - 1) * sector_size != len(buf):
        problems.append(f"The update sequence array covers {usa_count - 1} "
                        f"sectors of {sector_size} bytes but the record is "
                        f"{len(buf)} bytes.")
    usn = bytes(buf[usa_off:usa_off + 2])
    for i in range(1, usa_count):
        pos = i * sector_size - 2
        if pos + 2 > len(buf):
            break
        if bytes(buf[pos:pos + 2]) != usn:
            problems.append(
                f"Update sequence mismatch at the end of sector {i}: the "
                "record was torn mid-write or has been corrupted, and that "
                "sector's last two bytes are left as found.")
            ok = False
            continue
        buf[pos:pos + 2] = buf[usa_off + 2 * i:usa_off + 2 * i + 2]
    return bytes(buf), problems, ok


def decode_runs(data: bytes, start_vcn: int = 0) -> tuple[list, list[str]]:
    """A data run list → [(vcn, lcn or None for sparse, clusters)], problems."""
    runs: list = []
    problems: list[str] = []
    pos, lcn, vcn = 0, 0, start_vcn
    while pos < len(data):
        header = data[pos]
        if header == 0:
            return runs, problems
        len_size, off_size = header & 0x0F, header >> 4
        if not 1 <= len_size <= 8 or off_size > 8 or \
                pos + 1 + len_size + off_size > len(data):
            problems.append(f"A malformed data run at byte {pos} of the run "
                            "list; the runs after it are not known.")
            return runs, problems
        length = int.from_bytes(data[pos + 1:pos + 1 + len_size], "little")
        if length == 0:
            problems.append(f"A zero-length data run at byte {pos}.")
            return runs, problems
        if off_size == 0:
            runs.append((vcn, None, length))
        else:
            delta = int.from_bytes(
                data[pos + 1 + len_size:pos + 1 + len_size + off_size],
                "little", signed=True)
            lcn += delta
            if lcn < 0:
                problems.append(f"A data run points to negative cluster {lcn}.")
                return runs, problems
            runs.append((vcn, lcn, length))
        vcn += length
        pos += 1 + len_size + off_size
    problems.append("The run list has no terminating zero byte.")
    return runs, problems


def parse_record(raw: bytes, number: int, sector_size: int) -> MftEntry | None:
    """One MFT record's header and attributes. None for an empty record.

    Attribute lists are NOT followed here — that needs the volume;
    `NtfsVolume.entry` does it. Derived fields (names, streams, times) are
    filled by `assemble`.
    """
    if len(raw) < 48:
        return None
    sig = raw[:4]
    if sig not in (b"FILE", b"BAAD"):
        return None
    if sig == b"BAAD":
        return MftEntry(number, "BAAD", 0, 0, 0, 0, 0, 0, 0, None, False, [],
                        ["Marked BAAD: chkdsk found this record damaged and "
                         "gave up on it. Nothing in it is parsed."])
    buf, problems, fixup_ok = apply_fixups(raw, sector_size)
    lsn, seq, links, attr_off, flags, used, alloc, base_ref, _next_id = \
        struct.unpack_from("<QHHHHIIQH", buf, 8)
    stored = struct.unpack_from("<I", buf, 44)[0] if attr_off >= 0x30 else None
    base_record, base_seq = split_reference(base_ref)
    entry = MftEntry(number, "FILE", seq, lsn, flags, links, base_record,
                     base_seq, used, stored, fixup_ok, [], problems)
    if stored is not None and stored != number:
        problems.append(f"The record says it is number {stored}, but it was "
                        f"read as number {number}.")
    limit = len(buf)
    if used > len(buf):
        problems.append(f"The record claims {used} bytes in use, more than "
                        f"its {len(buf)}-byte size.")
    else:
        limit = used
    pos = attr_off
    seen = 0
    while pos + 16 <= limit and seen < 512:
        seen += 1
        atype, alen = struct.unpack_from("<II", buf, pos)
        if atype == 0xFFFFFFFF:
            break
        if alen < 16 or pos + alen > len(buf):
            problems.append(f"The attribute at offset {pos} (type 0x{atype:X}) "
                            f"has an impossible length {alen}; parsing stopped.")
            break
        nonres, name_len, name_off, aflags, aid = struct.unpack_from(
            "<BBHHH", buf, pos + 8)
        name = ""
        if name_len:
            if name_off + name_len * 2 > alen:
                problems.append(f"Attribute 0x{atype:X} at {pos} has a name "
                                "outside itself.")
            else:
                name = _utf16(buf[pos + name_off:pos + name_off + name_len * 2])
        if not nonres:
            if alen < 24:
                problems.append(f"Resident attribute 0x{atype:X} at {pos} is "
                                "too short for its header.")
                pos += alen
                continue
            vlen, voff = struct.unpack_from("<IH", buf, pos + 16)
            if voff + vlen > alen:
                problems.append(f"Resident attribute 0x{atype:X} at {pos}: its "
                                "value runs past the attribute's end.")
                value = bytes(buf[pos + voff:pos + alen])
            else:
                value = bytes(buf[pos + voff:pos + voff + vlen])
            entry.attributes.append(Attribute(atype, name, aflags, aid, True,
                                              number, value=value))
        else:
            if alen < 0x40:
                problems.append(f"Non-resident attribute 0x{atype:X} at {pos} "
                                "is too short for its header.")
                pos += alen
                continue
            start_vcn, last_vcn, runs_off, cu = struct.unpack_from(
                "<QQHH", buf, pos + 16)
            alloc_size, data_size, init_size = struct.unpack_from(
                "<QQQ", buf, pos + 40)
            runs, run_problems = decode_runs(buf[pos + runs_off:pos + alen],
                                             start_vcn)
            for p in run_problems:
                problems.append(f"Attribute 0x{atype:X} '{name}': {p}")
            entry.attributes.append(Attribute(
                atype, name, aflags, aid, False, number, start_vcn=start_vcn,
                last_vcn=last_vcn, runs=runs, alloc_size=alloc_size,
                data_size=data_size, init_size=init_size,
                compression_unit=cu))
        pos += alen
    assemble(entry)
    return entry


def assemble(entry: MftEntry) -> None:
    """Fill names, $STANDARD_INFORMATION and streams from the attributes."""
    entry.names, entry.streams, entry.si = [], [], None
    others = set()
    data_pieces: dict[str, list] = {}
    for a in entry.attributes:
        if a.type == 0x10 and a.resident and entry.si is None:
            v = a.value
            if len(v) >= 48:
                created, modified, changed, accessed, attrs = struct.unpack_from(
                    "<QQQQI", v, 0)
                owner = security = usn = None
                if len(v) >= 72:
                    owner, security = struct.unpack_from("<II", v, 48)
                    usn = struct.unpack_from("<Q", v, 64)[0]
                entry.si = StandardInfo(created, modified, changed, accessed,
                                        attrs, owner, security, usn)
            else:
                entry.problems.append("$STANDARD_INFORMATION is too short.")
        elif a.type == 0x30 and a.resident:
            v = a.value
            if len(v) < 66:
                entry.problems.append("A $FILE_NAME attribute is too short.")
                continue
            parent = struct.unpack_from("<Q", v, 0)[0]
            created, modified, changed, accessed, alloc, real, fflags = \
                struct.unpack_from("<QQQQQQI", v, 8)
            nlen, ns = v[64], v[65]
            if 66 + nlen * 2 > len(v):
                entry.problems.append("A $FILE_NAME's name runs past its end.")
                continue
            pr, ps = split_reference(parent)
            entry.names.append(FileName(pr, ps, created, modified, changed,
                                        accessed, alloc, real, fflags, ns,
                                        _utf16(v[66:66 + nlen * 2])))
        elif a.type == 0x80:
            data_pieces.setdefault(a.name, []).append(a)
        elif a.type == 0x20:
            entry.has_attribute_list = True
        elif a.type in ATTR_NAMES:
            others.add(ATTR_NAMES[a.type])
    for name, pieces in data_pieces.items():
        pieces.sort(key=lambda a: a.start_vcn)
        first = pieces[0]
        if first.resident:
            entry.streams.append(Stream(name, True, first.flags,
                                        len(first.value), len(first.value),
                                        len(first.value), [], first.value, 0,
                                        len(pieces)))
            continue
        runs: list = []
        for piece in pieces:
            if piece.resident:
                entry.problems.append(f"Stream '{name}' mixes resident and "
                                      "non-resident pieces.")
                continue
            runs.extend(piece.runs)
        head = next((p for p in pieces if not p.resident and p.start_vcn == 0),
                    None)
        if head is None:
            entry.problems.append(f"Stream '{name}' has no piece starting at "
                                  "VCN 0 (its sizes live in another record "
                                  "that was not read).")
            head = pieces[0]
        entry.streams.append(Stream(name, False, head.flags, head.data_size,
                                    head.alloc_size, head.init_size, runs, b"",
                                    head.compression_unit, len(pieces)))
    entry.other_types = sorted(others)


def parse_attribute_list(value: bytes) -> list[tuple]:
    """$ATTRIBUTE_LIST → [(type, name, start_vcn, record, sequence, id)]."""
    out, pos = [], 0
    while pos + 26 <= len(value):
        atype, rlen, nlen, noff, svcn, ref, aid = struct.unpack_from(
            "<IHBBQQH", value, pos)
        if rlen < 26 or pos + rlen > len(value):
            break
        name = _utf16(value[pos + noff:pos + noff + nlen * 2]) if nlen else ""
        rec, seq = split_reference(ref)
        out.append((atype, name, svcn, rec, seq, aid))
        pos += rlen
    return out


def timestomp_indicators(entry: MftEntry) -> list[str]:
    """Which INDICATORS this record's timestamps show. Never a conclusion."""
    si = entry.si
    fn = entry.preferred_name()
    found: list[str] = []
    if si is None:
        return found
    if fn is not None and si.created and fn.created and si.created < fn.created:
        found.append("si-created-before-fn-created")
    si_times = (si.created, si.modified, si.changed, si.accessed)
    if fn is not None and all(si_times):
        fn_times = (fn.created, fn.modified, fn.changed, fn.accessed)
        if all(timeutil.filetime_fraction(t) == 0 for t in si_times) and any(
                (timeutil.filetime_fraction(t) or 0) != 0 for t in fn_times if t):
            found.append("si-whole-seconds")
    if si.changed and si.created and si.changed < si.created:
        found.append("si-changed-before-created")
    return found


# ---------------------------------------------------------------------------
# the volume
# ---------------------------------------------------------------------------

class NtfsVolume:
    """An NTFS volume presented by `reader` (read_at + size), read-only."""

    def __init__(self, reader, *, try_backup: bool = True) -> None:
        self.reader = reader
        self.problems: list[str] = []
        head = reader.read_at(0, 512)
        try:
            self.boot = parse_boot_sector(head, "primary")
        except FileSystemError as exc:
            if not try_backup or reader.size < 1024:
                raise
            try:
                self.boot = parse_boot_sector(
                    reader.read_at(reader.size - 512, 512), "backup")
            except FileSystemError:
                raise exc from None
            self.problems.append(
                f"The primary boot sector could not be read ({exc}). The "
                "BACKUP boot sector in the volume's last sector was used.")
        self.problems.extend(self.boot.problems)
        self.cluster = self.boot.cluster_size
        self.record_size = self.boot.record_size
        self.sector = self.boot.bytes_per_sector
        if self.boot.size > reader.size:
            self.problems.append(
                f"The boot sector describes {self.boot.size:,} bytes but only "
                f"{reader.size:,} are present: the image or partition is "
                "truncated, and clusters beyond it read as missing.")
        self._bitmap: bytes | None = None
        self.mft_runs: list = []
        self.mft_size = 0
        self._load_mft()

    # -- $MFT ---------------------------------------------------------------
    def _load_mft(self) -> None:
        raw = self.reader.read_at(self.boot.mft_lcn * self.cluster,
                                  self.record_size)
        first = parse_record(raw, 0, self.sector)
        source = "$MFT"
        if first is None or first.stream("") is None:
            raw = self.reader.read_at(self.boot.mftmirr_lcn * self.cluster,
                                      self.record_size)
            first = parse_record(raw, 0, self.sector)
            source = "$MFTMirr"
            if first is None or first.stream("") is None:
                raise FileSystemError("Neither $MFT record 0 nor its mirror "
                                      "could be read; the MFT cannot be "
                                      "located.")
            self.problems.append("$MFT record 0 was unreadable; its copy in "
                                 "$MFTMirr was used to locate the MFT.")
        data = first.stream("")
        self.mft_runs = list(data.runs)
        self.mft_size = data.data_size
        if first.has_attribute_list:
            self._extend_mft_runs(first)
        if first.problems:
            self.problems.extend(f"{source} record 0: {p}" for p in first.problems)

    def _extend_mft_runs(self, first: MftEntry) -> None:
        """A badly fragmented $MFT keeps some of its own runs in extension
        records, which can only be found through the runs already known.
        The attribute list is in start-VCN order, so following it in order
        extends the run list before each next extension is needed."""
        listed = next((a for a in first.attributes if a.type == 0x20), None)
        value = listed.value if listed.resident else self._read_runs(
            listed.runs, 0, min(listed.data_size, 1 << 24))
        pieces = [a for a in first.attributes
                  if a.type == 0x80 and not a.name and not a.resident]
        for atype, name, _svcn, rec, _seq, aid in parse_attribute_list(value):
            if atype != 0x80 or name or rec == 0:
                continue
            raw = self._read_runs(self.mft_runs, rec * self.record_size,
                                  self.record_size)
            ext = parse_record(raw, rec, self.sector)
            if ext is None or not ext.is_extension or ext.base_record != 0:
                self.problems.append(
                    f"$MFT's attribute list names record {rec} for part of "
                    "its data, and that record is not an extension of $MFT; "
                    "records beyond the runs already known cannot be read.")
                break
            pieces.extend(a for a in ext.attributes if a.type == 0x80
                          and not a.name and not a.resident and a.id == aid)
            runs: list = []
            for piece in sorted(pieces, key=lambda a: a.start_vcn):
                runs.extend(piece.runs)
            self.mft_runs = runs

    @property
    def record_count(self) -> int:
        return self.mft_size // self.record_size

    def read_record_bytes(self, number: int) -> bytes:
        if not 0 <= number < self.record_count:
            raise FileSystemError(f"Record {number} is outside the MFT "
                                  f"(0–{self.record_count - 1}).")
        return self._read_runs(self.mft_runs, number * self.record_size,
                               self.record_size)

    def entry(self, number: int, *, follow_list: bool = True) -> MftEntry | None:
        """One record, with its attribute list followed into extension records."""
        entry = parse_record(self.read_record_bytes(number), number, self.sector)
        if entry is not None and follow_list and entry.has_attribute_list \
                and not entry.is_extension:
            self._follow_attribute_list(entry)
        return entry

    def _follow_attribute_list(self, entry: MftEntry) -> None:
        listed = next((a for a in entry.attributes if a.type == 0x20), None)
        if listed is None:
            return
        value = listed.value if listed.resident else self._read_runs(
            listed.runs, 0, min(listed.data_size, 1 << 24))
        wanted = {}
        for atype, name, svcn, rec, seq, aid in parse_attribute_list(value):
            if rec != entry.record:
                wanted.setdefault(rec, set()).add((atype, aid))
        for rec in sorted(wanted)[:1024]:
            try:
                ext = parse_record(self.read_record_bytes(rec), rec, self.sector)
            except FileSystemError as exc:
                entry.problems.append(f"Attribute list: {exc}")
                continue
            if ext is None or not ext.is_extension or \
                    ext.base_record != entry.record:
                entry.problems.append(
                    f"The attribute list names record {rec}, which no longer "
                    "belongs to this file" + ("" if ext is None else
                                              f" (its base is {ext.base_record})")
                    + "; attributes kept there are not included.")
                continue
            keys = wanted[rec]
            entry.attributes.extend(a for a in ext.attributes
                                    if (a.type, a.id) in keys)
            entry.problems.extend(f"Extension record {rec}: {p}"
                                  for p in ext.problems)
        assemble(entry)

    def iter_entries(self, *, should_cancel=None, start: int = 0,
                     follow_lists: bool = True, batch: int = 256):
        """Every record with a FILE or BAAD signature, in record order.

        Records are read `batch` at a time. Extension records are yielded too
        (their base_record is set) so a caller can count them; their
        attributes also appear in their base record's entry.
        """
        total = self.record_count
        n = start
        while n < total:
            if should_cancel is not None and should_cancel():
                raise Cancelled("MFT parsing was cancelled")
            count = min(batch, total - n)
            block = self._read_runs(self.mft_runs, n * self.record_size,
                                    count * self.record_size)
            for i in range(count):
                raw = block[i * self.record_size:(i + 1) * self.record_size]
                entry = parse_record(raw, n + i, self.sector)
                if entry is None:
                    continue
                if follow_lists and entry.has_attribute_list and \
                        not entry.is_extension:
                    self._follow_attribute_list(entry)
                yield entry
            n += count

    # -- reading ------------------------------------------------------------
    def _read_runs(self, runs: list, start: int, length: int) -> bytes:
        """`length` bytes from logical offset `start` of a run list. Sparse
        runs, gaps between runs and clusters beyond the image read as zero."""
        if length <= 0:
            return b""
        out = bytearray(length)
        end = start + length
        cs = self.cluster
        for vcn, lcn, count in runs:
            r_start, r_end = vcn * cs, (vcn + count) * cs
            if r_end <= start or r_start >= end or lcn is None:
                continue
            s, e = max(start, r_start), min(end, r_end)
            data = self.reader.read_at(lcn * cs + (s - r_start), e - s)
            out[s - start:s - start + len(data)] = data
        return bytes(out)

    def refuse_unreadable(self, stream: Stream) -> None:
        if stream.encrypted:
            raise FileSystemError(ENCRYPTED_REFUSAL)
        if stream.compressed:
            raise FileSystemError(COMPRESSED_REFUSAL)

    def read_stream(self, stream: Stream, offset: int = 0,
                    length: int | None = None) -> bytes:
        """Content bytes of a stream, within its data size. Bytes past the
        valid-data (initialized) length read as zero, as NTFS returns them."""
        self.refuse_unreadable(stream)
        size = stream.data_size
        if length is None:
            length = size - offset
        length = max(0, min(length, size - offset))
        if length == 0:
            return b""
        if stream.resident:
            return stream.value[offset:offset + length]
        data = bytearray(self._read_runs(stream.runs, offset, length))
        init = stream.init_size
        if offset + length > init:
            cut = max(0, init - offset)
            data[cut:] = bytes(len(data) - cut)
        return bytes(data)

    def iter_stream(self, stream: Stream, chunk: int = CHUNK):
        self.refuse_unreadable(stream)
        pos = 0
        while pos < stream.data_size:
            piece = self.read_stream(stream, pos, chunk)
            if not piece:
                break
            yield piece
            pos += len(piece)

    def run_problems(self, stream: Stream) -> list[str]:
        """Runs that point outside the volume or do not cover the stream."""
        out = []
        total = self.boot.total_clusters
        covered = 0
        for vcn, lcn, count in stream.runs:
            if vcn != covered:
                out.append(f"The runs skip from VCN {covered} to {vcn}; the "
                           "gap reads as zeroes.")
            covered = vcn + count
            if lcn is not None and lcn + count > total:
                out.append(f"A run at cluster {lcn} (+{count}) lies beyond "
                           f"the volume's {total} clusters.")
        need = -(-stream.data_size // self.cluster) if not stream.resident else 0
        if not stream.resident and covered < need:
            out.append(f"The runs cover {covered} clusters but the data needs "
                       f"{need}; the rest is in a record that was not read or "
                       "has been lost.")
        return out

    # -- allocation ----------------------------------------------------------
    def bitmap(self) -> bytes:
        if self._bitmap is None:
            entry = self.entry(6)
            stream = entry.stream("") if entry else None
            if stream is None:
                raise FileSystemError("$Bitmap (record 6) has no data stream.")
            self._bitmap = self.read_stream(stream)
        return self._bitmap

    def is_allocated(self, lcn: int) -> bool:
        bm = self.bitmap()
        index = lcn >> 3
        return index < len(bm) and bool(bm[index] >> (lcn & 7) & 1)

    def count_allocated(self, runs: list) -> tuple[int, int]:
        """(clusters in the runs, how many $Bitmap marks allocated now)."""
        bm = self.bitmap()
        total = used = 0
        for _vcn, lcn, count in runs:
            if lcn is None:
                continue
            total += count
            first, last = lcn, lcn + count          # [first, last)
            while first < last and first & 7:
                used += self.is_allocated(first)
                first += 1
            while first < last and last & 7:
                last -= 1
                used += self.is_allocated(last)
            if first < last:
                chunk = bm[first >> 3:last >> 3]
                used += int.from_bytes(chunk, "little").bit_count()
        return total, used

    _MIXED = re.compile(rb"\x00+|[^\x00\xff]")

    def free_extents(self):
        """(first cluster, count) for every run of unallocated clusters."""
        bm = self.bitmap()
        total = self.boot.total_clusters
        run_start = None
        run_end = 0

        def emit(s, e):
            e = min(e, total)
            if e > s:
                yield (s, e - s)

        for m in self._MIXED.finditer(bm):
            i = m.start()
            if run_start is not None and i * 8 != run_end:
                yield from emit(run_start, run_end)
                run_start = None
            if m.group()[0] == 0:
                s, e = i * 8, m.end() * 8
                if run_start is None:
                    run_start = s
                run_end = e
            else:
                byte = m.group()[0]
                for bit in range(8):
                    lcn = i * 8 + bit
                    if not byte >> bit & 1:
                        if run_start is None:
                            run_start = lcn
                        elif run_end != lcn:
                            yield from emit(run_start, run_end)
                            run_start = lcn
                        run_end = lcn + 1
                    elif run_start is not None:
                        yield from emit(run_start, run_end)
                        run_start = None
        if run_start is not None:
            yield from emit(run_start, run_end)

    # -- slack ---------------------------------------------------------------
    def file_slack(self, stream: Stream) -> dict | None:
        """The tail of the cluster holding a stream's last byte, beyond the
        data — and any whole clusters allocated past it.

        Offsets are volume-relative bytes. None for resident streams and for
        streams whose last cluster is sparse or not in the runs.
        """
        if stream.resident or not stream.runs:
            return None
        cs = self.cluster
        size = stream.data_size
        alloc_clusters = -(-stream.alloc_size // cs)
        if size == 0:
            return None
        last_vcn = (size - 1) // cs
        tail = size % cs
        lcn_of_last = None
        for vcn, lcn, count in stream.runs:
            if vcn <= last_vcn < vcn + count:
                lcn_of_last = None if lcn is None else lcn + (last_vcn - vcn)
                break
        if lcn_of_last is None:
            return None
        return {"offset": lcn_of_last * cs + tail if tail else None,
                "length": (cs - tail) if tail else 0,
                "last_cluster": lcn_of_last,
                "clusters_past_data": max(0, alloc_clusters - (last_vcn + 1))}

    # -- volume metadata -------------------------------------------------------
    def volume_info(self) -> dict:
        info = {"label": "", "version": "", "dirty": None}
        try:
            entry = self.entry(3)
        except FileSystemError:
            return info
        if entry is None:
            return info
        for a in entry.attributes:
            if a.type == 0x60 and a.resident:
                info["label"] = _utf16(a.value)
            elif a.type == 0x70 and a.resident and len(a.value) >= 12:
                major, minor = a.value[8], a.value[9]
                vflags = struct.unpack_from("<H", a.value, 10)[0]
                info["version"] = f"{major}.{minor}"
                info["dirty"] = bool(vflags & 0x0001)
        return info


# ---------------------------------------------------------------------------
# paths
# ---------------------------------------------------------------------------

def parent_matches(parent: tuple, parent_sequence: int) -> bool:
    """Does the record now at a parent's number still hold that parent?

    `parent` is (sequence, in_use, is_dir, ...). Equal sequences match; so
    does a FREED record whose sequence is one on from the reference, because
    NTFS increments the sequence when it frees a record.
    """
    seq, in_use = parent[0], parent[1]
    if seq == parent_sequence:
        return True
    return (not in_use) and seq == next_sequence(parent_sequence)


def build_paths(nodes: dict) -> dict:
    """record → (path, status), from record → (sequence, in_use, is_dir,
    parent_record, parent_sequence, name).

    status, worst along the path wins:
      ok              every parent reference checks out
      parent-deleted  an ancestor is deleted but its record not reused, so
                      the path still holds
      no-name         a record on the path has no $FILE_NAME (shown as #N)
      orphan          no record at a parent's number (the path starts there)
      parent-reused   a parent's record now belongs to something else; the
                      path is cut there, because above it is a stranger
      loop            parent references go round in a circle
    """
    rank = {"ok": 0, "parent-deleted": 1, "no-name": 2, "orphan": 3,
            "parent-reused": 4, "loop": 5}
    memo: dict = {}
    if ROOT in nodes:
        memo[ROOT] = ("", "ok")
    for record in nodes:
        if record in memo:
            continue
        chain: list = []
        link: dict = {}
        seen: set = set()
        current = record
        while True:
            if current in memo:
                base_path, base_status = memo[current]
                break
            if current in seen:
                base_path, base_status = "[loop]", "loop"
                break
            seen.add(current)
            node = nodes[current]
            chain.append(current)
            p_rec, p_seq = node[3], node[4]
            parent = nodes.get(p_rec)
            if parent is None:
                base_path, base_status = f"[no record {p_rec}]", "orphan"
                break
            if not parent_matches(parent, p_seq):
                base_path, base_status = (f"[record {p_rec} reused]",
                                          "parent-reused")
                break
            link[current] = "parent-deleted" if (not parent[1] and
                                                 p_rec != ROOT) else "ok"
            current = p_rec
        path, status = base_path, base_status
        for rec in reversed(chain):
            name = nodes[rec][5]
            status = max(status, link.get(rec, "ok"),
                         "ok" if name else "no-name", key=rank.get)
            piece = name or f"#{rec}"
            path = f"{path}/{piece}" if path else piece
            memo[rec] = (path, status)
    return memo
