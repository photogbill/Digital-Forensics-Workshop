# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Partition tables — MBR with its extended chain, and GPT — checked, not trusted.

A partition table is a claim about where volumes are, written by whatever
last partitioned the disk. It can be damaged, deliberately altered, or
simply disagree with itself, and a parser that believes it without checking
reads the wrong bytes with complete confidence. So every table here comes
back with what was CHECKED and what did not hold:

* **GPT** — the header's CRC32, the partition array's CRC32, and whether the
  backup header at the end of the disk agrees with the primary. A damaged
  primary falls back to the backup, and says so. A disk whose sector 0 has no
  protective 0xEE entry, or has other entries beside it (a hybrid MBR), is
  noted.
* **MBR** — status bytes that are not 0x00/0x80 (the usual sign that sector 0
  is a boot sector, not a table), the extended chain followed EBR by EBR with
  loop protection, and a protective 0xEE entry with no GPT behind it.
* **Both** — partitions that overlap, and partitions that run past the end of
  the image (a truncated image, or the wrong sector size).

**Sector size is decided, and the basis is recorded.** GPT's header sits at
LBA 1, so finding it at byte 512 or at byte 4096 settles the question. An MBR
cannot say; 512 is assumed unless a volume boot sector is found where a 4096
reading puts the first partition and not where a 512 reading does.

**Unpartitioned space is reported as regions**, because space between and
after partitions is a classic place for data a partition table does not
mention, and carving needs to be able to aim at it.

A disk with no table at all — a volume imaged on its own, a "superfloppy" —
is reported as scheme `none` with the whole disk as one region; its volume
boot sector is identified rather than being misread as an MBR, since boot
sectors also end in 55 AA.
"""

from __future__ import annotations

import struct
import uuid
import zlib
from dataclasses import asdict, dataclass

from . import filetype

EXTENDED_TYPES = (0x05, 0x0F, 0x85)
PROTECTIVE = 0xEE
MAX_EBR = 256
MAX_GPT_ENTRIES = 16384

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16 (<32 MiB)", 0x05: "Extended (CHS)",
    0x06: "FAT16", 0x07: "NTFS / exFAT / HPFS", 0x0B: "FAT32 (CHS)",
    0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12", 0x12: "OEM recovery / diagnostic",
    0x14: "Hidden FAT16 (<32 MiB)", 0x16: "Hidden FAT16",
    0x17: "Hidden NTFS / exFAT", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32 (LBA)",
    0x1E: "Hidden FAT16 (LBA)", 0x27: "Windows RE (hidden NTFS)",
    0x42: "Windows dynamic disk (LDM)", 0x82: "Linux swap / Solaris",
    0x83: "Linux", 0x85: "Linux extended", 0x8E: "Linux LVM",
    0xA5: "FreeBSD", 0xA6: "OpenBSD", 0xA8: "Apple UFS", 0xA9: "NetBSD",
    0xAB: "Apple boot", 0xAF: "Apple HFS / HFS+", 0xBE: "Solaris boot",
    0xBF: "Solaris", 0xDE: "Dell utility", 0xEE: "GPT protective",
    0xEF: "EFI system (MBR)", 0xFB: "VMware VMFS", 0xFC: "VMware swap",
    0xFD: "Linux RAID autodetect",
}

GPT_TYPES = {
    "C12A7328-F81F-11D2-BA4B-00A0C93EC93B": "EFI system partition",
    "E3C9E316-0B5C-4DB8-817D-F92DF00215AE": "Microsoft reserved",
    "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7": "Basic data (Windows)",
    "DE94BBA4-06D1-4D40-A16A-BFD50179D6AC": "Windows recovery environment",
    "5808C8AA-7E8F-42E0-85D2-E1E90434CFB3": "Windows LDM metadata",
    "AF9B60A0-1431-4F62-BC68-3311714A69AD": "Windows LDM data",
    "E75CAF8F-F680-4CEE-AFA3-B001E56EFC2D": "Windows Storage Spaces",
    "0FC63DAF-8483-4772-8E79-3D69D8477DE4": "Linux filesystem",
    "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709": "Linux root (x86-64)",
    "933AC7E1-2EB4-4F13-B844-0E14E2AEF915": "Linux /home",
    "0657FD6D-A4AB-43C4-84E5-0933C84B4F4F": "Linux swap",
    "E6D6D379-F507-44C2-A23C-238F2A3DF928": "Linux LVM",
    "A19D880F-05FC-4D3B-A006-743F0F84911E": "Linux RAID",
    "CA7D7CCB-63ED-4C53-861C-1742536059CC": "Linux LUKS",
    "BC13C2FF-59E6-4262-A352-B275FD6F7172": "Linux extended boot",
    "21686148-6449-6E6F-744E-656564454649": "BIOS boot",
    "024DEE41-33E7-11D3-9D69-0008C781F39F": "MBR partition scheme",
    "48465300-0000-11AA-AA11-00306543ECAC": "Apple HFS+",
    "7C3457EF-0000-11AA-AA11-00306543ECAC": "Apple APFS",
    "426F6F74-0000-11AA-AA11-00306543ECAC": "Apple boot",
    "516E7CB4-6ECF-11D6-8FF8-00022D09712B": "FreeBSD data",
    "83BD6B9D-7F41-11DC-BE0B-001560B84F0F": "FreeBSD boot",
    "AA31E02A-400F-11DB-9590-000C2911D1B8": "VMware VMFS",
}

GPT_ATTRIBUTES = {0: "platform-required", 1: "no-block-io",
                  2: "legacy-bios-bootable", 60: "read-only",
                  61: "shadow-copy", 62: "hidden", 63: "no-drive-letter"}

#: filetype ids that mean "a volume boot sector or a volume header is here".
VOLUME_TYPES = frozenset({"ntfs", "fat32", "fat", "exfat", "bitlocker", "luks",
                          "ext", "apfs", "hfsplus", "iso9660"})

ENCRYPTED_NOTE = ("Encrypted volume: its contents cannot be read without the "
                  "key. Detection only — decryption is out of scope for v1.")


@dataclass(frozen=True)
class Partition:
    index: int
    entry: str              # mbr:1 · ebr:5 · gpt:3 · gap · whole
    kind: str               # partition | extended | protective | gap | whole
    offset: int             # bytes from the start of the disk
    length: int
    start_lba: int
    sectors: int
    type_code: str
    type_label: str
    name: str
    guid: str
    attributes: int
    flags: tuple
    problems: tuple

    def as_dict(self) -> dict:
        data = asdict(self)
        data["flags"] = list(self.flags)
        data["problems"] = list(self.problems)
        return data


@dataclass(frozen=True)
class PartitionTable:
    scheme: str             # gpt | mbr | none
    sector_size: int
    sector_basis: str
    disk_id: str
    partitions: tuple       # partitions and extended containers, in disk order
    gaps: tuple
    problems: tuple
    notes: tuple

    def as_dict(self) -> dict:
        return {"scheme": self.scheme, "sector_size": self.sector_size,
                "sector_basis": self.sector_basis, "disk_id": self.disk_id,
                "partitions": [p.as_dict() for p in self.partitions],
                "gaps": [g.as_dict() for g in self.gaps],
                "problems": list(self.problems), "notes": list(self.notes)}

    def volumes(self) -> list[Partition]:
        """What can hold a file system: partitions, or the whole disk."""
        return [p for p in self.partitions if p.kind in ("partition", "whole")]


def guid_str(raw: bytes) -> str:
    """A GPT GUID as written everywhere else — mixed-endian, upper case."""
    return str(uuid.UUID(bytes_le=bytes(raw))).upper()


def _crc(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# file system identification at the start of a region
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FileSystemGuess:
    type_id: str
    label: str
    basis: str
    volume_label: str
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


def detect_filesystem(reader, offset: int, length: int) -> FileSystemGuess:
    """What the first bytes of a region say it holds, by signature only.

    The partition TYPE is a claim in the table; this is what the volume's own
    first sectors say. They disagree more often than one would like — an NTFS
    volume in a partition typed Linux, a BitLocker volume typed basic data —
    and both are kept.
    """
    head = reader.read_at(offset, min(filetype.HEAD_BYTES, max(0, length)))
    if not head or not any(head):
        return FileSystemGuess("empty", "No data (zeroes)", "signature", "",
                               "The first sectors are zero-filled.")
    found = filetype.identify(head, size=length)
    if found.type_id not in VOLUME_TYPES:
        note = ("" if found.type_id == "unknown" else
                f"No volume boot sector; the first bytes identify as {found.label}.")
        return FileSystemGuess("unknown", "Unrecognised", "none", "", note)
    label, note = "", ""
    if found.type_id == "fat32" and len(head) >= 82:
        label = head[71:82].decode("ascii", "replace").strip()
    elif found.type_id == "fat" and len(head) >= 54:
        label = head[43:54].decode("ascii", "replace").strip()
    if found.type_id in ("bitlocker", "luks"):
        note = ENCRYPTED_NOTE
    return FileSystemGuess(found.type_id, found.label, "signature",
                           label if label != "NO NAME" else "", note)


# ---------------------------------------------------------------------------
# the table
# ---------------------------------------------------------------------------

def _mbr_entries(sector: bytes) -> list[tuple]:
    out = []
    for i in range(4):
        base = 0x1BE + 16 * i
        status, ptype = sector[base], sector[base + 4]
        start, count = struct.unpack_from("<II", sector, base + 8)
        out.append((i + 1, status, ptype, start, count))
    return out


def _looks_like_mbr(sector: bytes) -> bool:
    if len(sector) < 512 or sector[510:512] != b"\x55\xaa":
        return False
    used = [(s, t, st, n) for _i, s, t, st, n in _mbr_entries(sector) if t and n]
    return bool(used) and all(s in (0x00, 0x80) for s, _t, _st, _n in used)


def read_table(reader) -> PartitionTable:
    """Read and check the partition table of the disk `reader` presents."""
    size = reader.size
    if size < 512:
        return PartitionTable("none", 512, "too small to hold a table", "", (),
                              (), ("The image is smaller than one sector.",), ())
    sector0 = reader.read_at(0, 512)
    for ss in (512, 4096):
        if size >= ss * 2 and reader.read_at(ss, 8) == b"EFI PART":
            return _read_gpt(reader, ss, sector0, primary=True)
    head = reader.read_at(0, filetype.HEAD_BYTES)
    boot = filetype.identify(head, size=size)
    if boot.type_id in VOLUME_TYPES and boot.type_id not in ("ext",):
        whole = Partition(1, "whole", "whole", 0, size, 0, size // 512, "",
                          "Whole disk (no partition table)", "", "", 0, (), ())
        return PartitionTable(
            "none", 512, "no table; volume boot sector at byte 0", "",
            (whole,), (), (),
            (f"Sector 0 is a {boot.label}, not a partition table: this image "
             "is a single volume.",))
    if _looks_like_mbr(sector0):
        entries = _mbr_entries(sector0)
        if any(t == PROTECTIVE for _i, _s, t, _st, _n in entries):
            for ss in (512, 4096):
                last = size // ss - 1
                if last > 1 and reader.read_at(last * ss, 8) == b"EFI PART":
                    return _read_gpt(reader, ss, sector0, primary=False)
        return _read_mbr(reader, sector0)
    whole = Partition(1, "whole", "whole", 0, size, 0, size // 512, "",
                      "Whole disk (no partition table)", "", "", 0, (), ())
    note = ("No partition table and no recognised volume boot sector at "
            "byte 0. The disk is treated as one region; carving can still "
            "search it.")
    if boot.type_id == "ext":
        note = ("No partition table: an ext2/3/4 superblock is at byte 1080, "
                "so this is probably a single Linux volume.")
    return PartitionTable("none", 512, "no table found", "", (whole,), (), (),
                          (note,))


def _read_mbr(reader, sector0: bytes) -> PartitionTable:
    size = reader.size
    problems: list[str] = []
    notes: list[str] = []
    disk_id = f"{struct.unpack_from('<I', sector0, 0x1B8)[0]:08X}"
    raw: list[dict] = []
    for number, status, ptype, start, count in _mbr_entries(sector0):
        if not ptype or not count:
            continue
        kind = ("extended" if ptype in EXTENDED_TYPES else
                "protective" if ptype == PROTECTIVE else "partition")
        raw.append(dict(entry=f"mbr:{number}", kind=kind, start=start,
                        count=count, ptype=ptype, status=status, problems=[]))
        if ptype == PROTECTIVE:
            problems.append(
                "Sector 0 holds a GPT protective entry (0xEE), but no GPT "
                "header was found at LBA 1 or at the end of the disk. The GPT "
                "may be damaged or wiped; the partitions it described are not "
                "listed here.")
    sector_size, basis = 512, "MBR: 512 assumed (an MBR does not record it)"
    primaries = [r for r in raw if r["kind"] == "partition"]
    extendeds = [r for r in raw if r["kind"] == "extended"]
    if primaries:
        probe = min(primaries, key=lambda r: r["start"])
        at512 = detect_filesystem(reader, probe["start"] * 512, 1 << 16)
        if at512.type_id in ("unknown", "empty") and probe["start"] * 4096 < size:
            at4k = detect_filesystem(reader, probe["start"] * 4096, 1 << 16)
            if at4k.type_id not in ("unknown", "empty"):
                sector_size = 4096
                basis = (f"MBR: 4096 — a {at4k.label} was found at LBA "
                         f"{probe['start']} × 4096 and nothing at × 512")
    elif extendeds:
        start = extendeds[0]["start"]
        if (reader.read_at(start * 512 + 510, 2) != b"\x55\xaa"
                and reader.read_at(start * 4096 + 4094, 2) == b"\x55\xaa"):
            sector_size = 4096
            basis = ("MBR: 4096 — the first EBR's signature is at LBA × 4096 "
                     "and not at × 512")
    ss = sector_size
    logical = 5
    for ext in extendeds:
        seen: set = set()
        base = ext["start"]
        current = base
        for _ in range(MAX_EBR):
            if current in seen:
                ext["problems"].append(
                    f"The extended partition's EBR chain loops back to LBA "
                    f"{current}; the walk stopped there.")
                break
            seen.add(current)
            if current * ss + ss > size:
                ext["problems"].append(
                    f"An EBR at LBA {current} lies beyond the end of the image.")
                break
            ebr = reader.read_at(current * ss, 512)
            if ebr[510:512] != b"\x55\xaa":
                ext["problems"].append(
                    f"The EBR at LBA {current} has no 55 AA signature; the "
                    "chain stops there and any later logical partitions are "
                    "not listed.")
                break
            entries = _mbr_entries(ebr)
            _n, status, ptype, start, count = entries[0]
            if ptype and count:
                raw.append(dict(entry=f"ebr:{logical}", kind="partition",
                                start=current + start, count=count,
                                ptype=ptype, status=status, problems=[]))
                logical += 1
            _n, _s, next_type, next_start, next_count = entries[1]
            if next_type in EXTENDED_TYPES and next_count:
                current = base + next_start
            else:
                break
        else:
            ext["problems"].append(f"More than {MAX_EBR} EBRs; stopped.")

    parts = []
    for r in raw:
        offset, length = r["start"] * sector_size, r["count"] * sector_size
        probs = list(r["problems"])
        if r["status"] not in (0x00, 0x80):
            probs.append(f"Status byte 0x{r['status']:02X} is neither 0x00 nor "
                         "0x80 — this entry may not be a partition at all.")
        if offset + length > size:
            probs.append(
                f"Runs {offset + length - size:,} bytes past the end of the "
                "image: the image is truncated, or the sector size is wrong.")
        flags = ("bootable",) if r["status"] == 0x80 else ()
        parts.append(dict(
            entry=r["entry"], kind=r["kind"], offset=offset, length=length,
            start_lba=r["start"], sectors=r["count"],
            type_code=f"0x{r['ptype']:02X}",
            type_label=MBR_TYPES.get(r["ptype"], "unknown type"),
            name="", guid="", attributes=r["status"], flags=flags,
            problems=probs))
    return _finish("mbr", sector_size, basis, disk_id, parts, problems, notes,
                   size, first_usable=sector_size, last_usable=size)


def _gpt_header(buf: bytes) -> dict | None:
    if len(buf) < 92 or buf[:8] != b"EFI PART":
        return None
    (revision, hsize, hcrc, _res, current, backup, first_usable, last_usable
     ) = struct.unpack_from("<IIIIQQQQ", buf, 8)
    disk_guid = buf[56:72]
    entries_lba, count, entry_size, entries_crc = struct.unpack_from(
        "<QIII", buf, 72)
    ok_size = 92 <= hsize <= len(buf)
    calc = None
    if ok_size:
        copy = bytearray(buf[:hsize])
        copy[16:20] = b"\x00\x00\x00\x00"
        calc = _crc(bytes(copy))
    return dict(revision=revision, header_size=hsize, header_crc=hcrc,
                header_crc_ok=bool(ok_size and calc == hcrc), current=current,
                backup=backup, first_usable=first_usable,
                last_usable=last_usable, disk_guid=guid_str(disk_guid),
                entries_lba=entries_lba, count=count, entry_size=entry_size,
                entries_crc=entries_crc)


def _read_gpt(reader, ss: int, sector0: bytes, *, primary: bool) -> PartitionTable:
    size = reader.size
    problems: list[str] = []
    notes: list[str] = []
    last_lba = size // ss - 1
    main = _gpt_header(reader.read_at(ss, ss)) if primary else None
    backup_at = (main["backup"] if main and main["header_crc_ok"]
                 else last_lba)
    backup = None
    if 0 < backup_at <= last_lba:
        backup = _gpt_header(reader.read_at(backup_at * ss, ss))
    basis = f"GPT header found at byte {ss} (LBA 1)"
    use = main
    if main is None or not main["header_crc_ok"]:
        if backup is not None and backup["header_crc_ok"]:
            use = backup
            basis = f"GPT backup header at LBA {backup_at} (sector size {ss})"
            problems.append(
                "The primary GPT header is missing or fails its CRC; the "
                "partitions are read from the BACKUP header at the end of the "
                "disk. Something damaged or altered the start of the disk.")
        elif main is not None:
            problems.append("The primary GPT header fails its CRC and no valid "
                            "backup was found; its values are used anyway and "
                            "should not be trusted.")
    if use is None:
        return PartitionTable("gpt", ss, basis, "", (), (),
                              ("No readable GPT header.",), ())
    if main is not None and main["header_crc_ok"]:
        if backup is None:
            notes.append(f"No backup GPT header at LBA {main['backup']} — the "
                         "image may be truncated (the backup is the disk's "
                         "last sector).")
        elif not backup["header_crc_ok"]:
            problems.append("The backup GPT header fails its CRC.")
        elif (backup["disk_guid"] != main["disk_guid"]
              or backup["entries_crc"] != main["entries_crc"]
              or backup["current"] != main["backup"]):
            problems.append(
                "The backup GPT header disagrees with the primary (disk GUID, "
                "partition array CRC or location). One of them was rewritten "
                "without the other.")
    count = min(use["count"], MAX_GPT_ENTRIES)
    esize = use["entry_size"]
    if esize < 128 or esize > 4096:
        problems.append(f"Partition entry size {esize} is not plausible.")
        return PartitionTable("gpt", ss, basis, use["disk_guid"], (), (),
                              tuple(problems), tuple(notes))
    array = reader.read_at(use["entries_lba"] * ss, count * esize)
    if _crc(array) != use["entries_crc"]:
        other = backup if use is main else main
        spare = b""
        if other is not None and other["header_crc_ok"] and \
                other["entries_crc"] == use["entries_crc"]:
            spare = reader.read_at(other["entries_lba"] * ss, count * esize)
        if spare and _crc(spare) == use["entries_crc"]:
            changed = [i + 1 for i in range(count)
                       if array[i * esize:(i + 1) * esize]
                       != spare[i * esize:(i + 1) * esize]]
            problems.append(
                "The GPT partition array at LBA "
                f"{use['entries_lba']} fails its CRC, and the other copy at "
                f"LBA {other['entries_lba']} passes. Entries that differ "
                f"between the two: {changed}. The listing below is from the "
                "copy that passes; the altered copy is what a tool reading "
                "only the start of the disk would have seen.")
            array = spare
        else:
            problems.append(
                "The GPT partition array fails its CRC and no intact copy was "
                "found: entries were altered or damaged after the table was "
                "written. They are listed, and should be checked against the "
                "volumes themselves.")
    entries = _mbr_entries(sector0) if _looks_like_mbr(sector0) else []
    types = [t for _i, _s, t, _st, _n in entries if t]
    if PROTECTIVE not in types:
        notes.append("Sector 0 has no protective 0xEE entry.")
    elif len(types) > 1:
        notes.append("Hybrid MBR: sector 0 lists partitions beside the GPT "
                     "protective entry. Legacy tools will see those instead.")
    parts = []
    for i in range(count):
        e = array[i * esize:(i + 1) * esize]
        if len(e) < 128 or not any(e[:16]):
            continue
        type_guid = guid_str(e[0:16])
        first, last, attrs = struct.unpack_from("<QQQ", e, 32)
        name = e[56:128].decode("utf-16-le", "replace").split("\x00", 1)[0]
        probs = []
        if last < first:
            probs.append("Its last LBA is before its first.")
        sectors = max(0, last - first + 1)
        offset, length = first * ss, sectors * ss
        if first < use["first_usable"] or last > use["last_usable"]:
            probs.append("Lies outside the header's usable LBA range.")
        if offset + length > size:
            probs.append(
                f"Runs {offset + length - size:,} bytes past the end of the "
                "image: the image is truncated.")
        flags = tuple(GPT_ATTRIBUTES[b] for b in sorted(GPT_ATTRIBUTES)
                      if attrs >> b & 1)
        parts.append(dict(
            entry=f"gpt:{i + 1}", kind="partition", offset=offset,
            length=length, start_lba=first, sectors=sectors,
            type_code=type_guid,
            type_label=GPT_TYPES.get(type_guid, "unknown type"), name=name,
            guid=guid_str(e[16:32]), attributes=attrs, flags=flags,
            problems=probs))
    return _finish("gpt", ss, basis, use["disk_guid"], parts, problems, notes,
                   size, first_usable=use["first_usable"] * ss,
                   last_usable=(use["last_usable"] + 1) * ss)


def _finish(scheme, ss, basis, disk_id, parts, problems, notes, size, *,
            first_usable: int, last_usable: int) -> PartitionTable:
    parts.sort(key=lambda p: (p["offset"], p["kind"] != "extended"))
    real = [p for p in parts if p["kind"] == "partition"]
    for a_i, a in enumerate(real):
        for b in real[a_i + 1:]:
            if b["offset"] < a["offset"] + a["length"] and \
                    a["offset"] < b["offset"] + b["length"]:
                a["problems"].append(f"Overlaps {b['entry']}.")
                b["problems"].append(f"Overlaps {a['entry']}.")
    for ext in [p for p in parts if p["kind"] == "extended"]:
        for p in real:
            if p["entry"].startswith("ebr:") and not (
                    ext["offset"] <= p["offset"]
                    and p["offset"] + p["length"] <= ext["offset"] + ext["length"]):
                p["problems"].append(
                    f"A logical partition that is not inside its extended "
                    f"partition {ext['entry']}.")
    partitions = tuple(Partition(index=i + 1, problems=tuple(p.pop("problems")),
                                 **p) for i, p in enumerate(parts))
    gaps = []
    cursor = first_usable
    end = min(last_usable, size)
    for p in sorted(real, key=lambda p: p["offset"]):
        if p["offset"] > cursor:
            gaps.append((cursor, p["offset"] - cursor))
        cursor = max(cursor, p["offset"] + p["length"])
    if end > cursor:
        gaps.append((cursor, end - cursor))
    gap_rows = tuple(
        Partition(index=0, entry="gap", kind="gap", offset=o, length=n,
                  start_lba=o // ss, sectors=n // ss, type_code="",
                  type_label="Unpartitioned space", name="", guid="",
                  attributes=0, flags=(), problems=())
        for o, n in gaps if n >= ss)
    return PartitionTable(scheme, ss, basis, disk_id, partitions, gap_rows,
                          tuple(problems), tuple(notes))
