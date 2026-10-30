# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows Shell Link files (`*.lnk`), read from the bytes per [MS-SHLLINK].

A shortcut records where its target was when the shortcut was last saved:
the target's own creation, access and write times and size (copied into the
header), the path as a chain of shell items (each folder's name, DOS-format
times and — from Windows Vista on — its NTFS MFT reference), the volume's
serial number, type and label, the network share if it was remote, and,
from the Distributed Link Tracking block, the NetBIOS name of the machine
and the NTFS object identifiers ("droids") of the target and its volume.
Windows writes them for files a user opens (`Recent\\`), for jump lists
(where each entry is one of these), and for the shortcuts people make.

**How it is read.** The 76-byte header (size 0x4C and the shell-link class
identifier are both checked — anything else is refused), then the sections
the header's flags say are present, in order: the LinkTargetIDList, the
LinkInfo, the five StringData strings and the ExtraData blocks up to the
terminal block. Every offset and length is checked against the bytes
present; a section that runs off the end is reported in `problems` and the
rest of the file is still read where it can be. `consumed` is the number of
bytes the structure occupies, which is how a jump list finds where one
shortcut ends and the next begins; bytes after the terminal block are
reported, not ignored.

**Strings declared longer than they are.** A description, relative path or
working directory declaring more than 260 characters is first read as
declared. If that runs the rest of the file off its end, it is re-read with
260 characters for those fields — the limit Windows applies, which a crafted
sample in LnkParse3's test set relies on to hide a command line; MS-SHLLINK
does not state it — and the result says so. Every string's declared and
read lengths are kept (`string_lengths`).

**Times are kept as they were stored.** The header's three times are
FILETIMEs (UTC) — RAW beside decoded, epoch named. Shell-item times are
MS-DOS date/time values: two-second resolution and NO time-zone field.
libyal's libfwsi documentation describes them as UTC; [MS-SHLLINK] does not
say. They are therefore decoded to a calendar value labelled
`"zone": "not stated in the format"` and never placed in a UTC column. The
tracker block's droids are version-1 UUIDs when Windows generated them: the
UUID's own 60-bit timestamp (100 ns since 1582-10-15) is kept raw, with its
FILETIME equivalent decoded beside it, and the node field is reported as a
MAC address — with the multicast bit measured, because a set bit means the
node is a random number rather than a network card's address.

**What is not read.** ANSI strings are decoded as Windows-1252 (the file does
not record its code page — the result says so); console, console code-page,
Darwin, shim and icon-environment blocks are identified and their main
string or value given, nothing more; the property store is decoded only for
common value types (strings, integers, FILETIMEs, GUIDs, booleans) — others
are listed by type and size; shell items other than root, volume, file
entry, network location, the CFSF delegate and the known-folder property
view are listed by type, size and first bytes only.
"""

from __future__ import annotations

import struct
import uuid

from . import timeutil
from .errors import FileSystemError

MAX_INPUT = 16 << 20
HEADER_SIZE = 0x4C
LNK_CLSID = "00021401-0000-0000-c000-000000000046"
LNK_CLSID_BYTES = uuid.UUID(LNK_CLSID).bytes_le
#: what every shell link begins with — used to find links inside containers
LNK_SIGNATURE = struct.pack("<I", HEADER_SIZE) + LNK_CLSID_BYTES
ANSI = "cp1252"

LINK_FLAGS = (
    (0x00000001, "HasTargetIDList"), (0x00000002, "HasLinkInfo"),
    (0x00000004, "HasName"), (0x00000008, "HasRelativePath"),
    (0x00000010, "HasWorkingDir"), (0x00000020, "HasArguments"),
    (0x00000040, "HasIconLocation"), (0x00000080, "IsUnicode"),
    (0x00000100, "ForceNoLinkInfo"), (0x00000200, "HasExpString"),
    (0x00000400, "RunInSeparateProcess"), (0x00001000, "HasDarwinID"),
    (0x00002000, "RunAsUser"), (0x00004000, "HasExpIcon"),
    (0x00008000, "NoPidlAlias"), (0x00020000, "RunWithShimLayer"),
    (0x00040000, "ForceNoLinkTrack"), (0x00080000, "EnableTargetMetadata"),
    (0x00100000, "DisableLinkPathTracking"),
    (0x00200000, "DisableKnownFolderTracking"),
    (0x00400000, "DisableKnownFolderAlias"), (0x00800000, "AllowLinkToLink"),
    (0x01000000, "UnaliasOnSave"), (0x02000000, "PreferEnvironmentPath"),
    (0x04000000, "KeepLocalIDListForUNCTarget"),
)
FILE_ATTRIBUTES = (
    (0x1, "READONLY"), (0x2, "HIDDEN"), (0x4, "SYSTEM"), (0x10, "DIRECTORY"),
    (0x20, "ARCHIVE"), (0x40, "DEVICE"), (0x80, "NORMAL"), (0x100, "TEMPORARY"),
    (0x200, "SPARSE_FILE"), (0x400, "REPARSE_POINT"), (0x800, "COMPRESSED"),
    (0x1000, "OFFLINE"), (0x2000, "NOT_CONTENT_INDEXED"),
    (0x4000, "ENCRYPTED"), (0x10000, "VIRTUAL"),
)
SHOW_COMMANDS = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED",
                 7: "SW_SHOWMINNOACTIVE"}
DRIVE_TYPES = {0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE",
               3: "DRIVE_FIXED", 4: "DRIVE_REMOTE", 5: "DRIVE_CDROM",
               6: "DRIVE_RAMDISK"}
HOTKEY_MODIFIERS = ((0x01, "SHIFT"), (0x02, "CTRL"), (0x04, "ALT"))

#: root / delegate shell-folder class identifiers (name shown beside the GUID)
SHELL_FOLDERS = {
    "20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer",
    "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places",
    "f02c1a0d-be21-4350-88b0-7367fc96ef3c": "Network",
    "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
    "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel",
    "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel (category view)",
    "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users Files",
    "031e4825-7b94-4dc3-b131-e946b44c8dd5": "Libraries",
    "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer",
    "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
    "679f85cb-0220-4080-b29b-5540cc05aab6": "Quick access",
    "018d5c66-4533-4307-9b53-224de2ed1fe6": "OneDrive",
    "4234d49b-0245-4df3-b780-3893943456e1": "Applications",
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "088e3905-0323-4b02-9826-5d99428e115f": "Downloads",
    "d3162b92-9365-467a-956b-92703aca08af": "Documents",
    "24ad3ad4-a569-4530-98e1-ab02f9417aa8": "Pictures",
    "3dfdf296-dbec-4fb4-81d1-6a3438bcf4de": "Music",
    "f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a": "Videos",
    "0db7e03f-fc29-4dc6-9020-ff41b59e513a": "3D Objects",
    "dffacdc5-679f-4156-8947-c5c76bc0b67f": "Users Files (profile)",
}

#: KNOWNFOLDERID values ([MS-SHLLINK] KnownFolderDataBlock; shobjidl)
KNOWN_FOLDERS = {
    "b4bfcc3a-db2c-424c-b029-7fe99a87c641": "Desktop",
    "fdd39ad0-238f-46af-adb4-6c85480369c7": "Documents",
    "374de290-123f-4565-9164-39c4925e467b": "Downloads",
    "33e28130-4e1e-4676-835a-98395c3bc3bb": "Pictures",
    "4bd8d571-6d19-48d3-be97-422220080e43": "Music",
    "18989b1d-99b5-455b-841c-ab7c74e4ddfc": "Videos",
    "5e6c858f-0e22-4760-9afe-ea3317b67173": "Profile",
    "905e63b6-c1bf-494e-b29c-65b732d3d21a": "ProgramFiles",
    "7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e": "ProgramFilesX86",
    "1ac14e77-02e7-4e5d-b744-2eb1ae5198b7": "System",
    "d65231b0-b2f1-4857-a4ce-a8e7c6ea7d27": "SystemX86",
    "f38bf404-1d43-42f2-9305-67de0b28fc23": "Windows",
    "3eb685db-65f9-4cf6-a03a-e3ef65729f3d": "RoamingAppData",
    "f1b32785-6fba-4fcf-9d55-7b8e7f157091": "LocalAppData",
    "625b53c3-ab48-4ec1-ba1f-a1ef4146fc19": "StartMenu",
    "a77f5d77-2e2b-44c3-a6a2-aba601054a51": "Programs",
    "a4115719-d62e-491d-aa7c-e74b8be3b067": "CommonStartMenu",
    "0139d44e-6afe-49f2-8690-3dafcae6ffb8": "CommonPrograms",
    "ae50c081-ebd2-438a-8655-8a092e34987a": "Recent",
    "dfdf76a2-c82a-4d63-906a-5644ac457385": "Public",
    "62ab5d82-fdc1-4dc3-a9dd-070d1d495d97": "ProgramData",
    "1777f761-68ad-4d8a-87bd-30b759fa33dd": "Favorites",
    "b97d20bb-f46a-4c97-ba10-5e3608430854": "Startup",
    "82a5ea35-d9cd-47c5-9629-e15d2f714e6e": "CommonStartup",
    "0762d272-c50a-4bb0-a382-697dcd729b80": "UserProfiles",
    "a52bba46-e9e1-435f-b3d9-28daa648c0f6": "OneDrive",
}

#: CSIDL values ([MS-SHLLINK] SpecialFolderDataBlock)
CSIDL = {0x00: "Desktop", 0x02: "Programs", 0x05: "Personal (My Documents)",
         0x06: "Favorites", 0x07: "Startup", 0x08: "Recent", 0x09: "SendTo",
         0x0B: "StartMenu", 0x0D: "MyMusic", 0x0E: "MyVideo",
         0x10: "DesktopDirectory", 0x11: "Drives (My Computer)",
         0x13: "NetHood", 0x14: "Fonts", 0x15: "Templates",
         0x16: "CommonStartMenu", 0x17: "CommonPrograms",
         0x18: "CommonStartup", 0x19: "CommonDesktopDirectory",
         0x1A: "AppData", 0x1C: "LocalAppData", 0x20: "InternetCache",
         0x23: "CommonAppData", 0x24: "Windows", 0x25: "System",
         0x26: "ProgramFiles", 0x27: "MyPictures", 0x28: "Profile",
         0x29: "SystemX86", 0x2A: "ProgramFilesX86"}

EXTRA_BLOCKS = {
    0xA0000001: "environment", 0xA0000002: "console", 0xA0000003: "tracker",
    0xA0000004: "console_codepage", 0xA0000005: "special_folder",
    0xA0000006: "darwin", 0xA0000007: "icon_environment", 0xA0000008: "shim",
    0xA0000009: "property_store", 0xA000000B: "known_folder",
    0xA000000C: "vista_id_list",
}
STRING_FIELDS = ((0x04, "name"), (0x08, "relative_path"),
                 (0x10, "working_dir"), (0x20, "arguments"),
                 (0x40, "icon_location"))
#: fields Windows reads at most MAX_PATH characters of (see parse_lnk)
CAPPED_STRINGS = ("name", "relative_path", "working_dir")
MAX_PATH_CHARS = 260
#: offset between the UUID epoch (1582-10-15) and the FILETIME epoch, in 100 ns
UUID_TO_FILETIME = 5748192000000000

VT_NAMES = {0x02: "VT_I2", 0x03: "VT_I4", 0x08: "VT_BSTR", 0x0B: "VT_BOOL",
            0x10: "VT_I1", 0x11: "VT_UI1", 0x12: "VT_UI2", 0x13: "VT_UI4",
            0x14: "VT_I8", 0x15: "VT_UI8", 0x16: "VT_INT", 0x17: "VT_UINT",
            0x1E: "VT_LPSTR", 0x1F: "VT_LPWSTR", 0x40: "VT_FILETIME",
            0x48: "VT_CLSID", 0x41: "VT_BLOB"}
NAMED_PROPERTIES = "d5cdd505-2e9c-101b-9397-08002b2cf9ae"


# ---------------------------------------------------------------------------
# small decoders
# ---------------------------------------------------------------------------

def _as_bytes(source, limit: int = MAX_INPUT, what: str = "shortcut") -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif hasattr(source, "read_at") and hasattr(source, "size"):
        if source.size > limit:
            raise FileSystemError(
                f"This {what} is {source.size:,} bytes, larger than the "
                f"{limit:,} bytes this parser accepts; it is not a {what} "
                "Windows would write. Check that the right file was chosen.")
        data = bytes(source.read_at(0, source.size))
    else:
        raise TypeError("expected bytes or a reader with .size and .read_at")
    if len(data) > limit:
        raise FileSystemError(
            f"This {what} is {len(data):,} bytes, larger than the {limit:,} "
            f"bytes this parser accepts. Check that the right file was chosen.")
    return data


def _utf16(raw: bytes) -> str:
    raw = bytes(raw)
    if len(raw) % 2:                    # a damaged length: drop the odd byte
        raw = raw[:-1]
    text = raw.decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _utf16z(buf: bytes, offset: int, end: int | None = None) -> tuple[str, int]:
    """NUL-terminated UTF-16LE at `offset`: (text, offset after the NUL)."""
    end = len(buf) if end is None else min(end, len(buf))
    pos = offset
    while pos + 1 < end and buf[pos:pos + 2] != b"\x00\x00":
        pos += 2
    return _utf16(buf[offset:pos]), min(pos + 2, end)


def _ansi(raw: bytes) -> str:
    return bytes(raw).decode(ANSI, "backslashreplace")


def _ansiz(buf: bytes, offset: int, end: int | None = None) -> tuple[str, int]:
    end = len(buf) if end is None else min(end, len(buf))
    stop = buf.find(b"\x00", offset, end)
    if stop < 0:
        stop = end
    return _ansi(buf[offset:stop]), min(stop + 1, end)


def guid_str(raw: bytes) -> str:
    """A GUID as stored by Windows (mixed-endian), lower case, 8-4-4-4-12."""
    return str(uuid.UUID(bytes_le=bytes(raw[:16])))


def _names(mask: int, table) -> list[str]:
    names = [name for bit, name in table if mask & bit]
    unknown = mask & ~sum(bit for bit, _n in table)
    if unknown:
        names.append(f"0x{unknown:08X}")
    return names


def filetime_field(raw: int) -> dict:
    return {"raw": raw, "epoch": "filetime",
            "utc": timeutil.decode(raw, "filetime")}


def dos_datetime(raw: int) -> dict:
    """An MS-DOS date/time as shell items store it (date in the low 16 bits,
    time in the high 16). Two-second resolution, no zone."""
    out = {"raw": raw, "epoch": "dos_datetime",
           "zone": "not stated in the format", "value": None}
    if not raw:
        return out
    date, time = raw & 0xFFFF, raw >> 16
    day, month, year = date & 0x1F, (date >> 5) & 0x0F, 1980 + (date >> 9)
    sec, minute, hour = (time & 0x1F) * 2, (time >> 5) & 0x3F, time >> 11
    if not (1 <= day <= 31 and 1 <= month <= 12 and hour < 24 and minute < 60
            and sec < 60):
        out["invalid"] = True
        return out
    out["value"] = (f"{year:04d}-{month:02d}-{day:02d}T"
                    f"{hour:02d}:{minute:02d}:{sec:02d}")
    return out


def droid_info(raw: bytes) -> dict:
    """A tracker/DestList droid GUID, with what a version-1 UUID carries."""
    value = uuid.UUID(bytes_le=bytes(raw[:16]))
    out = {"guid": str(value), "uuid_version": value.version
           if value.variant == uuid.RFC_4122 else None}
    if out["uuid_version"] == 1:
        ticks = value.time
        filetime = ticks - UUID_TO_FILETIME
        node = value.node
        out.update({
            "uuid_time_raw": ticks, "uuid_time_epoch": "uuid_v1 (100 ns since 1582-10-15)",
            "as_filetime": filetime if filetime > 0 else None,
            "utc": timeutil.decode(filetime, "filetime") if filetime > 0 else None,
            "clock_sequence": value.clock_seq,
            "mac": ":".join(f"{(node >> s) & 0xFF:02x}" for s in range(40, -8, -8)),
            "mac_is_random": bool(node & 0x010000000000),
        })
    return out


def _u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


# ---------------------------------------------------------------------------
# shell items
# ---------------------------------------------------------------------------

def _extension_blocks(item: bytes, start: int) -> tuple[list[dict], dict | None]:
    """Every 0xBEEFxxxx extension block found from `start` in one item:
    (their headers, the decoded 0xBEEF0004 block or None)."""
    blocks = []
    decoded = None
    pos = start
    while True:
        hit = item.find(b"\xef\xbe", pos)
        if hit < 0:
            break
        if hit < start + 6:
            pos = hit + 1
            continue
        base = hit - 6
        size = _u16(item, base)
        if size < 8 or base + size > len(item):
            pos = hit + 1
            continue
        sig = _u32(item, base + 4)
        blocks.append({"offset": base, "size": size,
                       "version": _u16(item, base + 2),
                       "signature": f"0x{sig:08X}"})
        if sig == 0xBEEF0004 and decoded is None:
            decoded = _beef0004(item[base:base + size])
            decoded["version"] = blocks[-1]["version"]
        pos = base + size
    return blocks, decoded


def _beef0004(blk: bytes) -> dict:
    """File-entry extension (0xBEEF0004): times, MFT reference, long name."""
    out: dict = {"kind": "file_entry_extension"}
    if len(blk) < 18:
        out["truncated"] = True
        return out
    version = _u16(blk, 2)
    out["created"] = dos_datetime(_u32(blk, 8))
    out["accessed"] = dos_datetime(_u32(blk, 12))
    name_off = {3: 20, 7: 38, 8: 42}.get(version, 46 if version >= 9 else 20)
    stored = _u16(blk, 16)
    if version >= 7 and len(blk) >= 28:
        ref = struct.unpack_from("<Q", blk, 20)[0]
        out["mft"] = (None if ref == 0 else
                      {"entry": ref & 0xFFFFFFFFFFFF, "sequence": ref >> 48})
    if stored and stored + 2 <= len(blk) and stored != name_off:
        out["long_name_offset_note"] = (
            f"long-name offset field says {stored}, version {version} layout "
            f"says {name_off}; the field was used")
        name_off = stored
    if name_off < len(blk) - 2:
        out["long_name"], after = _utf16z(blk, name_off, len(blk) - 2)
        local_off = None
        if version >= 7 and len(blk) >= 38:
            local_off = _u16(blk, 36)
        elif version >= 3 and len(blk) >= 20:
            local_off = _u16(blk, 18)
        if local_off:
            if version >= 7:
                localized, _ = _utf16z(blk, after, len(blk) - 2)
            else:
                localized, _ = _ansiz(blk, after, len(blk) - 2)
            if localized:
                out["localized_name"] = localized
    return out


def _file_entry(item: bytes) -> dict:
    t = item[2]
    out = {"kind": "file_entry", "type": f"0x{t:02X}",
           "is_directory": bool(t & 0x01), "is_file": bool(t & 0x02)}
    if len(item) < 14:
        out["truncated"] = True
        return out
    out["file_size"] = _u32(item, 4)
    out["modified"] = dos_datetime(_u32(item, 8))
    out["attributes"] = _u16(item, 12)
    # The item's last two bytes give the offset of its first extension
    # block (Windows XP on). When that offset lands on a 0xBEEF signature it
    # also bounds the primary name, which is not always NUL-terminated.
    first_ext = _u16(item, len(item) - 2) if len(item) >= 24 else 0
    bounded = (14 < first_ext <= len(item) - 10
               and item[first_ext + 6:first_ext + 8] == b"\xef\xbe")
    limit = first_ext if bounded else None
    if t & 0x04:
        out["primary_name"], after = _utf16z(item, 14, limit)
    else:
        out["primary_name"], after = _ansiz(item, 14, limit)
        if after % 2:
            after += 1
    blocks, decoded = _extension_blocks(item, first_ext if bounded else after)
    if blocks:
        out["extension_blocks"] = blocks
    if decoded:
        out["extension"] = decoded
    ext = out.get("extension") or {}
    out["name"] = ext.get("long_name") or out["primary_name"]
    return out


def _shell_item(item: bytes) -> dict:
    size = len(item)
    if size < 3:
        return {"kind": "unknown", "size": size, "truncated": True}
    t = item[2]
    if t == 0x1F and size >= 20:
        guid = guid_str(item[4:20])
        out = {"kind": "root", "type": "0x1F", "sort_index": item[3],
               "guid": guid, "folder": SHELL_FOLDERS.get(guid)}
        out["name"] = out["folder"] or "{" + guid + "}"
        if size > 20:
            blocks, _decoded = _extension_blocks(item, 20)
            if blocks:
                out["extension_blocks"] = blocks
        return out
    if t & 0x70 == 0x20:
        out = {"kind": "volume", "type": f"0x{t:02X}"}
        if t & 0x01:
            out["name"], _ = _ansiz(item, 3, min(size, 23))
        elif size >= 20:
            guid = guid_str(item[4:20])
            out["guid"] = guid
            out["folder"] = SHELL_FOLDERS.get(guid)
            out["name"] = out["folder"] or "{" + guid + "}"
        else:
            out["name"] = ""
        return out
    if t & 0x70 == 0x30:
        return _file_entry(item)
    if t & 0x70 == 0x40 and size > 5:
        out = {"kind": "network", "type": f"0x{t:02X}", "flags": item[4]}
        out["location"], after = _ansiz(item, 5)
        if item[4] & 0x80 and after < size:
            out["description"], after = _ansiz(item, after)
        if item[4] & 0x40 and after < size:
            out["comments"], after = _ansiz(item, after)
        out["name"] = out["location"]
        return out
    if size >= 10 and item[6:10] == b"CFSF":
        inner_size = _u16(item, 4)
        inner = item[10:6 + inner_size] if 6 + inner_size <= size else item[10:]
        out = {"kind": "delegate", "type": f"0x{t:02X}", "signature": "CFSF"}
        if len(inner) >= 3 and inner[2] & 0x70 == 0x30:
            entry = _file_entry(inner)
            gpos = 6 + inner_size
            if gpos + 32 <= size:
                out["delegate_class"] = guid_str(item[gpos:gpos + 16])
                out["delegate_folder"] = guid_str(item[gpos + 16:gpos + 32])
                blocks, decoded = _extension_blocks(item, gpos + 32)
                if decoded:
                    entry["extension"] = decoded
                    entry["name"] = decoded.get("long_name") or entry["name"]
                if blocks:
                    entry.setdefault("extension_blocks", blocks)
            out["file_entry"] = entry
            out["name"] = entry.get("name")
        return out
    if t == 0x00 and size >= 30 and _u32(item, 6) == 0x23FEBBEE:
        guid = guid_str(item[14:30])
        return {"kind": "known_folder_view", "type": "0x00", "guid": guid,
                "folder": KNOWN_FOLDERS.get(guid),
                "name": KNOWN_FOLDERS.get(guid) or "{" + guid + "}"}
    return {"kind": "unknown", "type": f"0x{t:02X}", "size": size,
            "head_hex": bytes(item[:48]).hex()}


def parse_shell_items(buf: bytes, problems: list | None = None,
                      where: str = "ID list") -> list[dict]:
    """An ITEMIDLIST (no leading size) → its items, in order."""
    problems = problems if problems is not None else []
    items = []
    pos = 0
    while pos + 2 <= len(buf):
        size = _u16(buf, pos)
        if size == 0:
            return items
        if size < 3 or pos + size > len(buf):
            problems.append(f"The {where}'s item {len(items)} declares "
                            f"{size} bytes, which do not fit; the rest of the "
                            "list is not read.")
            return items
        entry = _shell_item(buf[pos:pos + size])
        entry["offset"] = pos
        items.append(entry)
        pos += size
    problems.append(f"The {where} ends without its terminating empty item.")
    return items


def shell_path(items: list[dict]) -> str:
    """The items joined as Explorer would show the path."""
    parts = []
    for it in items:
        name = it.get("name")
        if not name:
            continue
        if it["kind"] == "volume":
            name = name.rstrip("\\")
        parts.append(name)
    return "\\".join(parts)


# ---------------------------------------------------------------------------
# LinkInfo
# ---------------------------------------------------------------------------

def _link_info(li: bytes, problems: list) -> dict:
    size = len(li)
    out: dict = {"size": size}
    if size < 28:
        problems.append("LinkInfo is shorter than its 28-byte header.")
        return out
    hdr_size, flags, vol_off, base_off, net_off, suffix_off = struct.unpack_from(
        "<IIIIII", li, 4)
    out.update({"header_size": hdr_size, "flags": flags,
                "volume_id_and_local_base_path": bool(flags & 1),
                "common_network_relative_link": bool(flags & 2)})
    base_u = suffix_u = 0
    if hdr_size >= 0x24 and size >= 0x24:
        base_u, suffix_u = struct.unpack_from("<II", li, 28)

    def ok(off, what):
        if off >= size:
            problems.append(f"LinkInfo's {what} offset 0x{off:X} is outside "
                            f"its {size} bytes; it is not read.")
            return False
        return True

    if flags & 1:
        if vol_off and ok(vol_off, "volume ID"):
            out["volume"] = _volume_id(li, vol_off, problems)
        if base_off and ok(base_off, "local base path"):
            out["local_base_path"], _ = _ansiz(li, base_off)
        if base_u and ok(base_u, "Unicode local base path"):
            out["local_base_path_unicode"], _ = _utf16z(li, base_u)
    if flags & 2 and net_off and ok(net_off, "network link"):
        out["network"] = _network_link(li, net_off, problems)
    if suffix_off and ok(suffix_off, "common path suffix"):
        out["common_path_suffix"], _ = _ansiz(li, suffix_off)
    if suffix_u and ok(suffix_u, "Unicode common path suffix"):
        out["common_path_suffix_unicode"], _ = _utf16z(li, suffix_u)
    return out


def _volume_id(li: bytes, off: int, problems: list) -> dict:
    if off + 16 > len(li):
        problems.append("LinkInfo's VolumeID runs past the end of LinkInfo.")
        return {}
    vsize, dtype, serial, label_off = struct.unpack_from("<IIII", li, off)
    out = {"drive_type": dtype, "drive_type_name": DRIVE_TYPES.get(dtype),
           "serial": f"{serial:08X}",
           "serial_short": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}"}
    end = min(len(li), off + vsize)
    if label_off == 0x14 and off + 20 <= len(li):
        u_off = _u32(li, off + 16)
        out["label"], _ = _utf16z(li, off + u_off, end)
    elif label_off:
        out["label"], _ = _ansiz(li, off + label_off, end)
    return out


def _network_link(li: bytes, off: int, problems: list) -> dict:
    if off + 20 > len(li):
        problems.append("LinkInfo's network link runs past the end of LinkInfo.")
        return {}
    nsize, nflags, name_off, dev_off, provider = struct.unpack_from(
        "<IIIII", li, off)
    end = min(len(li), off + nsize)
    out = {"flags": nflags, "provider_type": f"0x{provider:08X}"
           if nflags & 2 else None}
    if name_off:
        out["net_name"], _ = _ansiz(li, off + name_off, end)
    if nflags & 1 and dev_off:
        out["device_name"], _ = _ansiz(li, off + dev_off, end)
    if name_off > 0x14 and off + 28 <= len(li):
        u_name, u_dev = struct.unpack_from("<II", li, off + 20)
        if u_name:
            out["net_name_unicode"], _ = _utf16z(li, off + u_name, end)
        if u_dev:
            out["device_name_unicode"], _ = _utf16z(li, off + u_dev, end)
    return out


# ---------------------------------------------------------------------------
# property store (minimal)
# ---------------------------------------------------------------------------

def _typed_value(buf: bytes, pos: int, end: int):
    if pos + 4 > end:
        return None, None
    vt = _u16(buf, pos)
    p = pos + 4
    try:
        if vt in (0x1F,):
            chars = _u32(buf, p)
            return vt, _utf16(buf[p + 4:p + 4 + 2 * chars]).rstrip("\x00")
        if vt == 0x08:
            nbytes = _u32(buf, p)
            return vt, _utf16(buf[p + 4:p + 4 + nbytes]).rstrip("\x00")
        if vt == 0x1E:
            nbytes = _u32(buf, p)
            return vt, _ansi(buf[p + 4:p + 4 + nbytes]).rstrip("\x00")
        if vt in (0x03, 0x16):
            return vt, struct.unpack_from("<i", buf, p)[0]
        if vt in (0x13, 0x17):
            return vt, _u32(buf, p)
        if vt == 0x02:
            return vt, struct.unpack_from("<h", buf, p)[0]
        if vt == 0x12:
            return vt, _u16(buf, p)
        if vt in (0x10, 0x11):
            return vt, buf[p]
        if vt == 0x14:
            return vt, struct.unpack_from("<q", buf, p)[0]
        if vt == 0x15:
            return vt, struct.unpack_from("<Q", buf, p)[0]
        if vt == 0x0B:
            return vt, struct.unpack_from("<h", buf, p)[0] != 0
        if vt == 0x40:
            return vt, filetime_field(struct.unpack_from("<Q", buf, p)[0])
        if vt == 0x48:
            return vt, guid_str(buf[p:p + 16])
    except (struct.error, ValueError):
        return vt, None
    return vt, None


def parse_property_store(buf: bytes, problems: list | None = None) -> list[dict]:
    """Serialized property storages (one or more `1SPS` blocks), minimal."""
    problems = problems if problems is not None else []
    stores = []
    pos = 0
    while pos + 4 <= len(buf):
        ssize = _u32(buf, pos)
        if ssize == 0:
            break
        if ssize < 24 or pos + ssize > len(buf) or buf[pos + 4:pos + 8] != b"1SPS":
            problems.append(f"A property storage at offset {pos} is damaged "
                            "or truncated; the rest of the store is not read.")
            break
        fmt = guid_str(buf[pos + 8:pos + 24])
        props = []
        p = pos + 24
        end = pos + ssize
        while p + 4 <= end:
            vsize = _u32(buf, p)
            if vsize == 0:
                break
            if p + vsize > end or vsize < 9:
                problems.append(f"A property value in storage {fmt} is damaged.")
                break
            if fmt == NAMED_PROPERTIES:
                nsize = _u32(buf, p + 4)
                name = _utf16(buf[p + 9:p + 9 + nsize]).rstrip("\x00")
                vt, value = _typed_value(buf, p + 9 + nsize, p + vsize)
                prop = {"name": name}
            else:
                prop = {"id": _u32(buf, p + 4)}
                vt, value = _typed_value(buf, p + 9, p + vsize)
            prop.update({"vt": vt, "vt_name": VT_NAMES.get(vt), "value": value,
                         "size": vsize})
            props.append(prop)
            p += vsize
        stores.append({"format_id": fmt, "properties": props})
        pos += ssize
    return stores


# ---------------------------------------------------------------------------
# extra data
# ---------------------------------------------------------------------------

def _extra_block(sig: int, blk: bytes, problems: list) -> dict:
    kind = EXTRA_BLOCKS.get(sig, "unknown")
    out: dict = {"signature": f"0x{sig:08X}", "kind": kind, "size": len(blk)}
    try:
        if kind in ("environment", "darwin", "icon_environment"):
            out["ansi"], _ = _ansiz(blk, 8, min(len(blk), 268))
            if len(blk) >= 788:
                out["unicode"], _ = _utf16z(blk, 268, 788)
        elif kind == "tracker":
            out["length"], out["version"] = struct.unpack_from("<II", blk, 8)
            out["machine_id"], _ = _ansiz(blk, 16, 32)
            out["droid_volume"] = droid_info(blk[32:48])
            out["droid_file"] = droid_info(blk[48:64])
            out["birth_droid_volume"] = droid_info(blk[64:80])
            out["birth_droid_file"] = droid_info(blk[80:96])
        elif kind == "console_codepage":
            out["codepage"] = _u32(blk, 8)
        elif kind == "special_folder":
            fid, off = struct.unpack_from("<II", blk, 8)
            out.update({"folder_id": fid, "folder": CSIDL.get(fid),
                        "first_child_offset": off})
        elif kind == "known_folder":
            guid = guid_str(blk[8:24])
            out.update({"guid": guid, "folder": KNOWN_FOLDERS.get(guid),
                        "first_child_offset": _u32(blk, 24)})
        elif kind == "shim":
            out["layer"], _ = _utf16z(blk, 8)
        elif kind == "property_store":
            out["stores"] = parse_property_store(blk[8:], problems)
        elif kind == "vista_id_list":
            out["items"] = parse_shell_items(blk[8:], problems,
                                             "Vista ID-list block")
            out["path"] = shell_path(out["items"])
        elif kind == "console":
            out["face_name"], _ = _utf16z(blk, 44, 108)
    except (struct.error, ValueError):
        problems.append(f"Extra data block {out['signature']} is shorter than "
                        "its documented layout; what fitted was read.")
    return out


# ---------------------------------------------------------------------------
# the file
# ---------------------------------------------------------------------------

def parse_lnk(data) -> dict:
    """Parse one shell link. Raises FileSystemError if `data` is not one."""
    buf = _as_bytes(data)
    if len(buf) < HEADER_SIZE:
        raise FileSystemError(
            f"This is not a Windows shortcut: it is {len(buf)} bytes, shorter "
            "than the 76-byte shell-link header.")
    if buf[:20] != LNK_SIGNATURE:
        raise FileSystemError(
            "This is not a Windows shortcut: it does not begin with the "
            "shell-link header size (0x4C) and class identifier "
            f"{{{LNK_CLSID}}}.")
    problems: list[str] = []
    notes: list[str] = []
    (flags, attrs, t_create, t_access, t_write, fsize, icon, show,
     hotkey) = struct.unpack_from("<IIQQQIiIH", buf, 20)
    unicode = bool(flags & 0x80)
    header = {
        "flags": flags, "flag_names": _names(flags, LINK_FLAGS),
        "file_attributes": attrs,
        "attribute_names": _names(attrs, FILE_ATTRIBUTES),
        "times": {"target_created": filetime_field(t_create),
                  "target_accessed": filetime_field(t_access),
                  "target_modified": filetime_field(t_write)},
        "file_size": fsize, "icon_index": icon, "show_command": show,
        "show_command_name": SHOW_COMMANDS.get(show, "SW_SHOWNORMAL (by rule: "
                                               "unlisted values act as 1)"),
        "hotkey": {"raw": hotkey, "key": hotkey & 0xFF,
                   "modifiers": [n for b, n in HOTKEY_MODIFIERS
                                 if (hotkey >> 8) & b]},
    }
    result: dict = {"format": "lnk", "size": len(buf), "header": header,
                    "id_list": None, "link_info": None, "strings": {},
                    "string_lengths": {}, "extra": [], "problems": problems,
                    "notes": notes}
    pos = HEADER_SIZE
    truncated = False

    if flags & 0x01:
        if pos + 2 > len(buf):
            problems.append("The file ends where the target ID list's size "
                            "should be.")
            truncated = True
        else:
            idsize = _u16(buf, pos)
            if pos + 2 + idsize > len(buf):
                problems.append(
                    f"The target ID list declares {idsize} bytes but only "
                    f"{len(buf) - pos - 2} remain; what is present was read.")
                items = parse_shell_items(buf[pos + 2:], problems)
                truncated = True
                pos = len(buf)
            else:
                items = parse_shell_items(buf[pos + 2:pos + 2 + idsize], problems)
                pos += 2 + idsize
            result["id_list"] = {"size": idsize, "items": items,
                                 "path": shell_path(items)}

    if flags & 0x02 and not flags & 0x100 and not truncated:
        if pos + 4 > len(buf):
            problems.append("The file ends where LinkInfo should begin.")
            truncated = True
        else:
            li_size = _u32(buf, pos)
            if li_size < 4 or pos + li_size > len(buf):
                problems.append(f"LinkInfo declares {li_size} bytes, which do "
                                "not fit in the file; what is present was read.")
                result["link_info"] = _link_info(buf[pos:], problems)
                truncated = True
                pos = len(buf)
            else:
                result["link_info"] = _link_info(buf[pos:pos + li_size], problems)
                pos += li_size
    elif flags & 0x02 and flags & 0x100 and not truncated:
        # ForceNoLinkInfo: the structure, if written, is still skipped by size
        if pos + 4 <= len(buf):
            li_size = _u32(buf, pos)
            if 4 <= li_size and pos + li_size <= len(buf):
                notes.append("LinkInfo is present but ForceNoLinkInfo is set; "
                             "it was parsed and is shown, Windows ignores it.")
                result["link_info"] = _link_info(buf[pos:pos + li_size], problems)
                pos += li_size
            else:
                problems.append(f"LinkInfo declares {li_size} bytes, which do "
                                "not fit in the file; the rest is not read.")
                truncated = True

    if not truncated:
        strings, lengths, end, s_problems, s_trunc = _string_data(
            buf, pos, flags, cap=None)
        if s_trunc and any(v["declared"] > MAX_PATH_CHARS for k, v in
                           lengths.items() if k in CAPPED_STRINGS):
            capped = _string_data(buf, pos, flags, cap=MAX_PATH_CHARS)
            if not capped[4]:
                strings, lengths, end, s_problems, s_trunc = capped
                over = [f"{k} ({v['declared']} declared)" for k, v in
                        lengths.items() if v["declared"] != v["read"]]
                notes.append(
                    "Read with the 260-character limit — " + ", ".join(over) +
                    ": more characters declared than were read. Read as "
                    "declared, the strings run past the end of the file; "
                    "read with Windows' 260-character limit for these "
                    "fields, the rest of the file parses. A string declared "
                    "longer than it is read is a known way of hiding "
                    "content from the properties dialog.")
        result["strings"], result["string_lengths"] = strings, lengths
        problems.extend(s_problems)
        truncated = s_trunc
        pos = end
    if not unicode and result["strings"]:
        notes.append(f"Strings are ANSI and were decoded as {ANSI}; the "
                     "shortcut does not record its code page.")

    terminal = False
    while not truncated and pos + 4 <= len(buf):
        bsize = _u32(buf, pos)
        if bsize < 4:
            terminal = True
            pos += 4
            break
        if bsize < 8 or pos + bsize > len(buf):
            problems.append(f"Extra data block at offset {pos} declares "
                            f"{bsize} bytes, which do not fit; extra data "
                            "after it is not read.")
            truncated = True
            break
        sig = _u32(buf, pos + 4)
        block = _extra_block(sig, buf[pos:pos + bsize], problems)
        block["offset"] = pos
        result["extra"].append(block)
        if block["kind"] == "unknown":
            notes.append(f"Extra data block {block['signature']} at offset "
                         f"{pos} is not a documented type; it is listed, "
                         "not decoded.")
        pos += bsize
    if not truncated and not terminal:
        problems.append("The extra data has no terminal block; the file may "
                        "be truncated.")
    result["consumed"] = pos
    if pos < len(buf):
        result["trailing_bytes"] = len(buf) - pos
        if terminal:
            notes.append(f"{len(buf) - pos} bytes follow the terminal block; "
                         "they are not part of the shortcut structure.")

    for blk in result["extra"]:
        if blk["kind"] == "tracker":
            result["tracker"] = blk
    result["target_path"], result["target_path_source"] = _best_path(result)
    result["target_mft"] = _target_mft(result)
    return result


def _string_data(buf: bytes, pos: int, flags: int, cap: int | None):
    """The StringData section: (strings, lengths, end, problems, truncated).

    `cap` limits how many characters of the description, relative path and
    working directory are read (see parse_lnk); the declared count is kept
    beside the count read."""
    unicode = bool(flags & 0x80)
    strings, lengths, problems = {}, {}, []
    for bit, key in STRING_FIELDS:
        if not flags & bit:
            continue
        if pos + 2 > len(buf):
            problems.append(f"The file ends where the {key} string should be.")
            return strings, lengths, len(buf), problems, True
        declared = _u16(buf, pos)
        chars = declared
        if cap is not None and key in CAPPED_STRINGS and chars > cap:
            chars = cap
        nbytes = chars * (2 if unicode else 1)
        if pos + 2 + nbytes > len(buf):
            problems.append(f"The {key} string declares {declared} characters "
                            "but runs past the end of the file; the part "
                            "present was read.")
            raw = buf[pos + 2:]
            strings[key] = _utf16(raw[:len(raw) & ~1]) if unicode else _ansi(raw)
            lengths[key] = {"declared": declared, "read": len(strings[key])}
            return strings, lengths, len(buf), problems, True
        raw = buf[pos + 2:pos + 2 + nbytes]
        pos += 2 + nbytes
        strings[key] = _utf16(raw) if unicode else _ansi(raw)
        lengths[key] = {"declared": declared, "read": chars}
    return strings, lengths, pos, problems, False


def _best_path(r: dict) -> tuple[str | None, str | None]:
    li = r.get("link_info") or {}
    suffix = li.get("common_path_suffix_unicode") or li.get("common_path_suffix") or ""
    base = li.get("local_base_path_unicode") or li.get("local_base_path")
    if base:
        return base + suffix, "link_info.local_base_path"
    net = li.get("network") or {}
    name = net.get("net_name_unicode") or net.get("net_name")
    if name:
        sep = "" if (not suffix or name.endswith("\\")) else "\\"
        return name + sep + suffix, "link_info.network"
    idl = r.get("id_list") or {}
    if idl.get("path"):
        return idl["path"], "id_list"
    for blk in r.get("extra", []):
        if blk["kind"] == "environment" and (blk.get("unicode") or blk.get("ansi")):
            return blk.get("unicode") or blk.get("ansi"), "environment_block"
    rel = r["strings"].get("relative_path")
    if rel:
        return rel, "relative_path"
    return None, None


def _target_mft(r: dict) -> dict | None:
    """The MFT reference in the LAST shell item, when it carries one."""
    items = (r.get("id_list") or {}).get("items") or []
    if not items:
        return None
    last = items[-1]
    entry = last.get("file_entry") if last["kind"] == "delegate" else last
    ext = (entry or {}).get("extension") or {}
    mft = ext.get("mft")
    if mft:
        return dict(mft, source="id_list[-1] 0xBEEF0004 extension")
    return None


def to_rows(parsed: dict, *, source_path: str) -> list[dict]:
    """One `lnk` row per non-zero target time in the header (or one row
    without a time when all three are zero)."""
    target = parsed.get("target_path") or "(no target path recorded)"
    tracker = parsed.get("tracker") or {}
    detail_base = {
        "target_path": parsed.get("target_path"),
        "target_path_source": parsed.get("target_path_source"),
        "arguments": parsed["strings"].get("arguments"),
        "working_dir": parsed["strings"].get("working_dir"),
        "target_size": parsed["header"]["file_size"],
        "target_attributes": parsed["header"]["attribute_names"],
        "volume": ((parsed.get("link_info") or {}).get("volume")),
        "machine_id": tracker.get("machine_id"),
        "droid_file_mac": (tracker.get("droid_file") or {}).get("mac"),
        "target_mft": parsed.get("target_mft"),
        "times": {k: {"raw": v["raw"], "utc": v["utc"]}
                  for k, v in parsed["header"]["times"].items()},
        "problems": list(parsed.get("problems", [])),
    }
    rows = []
    labels = {"target_created": "creation", "target_accessed": "access",
              "target_modified": "write"}
    for role, label in labels.items():
        t = parsed["header"]["times"][role]
        if not t["raw"]:
            continue
        rows.append({
            "artefact": "lnk", "at_utc": t["utc"], "at_raw": t["raw"],
            "at_epoch": "filetime",
            "title": f"Shortcut target {label} time: {target}",
            "value": (f"The shortcut records its target's {label} time as "
                      f"{t['utc'] or 'undecodable'} (target {target})"),
            "detail": dict(detail_base, time_role=role),
            "row_ref_suffix": f"lnk:{role}",
        })
    if not rows:
        rows.append({
            "artefact": "lnk", "at_utc": None, "at_raw": None, "at_epoch": None,
            "title": f"Shortcut: {target}",
            "value": f"The shortcut records target {target} and no target times",
            "detail": dict(detail_base, time_role=None),
            "row_ref_suffix": "lnk",
        })
    return rows
