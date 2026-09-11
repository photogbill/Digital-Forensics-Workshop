# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""What a file IS, decided by its bytes — never by its name, never by a model.

**Type identification is signatures and magic numbers.** A model's guess in
this field would flow into a report as fact, so no model ever writes it;
and a file extension is a claim made by whoever named the file, so it is
recorded as `declared_ext` and compared, never believed.

Every answer says how it was reached:

    basis        signature            magic bytes at a known offset
                 signature+container  magic bytes, then the container's own
                                      structure read (a ZIP's entry names,
                                      an OLE directory, a RIFF form type)
                 heuristic            no signature; a property of the bytes
                                      (decodes as UTF-8, no NULs)
                 none                 nothing matched
    confidence   strong | weak | none

A WEAK signature (two bytes, or a pattern real data produces by accident —
`BM`, an MBR's `55 AA`, an MPEG frame sync) never raises an extension
mismatch. Flagging `holiday.jpg` because its first two bytes happen to read
`BM` would bury the real finding — a `.jpg` that is a ZIP — under noise.

**Nothing here says a file is complete.** A JPEG whose header parsed and
whose tail is missing is still identified as JPEG, and the ingest records
it that way; completeness is a separate question for the recovery phases.
"""

from __future__ import annotations

import math
import struct
import zipfile
from dataclasses import asdict, dataclass

#: How much of every file the ingest keeps for identification. Enough to
#: reach the ISO 9660 volume descriptor at 32 769 and an ext superblock at
#: 1080, and to see an OLE directory in a small document.
HEAD_BYTES = 65536


@dataclass(frozen=True)
class Signature:
    type_id: str
    label: str
    family: str
    offset: int
    magic: bytes
    extensions: tuple
    confidence: str = "strong"


def _s(type_id, label, family, offset, magic, exts, confidence="strong"):
    return Signature(type_id, label, family, offset, magic, tuple(exts),
                     confidence)


#: ORDER MATTERS: the first strong match wins, so a longer or more specific
#: signature sits above a shorter one that would also match (RAR5 above
#: RAR4, a Prefetch MAM header above nothing).
SIGNATURES = (
    # images
    _s("jpeg", "JPEG image", "image", 0, b"\xff\xd8\xff",
       ("jpg", "jpeg", "jpe", "jfif")),
    _s("png", "PNG image", "image", 0, b"\x89PNG\r\n\x1a\n", ("png",)),
    _s("gif", "GIF image", "image", 0, b"GIF87a", ("gif",)),
    _s("gif", "GIF image", "image", 0, b"GIF89a", ("gif",)),
    _s("tiff", "TIFF image", "image", 0, b"II*\x00",
       ("tif", "tiff", "dng", "nef", "arw", "cr2")),
    _s("tiff", "TIFF image", "image", 0, b"MM\x00*",
       ("tif", "tiff", "dng", "nef")),
    _s("psd", "Photoshop document", "image", 0, b"8BPS", ("psd", "psb")),
    _s("jp2", "JPEG 2000 image", "image", 0,
       b"\x00\x00\x00\x0cjP  \r\n\x87\n", ("jp2", "j2k", "jpf", "jpx")),
    _s("ico", "Windows icon", "image", 0, b"\x00\x00\x01\x00", ("ico",),
       "weak"),
    _s("bmp", "BMP image", "image", 0, b"BM", ("bmp", "dib"), "weak"),
    # documents
    _s("pdf", "PDF document", "document", 0, b"%PDF-", ("pdf",)),
    _s("rtf", "Rich Text document", "document", 0, b"{\\rtf", ("rtf",)),
    _s("postscript", "PostScript document", "document", 0, b"%!PS",
       ("ps", "eps")),
    _s("djvu", "DjVu document", "document", 0, b"AT&TFORM", ("djvu", "djv")),
    _s("ole2", "OLE2 compound file", "document", 0,
       b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
       ("doc", "xls", "ppt", "msg", "msi", "db", "vsd", "pub")),
    _s("pst", "Outlook data file (PST/OST)", "document", 0, b"!BDN",
       ("pst", "ost")),
    # archives and containers
    _s("zip", "ZIP archive", "archive", 0, b"PK\x03\x04",
       ("zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "jar", "apk",
        "epub", "kmz", "aff4", "xpi", "vsdx", "3mf")),
    _s("zip", "ZIP archive (empty)", "archive", 0, b"PK\x05\x06", ("zip",)),
    _s("zip", "ZIP archive (spanned)", "archive", 0, b"PK\x07\x08", ("zip",)),
    _s("7z", "7-Zip archive", "archive", 0, b"7z\xbc\xaf\x27\x1c", ("7z",)),
    _s("rar5", "RAR archive (v5)", "archive", 0, b"Rar!\x1a\x07\x01\x00",
       ("rar",)),
    _s("rar", "RAR archive (v4)", "archive", 0, b"Rar!\x1a\x07\x00",
       ("rar",)),
    _s("gzip", "gzip stream", "archive", 0, b"\x1f\x8b", ("gz", "tgz"),
       "weak"),
    _s("bzip2", "bzip2 stream", "archive", 0, b"BZh", ("bz2", "tbz2"),
       "weak"),
    _s("xz", "xz stream", "archive", 0, b"\xfd7zXZ\x00", ("xz", "txz")),
    _s("zstd", "Zstandard stream", "archive", 0, b"\x28\xb5\x2f\xfd",
       ("zst",)),
    _s("lz4", "LZ4 frame", "archive", 0, b"\x04\x22\x4d\x18", ("lz4",)),
    _s("cab", "Microsoft Cabinet", "archive", 0, b"MSCF", ("cab",)),
    _s("tar", "tar archive", "archive", 257, b"ustar", ("tar",)),
    _s("ar", "ar archive (deb)", "archive", 0, b"!<arch>\n", ("deb", "a")),
    _s("rpm", "RPM package", "archive", 0, b"\xed\xab\xee\xdb", ("rpm",)),
    # executables
    _s("elf", "ELF executable", "executable", 0, b"\x7fELF",
       ("", "so", "o", "elf")),
    _s("macho", "Mach-O executable", "executable", 0, b"\xcf\xfa\xed\xfe",
       ("", "dylib")),
    _s("macho", "Mach-O executable", "executable", 0, b"\xce\xfa\xed\xfe",
       ("", "dylib")),
    _s("dex", "Android DEX", "executable", 0, b"dex\n", ("dex",)),
    _s("wasm", "WebAssembly module", "executable", 0, b"\x00asm", ("wasm",)),
    _s("swf", "Flash (SWF)", "executable", 0, b"FWS", ("swf",), "weak"),
    _s("swf", "Flash (SWF, compressed)", "executable", 0, b"CWS", ("swf",),
       "weak"),
    # databases and application data
    _s("sqlite", "SQLite database", "database", 0, b"SQLite format 3\x00",
       ("sqlite", "sqlite3", "db", "", "places", "history")),
    _s("sqlite-wal", "SQLite write-ahead log", "database", 0,
       b"\x37\x7f\x06\x82", ("", "sqlite-wal", "db-wal", "sqlite3-wal")),
    _s("sqlite-wal", "SQLite write-ahead log", "database", 0,
       b"\x37\x7f\x06\x83", ("", "sqlite-wal", "db-wal", "sqlite3-wal")),
    _s("kdbx", "KeePass database", "database", 0,
       b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5", ("kdbx", "kdb")),
    _s("pcap", "pcap capture", "database", 0, b"\xd4\xc3\xb2\xa1",
       ("pcap", "cap")),
    _s("pcap", "pcap capture", "database", 0, b"\xa1\xb2\xc3\xd4",
       ("pcap", "cap")),
    _s("pcapng", "pcapng capture", "database", 0, b"\x0a\x0d\x0d\x0a",
       ("pcapng",)),
    # Windows system artefacts
    _s("regf", "Windows registry hive", "system", 0, b"regf",
       ("", "dat", "hve", "log1", "log2", "sav")),
    _s("evtx", "Windows event log (EVTX)", "system", 0, b"ElfFile\x00",
       ("evtx",)),
    _s("evt", "Windows event log (legacy EVT)", "system", 4, b"LfLe",
       ("evt",)),
    _s("prefetch", "Windows Prefetch (compressed, Win10+)", "system", 0,
       b"MAM\x04", ("pf",)),
    _s("prefetch", "Windows Prefetch", "system", 4, b"SCCA", ("pf",)),
    _s("lnk", "Windows shortcut (LNK)", "system", 0,
       b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00"
       b"\x00\x00\x00\x46", ("lnk",)),
    _s("ese", "ESE database (SRUM, Windows Search, WebCache)", "system", 4,
       b"\xef\xcd\xab\x89", ("edb", "dat", "db")),
    _s("thumbcache", "Windows thumbcache", "system", 0, b"CMMM", ("db",)),
    _s("hiberfil", "Windows hibernation file", "system", 0, b"hibr",
       ("sys",)),
    _s("hiberfil", "Windows hibernation file", "system", 0, b"HIBR",
       ("sys",)),
    _s("hiberfil", "Windows hibernation file (resumed)", "system", 0,
       b"wake", ("sys",)),
    _s("hiberfil", "Windows hibernation file (resumed)", "system", 0,
       b"WAKE", ("sys",)),
    # disks, volumes and forensic images
    _s("ewf", "EnCase image (E01)", "disk", 0, b"EVF\x09\x0d\x0a\xff\x00",
       ("e01", "ex01", "s01", "l01")),
    _s("ewf2", "EnCase image (Ex01)", "disk", 0, b"EVF2\r\n\x81\x00",
       ("ex01", "lx01")),
    _s("aff", "AFF image", "disk", 0, b"AFF10\r\n", ("aff",)),
    _s("vhdx", "Hyper-V disk (VHDX)", "disk", 0, b"vhdxfile", ("vhdx",)),
    _s("vhd", "Virtual PC disk (VHD, dynamic)", "disk", 0, b"conectix",
       ("vhd",)),
    _s("vmdk", "VMware disk (sparse)", "disk", 0, b"KDMV", ("vmdk",)),
    _s("vmdk", "VMware disk (descriptor)", "disk", 0,
       b"# Disk DescriptorFile", ("vmdk",)),
    _s("qcow", "QEMU disk (qcow)", "disk", 0, b"QFI\xfb",
       ("qcow", "qcow2")),
    _s("bitlocker", "BitLocker volume", "crypto", 3, b"-FVE-FS-",
       ("", "img", "dd", "raw", "bin")),
    _s("luks", "LUKS encrypted volume", "crypto", 0, b"LUKS\xba\xbe",
       ("", "img", "dd", "raw", "bin")),
    _s("ntfs", "NTFS volume boot sector", "disk", 3, b"NTFS    ",
       ("", "img", "dd", "raw", "bin", "001")),
    _s("exfat", "exFAT volume boot sector", "disk", 3, b"EXFAT   ",
       ("", "img", "dd", "raw", "bin", "001")),
    _s("fat32", "FAT32 volume boot sector", "disk", 82, b"FAT32   ",
       ("", "img", "dd", "raw", "bin", "001")),
    _s("fat", "FAT12/16 volume boot sector", "disk", 54, b"FAT1",
       ("", "img", "dd", "raw", "bin", "001")),
    _s("gpt", "GPT-partitioned disk", "disk", 512, b"EFI PART",
       ("", "img", "dd", "raw", "bin", "001")),
    _s("apfs", "APFS container", "disk", 32, b"NXSB",
       ("", "img", "dd", "raw", "bin", "dmg")),
    _s("iso9660", "ISO 9660 image", "disk", 32769, b"CD001", ("iso",)),
    # audio and video
    _s("flac", "FLAC audio", "audio", 0, b"fLaC", ("flac",)),
    _s("ogg", "Ogg container", "audio", 0, b"OggS",
       ("ogg", "oga", "ogv", "opus")),
    _s("mp3", "MP3 audio (ID3 tagged)", "audio", 0, b"ID3", ("mp3",)),
    _s("midi", "MIDI", "audio", 0, b"MThd", ("mid", "midi")),
    _s("amr", "AMR audio", "audio", 0, b"#!AMR", ("amr",)),
    _s("asf", "ASF (WMV/WMA)", "video", 0,
       b"\x30\x26\xb2\x75\x8e\x66\xcf\x11", ("wmv", "wma", "asf")),
    _s("matroska", "Matroska/WebM", "video", 0, b"\x1a\x45\xdf\xa3",
       ("mkv", "webm", "mka")),
    _s("flv", "Flash video", "video", 0, b"FLV\x01", ("flv",)),
    _s("mpeg-ps", "MPEG program stream", "video", 0, b"\x00\x00\x01\xba",
       ("mpg", "mpeg", "vob")),
    # keys and text containers with fixed headers
    _s("pgp", "PGP armoured data", "crypto", 0, b"-----BEGIN PGP",
       ("asc", "gpg", "pgp")),
    _s("ssh-key", "OpenSSH private key", "crypto", 0,
       b"-----BEGIN OPENSSH PRIVATE KEY-----", ("", "key")),
    _s("pem", "PEM-encoded key or certificate", "crypto", 0, b"-----BEGIN ",
       ("pem", "crt", "cer", "key", "csr")),
    # fonts
    _s("otf", "OpenType font", "font", 0, b"OTTO", ("otf",)),
    _s("woff", "WOFF font", "font", 0, b"wOFF", ("woff",)),
    _s("woff2", "WOFF2 font", "font", 0, b"wOF2", ("woff2",)),
    _s("ttf", "TrueType font", "font", 0, b"\x00\x01\x00\x00\x00", ("ttf",),
       "weak"),
    # weak, last: patterns ordinary data produces by accident
    _s("mp3", "MP3 audio (frame sync)", "audio", 0, b"\xff\xfb", ("mp3",),
       "weak"),
    _s("mp3", "MP3 audio (frame sync)", "audio", 0, b"\xff\xf3", ("mp3",),
       "weak"),
    _s("mbr", "MBR boot record", "disk", 510, b"\x55\xaa",
       ("", "img", "dd", "raw", "bin", "001"), "weak"),
    _s("ext", "ext2/3/4 superblock", "disk", 1080, b"\x53\xef",
       ("", "img", "dd", "raw", "bin", "001"), "weak"),
    _s("hfsplus", "HFS+ volume header", "disk", 1024, b"H+",
       ("", "img", "dd", "raw", "bin", "dmg"), "weak"),
)


@dataclass(frozen=True)
class TypeResult:
    type_id: str
    label: str
    family: str
    basis: str
    confidence: str
    extensions: tuple
    declared_ext: str
    ext_mismatch: bool
    head_entropy: float | None
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


def declared_extension(name: str) -> str:
    base = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if "." not in base.lstrip("."):
        return ""
    return base.rsplit(".", 1)[-1].lower()


def entropy(data: bytes) -> float | None:
    """Shannon entropy in bits per byte, 0–8. None for too little data.

    Near 8 means compressed, encrypted or random — and those three cannot be
    told apart from entropy alone, which is why the note on a high-entropy
    unknown says all three. A VeraCrypt container is DESIGNED to be
    indistinguishable from random data; no signature finds one.
    """
    if len(data) < 256:
        return None
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


_RIFF = {b"WAVE": ("wav", "WAV audio", "audio", ("wav",)),
         b"AVI ": ("avi", "AVI video", "video", ("avi",)),
         b"WEBP": ("webp", "WebP image", "image", ("webp",)),
         b"RMID": ("midi", "RIFF MIDI", "audio", ("rmi", "mid")),
         b"ACON": ("ani", "Animated cursor", "image", ("ani",))}

_FTYP = {b"qt  ": ("mov", "QuickTime movie", "video", ("mov", "qt")),
         b"heic": ("heic", "HEIC image", "image", ("heic", "heif")),
         b"heix": ("heic", "HEIC image", "image", ("heic", "heif")),
         b"mif1": ("heif", "HEIF image", "image", ("heif", "heic", "avif")),
         b"msf1": ("heif", "HEIF image sequence", "image", ("heif", "heic")),
         b"avif": ("avif", "AVIF image", "image", ("avif",)),
         b"M4A ": ("m4a", "MPEG-4 audio", "audio", ("m4a", "mp4")),
         b"M4V ": ("m4v", "MPEG-4 video", "video", ("m4v", "mp4")),
         b"crx ": ("cr3", "Canon CR3 raw", "image", ("cr3",))}

_OOXML = (("word/", "docx", "Word document (OOXML)", ("docx", "docm", "dotx")),
          ("xl/", "xlsx", "Excel workbook (OOXML)", ("xlsx", "xlsm", "xltx")),
          ("ppt/", "pptx", "PowerPoint presentation (OOXML)",
           ("pptx", "pptm", "potx")),
          ("visio/", "vsdx", "Visio drawing (OOXML)", ("vsdx",)))

_ODF = {"application/vnd.oasis.opendocument.text": ("odt", "OpenDocument text", ("odt",)),
        "application/vnd.oasis.opendocument.spreadsheet": ("ods", "OpenDocument spreadsheet", ("ods",)),
        "application/vnd.oasis.opendocument.presentation": ("odp", "OpenDocument presentation", ("odp",)),
        "application/epub+zip": ("epub", "EPUB book", ("epub",))}

_OLE_NAMES = ((b"W\x00o\x00r\x00d\x00D\x00o\x00c\x00u\x00m\x00e\x00n\x00t\x00",
               "doc", "Word document (legacy)", ("doc", "dot")),
              (b"W\x00o\x00r\x00k\x00b\x00o\x00o\x00k\x00",
               "xls", "Excel workbook (legacy)", ("xls", "xlt")),
              (b"P\x00o\x00w\x00e\x00r\x00P\x00o\x00i\x00n\x00t\x00 \x00D\x00o\x00c\x00",
               "ppt", "PowerPoint presentation (legacy)", ("ppt", "pps")),
              (b"_\x00_\x00s\x00u\x00b\x00s\x00t\x00g\x001\x00.\x000\x00_\x00",
               "msg", "Outlook message", ("msg",)),
              (b"C\x00a\x00t\x00a\x00l\x00o\x00g\x00",
               "thumbsdb", "Thumbs.db thumbnail cache", ("db",)))


def _match(head: bytes, sig: Signature) -> bool:
    end = sig.offset + len(sig.magic)
    return len(head) >= end and head[sig.offset:end] == sig.magic


def _result(type_id, label, family, basis, confidence, exts, declared,
            ent, note="") -> TypeResult:
    mismatch = bool(confidence == "strong" and declared
                    and declared not in exts)
    return TypeResult(type_id, label, family, basis, confidence, tuple(exts),
                      declared, mismatch, ent, note)


def _zip_names(head: bytes, reader) -> tuple[list[str], str]:
    """Entry names from the central directory when a reader is available,
    otherwise from the local headers visible in the head."""
    if reader is not None:
        try:
            reader.seek(0)
            with zipfile.ZipFile(reader, "r") as zf:
                return zf.namelist(), "central directory"
        except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
            pass
    names, pos = [], 0
    while pos + 30 <= len(head) and head[pos:pos + 4] == b"PK\x03\x04":
        flags, _method = struct.unpack_from("<HH", head, pos + 6)
        csize, _usize, nlen, xlen = struct.unpack_from("<IIHH", head, pos + 18)
        name = head[pos + 30:pos + 30 + nlen].decode("utf-8", "replace")
        names.append(name)
        if flags & 0x08:                 # sizes follow the data; cannot hop
            break
        pos += 30 + nlen + xlen + csize
    return names, "local headers in the first 64 KiB"


def _refine_zip(head, reader, declared, ent) -> TypeResult | None:
    names, where = _zip_names(head, reader)
    if names and names[0] == "mimetype" and len(head) > 38:
        (csize,) = struct.unpack_from("<I", head, 18)
        nlen, xlen = struct.unpack_from("<HH", head, 26)
        start = 30 + nlen + xlen
        mime = head[start:start + min(csize, 100)].decode("ascii", "ignore")
        for key, (tid, label, exts) in _ODF.items():
            if mime.startswith(key):
                return _result(tid, label, "document", "signature+container",
                               "strong", exts, declared, ent,
                               f"mimetype entry: {key}")
    lowered = [n.lower() for n in names]
    if "[content_types].xml" in lowered:
        for prefix, tid, label, exts in _OOXML:
            if any(n.startswith(prefix) for n in lowered):
                return _result(tid, label, "document", "signature+container",
                               "strong", exts, declared, ent,
                               f"entry names from the {where}")
    if "androidmanifest.xml" in lowered and "classes.dex" in lowered:
        return _result("apk", "Android package", "executable",
                       "signature+container", "strong", ("apk",), declared,
                       ent, f"entry names from the {where}")
    if "meta-inf/manifest.mf" in lowered:
        return _result("jar", "Java archive", "executable",
                       "signature+container", "strong", ("jar", "war", "ear"),
                       declared, ent, f"entry names from the {where}")
    if "information.turtle" in lowered or "container.description" in lowered:
        return _result("aff4", "AFF4 image", "disk", "signature+container",
                       "strong", ("aff4",), declared, ent,
                       f"entry names from the {where}")
    return None


def _refine_pe(head, declared, ent) -> TypeResult:
    exts_exe = ("exe", "dll", "sys", "scr", "cpl", "ocx", "drv", "efi",
                "mui", "com", "ax")
    if len(head) >= 0x40:
        (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
        if e_lfanew + 24 <= len(head) and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            (characteristics,) = struct.unpack_from("<H", head, e_lfanew + 22)
            if characteristics & 0x2000:
                return _result("pe-dll", "Windows DLL (PE)", "executable",
                               "signature+container", "strong", exts_exe,
                               declared, ent, "PE header, DLL flag set")
            return _result("pe", "Windows executable (PE)", "executable",
                           "signature+container", "strong", exts_exe,
                           declared, ent, "PE header present")
    return _result("mz", "DOS MZ executable (no PE header in view)",
                   "executable", "signature", "weak", exts_exe, declared, ent)


def identify(head: bytes, *, name: str = "", size: int | None = None,
             reader=None) -> TypeResult:
    """Identify one file from its first bytes.

    `reader`, if given, is the file's own READ-ONLY handle, used only to
    read a ZIP's central directory; it is never written to.
    """
    declared = declared_extension(name)
    ent = entropy(head)
    if size == 0 or (size is None and not head):
        return _result("empty", "Empty file", "empty", "signature", "strong",
                       ("",) if not declared else (declared,), declared,
                       None, "zero bytes")

    if head[:2] == b"MZ":
        return _refine_pe(head, declared, ent)
    if head[:4] == b"RIFF" and len(head) >= 12:
        form = head[8:12]
        if form in _RIFF:
            tid, label, fam, exts = _RIFF[form]
            return _result(tid, label, fam, "signature+container", "strong",
                           exts, declared, ent, f"RIFF form {form!r}")
        return _result("riff", "RIFF container", "audio", "signature",
                       "weak", ("wav", "avi", "webp"), declared, ent,
                       f"unrecognised RIFF form {form!r}")
    if len(head) >= 12 and head[4:8] == b"ftyp":
        brand = head[8:12]
        if brand in _FTYP:
            tid, label, fam, exts = _FTYP[brand]
        elif brand.startswith(b"3g"):
            tid, label, fam, exts = "3gp", "3GPP video", "video", ("3gp", "3g2")
        else:
            tid, label, fam, exts = ("mp4", "MPEG-4 container", "video",
                                     ("mp4", "m4v", "m4a", "mov"))
        return _result(tid, label, fam, "signature+container", "strong",
                       exts, declared, ent, f"ftyp brand {brand!r}")
    if head[:4] == b"\xca\xfe\xba\xbe" and len(head) >= 8:
        (count,) = struct.unpack_from(">I", head, 4)
        if count < 30:
            return _result("macho-fat", "Mach-O universal binary",
                           "executable", "signature+container", "strong",
                           ("", "dylib"), declared, ent,
                           f"{count} architectures")
        return _result("java-class", "Java class file", "executable",
                       "signature+container", "strong", ("class",),
                       declared, ent)

    for sig in SIGNATURES:
        if sig.confidence != "strong" or not _match(head, sig):
            continue
        if sig.type_id == "zip" and sig.magic == b"PK\x03\x04":
            refined = _refine_zip(head, reader, declared, ent)
            if refined is not None:
                return refined
        if sig.type_id == "ole2":
            for needle, tid, label, exts in _OLE_NAMES:
                if needle in head:
                    return _result(tid, label, "document",
                                   "signature+container", "strong", exts,
                                   declared, ent,
                                   "OLE directory name in the first 64 KiB")
            return _result("ole2", sig.label, sig.family, "signature",
                           "strong", sig.extensions, declared, ent,
                           "OLE directory not in view; sub-type unknown")
        return _result(sig.type_id, sig.label, sig.family, "signature",
                       "strong", sig.extensions, declared, ent)

    for sig in SIGNATURES:
        if sig.confidence == "weak" and _match(head, sig):
            return _result(sig.type_id, sig.label, sig.family, "signature",
                           "weak", sig.extensions, declared, ent,
                           "weak signature: real data produces this by "
                           "accident")

    text = _text_kind(head)
    if text is not None:
        tid, label = text
        return _result(tid, label, "text", "heuristic", "weak",
                       ("txt", "log", "csv", "json", "xml", "html", "htm",
                        "md", "ini", "cfg", "py", "js", "ps1", "bat", "eml"),
                       declared, ent, "no signature; decodes as text")
    note = "no signature matched"
    if ent is not None and ent > 7.5:
        note += ("; high entropy — compressed, encrypted or random, and "
                 "entropy alone cannot say which")
    return _result("unknown", "Unidentified", "unknown", "none", "none", (),
                   declared, ent, note)


def _text_kind(head: bytes):
    if head.startswith(b"\xef\xbb\xbf"):
        return "text-utf8", "Text (UTF-8 with BOM)"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "text-utf16", "Text (UTF-16 with BOM)"
    if b"\x00" in head:
        return None
    sample = head[:8192]
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError as exc:
        if exc.start < len(sample) - 4:       # not just a cut multibyte tail
            return None
        decoded = sample[:exc.start].decode("utf-8", "ignore")
    stripped = decoded.lstrip().lower()
    if stripped.startswith("<?xml"):
        return "xml", "XML document"
    if stripped.startswith(("<!doctype html", "<html")):
        return "html", "HTML document"
    return "text", "Text"
