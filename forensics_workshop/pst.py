# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Outlook data files (.pst Personal Folders, .ost Offline Folders) from the bytes.

Implemented from Microsoft's open specification [MS-PST] (v20170919): the
NDB layer (header, Node and Block B-trees, blocks, data trees, subnode
trees, block encoding), the LTP layer (Heap-on-Node, BTree-on-Heap,
Property Context, Table Context) and the Messaging layer (message store,
folder hierarchy, contents tables, Message objects, recipient and
attachment tables). Compressed RTF bodies are decompressed per
[MS-OXRTFCP]. The Outlook 2013 OST layout with 4 KB pages (wVer 36), which
[MS-PST] does not describe, follows libyal's PFF format document: 4096-byte
B-tree pages, 512-byte-aligned blocks with a 24-byte trailer, and
zlib-compressed block data.

Nothing is opened by name. The file is a reader with `.size` and
`.read_at(offset, n)` (or bytes); every structure is found by following the
two B-trees from the header, so a multi-gigabyte file is read a page and a
block at a time and never held in memory.

**What is checked.** The header's two CRCs; on every B-tree page its type
byte (twice), its BID against the reference that led to it, its signature
and its CRC; on every block its trailer size, BID, signature and CRC, and,
for a data tree, that the blocks add up to the total the tree claims. A
mismatch is REPORTED in `problems` (on the file, or on the message it
affected) and the structure is still read where it can be: a damaged block
is itself evidence. A page whose type byte is wrong is not a B-tree page at
all, and the entries below it are reported unread rather than guessed at.
What cannot be read at all — no `!BDN` signature, an unknown format
version, an unreadable B-tree root — raises `FileSystemError`.

**Encoding is not encryption.** NDB_CRYPT_PERMUTE and NDB_CRYPT_CYCLIC are
keyless obfuscations ([MS-PST] §5.1, §5.2, tables transcribed from the
specification) and are undone here. A PST *password* is a CRC-32 stored in
the message store for the Outlook UI to check; it protects nothing, and its
presence is recorded as a measurement. Windows Information Protection
(bCryptMethod 0x10) is real encryption with enterprise-held keys: such a
file is refused, with the reason.

**Time.** PidTagClientSubmitTime, PidTagMessageDeliveryTime, creation and
modification times are FILETIMEs (UTC by definition); each is kept raw
beside its decoded value. A message row's time is the client submit time
(when the sender's client submitted it) or, failing that, the delivery time
(when this store received it) — which one is named on the row.

**Rows.** `to_rows` gives one `email` row per message a folder's contents
table lists (contacts, distribution lists, appointments, tasks, sticky notes
and journal entries are `pst-item` rows, since they are not mail), and one
`email-store` row for the file: kind, layout, encoding, header, folders, the
file's problems, and a census of the node B-tree.

**What this does NOT read.** Deleted items: messages and folders whose
nodes survive in free space or in the B-trees but are listed in no table
are not recovered — out of scope; the store row counts the message nodes
that no folder lists (and names the first 50), as a measurement only. The
allocation maps (AMap, PMap, FMap, density list) are not read, so nothing
here says which space is free. Search folders are listed but their
contents (references to messages in other folders) are not repeated.
Named properties (0x8000 and above) are kept by number; the Name-to-ID map
that names them is not read. Folder-associated (FAI) items — views, rules,
forms — are not listed. A multi-block heap in a 4 KB-page OST uses libyal's
documented HID layout (14-bit index, 13-bit block index); no real sample had
one. Whether an encoded 4 KB file encodes before or after compressing is
undocumented: both orders are tried and zlib's Adler-32 check decides; no
real sample was both. HTML and RTF bodies are reduced to text for the
excerpt by an approximate tag/control-word stripper, and the excerpt says
so; the full body is available unreduced through `Pst.body`.

**Validation.** The [MS-PST] §3 sample dumps (header, B-tree pages,
SLBLOCK, the message store's heap, the root hierarchy table) read with no
problem and to the values the specification annotates. Nineteen real files
(Unicode PSTs, a 512-byte-page OST and 4 KB-page OSTs) agree with libpff
on every folder, message, header field, attachment byte and body compared.
No real ANSI file was available: the ANSI layout is checked on files the
test suite writes from the specification, which libpff also reads.
"""

from __future__ import annotations

import codecs
import re
import struct
import zlib
from collections import OrderedDict
from dataclasses import dataclass, field
from html.parser import HTMLParser

from . import timeutil
from .errors import Cancelled, FileSystemError

MAGIC = b"!BDN"
MAX_PROBLEMS = 500
MAX_BT_DEPTH = 8
MAX_TREE_DEPTH = 4
EXCERPT = 2000

CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC, CRYPT_WIP = 0x00, 0x01, 0x02, 0x10
CRYPT_NAMES = {CRYPT_NONE: "none", CRYPT_PERMUTE: "permute",
               CRYPT_CYCLIC: "cyclic", CRYPT_WIP: "wip-protected"}

PTYPE_BBT, PTYPE_NBT = 0x80, 0x81

# NID types ([MS-PST] 2.2.2.1) and the special internal NIDs (2.4.1)
NID_TYPE_HID = 0x00
NID_TYPE_NORMAL_FOLDER = 0x02
NID_TYPE_SEARCH_FOLDER = 0x03
NID_TYPE_NORMAL_MESSAGE = 0x04
NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_ASSOC_MESSAGE = 0x08
NID_TYPE_HIERARCHY_TABLE = 0x0D
NID_TYPE_CONTENTS_TABLE = 0x0E
NID_TYPE_ATTACHMENT_TABLE = 0x11
NID_TYPE_RECIPIENT_TABLE = 0x12
NID_TYPE_LTP = 0x1F
NID_TYPE_NAMES = {
    0x00: "HID", 0x01: "INTERNAL", 0x02: "NORMAL_FOLDER", 0x03: "SEARCH_FOLDER",
    0x04: "NORMAL_MESSAGE", 0x05: "ATTACHMENT", 0x06: "SEARCH_UPDATE_QUEUE",
    0x07: "SEARCH_CRITERIA_OBJECT", 0x08: "ASSOC_MESSAGE",
    0x0A: "CONTENTS_TABLE_INDEX", 0x0B: "RECEIVE_FOLDER_TABLE",
    0x0C: "OUTGOING_QUEUE_TABLE", 0x0D: "HIERARCHY_TABLE",
    0x0E: "CONTENTS_TABLE", 0x0F: "ASSOC_CONTENTS_TABLE",
    0x10: "SEARCH_CONTENTS_TABLE", 0x11: "ATTACHMENT_TABLE",
    0x12: "RECIPIENT_TABLE", 0x13: "SEARCH_TABLE_INDEX", 0x1F: "LTP"}
NID_MESSAGE_STORE = 0x21
NID_ROOT_FOLDER = 0x122

# heap client signatures ([MS-PST] 2.3.1.2)
HN_SIG = 0xEC
BTYPE_TC, BTYPE_BTH, BTYPE_PC = 0x7C, 0xB5, 0xBC

# property types ([MS-OXCDATA] 2.11.1)
PT_NULL, PT_I2, PT_LONG, PT_R4, PT_DOUBLE = 0x0001, 0x0002, 0x0003, 0x0004, 0x0005
PT_CURRENCY, PT_APPTIME, PT_ERROR, PT_BOOLEAN = 0x0006, 0x0007, 0x000A, 0x000B
PT_OBJECT, PT_I8, PT_STRING8, PT_UNICODE = 0x000D, 0x0014, 0x001E, 0x001F
PT_SYSTIME, PT_CLSID, PT_BINARY = 0x0040, 0x0048, 0x0102
MV_FLAG = 0x1000
FIXED_SIZE = {PT_NULL: 0, PT_I2: 2, PT_LONG: 4, PT_R4: 4, PT_DOUBLE: 8,
              PT_CURRENCY: 8, PT_APPTIME: 8, PT_ERROR: 4, PT_BOOLEAN: 1,
              PT_I8: 8, PT_SYSTIME: 8, PT_CLSID: 16}

#: the property tags this reader asks for ([MS-OXPROPS])
PR = {
    "message_class": 0x001A, "subject": 0x0037, "client_submit_time": 0x0039,
    "sent_representing_name": 0x0042, "sent_representing_email": 0x0065,
    "transport_headers": 0x007D, "recipient_type": 0x0C15,
    "sender_name": 0x0C1A, "sender_addrtype": 0x0C1E, "sender_email": 0x0C1F,
    "display_bcc": 0x0E02, "display_cc": 0x0E03, "display_to": 0x0E04,
    "delivery_time": 0x0E06, "message_flags": 0x0E07, "message_size": 0x0E08,
    "attach_size": 0x0E20, "record_key": 0x0FF9, "body": 0x1000,
    "rtf_compressed": 0x1009, "html": 0x1013, "internet_message_id": 0x1035,
    "display_name": 0x3001, "addrtype": 0x3002, "email_address": 0x3003,
    "creation_time": 0x3007, "last_modified": 0x3008,
    "ipm_subtree_entryid": 0x35E0, "wastebasket_entryid": 0x35E3,
    "finder_entryid": 0x35E7, "content_count": 0x3602, "unread_count": 0x3603,
    "subfolders": 0x360A, "container_class": 0x3613, "attach_data": 0x3701,
    "attach_filename": 0x3704, "attach_method": 0x3705,
    "attach_long_filename": 0x3707, "rendering_position": 0x370B,
    "attach_mime": 0x370E, "attach_content_id": 0x3712,
    "smtp_address": 0x39FE, "internet_cpid": 0x3FDE,
    "message_codepage": 0x3FFD, "sender_smtp": 0x5D01,
    "sent_representing_smtp": 0x5D02, "pst_password": 0x67FF,
}

RECIPIENT_KINDS = {0: "originator", 1: "to", 2: "cc", 3: "bcc"}
ATTACH_METHODS = {0: "none", 1: "by-value", 2: "by-reference",
                  3: "by-reference-resolve", 4: "by-reference-only",
                  5: "embedded-message", 6: "ole-storage",
                  7: "by-web-reference"}
MSGFLAG_HASATTACH = 0x10

#: message classes that are Outlook items but not mail; their rows say so
NON_MAIL_CLASSES = ("IPM.CONTACT", "IPM.DISTLIST", "IPM.APPOINTMENT",
                    "IPM.TASK", "IPM.STICKYNOTE", "IPM.ACTIVITY")

#: [MS-PST] §5.1 mpbbCrypt: R (encode), S, I (decode), 3 x 256 bytes,
#: transcribed from the specification's table.
_MPBB_CRYPT = bytes.fromhex(
    "41361362a8216ebbf416cc047f64e85d1ef2cb2a74c55e35d295479e962d9a88"
    "4c7d843fdbac31b6485ff6c4d8398be7233b388ec8c1df25b120a546604e9cfb"
    "aad35651457c550007c92b9d859b09a08fadb30f63ab894bd7a7155a716642bf"
    "264a6b98faea7753b270052cfd593a867ece06eb827857c78d43afb41cd45bcd"
    "e2e9274fc3087280cfb0eff5286dbe304d3492d50e3c2232e5e4f99fc2d10a81"
    "12e1ee918376e397e6618a1779a4b7dc907a5c8c02a6ca69de501a1193b95287"
    "58fced1d37491b6ae0293399bd6cd994f340546ff0c673b8d63e6518441fdd67"
    "10f10c19ecae03a1147ba90bfff8a3c0a201f72ebc2468750dfeba2fb5d0da3d"
    "14530f56b3c87a9ceb65481716159f02cc547c83000d0c0ba262a876dbd9edc7"
    "c5a4dcac8574d6d0a79bae9a967166c36399b8dd73928e847da55ed15d93b157"
    "5150808952944f4e0a6bbc8d7f6e47464140440111cb033ff7f4e1a98f3c3af9"
    "fbf0193082092ec99da08649ee6f4d6dc42d813425871b88aafc06a11238fd4c"
    "4272641337246a757743ffe6b44b365ce4d8353d45b92cecb7312b290768a30e"
    "697b189e2139be281a5b78f523ca2ab0af3efe048ce7e5983295d3f64ae8a6ea"
    "e9f3d52f7020f21f0567ad5510cecde3273bdabad7c226d4911dd21c2233f8fa"
    "f15aefcf90b68bb5bdc0bf08971e6ce261e0c6c159abbb58de5fdf60797eb28a"
    "47f1b4e60b6a7248854e9eebe2f89453e0bba002e85a09abdbe3bac67cc310dd"
    "39059630f53760828cc9134a6b1df3fb8f2697ca911701c4322d6e3195ffd923"
    "d1005e79dc443b1a28c5615720903d83b943be67d2464276c06d5b7eb20f1629"
    "3ca903540dda5ddff6b7c762cd8d06d3695c86d614f7a56675acb1e94521700c"
    "879f74a4224c6fbf1f56aa2eb3783350b0a392bccf191ca763cb1e4d3e4b1b9b"
    "4fe7f0eead3ab55904ea40552551e57a893868527bfc27aed7bdfa07f4cc8e5f"
    "ef359c842b15d5773449b6120a7f7188fd9d18417d93d8582ccefe24afdeb836"
    "c8a180a69998a82f0e816573e4c2a28ad4e111d0088b2af2ed9a643fc16cf9ec")
_ENC_R = _MPBB_CRYPT[0:256]
_ENC_S = _MPBB_CRYPT[256:512]
_ENC_I = _MPBB_CRYPT[512:768]

#: [MS-OXRTFCP] 2.1.2.1 — the dictionary every compressed RTF stream starts with
_RTF_PREBUF = (b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil "
               b"\\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbol"
               b"ArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n"
               b"\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx")


class _Missing:
    def __repr__(self) -> str:
        return "MISSING"


MISSING = _Missing()


def crc32(data: bytes) -> int:
    """[MS-PST] §5.3 ComputeCRC with seed 0: the reflected 0xEDB88320 CRC
    WITHOUT the usual pre/post inversion. zlib computes the inverted form,
    so the inversion is undone around it."""
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def signature(ib: int, bid: int) -> int:
    """[MS-PST] §5.5 ComputeSig: the block/page signature from offset and BID."""
    value = (ib ^ bid) & 0xFFFFFFFF
    return ((value >> 16) ^ value) & 0xFFFF


def decode_permute(data: bytes) -> bytes:
    """Undo NDB_CRYPT_PERMUTE ([MS-PST] §5.1): a byte substitution by mpbbI."""
    return bytes(data).translate(_ENC_I)


def encode_permute(data: bytes) -> bytes:
    return bytes(data).translate(_ENC_R)


def cyclic(data: bytes, key: int) -> bytes:
    """NDB_CRYPT_CYCLIC ([MS-PST] §5.2): symmetric, keyed by the low DWORD of
    the block's BID. The same call encodes and decodes."""
    w = ((key & 0xFFFFFFFF) ^ ((key & 0xFFFFFFFF) >> 16)) & 0xFFFF
    out = bytearray(len(data))
    r, s, i_tab = _ENC_R, _ENC_S, _ENC_I
    for pos, b in enumerate(data):
        lo, hi = w & 0xFF, w >> 8
        b = r[(b + lo) & 0xFF]
        b = s[(b + hi) & 0xFF]
        b = i_tab[(b - hi) & 0xFF]
        out[pos] = (b - lo) & 0xFF
        w = (w + 1) & 0xFFFF
    return bytes(out)


def _utf16(raw: bytes) -> str:
    """UTF-16LE with unpaired surrogates kept as escapes (as ntfs._utf16)."""
    text = bytes(raw).decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


_CODEPAGE_NAMES = {65001: "utf-8", 20127: "ascii", 1200: "utf-16-le",
                   1201: "utf-16-be", 50220: "iso2022_jp", 50221: "iso2022_jp",
                   50222: "iso2022_jp", 51932: "euc_jp", 51949: "euc_kr",
                   52936: "hz", 54936: "gb18030", 10000: "mac_roman",
                   20866: "koi8_r", 21866: "koi8_u", 28591: "latin-1"}


def codec_for(codepage) -> str | None:
    """A Python codec for a Windows code page number, or None if unknown."""
    try:
        cp = int(codepage)
    except (TypeError, ValueError):
        return None
    name = _CODEPAGE_NAMES.get(cp)
    if name is None and 28592 <= cp <= 28606:
        name = f"iso8859_{cp - 28590}"
    if name is None:
        name = f"cp{cp}"
    try:
        codecs.lookup(name)
    except LookupError:
        return None
    return name


def _strip_nul(text: str) -> str:
    return text.rstrip("\x00")


# ---------------------------------------------------------------------------
# readers
# ---------------------------------------------------------------------------

class _BytesReader:
    def __init__(self, data) -> None:
        self._data = bytes(data)
        self.size = len(self._data)

    def read_at(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError("offset and length must not be negative")
        return self._data[offset:offset + length]


def _as_reader(source):
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _BytesReader(source)
    if not hasattr(source, "read_at") or not hasattr(source, "size"):
        raise TypeError("open_pst wants bytes or a reader with .size and "
                        ".read_at(offset, length)")
    return source


class _LRU(OrderedDict):
    def __init__(self, cap: int) -> None:
        super().__init__()
        self.cap = cap

    def fetch(self, key):
        value = self.get(key)
        if value is not None:
            self.move_to_end(key)
        return value

    def store(self, key, value) -> None:
        self[key] = value
        self.move_to_end(key)
        while len(self) > self.cap:
            self.popitem(last=False)


# ---------------------------------------------------------------------------
# layouts and header
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Layout:
    name: str              # "ansi" | "unicode" | "unicode-4k"
    unicode: bool
    page: int              # page size
    page_crc_span: int     # bytes of a page covered by its CRC
    bt_area: int           # bytes of a B-tree page that hold entries
    block_trailer: int
    block_align: int
    id_size: int           # BID / IB size

    @property
    def four_k(self) -> bool:
        return self.page == 4096


ANSI = Layout("ansi", False, 512, 500, 496, 12, 64, 4)
UNICODE = Layout("unicode", True, 512, 496, 488, 16, 64, 8)
UNICODE_4K = Layout("unicode-4k", True, 4096, 4072, 4056, 24, 512, 8)


@dataclass
class Header:
    client: str                 # "SM" pst, "SO" ost, "AB" pab
    version: int                # wVer
    client_version: int         # wVerClient
    layout: str
    crypt_method: int
    crc_partial_stored: int
    crc_partial_computed: int
    crc_full_stored: int | None
    crc_full_computed: int | None
    unique: int
    bid_next_b: int
    bid_next_p: int
    file_eof: int
    amap_last: int
    amap_free: int
    amap_valid: int
    nbt: tuple                  # (bid, ib)
    bbt: tuple
    sentinel: int

    def as_dict(self) -> dict:
        return {"client": self.client, "version": self.version,
                "client_version": self.client_version, "layout": self.layout,
                "crypt_method": self.crypt_method,
                "crypt_name": CRYPT_NAMES.get(self.crypt_method,
                                              f"0x{self.crypt_method:02X}"),
                "crc_partial_ok": self.crc_partial_stored == self.crc_partial_computed,
                "crc_full_ok": (None if self.crc_full_stored is None else
                                self.crc_full_stored == self.crc_full_computed),
                "unique": self.unique, "bid_next_b": self.bid_next_b,
                "bid_next_p": self.bid_next_p, "file_eof": self.file_eof,
                "amap_last": self.amap_last, "amap_free": self.amap_free,
                "amap_valid": self.amap_valid,
                "nbt_root": {"bid": self.nbt[0], "ib": self.nbt[1]},
                "bbt_root": {"bid": self.bbt[0], "ib": self.bbt[1]}}


def parse_header(raw: bytes) -> tuple[Header, Layout, list]:
    """The HEADER ([MS-PST] 2.2.2.6) and which layout the file uses."""
    problems: list = []
    if len(raw) < 512 or raw[:4] != MAGIC:
        raise FileSystemError(
            "This is not an Outlook data file: it does not begin with the "
            "PST/OST signature '!BDN' (or is shorter than a header).")
    client = raw[8:10].decode("latin-1")
    version, client_version = struct.unpack_from("<HH", raw, 10)
    if version in (14, 15):
        layout = ANSI
    elif version == 36:
        layout = UNICODE_4K
    elif version >= 21:
        layout = UNICODE
        if version not in (23, 37):
            problems.append(f"Header format version {version} is not one "
                            "[MS-PST] names; it is read as the Unicode layout.")
    else:
        raise FileSystemError(
            f"Format version {version} is not one this reader knows (ANSI "
            "PST/OST is 14 or 15, Unicode 23, Outlook 2013 OST 36). The file "
            "may be damaged at offset 10 or be another product's format.")
    if layout.unicode and len(raw) < 564:
        raise FileSystemError("The file is shorter than a Unicode PST header.")
    if client not in ("SM", "SO", "AB"):
        problems.append(f"Header client signature {client!r} is not SM (PST), "
                        "SO (OST) or AB (PAB).")
    crc_partial_stored = struct.unpack_from("<I", raw, 4)[0]
    crc_partial = crc32(raw[8:8 + 471])
    if crc_partial != crc_partial_stored:
        problems.append("Header partial CRC does not match (stored "
                        f"0x{crc_partial_stored:08X}, computed 0x{crc_partial:08X}).")
    if layout.unicode:
        bid_next_p, unique = struct.unpack_from("<QI", raw, 32)
        (_r, file_eof, amap_last, amap_free, _pmap, nbt_bid, nbt_ib, bbt_bid,
         bbt_ib, amap_valid, _b, _w) = struct.unpack_from("<IQQQQQQQQBBH", raw, 180)
        sentinel, crypt = raw[512], raw[513]
        bid_next_b = struct.unpack_from("<Q", raw, 516)[0]
        crc_full_stored = struct.unpack_from("<I", raw, 524)[0]
        crc_full = crc32(raw[8:8 + 516])
        if crc_full != crc_full_stored:
            problems.append("Header full CRC does not match (stored "
                            f"0x{crc_full_stored:08X}, computed 0x{crc_full:08X}).")
    else:
        bid_next_b, bid_next_p, unique = struct.unpack_from("<III", raw, 24)
        (_r, file_eof, amap_last, amap_free, _pmap, nbt_bid, nbt_ib, bbt_bid,
         bbt_ib, amap_valid, _b, _w) = struct.unpack_from("<IIIIIIIIIBBH", raw, 164)
        sentinel, crypt = raw[460], raw[461]
        crc_full_stored = crc_full = None
    if sentinel != 0x80:
        problems.append(f"Header sentinel byte is 0x{sentinel:02X}, not 0x80.")
    header = Header(client, version, client_version, layout.name, crypt,
                    crc_partial_stored, crc_partial, crc_full_stored, crc_full,
                    unique, bid_next_b, bid_next_p, file_eof, amap_last,
                    amap_free, amap_valid, (nbt_bid, nbt_ib), (bbt_bid, bbt_ib),
                    sentinel)
    return header, layout, problems


# ---------------------------------------------------------------------------
# messaging-layer records
# ---------------------------------------------------------------------------

@dataclass
class Folder:
    nid: int
    name: str
    path: str
    parent_nid: int | None
    kind: str                       # "normal" | "search"
    content_count: int | None = None
    unread_count: int | None = None
    has_subfolders: bool | None = None
    container_class: str | None = None
    children: list = field(default_factory=list)
    problems: list = field(default_factory=list)

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def as_dict(self, recursive: bool = False) -> dict:
        out = {"nid": self.nid, "name": self.name, "path": self.path,
               "parent_nid": self.parent_nid, "kind": self.kind,
               "content_count": self.content_count,
               "unread_count": self.unread_count,
               "has_subfolders": self.has_subfolders,
               "container_class": self.container_class,
               "problems": list(self.problems)}
        if recursive:
            out["children"] = [c.as_dict(True) for c in self.children]
        return out


@dataclass
class Recipient:
    kind: str               # to / cc / bcc / originator / type-N
    type_raw: int | None
    name: str
    email: str
    smtp: str
    addrtype: str

    @property
    def address(self) -> str:
        return self.smtp or self.email

    def formatted(self) -> str:
        addr = self.address
        if self.name and addr and self.name != addr:
            return f"{self.name} <{addr}>"
        return self.name or addr

    def as_dict(self) -> dict:
        return {"kind": self.kind, "type_raw": self.type_raw, "name": self.name,
                "email": self.email, "smtp": self.smtp, "addrtype": self.addrtype}


@dataclass
class Attachment:
    index: int
    nid: int | None
    filename: str               # long file name, else the short (8.3) one
    short_filename: str
    display_name: str
    size: int | None            # PidTagAttachmentSize (the attachment object's size)
    method: int | None
    method_name: str
    mime_type: str
    content_id: str
    data_type: str              # "binary" | "object" | "none"
    problems: list = field(default_factory=list)
    _bid_data: int = field(default=0, repr=False)
    _bid_sub: int = field(default=0, repr=False)

    def as_dict(self) -> dict:
        return {"index": self.index, "nid": self.nid, "filename": self.filename,
                "short_filename": self.short_filename,
                "display_name": self.display_name, "size": self.size,
                "method": self.method, "method_name": self.method_name,
                "mime_type": self.mime_type, "content_id": self.content_id,
                "data_type": self.data_type, "problems": list(self.problems)}


def _time_pair(raw):
    return {"raw": raw, "utc": timeutil.decode(raw, "filetime"),
            "epoch": "filetime"}


@dataclass
class Message:
    nid: int
    folder_nid: int | None
    folder_path: str
    message_class: str = ""
    subject: str = ""
    subject_prefix_length: int | None = None   # from the 0x01 control prefix
    sender_name: str = ""
    sender_email: str = ""
    sender_smtp: str = ""
    sender_addrtype: str = ""
    sent_representing_name: str = ""
    sent_representing_email: str = ""
    display_to: str = ""
    display_cc: str = ""
    display_bcc: str = ""
    recipients: list = field(default_factory=list)
    client_submit_time: int | None = None
    delivery_time: int | None = None
    creation_time: int | None = None
    modified_time: int | None = None
    internet_message_id: str = ""
    transport_headers: str = ""
    flags: int | None = None
    size: int | None = None
    codepage: str | None = None
    body_kind: str = "none"                    # plain | html | rtf | none
    body_excerpt: str = ""
    attachments: list = field(default_factory=list)
    embedded: bool = False
    problems: list = field(default_factory=list)
    _bid_data: int = field(default=0, repr=False)
    _bid_sub: int = field(default=0, repr=False)

    @property
    def sender(self) -> str:
        addr = self.sender_smtp or self.sender_email
        if self.sender_name and addr and self.sender_name != addr:
            return f"{self.sender_name} <{addr}>"
        return self.sender_name or addr

    def addressed(self, kind: str) -> str:
        found = [r.formatted() for r in self.recipients if r.kind == kind]
        if found:
            return ", ".join(x for x in found if x)
        return {"to": self.display_to, "cc": self.display_cc,
                "bcc": self.display_bcc}.get(kind, "")

    def as_dict(self) -> dict:
        return {
            "nid": self.nid, "folder_nid": self.folder_nid,
            "folder_path": self.folder_path,
            "message_class": self.message_class, "subject": self.subject,
            "subject_prefix_length": self.subject_prefix_length,
            "sender": {"name": self.sender_name, "email": self.sender_email,
                       "smtp": self.sender_smtp, "addrtype": self.sender_addrtype},
            "sent_representing": {"name": self.sent_representing_name,
                                  "email": self.sent_representing_email},
            "display_to": self.display_to, "display_cc": self.display_cc,
            "display_bcc": self.display_bcc,
            "recipients": [r.as_dict() for r in self.recipients],
            "client_submit_time": _time_pair(self.client_submit_time),
            "delivery_time": _time_pair(self.delivery_time),
            "creation_time": _time_pair(self.creation_time),
            "modified_time": _time_pair(self.modified_time),
            "internet_message_id": self.internet_message_id,
            "transport_headers": self.transport_headers,
            "flags": self.flags, "size": self.size, "codepage": self.codepage,
            "body_kind": self.body_kind, "body_excerpt": self.body_excerpt,
            "attachments": [a.as_dict() for a in self.attachments],
            "embedded": self.embedded, "problems": list(self.problems)}


@dataclass(frozen=True)
class NodeEntry:
    nid: int
    bid_data: int
    bid_sub: int
    nid_parent: int


@dataclass(frozen=True)
class BlockEntry:
    bid: int
    ib: int
    cb: int
    cref: int


def parse_bt_page(raw: bytes, ib: int, bid: int, ptype: int, layout: Layout):
    """A BTPAGE ([MS-PST] 2.2.2.7.7.1) read from `raw` (the page's bytes, found
    at file offset `ib`, reached through a reference naming `bid`).

    Returns ((level, entries), problems), or (None, problems) when the bytes
    are not a page of the expected B-tree. Entries are BTENTRY tuples
    (key, bid, ib) on intermediate pages, BlockEntry/NodeEntry on leaves.
    """
    L = layout
    problems: list = []
    tree = "block B-tree" if ptype == PTYPE_BBT else "node B-tree"
    if len(raw) < L.page:
        problems.append(f"A {tree} page at offset {ib} lies beyond the end of "
                        "the file; the entries below it were not read.")
        return None, problems
    t = L.page_crc_span
    if L.unicode:
        p_type, p_rep, wsig, dwcrc, pbid = struct.unpack_from("<BBHIQ", raw, t)
    else:
        p_type, p_rep, wsig, pbid, dwcrc = struct.unpack_from("<BBHII", raw, t)
    if p_type != ptype or p_rep != ptype:
        problems.append(f"The page at offset {ib} that the {tree} points to "
                        f"is not a {tree} page (type bytes 0x{p_type:02X}/"
                        f"0x{p_rep:02X}); the entries below it were not read.")
        return None, problems
    if pbid != bid:
        problems.append(f"{tree} page at offset {ib}: its trailer BID "
                        f"0x{pbid:X} differs from the 0x{bid:X} that points to it.")
    if wsig != signature(ib, pbid):
        problems.append(f"{tree} page at offset {ib}: signature 0x{wsig:04X} "
                        f"does not match (expected 0x{signature(ib, pbid):04X}).")
    if dwcrc != crc32(raw[:t]):
        problems.append(f"{tree} page at offset {ib}: CRC mismatch (stored "
                        f"0x{dwcrc:08X}, computed 0x{crc32(raw[:t]):08X}).")
    if L.four_k:
        c_ent, _c_max, cb_ent, level = struct.unpack_from("<HHBB", raw, L.bt_area)
    else:
        c_ent, _c_max, cb_ent, level = struct.unpack_from("<BBBB", raw, L.bt_area)
    n = L.id_size
    if level:
        need, fmt = 3 * n, ("<QQQ" if L.unicode else "<III")
    elif ptype == PTYPE_BBT:
        need, fmt = 2 * n + 4, ("<QQHH" if L.unicode else "<IIHH")
    else:
        need, fmt = 3 * n + 4, ("<QQQI" if L.unicode else "<IIII")
    if cb_ent < need:
        problems.append(f"{tree} page at offset {ib}: entry size {cb_ent} is "
                        f"smaller than the {need} bytes an entry needs; not read.")
        return None, problems
    if c_ent * cb_ent > L.bt_area:
        problems.append(f"{tree} page at offset {ib}: {c_ent} entries of "
                        f"{cb_ent} bytes do not fit the page; read as many as fit.")
        c_ent = L.bt_area // cb_ent
    entries = []
    for i in range(c_ent):
        vals = struct.unpack_from(fmt, raw, i * cb_ent)
        if level:
            key = vals[0] & 0xFFFFFFFF if ptype == PTYPE_NBT else vals[0]
            entries.append((key, vals[1], vals[2]))
        elif ptype == PTYPE_BBT:
            entries.append(BlockEntry(vals[0], vals[1], vals[2], vals[3]))
        else:
            entries.append(NodeEntry(vals[0] & 0xFFFFFFFF, vals[1], vals[2], vals[3]))
    return (level, tuple(entries)), problems


def check_block(raw: bytes, ib: int, bid: int, cb: int, layout: Layout):
    """Check a block's BLOCKTRAILER ([MS-PST] 2.2.2.8.1) against what the block
    B-tree says (`bid`, `ib`, `cb`). `raw` is the whole block as on disk.
    Returns (inflated size, problems); the inflated size is `cb` except for a
    compressed block in a 4 KB-page file."""
    L = layout
    problems: list = []
    size = -(-(cb + L.block_trailer) // L.block_align) * L.block_align
    key = bid & ~1
    if len(raw) < size:
        problems.append(f"Block 0x{key:X} at offset {ib} runs past the end of the "
                        "file; its trailer could not be checked.")
        return cb, problems
    tr = raw[size - L.block_trailer:size]
    inflated = cb
    if L.four_k:
        t_cb, t_sig, t_crc, t_bid, _u1, inflated, _u2 = struct.unpack_from(
            "<HHIQHHI", tr)
    elif L.unicode:
        t_cb, t_sig, t_crc, t_bid = struct.unpack_from("<HHIQ", tr)
    else:
        t_cb, t_sig, t_bid, t_crc = struct.unpack_from("<HHII", tr)
    data = raw[:cb]
    if t_cb != cb:
        problems.append(f"Block 0x{key:X}: trailer size {t_cb} differs from the "
                        f"block B-tree's {cb}.")
    if t_bid & ~1 != key:
        problems.append(f"Block 0x{key:X} at offset {ib}: its trailer names BID "
                        f"0x{t_bid:X}.")
    if t_sig != signature(ib, t_bid):
        problems.append(f"Block 0x{key:X} at offset {ib}: signature mismatch "
                        f"(stored 0x{t_sig:04X}, expected "
                        f"0x{signature(ib, t_bid):04X}).")
    if t_crc != crc32(data):
        problems.append(f"Block 0x{key:X} at offset {ib}: CRC mismatch (stored "
                        f"0x{t_crc:08X}, computed 0x{crc32(data):08X}); its data "
                        "is read as found.")
    return inflated, problems


# ---------------------------------------------------------------------------
# the file
# ---------------------------------------------------------------------------

class Pst:
    """An opened PST/OST. Build with `open_pst`."""

    def __init__(self, reader) -> None:
        self.reader = _as_reader(reader)
        self.size = self.reader.size
        self.problems: list = []
        self._problem_keys: set = set()
        self.suppressed_problems = 0
        raw = self.reader.read_at(0, 564)
        self.header, self.layout, header_problems = parse_header(raw)
        for p in header_problems:
            self._problem(p)
        h = self.header
        self.kind = ("ost" if h.client == "SO" else "pab" if h.client == "AB"
                     else "pst-unicode" if self.layout.unicode else "pst-ansi")
        if h.crypt_method == CRYPT_WIP:
            raise FileSystemError(
                "This file is protected with Windows Information Protection "
                "(bCryptMethod 0x10): its data blocks are encrypted with keys "
                "held by the organisation, and this reader does not decrypt "
                "them. Its header was read; nothing else can be.")
        if h.crypt_method not in (CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC):
            raise FileSystemError(
                f"Encoding method 0x{h.crypt_method:02X} is not one [MS-PST] "
                "defines (0 none, 1 permute, 2 cyclic); the data blocks "
                "cannot be decoded.")
        self.encryption = CRYPT_NAMES[h.crypt_method]
        if h.file_eof and self.size < h.file_eof:
            self._problem(f"The file is {self.size} bytes but its header says "
                          f"{h.file_eof}: it is truncated (or an incomplete "
                          "copy); structures past the end are reported unread.")
        elif h.file_eof and self.size > h.file_eof:
            self._problem(f"The file is {self.size} bytes, {self.size - h.file_eof}"
                          " more than the size its header records.")
        self._pages = _LRU(4096 if not self.layout.four_k else 1024)
        self._blocks = _LRU(512)
        self._folder_root: Folder | None = None
        self._folder_by_nid: dict = {}
        self._store: dict | None = None
        if self._bt_page(h.nbt[1], h.nbt[0], PTYPE_NBT) is None or \
                self._bt_page(h.bbt[1], h.bbt[0], PTYPE_BBT) is None:
            raise FileSystemError(
                "The root page of the node or block B-tree named in the header "
                "could not be read, so no folder or message can be located. "
                + "; ".join(self.problems[-2:]))

    # -- problems -----------------------------------------------------------

    def _problem(self, text: str, sink: list | None = None) -> None:
        if sink is not None and sink is not self.problems:
            if text not in sink:
                sink.append(text)
            return
        if text in self._problem_keys:
            return
        self._problem_keys.add(text)
        if len(self.problems) >= MAX_PROBLEMS:
            self.suppressed_problems += 1
            return
        self.problems.append(text)

    # -- NDB: pages and B-trees ----------------------------------------------

    def _read(self, ib: int, n: int) -> bytes:
        if ib < 0 or ib >= self.size:
            return b""
        return self.reader.read_at(ib, n)

    def _bt_page(self, ib: int, bid: int, ptype: int):
        """(level, entries) of the B-tree page at `ib`, or None if unreadable."""
        cached = self._pages.fetch((ib, ptype))
        if cached is not None:
            return cached
        raw = self._read(ib, self.layout.page)
        result, problems = parse_bt_page(raw, ib, bid, ptype, self.layout)
        for text in problems:
            self._problem(text)
        if result is not None:
            self._pages.store((ib, ptype), result)
        return result

    def _bt_find(self, root: tuple, key: int, ptype: int):
        bid, ib = root
        expect = None
        for _ in range(MAX_BT_DEPTH + 1):
            page = self._bt_page(ib, bid, ptype)
            if page is None:
                return None
            level, entries = page
            if expect is not None and level != expect:
                self._problem(f"B-tree page at offset {ib} has level {level} "
                              f"where {expect} was expected.")
            if level == 0:
                for e in entries:
                    k = e.nid if ptype == PTYPE_NBT else e.bid & ~1
                    if k == key:
                        return e
                return None
            choice = None
            for e in entries:
                k = e[0] if ptype == PTYPE_NBT else e[0] & ~1
                if k <= key:
                    choice = e
                else:
                    break
            if choice is None:
                return None
            bid, ib, expect = choice[1], choice[2], level - 1
        self._problem("A B-tree is deeper than the 8 levels [MS-PST] allows; "
                      "the lookup was abandoned.")
        return None

    def _bt_iter(self, root: tuple, ptype: int):
        seen = set()
        stack = [(root[0], root[1], 0)]
        while stack:
            bid, ib, depth = stack.pop()
            if ib in seen or depth > MAX_BT_DEPTH:
                self._problem(f"B-tree page at offset {ib} is reached twice or "
                              "too deep; it was read once only.")
                continue
            seen.add(ib)
            page = self._bt_page(ib, bid, ptype)
            if page is None:
                continue
            level, entries = page
            if level == 0:
                yield from entries
            else:
                for e in reversed(entries):
                    stack.append((e[1], e[2], depth + 1))

    def node(self, nid: int) -> NodeEntry | None:
        """The NBT entry for a top-level NID, or None."""
        return self._bt_find(self.header.nbt, nid & 0xFFFFFFFF, PTYPE_NBT)

    def block_entry(self, bid: int) -> BlockEntry | None:
        return self._bt_find(self.header.bbt, bid & ~1, PTYPE_BBT)

    def iter_nodes(self):
        """Every leaf NBT entry, in key order."""
        return self._bt_iter(self.header.nbt, PTYPE_NBT)

    def iter_block_entries(self):
        return self._bt_iter(self.header.bbt, PTYPE_BBT)

    # -- NDB: blocks ------------------------------------------------------------

    def block(self, bid: int, sink: list | None = None) -> bytes | None:
        """One block's data: trailer checked, decoded, inflated. None if absent.
        Damage found in a block is reported to `sink` every time the block is
        read — a block can be shared by several messages."""
        key = bid & ~1
        cached = self._blocks.fetch(key)
        if cached is None:
            local: list = []
            data = self._load_block(key, local)
            cached = (data, tuple(local))
            if data is not None:
                self._blocks.store(key, cached)
        for text in cached[1]:
            self._problem(text, sink)
        return cached[0]

    def _load_block(self, key: int, sink: list) -> bytes | None:
        entry = self.block_entry(key)
        if entry is None:
            self._problem(f"Block 0x{key:X} is not in the block B-tree; the "
                          "data it held is missing.", sink)
            return None
        L = self.layout
        size = -(-(entry.cb + L.block_trailer) // L.block_align) * L.block_align
        raw = self._read(entry.ib, size)
        if len(raw) < entry.cb:
            self._problem(f"Block 0x{key:X} at offset {entry.ib} runs past the end "
                          "of the file; its data is missing.", sink)
            return None
        data = raw[:entry.cb]
        inflated, problems = check_block(raw, entry.ib, key, entry.cb, L)
        for text in problems:
            self._problem(text, sink)
        external = not key & 2
        compressed = L.four_k and inflated != entry.cb
        if not compressed:
            data = self._decode(key, data) if external else data
        else:
            data = self._inflate(key, data, inflated, external, sink)
        return data

    def _decode(self, bid: int, data: bytes) -> bytes:
        if self.header.crypt_method == CRYPT_PERMUTE:
            return decode_permute(data)
        if self.header.crypt_method == CRYPT_CYCLIC:
            return cyclic(data, bid)
        return data

    def _inflate(self, bid: int, stored: bytes, inflated: int, external: bool,
                 sink: list | None) -> bytes | None:
        """A compressed 4 KB-page block. Whether an encoded file encodes before
        or after compressing is not documented and no sample showed it, so
        both orders are tried; zlib's Adler-32 check rejects the wrong one."""
        encoded = external and self.header.crypt_method != CRYPT_NONE
        attempts = ((lambda: zlib.decompress(self._decode(bid, stored))),
                    (lambda: self._decode(bid, zlib.decompress(stored)))) \
            if encoded else ((lambda: zlib.decompress(stored)),)
        for attempt in attempts:
            try:
                out = attempt()
                break
            except zlib.error:
                continue
        else:
            self._problem(f"Block 0x{bid:X} is marked compressed ({len(stored)} -> "
                          f"{inflated} bytes) but does not inflate; it is "
                          "unreadable.", sink)
            return None
        if len(out) != inflated:
            self._problem(f"Block 0x{bid:X} inflated to {len(out)} bytes, not "
                          f"the {inflated} its trailer records.", sink)
        return out

    def data_blocks(self, bid: int, sink: list | None = None, _depth: int = 0):
        """Yield the data blocks of a node's data tree, in order ([MS-PST]
        2.2.2.8.3.2). A data block yields itself; an XBLOCK/XXBLOCK its leaves."""
        if not bid:
            return
        data = self.block(bid, sink)
        if data is None:
            return
        if not bid & 2:
            yield data
            return
        if _depth >= 2 or len(data) < 8:
            self._problem(f"Internal block 0x{bid:X} is nested deeper than an "
                          "XXBLOCK allows or is too short; not followed.", sink)
            return
        btype, level, count, total = struct.unpack_from("<BBHI", data, 0)
        if btype != 1 or level not in (1, 2):
            self._problem(f"Internal block 0x{bid:X} is not an XBLOCK/XXBLOCK "
                          f"(type {btype}, level {level}); its data is missing.", sink)
            return
        n = self.layout.id_size
        fmt = "<Q" if n == 8 else "<I"
        room = (len(data) - 8) // n
        if count > room:
            self._problem(f"XBLOCK 0x{bid:X} lists {count} blocks but holds "
                          f"room for {room}.", sink)
            count = room
        seen = 0
        for i in range(count):
            child = struct.unpack_from(fmt, data, 8 + i * n)[0]
            if level == 1 and child & 2:
                self._problem(f"XBLOCK 0x{bid:X} points at internal block "
                              f"0x{child:X} where a data block belongs.", sink)
                continue
            for blob in self.data_blocks(child, sink, _depth + 1):
                seen += len(blob)
                yield blob
        if seen != total:
            self._problem(f"Data tree 0x{bid:X} holds {seen} bytes but records "
                          f"{total}.", sink)

    def node_bytes(self, bid: int, sink: list | None = None) -> bytes:
        return b"".join(self.data_blocks(bid, sink))

    def subnodes(self, bid: int, sink: list | None = None, _depth: int = 0) -> dict:
        """{nid: (bid_data, bid_sub)} from a subnode tree ([MS-PST] 2.2.2.8.3.3)."""
        out: dict = {}
        if not bid:
            return out
        data = self.block(bid, sink)
        if data is None:
            return out
        if len(data) < 4:
            self._problem(f"Subnode block 0x{bid:X} is too short.", sink)
            return out
        btype, level, count = struct.unpack_from("<BBH", data, 0)
        if btype != 2 or level not in (0, 1) or _depth > 1:
            self._problem(f"Block 0x{bid:X} is not an SLBLOCK/SIBLOCK (type "
                          f"{btype}, level {level}); the subnodes it held are "
                          "missing.", sink)
            return out
        uni = self.layout.unicode
        hdr = 8 if uni else 4
        size = (24 if level == 0 else 16) if uni else (12 if level == 0 else 8)
        room = (len(data) - hdr) // size
        if count > room:
            self._problem(f"Subnode block 0x{bid:X} lists {count} entries but "
                          f"holds {room}.", sink)
            count = room
        for i in range(count):
            off = hdr + i * size
            if level == 0:
                nid, bdata, bsub = struct.unpack_from("<QQQ" if uni else "<III",
                                                      data, off)
                out[nid & 0xFFFFFFFF] = (bdata, bsub)
            else:
                _nid, child = struct.unpack_from("<QQ" if uni else "<II", data, off)
                out.update(self.subnodes(child, sink, _depth + 1))
        return out

    # -- LTP ------------------------------------------------------------------

    def _context(self, bid_data: int, bid_sub: int, what: str, sink: list | None,
                 subnodes: dict | None = None):
        blocks = list(self.data_blocks(bid_data, sink))
        if not blocks:
            raise _Unreadable(f"{what}: its data is missing or unreadable.")
        subs = subnodes if subnodes is not None else self.subnodes(bid_sub, sink)
        return _Heap(self, blocks, subs, what, sink)

    def property_context(self, bid_data: int, bid_sub: int = 0, *, what: str = "node",
                         sink: list | None = None, codepage: str | None = None):
        heap = self._context(bid_data, bid_sub, what, sink)
        return PropertyContext(heap, codepage=codepage)

    def table_context(self, bid_data: int, bid_sub: int = 0, *, what: str = "table",
                      sink: list | None = None, codepage: str | None = None):
        heap = self._context(bid_data, bid_sub, what, sink)
        return TableContext(heap, codepage=codepage)

    def node_pc(self, nid: int, what: str, sink: list | None = None,
                codepage: str | None = None):
        entry = self.node(nid)
        if entry is None:
            raise _Unreadable(f"{what} (NID 0x{nid:X}) is not in the node B-tree.")
        return self.property_context(entry.bid_data, entry.bid_sub, what=what,
                                     sink=sink, codepage=codepage)

    def node_tc(self, nid: int, what: str, sink: list | None = None,
                codepage: str | None = None):
        entry = self.node(nid)
        if entry is None:
            raise _Unreadable(f"{what} (NID 0x{nid:X}) is not in the node B-tree.")
        return self.table_context(entry.bid_data, entry.bid_sub, what=what,
                                  sink=sink, codepage=codepage)

    # -- messaging: store and folders -----------------------------------------

    @property
    def store(self) -> dict:
        """The message store's identifying properties ([MS-PST] 2.4.3)."""
        if self._store is not None:
            return self._store
        out: dict = {"display_name": "", "record_key": None, "pst_password_raw": None,
                     "ipm_subtree_nid": None, "wastebasket_nid": None,
                     "finder_nid": None}
        try:
            pc = self.node_pc(NID_MESSAGE_STORE, "The message store")
        except _Unreadable as exc:
            self._problem(str(exc))
            self._store = out
            return out
        out["display_name"] = pc.text(PR["display_name"])
        rk = pc.get(PR["record_key"])
        out["record_key"] = rk.hex() if isinstance(rk, bytes) else None
        pw = pc.get(PR["pst_password"])
        out["pst_password_raw"] = (f"{pw & 0xFFFFFFFF:08X}"
                                   if isinstance(pw, int) else None)
        for key, prop in (("ipm_subtree_nid", "ipm_subtree_entryid"),
                          ("wastebasket_nid", "wastebasket_entryid"),
                          ("finder_nid", "finder_entryid")):
            eid = pc.get(PR[prop])
            if isinstance(eid, bytes) and len(eid) >= 24:
                out[key] = struct.unpack_from("<I", eid, 20)[0]
        self._store = out
        return out

    def folders(self) -> Folder:
        """The folder tree from the root folder (NID 0x122), with paths.
        The root's own path is "/"; its children are "/<name>", and so on."""
        if self._folder_root is not None:
            return self._folder_root
        root = self._load_folder(NID_ROOT_FOLDER, None, "", 0)
        self._folder_root = root
        return root

    def iter_folders(self):
        yield from self.folders().walk()

    def folder(self, nid: int) -> Folder | None:
        self.folders()
        return self._folder_by_nid.get(nid)

    def _load_folder(self, nid: int, parent: Folder | None, parent_path: str,
                     depth: int) -> Folder:
        kind = "search" if nid & 0x1F == NID_TYPE_SEARCH_FOLDER else "normal"
        folder = Folder(nid, "", "/", parent.nid if parent else None, kind)
        self._folder_by_nid[nid] = folder
        try:
            pc = self.node_pc(nid, f"Folder 0x{nid:X}", folder.problems)
            folder.name = pc.text(PR["display_name"])
            folder.content_count = pc.get_int(PR["content_count"])
            folder.unread_count = pc.get_int(PR["unread_count"])
            sub = pc.get(PR["subfolders"])
            folder.has_subfolders = bool(sub) if sub is not None else None
            folder.container_class = pc.text(PR["container_class"]) or None
        except _Unreadable as exc:
            folder.problems.append(str(exc))
        except (struct.error, IndexError, ValueError) as exc:
            folder.problems.append(f"Folder 0x{nid:X} properties are damaged: {exc}")
        if parent is not None:
            name = folder.name or f"[folder 0x{nid:X}]"
            folder.path = f"{parent_path.rstrip('/')}/{name.replace('/', '%2F')}"
        if depth > 64:
            folder.problems.append("Folder nesting deeper than 64; not followed.")
            return folder
        hier = (nid & ~0x1F) | NID_TYPE_HIERARCHY_TABLE
        entry = self.node(hier)
        if entry is None:
            if folder.has_subfolders:
                folder.problems.append("The folder records sub-folders but its "
                                       "hierarchy table is missing.")
            return folder
        try:
            tc = self.table_context(entry.bid_data, entry.bid_sub,
                                    what=f"Hierarchy table of folder 0x{nid:X}",
                                    sink=folder.problems)
            child_nids = [row_id for row_id, _row in tc.rows(columns=())]
        except _Unreadable as exc:
            folder.problems.append(str(exc))
            child_nids = []
        for child_nid in child_nids:
            if child_nid in self._folder_by_nid:
                folder.problems.append(f"Sub-folder 0x{child_nid:X} is listed "
                                       "twice in the hierarchy; read once.")
                continue
            if child_nid & 0x1F not in (NID_TYPE_NORMAL_FOLDER, NID_TYPE_SEARCH_FOLDER):
                folder.problems.append(f"Hierarchy row 0x{child_nid:X} is not a "
                                       "folder NID; skipped.")
                continue
            child = self._load_folder(child_nid, folder, folder.path, depth + 1)
            child_entry = self.node(child_nid)
            if child_entry is not None and child_entry.nid_parent != nid:
                child.problems.append(
                    f"Its node records parent 0x{child_entry.nid_parent:X}; the "
                    f"hierarchy table of 0x{nid:X} lists it.")
            folder.children.append(child)
        return folder

    # -- messaging: messages ---------------------------------------------------

    def message_nids(self, folder: Folder) -> list:
        """The message NIDs a folder's contents table lists, in row order."""
        if folder.kind == "search":
            return []
        nid = (folder.nid & ~0x1F) | NID_TYPE_CONTENTS_TABLE
        entry = self.node(nid)
        if entry is None:
            if folder.content_count:
                folder.problems.append(f"The folder records {folder.content_count}"
                                       " items but its contents table is missing.")
            return []
        try:
            tc = self.table_context(entry.bid_data, entry.bid_sub,
                                    what=f"Contents table of {folder.path}",
                                    sink=folder.problems)
            nids = [row_id for row_id, _row in tc.rows(columns=())]
        except _Unreadable as exc:
            folder.problems.append(str(exc))
            return []
        if folder.content_count is not None and folder.content_count != len(nids):
            note = (f"PidTagContentCount records {folder.content_count} items; "
                    f"the contents table lists {len(nids)}.")
            if note not in folder.problems:
                folder.problems.append(note)
        return nids

    def messages(self, folder: Folder, *, should_cancel=None):
        """Yield every Message the folder's contents table lists. Search
        folders yield nothing: their rows point at messages in other folders."""
        for nid in self.message_nids(folder):
            if should_cancel is not None and should_cancel():
                raise Cancelled("PST message listing was cancelled")
            yield self.message(nid, folder=folder)

    def iter_messages(self, *, should_cancel=None):
        """(folder, message) for every message in every non-search folder."""
        for folder in self.iter_folders():
            for msg in self.messages(folder, should_cancel=should_cancel):
                yield folder, msg

    def message(self, nid: int, *, folder: Folder | None = None) -> Message:
        """One top-level message by NID. Damage is reported on the message."""
        folder_path = folder.path if folder else ""
        msg = Message(nid, folder.nid if folder else None, folder_path)
        entry = self.node(nid)
        if entry is None:
            msg.problems.append(f"Message 0x{nid:X} is listed in the folder but "
                                "its node is not in the node B-tree.")
            return msg
        if folder is not None and entry.nid_parent != folder.nid:
            msg.problems.append(f"Its node records parent folder "
                                f"0x{entry.nid_parent:X}, not 0x{folder.nid:X} "
                                "whose contents table lists it.")
        if folder is None:
            parent = self.folder(entry.nid_parent)
            if parent is not None:
                msg.folder_nid, msg.folder_path = parent.nid, parent.path
        msg._bid_data, msg._bid_sub = entry.bid_data, entry.bid_sub
        self._fill_message(msg)
        return msg

    def _fill_message(self, msg: Message) -> None:
        try:
            subs = self.subnodes(msg._bid_sub, msg.problems)
            heap = self._context(msg._bid_data, 0, f"Message 0x{msg.nid:X}",
                                 msg.problems, subnodes=subs)
            pc = PropertyContext(heap)
            cp = pc.get_int(PR["message_codepage"]) or pc.get_int(PR["internet_cpid"])
            msg.codepage = codec_for(cp) if cp else None
            pc.codepage = msg.codepage or "cp1252"
            self._message_properties(msg, pc)
            self._message_body(msg, pc)
            self._message_recipients(msg, subs)
            self._message_attachments(msg, subs)
        except _Unreadable as exc:
            msg.problems.append(str(exc))
        except (struct.error, IndexError, ValueError, KeyError) as exc:
            msg.problems.append(f"Message 0x{msg.nid:X} is damaged where it was "
                                f"read ({type(exc).__name__}: {exc}); what was "
                                "read before the damage is kept.")

    def _message_properties(self, msg: Message, pc: PropertyContext) -> None:
        msg.message_class = pc.text(PR["message_class"])
        subject = pc.text(PR["subject"])
        if subject[:1] == "\x01" and len(subject) >= 2:
            msg.subject_prefix_length = max(0, ord(subject[1]) - 1)
            subject = subject[2:]
        msg.subject = subject
        msg.sender_name = pc.text(PR["sender_name"])
        msg.sender_email = pc.text(PR["sender_email"])
        msg.sender_smtp = pc.text(PR["sender_smtp"])
        msg.sender_addrtype = pc.text(PR["sender_addrtype"])
        msg.sent_representing_name = pc.text(PR["sent_representing_name"])
        msg.sent_representing_email = (pc.text(PR["sent_representing_smtp"])
                                       or pc.text(PR["sent_representing_email"]))
        msg.display_to = pc.text(PR["display_to"])
        msg.display_cc = pc.text(PR["display_cc"])
        msg.display_bcc = pc.text(PR["display_bcc"])
        msg.client_submit_time = pc.get_int(PR["client_submit_time"])
        msg.delivery_time = pc.get_int(PR["delivery_time"])
        msg.creation_time = pc.get_int(PR["creation_time"])
        msg.modified_time = pc.get_int(PR["last_modified"])
        msg.internet_message_id = pc.text(PR["internet_message_id"])
        msg.transport_headers = pc.text(PR["transport_headers"])
        msg.flags = pc.get_int(PR["message_flags"])
        msg.size = pc.get_int(PR["message_size"])

    def _message_body(self, msg: Message, pc: PropertyContext) -> None:
        if pc.has(PR["body"]):
            msg.body_kind = "plain"
            msg.body_excerpt = _excerpt(pc.text(PR["body"], limit=EXCERPT * 4))
            return
        if pc.has(PR["html"]):
            msg.body_kind = "html"
            html = _html_text(pc, PR["html"], limit=EXCERPT * 50)
            msg.body_excerpt = _excerpt("[HTML body reduced to text — approximate] "
                                        + html_to_text(html))
            return
        if pc.has(PR["rtf_compressed"]):
            msg.body_kind = "rtf"
            raw = pc.get(PR["rtf_compressed"])
            try:
                rtf = decompress_rtf(raw if isinstance(raw, bytes) else b"")
            except ValueError as exc:
                msg.problems.append(f"Compressed RTF body: {exc}")
                msg.body_excerpt = "[body only as RTF; it could not be decompressed]"
                return
            msg.body_excerpt = _excerpt("[RTF body reduced to text — approximate] "
                                        + rtf_to_text(rtf))

    def body(self, msg: Message) -> tuple[str, str | bytes | None]:
        """(kind, full body): plain text, HTML text, or decompressed RTF bytes."""
        pc = self._message_pc(msg)
        if pc.has(PR["body"]):
            return "plain", pc.text(PR["body"])
        if pc.has(PR["html"]):
            return "html", _html_text(pc, PR["html"])
        if pc.has(PR["rtf_compressed"]):
            raw = pc.get(PR["rtf_compressed"])
            return "rtf", decompress_rtf(raw if isinstance(raw, bytes) else b"")
        return "none", None

    def _message_pc(self, msg: Message) -> PropertyContext:
        subs = self.subnodes(msg._bid_sub, msg.problems)
        heap = self._context(msg._bid_data, 0, f"Message 0x{msg.nid:X}",
                             msg.problems, subnodes=subs)
        return PropertyContext(heap, codepage=msg.codepage or "cp1252")

    def _subnode_tc(self, subs: dict, nid_type: int, what: str, msg: Message):
        found = [n for n in subs if n & 0x1F == nid_type]
        if not found:
            return None
        if len(found) > 1:
            msg.problems.append(f"{len(found)} {what} subnodes; the first is read.")
        bid_data, bid_sub = subs[sorted(found)[0]]
        return self.table_context(bid_data, bid_sub, what=f"{what} of message "
                                  f"0x{msg.nid:X}", sink=msg.problems,
                                  codepage=msg.codepage or "cp1252")

    def _message_recipients(self, msg: Message, subs: dict) -> None:
        tc = self._subnode_tc(subs, NID_TYPE_RECIPIENT_TABLE, "Recipient table", msg)
        if tc is None:
            return          # appointments, notes, drafts: no table is written
        cols = (PR["recipient_type"], PR["display_name"], PR["email_address"],
                PR["smtp_address"], PR["addrtype"])
        for _row_id, row in tc.rows(columns=cols):
            rtype = row.get(PR["recipient_type"])
            rtype = rtype if isinstance(rtype, int) else None
            kind = (RECIPIENT_KINDS.get(rtype & 0x0FFFFFFF, f"type-{rtype}")
                    if rtype is not None else "unknown")
            msg.recipients.append(Recipient(
                kind, rtype, _as_text(row.get(PR["display_name"])),
                _as_text(row.get(PR["email_address"])),
                _as_text(row.get(PR["smtp_address"])),
                _as_text(row.get(PR["addrtype"]))))

    def _message_attachments(self, msg: Message, subs: dict) -> None:
        tc = self._subnode_tc(subs, NID_TYPE_ATTACHMENT_TABLE, "Attachment table",
                              msg)
        if tc is None:
            if msg.flags is not None and msg.flags & MSGFLAG_HASATTACH:
                msg.problems.append("PidTagMessageFlags says the message has "
                                    "attachments but there is no attachment table.")
            return
        cols = (PR["attach_size"], PR["attach_filename"], PR["attach_method"])
        for index, (row_id, row) in enumerate(tc.rows(columns=cols)):
            att = Attachment(index, row_id, "", _as_text(row.get(PR["attach_filename"])),
                             "", row.get(PR["attach_size"]) if isinstance(
                                 row.get(PR["attach_size"]), int) else None,
                             row.get(PR["attach_method"]) if isinstance(
                                 row.get(PR["attach_method"]), int) else None,
                             "", "", "", "none")
            sub = subs.get(row_id)
            if sub is None:
                att.problems.append(f"Attachment row 0x{row_id:X} has no "
                                    "attachment subnode; only the table row is known.")
            else:
                att._bid_data, att._bid_sub = sub
                try:
                    pc = self.property_context(sub[0], sub[1], what=f"Attachment "
                                               f"0x{row_id:X}", sink=att.problems,
                                               codepage=msg.codepage or "cp1252")
                    att.short_filename = pc.text(PR["attach_filename"]) or att.short_filename
                    att.display_name = pc.text(PR["display_name"])
                    att.mime_type = pc.text(PR["attach_mime"])
                    att.content_id = pc.text(PR["attach_content_id"])
                    long_name = pc.text(PR["attach_long_filename"])
                    size = pc.get_int(PR["attach_size"])
                    method = pc.get_int(PR["attach_method"])
                    att.size = size if size is not None else att.size
                    att.method = method if method is not None else att.method
                    ptype = pc.type_of(PR["attach_data"])
                    att.data_type = ("object" if ptype == PT_OBJECT else
                                     "binary" if ptype is not None else "none")
                    att.filename = long_name
                except _Unreadable as exc:
                    att.problems.append(str(exc))
            att.filename = att.filename or att.short_filename
            att.method_name = (ATTACH_METHODS.get(att.method, f"method-{att.method}")
                               if att.method is not None else "unknown")
            msg.attachments.append(att)

    def _attachment(self, msg: Message, n: int) -> tuple[Attachment, PropertyContext]:
        if not 0 <= n < len(msg.attachments):
            raise FileSystemError(f"Message 0x{msg.nid:X} has "
                                  f"{len(msg.attachments)} attachments; there is "
                                  f"no attachment {n}.")
        att = msg.attachments[n]
        if not att._bid_data:
            raise FileSystemError(f"Attachment {n} of message 0x{msg.nid:X} has no "
                                  "attachment object to read; only its table row "
                                  "survives.")
        try:
            pc = self.property_context(att._bid_data, att._bid_sub,
                                       what=f"Attachment {n}", sink=att.problems)
        except _Unreadable as exc:
            raise FileSystemError(str(exc)) from None
        return att, pc

    def attachment_chunks(self, msg: Message, n: int):
        """Stream attachment `n`'s binary content block by block."""
        att, pc = self._attachment(msg, n)
        ptype = pc.type_of(PR["attach_data"])
        if ptype == PT_OBJECT and att.method == 5:
            raise FileSystemError(
                f"Attachment {n} ({att.filename or 'unnamed'}) is an embedded "
                "message, not a byte stream; open it with embedded_message().")
        if ptype == PT_OBJECT:                  # OLE storage: the object's bytes
            obj = pc.get(PR["attach_data"])
            sub = pc.heap.subnodes.get(obj[1])
            if sub is None:
                raise FileSystemError(f"Attachment {n}'s object subnode "
                                      f"0x{obj[1]:X} is missing.")
            yield from self.data_blocks(sub[0], att.problems)
            return
        if ptype is None:
            raise FileSystemError(
                f"Attachment {n} ({att.filename or 'unnamed'}) carries no data "
                f"property (method {att.method_name}).")
        yield from pc.chunks(PR["attach_data"])

    def read_attachment(self, msg: Message, n: int) -> bytes:
        """Attachment `n`'s content as bytes: the data of a by-value
        attachment, or the stored object of an OLE-storage one (method 6).
        An embedded message (method 5) is refused: see embedded_message()."""
        return b"".join(self.attachment_chunks(msg, n))

    def embedded_message(self, msg: Message, n: int) -> Message:
        """Attachment `n` read as the message it embeds ([MS-PST] 2.4.6.2.2)."""
        att, pc = self._attachment(msg, n)
        obj = pc.get(PR["attach_data"])
        if not isinstance(obj, tuple) or obj[0] != "object":
            raise FileSystemError(f"Attachment {n} is not an embedded message.")
        sub = pc.heap.subnodes.get(obj[1])
        if sub is None:
            raise FileSystemError(f"Embedded message subnode 0x{obj[1]:X} of "
                                  f"attachment {n} is missing.")
        inner = Message(obj[1], msg.folder_nid, msg.folder_path, embedded=True)
        inner._bid_data, inner._bid_sub = sub
        self._fill_message(inner)
        return inner

    # -- census -------------------------------------------------------------------

    def node_census(self) -> dict:
        """Counts of top-level NBT nodes by NID type (a measurement)."""
        counts: dict = {}
        for entry in self.iter_nodes():
            name = NID_TYPE_NAMES.get(entry.nid & 0x1F, f"0x{entry.nid & 0x1F:02X}")
            counts[name] = counts.get(name, 0) + 1
        return counts


class _Unreadable(Exception):
    """A structure below the file level could not be read; reported, not raised."""


def open_pst(reader_or_bytes) -> Pst:
    """Open a PST/OST from bytes or a reader (`.size`, `.read_at`)."""
    return Pst(reader_or_bytes)


# ---------------------------------------------------------------------------
# LTP: heap, BTH, PC, TC
# ---------------------------------------------------------------------------

class _Heap:
    """Heap-on-Node ([MS-PST] 2.3.1) over a node's data blocks."""

    def __init__(self, pst: Pst, blocks: list, subnodes: dict, what: str,
                 sink: list | None) -> None:
        self.pst, self.blocks, self.subnodes, self.what = pst, blocks, subnodes, what
        self.sink = sink
        b0 = blocks[0]
        if len(b0) < 12:
            raise _Unreadable(f"{what}: its heap header is truncated.")
        _ib, sig, self.client_sig, self.user_root = struct.unpack_from("<HBBI", b0, 0)
        if sig != HN_SIG:
            raise _Unreadable(f"{what}: its data is not a heap (signature "
                              f"0x{sig:02X}, not 0xEC) — damaged, or not decoded.")
        self._maps: dict = {}
        self.four_k = pst.layout.four_k

    def problem(self, text: str) -> None:
        self.pst._problem(f"{self.what}: {text}", self.sink)

    def _map(self, i: int) -> tuple:
        if i in self._maps:
            return self._maps[i]
        blk = self.blocks[i]
        offsets: tuple = ()
        if len(blk) >= 2:
            ibm = struct.unpack_from("<H", blk, 0)[0]
            if ibm + 4 <= len(blk):
                c_alloc, _c_free = struct.unpack_from("<HH", blk, ibm)
                if ibm + 4 + 2 * (c_alloc + 1) <= len(blk):
                    offsets = struct.unpack_from(f"<{c_alloc + 1}H", blk, ibm + 4)
        if not offsets:
            self.problem(f"heap block {i} has no readable page map.")
        self._maps[i] = offsets
        return offsets

    def get(self, hid: int) -> bytes | None:
        if hid & 0x1F != NID_TYPE_HID:
            return None
        if self.four_k:
            index, block = (hid >> 5) & 0x3FFF, hid >> 19
        else:
            index, block = (hid >> 5) & 0x7FF, hid >> 16
        if block >= len(self.blocks):
            self.problem(f"HID 0x{hid:X} names heap block {block} of "
                         f"{len(self.blocks)}.")
            return None
        offsets = self._map(block)
        if not 1 <= index < len(offsets):
            self.problem(f"HID 0x{hid:X} names allocation {index}, which the "
                         "page map does not hold.")
            return None
        start, end = offsets[index - 1], offsets[index]
        if not start <= end <= len(self.blocks[block]):
            self.problem(f"HID 0x{hid:X} spans bytes {start}-{end} outside its block.")
            return None
        return self.blocks[block][start:end]

    def hnid_bytes(self, hnid: int) -> bytes | None:
        if hnid == 0:
            return b""
        if hnid & 0x1F == NID_TYPE_HID:
            return self.get(hnid)
        return b"".join(self.hnid_chunks(hnid))

    def hnid_chunks(self, hnid: int):
        if hnid & 0x1F == NID_TYPE_HID:
            data = self.get(hnid)
            if data:
                yield data
            return
        sub = self.subnodes.get(hnid)
        if sub is None:
            self.problem(f"value subnode 0x{hnid:X} is missing.")
            return
        yield from self.pst.data_blocks(sub[0], self.sink)

    def bth(self, hid: int):
        """(cbKey, cbEnt, [(key, data)]) of a BTree-on-Heap ([MS-PST] 2.3.2)."""
        hdr = self.get(hid)
        if hdr is None or len(hdr) < 8:
            raise _Unreadable(f"{self.what}: BTH header 0x{hid:X} is unreadable.")
        btype, cb_key, cb_ent, levels, root = struct.unpack_from("<BBBBI", hdr, 0)
        if btype != BTYPE_BTH or cb_key not in (2, 4, 8, 16) or not 0 < cb_ent <= 32:
            raise _Unreadable(f"{self.what}: BTH header is not valid (type "
                              f"0x{btype:02X}, key {cb_key}, entry {cb_ent}).")
        records = []
        if not root:
            return cb_key, cb_ent, records
        stack = [(root, levels)]
        seen = set()
        while stack:
            hid_now, level = stack.pop()
            if hid_now in seen:
                self.problem(f"BTH record array 0x{hid_now:X} is referenced twice.")
                continue
            seen.add(hid_now)
            data = self.get(hid_now)
            if data is None:
                continue
            if level > 0:
                size = cb_key + 4
                children = [struct.unpack_from("<I", data, i + cb_key)[0]
                            for i in range(0, len(data) - size + 1, size)]
                for child in reversed(children):
                    stack.append((child, level - 1))
            else:
                size = cb_key + cb_ent
                if len(data) % size:
                    self.problem(f"BTH leaf 0x{hid_now:X} is {len(data)} bytes, "
                                 f"not a multiple of {size}.")
                for i in range(0, len(data) - size + 1, size):
                    records.append((data[i:i + cb_key], data[i + cb_key:i + size]))
        return cb_key, cb_ent, records


class _Detached:
    """Stands in for the file when a heap is read from loose bytes."""

    def __init__(self, layout: Layout) -> None:
        self.layout = layout
        self.problems: list = []

    def _problem(self, text: str, sink: list | None = None) -> None:
        target = self.problems if sink is None else sink
        if text not in target:
            target.append(text)

    def data_blocks(self, bid: int, sink: list | None = None):
        return iter(())


def heap_from_bytes(blocks: list, *, layout: Layout = UNICODE, problems=None):
    """A Heap-on-Node over loose data blocks (no file, no subnodes) — for
    reading a carved or exported HN, and for tests. Wrap the result in
    PropertyContext or TableContext."""
    holder = _Detached(layout)
    return _Heap(holder, [bytes(b) for b in blocks], {}, "detached heap",
                 problems if problems is not None else holder.problems)


def _decode_value(ptype: int, raw: bytes, codepage: str):
    """A property value from its stored bytes ([MS-OXCDATA] 2.11.1)."""
    if ptype & MV_FLAG:
        return _decode_mv(ptype & ~MV_FLAG, raw, codepage)
    if ptype == PT_UNICODE:
        return _strip_nul(_utf16(raw[:len(raw) - len(raw) % 2]))
    if ptype == PT_STRING8:
        return _strip_nul(bytes(raw).decode(codepage, "replace"))
    if ptype in (PT_BINARY, 0x00FB, 0x00FD, 0x00FE):
        return bytes(raw)
    size = FIXED_SIZE.get(ptype)
    if size is None:
        return bytes(raw)
    if len(raw) < size:
        raise ValueError(f"property type 0x{ptype:04X} needs {size} bytes, "
                         f"found {len(raw)}")
    if ptype == PT_NULL:
        return None
    if ptype == PT_I2:
        return struct.unpack_from("<h", raw)[0]
    if ptype in (PT_LONG,):
        return struct.unpack_from("<i", raw)[0]
    if ptype == PT_ERROR:
        return struct.unpack_from("<I", raw)[0]
    if ptype == PT_R4:
        return struct.unpack_from("<f", raw)[0]
    if ptype in (PT_DOUBLE, PT_APPTIME):
        return struct.unpack_from("<d", raw)[0]
    if ptype == PT_BOOLEAN:
        return raw[0] != 0
    if ptype in (PT_I8, PT_CURRENCY):
        return struct.unpack_from("<q", raw)[0]
    if ptype == PT_SYSTIME:
        return struct.unpack_from("<Q", raw)[0]
    if ptype == PT_CLSID:
        a, b, c = struct.unpack_from("<IHH", raw)
        tail = raw[8:16].hex()
        return f"{a:08x}-{b:04x}-{c:04x}-{tail[:4]}-{tail[4:]}"
    return bytes(raw)


def _decode_mv(base: int, raw: bytes, codepage: str) -> list:
    size = FIXED_SIZE.get(base)
    if size:
        return [_decode_value(base, raw[i:i + size], codepage)
                for i in range(0, len(raw) - size + 1, size)]
    if len(raw) < 4:
        return []
    count = struct.unpack_from("<I", raw, 0)[0]
    if 4 + 4 * count > len(raw):
        raise ValueError(f"multi-value array of {count} items does not fit "
                         f"{len(raw)} bytes")
    offs = list(struct.unpack_from(f"<{count}I", raw, 4)) + [len(raw)]
    return [_decode_value(base, raw[offs[i]:offs[i + 1]], codepage)
            for i in range(count)]


class PropertyContext:
    """Property Context ([MS-PST] 2.3.3): {prop id: (type, value-or-HNID)}."""

    def __init__(self, heap: _Heap, *, codepage: str | None = None) -> None:
        self.heap = heap
        self.codepage = codepage or "cp1252"
        if heap.client_sig != BTYPE_PC:
            raise _Unreadable(f"{heap.what}: expected a property context "
                              f"(0xBC), found heap type 0x{heap.client_sig:02X}.")
        cb_key, cb_ent, records = heap.bth(heap.user_root)
        if cb_key != 2 or cb_ent != 6:
            raise _Unreadable(f"{heap.what}: property BTH has key/entry sizes "
                              f"{cb_key}/{cb_ent}, not 2/6.")
        self.props: dict = {}
        for key, data in records:
            pid = struct.unpack_from("<H", key)[0]
            ptype, value = struct.unpack_from("<HI", data)
            self.props[pid] = (ptype, value)

    def has(self, pid: int) -> bool:
        return pid in self.props

    def type_of(self, pid: int) -> int | None:
        found = self.props.get(pid)
        return found[0] if found else None

    def tags(self) -> list:
        return sorted((pid << 16) | t for pid, (t, _v) in self.props.items())

    def _stored(self, ptype: int, value: int) -> bytes | None:
        size = FIXED_SIZE.get(ptype)
        if size is not None and not ptype & MV_FLAG:
            if size <= 4:
                return struct.pack("<I", value)[:size]
            return self.heap.get(value)
        return self.heap.hnid_bytes(value)

    def get(self, pid: int, default=None, *, limit_bytes: int | None = None):
        """The decoded value, or `default`. `limit_bytes` caps how much of a
        string or binary value held in a subnode is read (for excerpts)."""
        found = self.props.get(pid)
        if found is None:
            return default
        ptype, value = found
        if ptype == PT_OBJECT:
            ref = self.heap.get(value) if value & 0x1F == NID_TYPE_HID else None
            if ref is None or len(ref) < 8:
                return ("object", value, None)
            nid, size = struct.unpack_from("<II", ref)
            return ("object", nid, size)
        if limit_bytes is not None and ptype in (PT_UNICODE, PT_STRING8, PT_BINARY) \
                and value & 0x1F != NID_TYPE_HID and value:
            parts, got = [], 0
            for chunk in self.heap.hnid_chunks(value):
                parts.append(chunk)
                got += len(chunk)
                if got >= limit_bytes:
                    break
            raw = b"".join(parts)[:limit_bytes]
        else:
            raw = self._stored(ptype, value)
        if raw is None:
            return default
        try:
            return _decode_value(ptype, raw, self.codepage)
        except ValueError as exc:
            self.heap.problem(f"property 0x{pid:04X}: {exc}")
            return default

    def get_int(self, pid: int) -> int | None:
        value = self.get(pid)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def text(self, pid: int, *, limit: int | None = None) -> str:
        """A string property ('' if absent); `limit` caps characters read."""
        value = self.get(pid, limit_bytes=None if limit is None else limit * 2)
        return _as_text(value)

    def chunks(self, pid: int):
        found = self.props.get(pid)
        if found is None:
            return
        ptype, value = found
        if FIXED_SIZE.get(ptype) is not None and not ptype & MV_FLAG:
            raw = self._stored(ptype, value)
            if raw:
                yield raw
            return
        yield from self.heap.hnid_chunks(value)


def _as_text(value) -> str:
    if value is None or value is MISSING:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return ""
    return str(value)


@dataclass(frozen=True)
class Column:
    tag: int
    ib_data: int
    cb_data: int
    i_bit: int

    @property
    def pid(self) -> int:
        return self.tag >> 16

    @property
    def ptype(self) -> int:
        return self.tag & 0xFFFF


class TableContext:
    """Table Context ([MS-PST] 2.3.4): column descriptors, RowIndex, Row Matrix."""

    def __init__(self, heap: _Heap, *, codepage: str | None = None) -> None:
        self.heap = heap
        self.codepage = codepage or "cp1252"
        if heap.client_sig != BTYPE_TC:
            raise _Unreadable(f"{heap.what}: expected a table context (0x7C), "
                              f"found heap type 0x{heap.client_sig:02X}.")
        info = heap.get(heap.user_root)
        if info is None or len(info) < 22:
            raise _Unreadable(f"{heap.what}: TCINFO is unreadable.")
        (btype, c_cols, ib4, ib2, ib1, ibm, self.hid_row_index, self.hnid_rows,
         _hid_index) = struct.unpack_from("<BB4HIII", info, 0)
        if btype != BTYPE_TC:
            raise _Unreadable(f"{heap.what}: TCINFO type 0x{btype:02X} is not 0x7C.")
        if len(info) < 22 + 8 * c_cols:
            raise _Unreadable(f"{heap.what}: {c_cols} column descriptors do not "
                              "fit the TCINFO.")
        self.rgib = (ib4, ib2, ib1, ibm)
        self.row_size = ibm
        self.columns = [Column(*struct.unpack_from("<IHBB", info, 22 + 8 * i))
                        for i in range(c_cols)]
        self.by_pid = {c.pid: c for c in self.columns}
        ceb = (c_cols + 7) // 8
        if not (ib4 <= ib2 <= ib1 and ib1 + ceb <= ibm):
            heap.problem(f"row layout offsets {self.rgib} are inconsistent with "
                         f"{c_cols} columns.")
        for c in self.columns:
            if c.ib_data + c.cb_data > ib1 or c.i_bit >= c_cols:
                heap.problem(f"column 0x{c.tag:08X} lies outside the row.")

    def row_index(self) -> list:
        """[(row id, row index)] from the RowIndex BTH, in row-index order."""
        if not self.hid_row_index:
            return []
        cb_key, cb_ent, records = self.heap.bth(self.hid_row_index)
        out = []
        for key, data in records:
            row_id = int.from_bytes(key[:4], "little")
            idx = int.from_bytes(data[:4] if cb_ent >= 4 else data[:2], "little")
            out.append((row_id, idx))
        out.sort(key=lambda p: p[1])
        return out

    def _matrix_blocks(self):
        if not self.hnid_rows:
            return
        if self.hnid_rows & 0x1F == NID_TYPE_HID:
            data = self.heap.get(self.hnid_rows)
            if data is not None:
                yield data
            return
        yield from self.heap.hnid_chunks(self.hnid_rows)

    def rows(self, columns=None):
        """Yield (row id, {pid: value}) for each row the RowIndex lists, read
        from the Row Matrix in order. `columns` limits which pids are decoded
        (`()` decodes none — row ids only)."""
        index = self.row_index()
        if not index:
            return
        wanted = {idx: rid for rid, idx in index}
        if len(wanted) != len(index):
            self.heap.problem("the RowIndex lists one row index twice.")
        last = max(wanted)
        size = self.row_size
        if size <= 0:
            self.heap.problem("row size is zero; rows unreadable.")
            return
        cols = (self.columns if columns is None else
                [self.by_pid[p] for p in columns if p in self.by_pid])
        n = 0
        extra = 0
        found = set()
        for blk in self._matrix_blocks():
            per = len(blk) // size
            for r in range(per):
                if n > last:
                    if any(blk[r * size:(r + 1) * size]):
                        extra += 1
                    n += 1
                    continue
                row = blk[r * size:(r + 1) * size]
                if n in wanted:
                    rid = wanted[n]
                    stored = struct.unpack_from("<I", row, 0)[0]
                    if stored != rid:
                        self.heap.problem(f"row {n} carries row id 0x{stored:X}; "
                                          f"the RowIndex says 0x{rid:X}.")
                    found.add(n)
                    yield rid, {c.pid: self._cell(row, c) for c in cols}
                n += 1
        missing = len(wanted) - len(found)
        if missing:
            self.heap.problem(f"{missing} rows the RowIndex lists are not in "
                              "the row matrix (truncated or damaged).")
        if extra:
            self.heap.problem(f"{extra} non-empty row slots follow the last "
                              "indexed row (not read; recovery is out of scope).")

    def _cell(self, row: bytes, col: Column):
        ceb_at = self.rgib[2]
        byte = ceb_at + col.i_bit // 8
        if byte >= len(row) or not row[byte] & (1 << (7 - col.i_bit % 8)):
            return MISSING
        raw = row[col.ib_data:col.ib_data + col.cb_data]
        ptype = col.ptype
        size = FIXED_SIZE.get(ptype)
        try:
            if size is not None and not ptype & MV_FLAG and size <= 8:
                return _decode_value(ptype, raw, self.codepage)
            hnid = struct.unpack_from("<I", raw)[0]
            if ptype == PT_OBJECT:
                return ("object", hnid, None)
            data = self.heap.hnid_bytes(hnid)
            if data is None:
                return MISSING
            return _decode_value(ptype, data, self.codepage)
        except (ValueError, struct.error) as exc:
            self.heap.problem(f"column 0x{col.tag:08X}: {exc}")
            return MISSING


# ---------------------------------------------------------------------------
# bodies: compressed RTF, HTML and RTF to text
# ---------------------------------------------------------------------------

def decompress_rtf(data: bytes) -> bytes:
    """[MS-OXRTFCP] decompression. Raises ValueError on a malformed stream.
    The CRC of a compressed stream is checked; a mismatch raises too, since
    the output of a corrupt LZ stream is not the message's body."""
    if len(data) < 16:
        raise ValueError("compressed RTF header is truncated")
    comp_size, raw_size, comp_type, crc = struct.unpack_from("<IIII", data, 0)
    if comp_type == 0x414C454D:                       # "MELA": stored
        return bytes(data[16:16 + raw_size])
    if comp_type != 0x75465A4C:                       # "LZFu"
        raise ValueError(f"unknown compressed RTF type 0x{comp_type:08X}")
    end = min(len(data), comp_size + 4)
    body = data[16:end]
    if crc32(body) != crc:
        raise ValueError("compressed RTF CRC mismatch")
    dictionary = bytearray(4096)
    dictionary[:len(_RTF_PREBUF)] = _RTF_PREBUF
    write = len(_RTF_PREBUF)
    out = bytearray()
    pos, n = 0, len(body)
    while pos < n:
        control = body[pos]
        pos += 1
        for bit in range(8):
            if pos >= n:
                break
            if control & (1 << bit):
                if pos + 2 > n:
                    raise ValueError("compressed RTF reference is truncated")
                ref = (body[pos] << 8) | body[pos + 1]
                pos += 2
                offset, length = ref >> 4, (ref & 0xF) + 2
                if offset == write:
                    return bytes(out[:raw_size]) if raw_size else bytes(out)
                for k in range(length):
                    b = dictionary[(offset + k) & 0xFFF]
                    out.append(b)
                    dictionary[write] = b
                    write = (write + 1) & 0xFFF
            else:
                b = body[pos]
                pos += 1
                out.append(b)
                dictionary[write] = b
                write = (write + 1) & 0xFFF
        if raw_size and len(out) > raw_size + 4096:
            raise ValueError("compressed RTF expands beyond its recorded size")
    return bytes(out[:raw_size]) if raw_size else bytes(out)


_RTF_SKIP = {b"fonttbl", b"colortbl", b"stylesheet", b"info", b"pict", b"object",
             b"header", b"footer", b"headerl", b"headerr", b"footerl", b"footerr",
             b"listtable", b"listoverridetable", b"rsidtbl", b"themedata",
             b"colorschememapping", b"latentstyles", b"datastore", b"xmlnstbl",
             b"generator", b"mmathPr", b"filetbl", b"revtbl", b"fldinst"}
_RTF_TOKEN = re.compile(rb"\\([a-zA-Z]+)(-?\d+)? ?|\\'([0-9a-fA-F]{2})|\\(.)|([{}])|"
                        rb"([^\\{}\r\n]+)|[\r\n]+", re.S)


def rtf_to_text(rtf: bytes, limit: int = EXCERPT * 4) -> str:
    """Approximate visible text of an RTF document (for excerpts only)."""
    out: list = []
    size = 0
    stack: list = []
    skip = False
    html_suppress = False
    uc, pending = 1, 0
    codec = "cp1252"
    star = False
    for m in _RTF_TOKEN.finditer(rtf):
        word, arg, hexbyte, sym, brace, text = m.groups()
        if brace == b"{":
            stack.append((skip, uc))
            star = False
            continue
        if brace == b"}":
            if stack:
                skip, uc = stack.pop()
            continue
        if word is not None:
            if star or word in _RTF_SKIP:
                skip = True
            star = False
            if word == b"ansicpg" and arg:
                codec = codec_for(arg.decode()) or codec
            elif word == b"uc" and arg:
                uc = int(arg)
            elif word == b"htmlrtf":
                html_suppress = arg != b"0"
            elif skip or html_suppress:
                continue
            elif word in (b"par", b"line", b"row", b"sect", b"page"):
                out.append("\n")
            elif word in (b"tab", b"cell"):
                out.append("\t")
            elif word == b"u" and arg:
                out.append(chr(int(arg) & 0xFFFF))
                pending = uc
            continue
        if sym is not None:
            if sym == b"*":
                star = True
            elif not (skip or html_suppress) and sym in (b"\\", b"{", b"}"):
                out.append(sym.decode())
            elif not (skip or html_suppress) and sym == b"~":
                out.append("\u00a0")
            continue
        if skip or html_suppress:
            continue
        if hexbyte is not None:
            if pending:
                pending -= 1
                continue
            out.append(bytes([int(hexbyte, 16)]).decode(codec, "replace"))
        elif text is not None:
            chunk = text.decode(codec, "replace")
            if pending:
                drop = min(pending, len(chunk))
                chunk, pending = chunk[drop:], pending - drop
            out.append(chunk)
            size += len(chunk)
        if size > limit:
            break
    return "".join(out)


class _HtmlText(HTMLParser):
    BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "h5", "h6",
             "table", "blockquote", "pre", "hr"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.out: list = []
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head", "title"):
            self.hidden += 1
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head", "title"):
            self.hidden = max(0, self.hidden - 1)
        elif tag in self.BLOCK:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.out.append(data)


def html_to_text(html: str) -> str:
    parser = _HtmlText()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):
        pass
    return "".join(parser.out)


def _html_text(pc: PropertyContext, pid: int, *, limit: int | None = None) -> str:
    """PidTagHtml as text. Stored as binary it is decoded with
    PidTagInternetCodepage, else the document's own meta charset, else UTF-8;
    undecodable bytes are replaced (shown as U+FFFD), never guessed."""
    value = pc.get(pid, limit_bytes=limit)
    if isinstance(value, str):
        return value
    if not isinstance(value, bytes):
        return ""
    match = re.search(rb"charset=[\"']?([A-Za-z0-9_\-]+)", value[:4096])
    names = [codec_for(pc.get_int(PR["internet_cpid"])) if
             pc.get_int(PR["internet_cpid"]) else None,
             match.group(1).decode("ascii") if match else None, "utf-8"]
    for name in names:
        if not name:
            continue
        try:
            codecs.lookup(name)
        except LookupError:
            continue
        return value.decode(name, "replace")
    return value.decode("utf-8", "replace")


def _excerpt(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r" *\n[ \n]*\n", "\n\n", text)
    return text.strip()[:EXCERPT]


# ---------------------------------------------------------------------------
# artefact rows
# ---------------------------------------------------------------------------

def _header_value(headers: str, name: str) -> str:
    match = re.search(rf"(?im)^{name}:[ \t]*(.*(?:\r?\n[ \t]+.*)*)", headers or "")
    return re.sub(r"\r?\n[ \t]+", " ", match.group(1)).strip() if match else ""


def message_row(msg: Message) -> dict:
    """One artefact row for a message."""
    if msg.client_submit_time:
        at_raw, basis = msg.client_submit_time, "client-submit-time"
    elif msg.delivery_time:
        at_raw, basis = msg.delivery_time, "delivery-time"
    else:
        at_raw, basis = None, None
    at_utc = timeutil.decode(at_raw, "filetime") if at_raw else None
    upper = (msg.message_class or "").upper()
    mail = not upper.startswith(NON_MAIL_CLASSES)
    names = [a.filename or a.display_name or f"attachment-{a.index}"
             for a in msg.attachments]
    email = {"from": msg.sender, "to": msg.addressed("to"),
             "cc": msg.addressed("cc"), "subject": msg.subject,
             "message_id": msg.internet_message_id,
             "date_raw": _header_value(msg.transport_headers, "Date"),
             "attachments": names}
    headers = msg.transport_headers or ""
    detail = {
        "email": email, "folder": msg.folder_path, "nid": msg.nid,
        "message_class": msg.message_class, "bcc": msg.addressed("bcc"),
        "sender": {"name": msg.sender_name, "email": msg.sender_email,
                   "smtp": msg.sender_smtp, "addrtype": msg.sender_addrtype},
        "recipients": [r.as_dict() for r in msg.recipients],
        "client_submit_raw": msg.client_submit_time,
        "client_submit_utc": timeutil.decode(msg.client_submit_time, "filetime"),
        "delivery_raw": msg.delivery_time,
        "delivery_utc": timeutil.decode(msg.delivery_time, "filetime"),
        "creation_raw": msg.creation_time,
        "creation_utc": timeutil.decode(msg.creation_time, "filetime"),
        "modified_raw": msg.modified_time,
        "modified_utc": timeutil.decode(msg.modified_time, "filetime"),
        "time_basis": basis, "body_kind": msg.body_kind,
        "body_excerpt": msg.body_excerpt,
        "attachments_detail": [a.as_dict() for a in msg.attachments],
        "transport_headers": headers[:4000],
        "transport_headers_truncated": len(headers) > 4000,
        "flags": msg.flags, "size": msg.size, "codepage": msg.codepage,
        "problems": list(msg.problems),
    }
    title = msg.subject or "(no subject)"
    if mail:
        value = f"{email['from']} → {email['to']}: {msg.subject}".strip(" →:")
    else:
        value = f"[{msg.message_class}] {msg.subject}".strip()
    return {"artefact": "email" if mail else "pst-item", "at_utc": at_utc,
            "at_raw": at_raw, "at_epoch": "filetime" if at_raw else None,
            "title": title, "value": value or title, "detail": detail,
            "row_ref_suffix": f"nid{msg.nid:x}"}


def to_rows(pst: Pst, *, source_path: str, should_cancel=None) -> list[dict]:
    """Artefact rows: one `email` row per message (a `pst-item` row for
    contacts, appointments, tasks, notes and journal items, which are not
    mail), and one `email-store` summary row for the file."""
    rows = []
    listed: set = set()
    folders = list(pst.iter_folders())
    for folder in folders:
        for msg in pst.messages(folder, should_cancel=should_cancel):
            listed.add(msg.nid)
            row = message_row(msg)
            row["detail"]["source"] = source_path
            rows.append(row)
    census: dict = {}
    unlisted = []
    for entry in pst.iter_nodes():
        name = NID_TYPE_NAMES.get(entry.nid & 0x1F, f"0x{entry.nid & 0x1F:02X}")
        census[name] = census.get(name, 0) + 1
        if entry.nid & 0x1F == NID_TYPE_NORMAL_MESSAGE and entry.nid not in listed:
            unlisted.append(entry.nid)
    in_nbt = census.get("NORMAL_MESSAGE", 0)
    store = pst.store
    folder_problems = [f"{f.path}: {p}" for f in folders for p in f.problems]
    rows.append({
        "artefact": "email-store", "at_utc": None, "at_raw": None,
        "at_epoch": None,
        "title": store.get("display_name") or source_path.rsplit("/", 1)[-1],
        "value": (f"{pst.kind} ({pst.layout.name}, encoding {pst.encryption}): "
                  f"{len(folders)} folders, {len(listed)} messages listed in "
                  f"folder contents tables; {in_nbt} message nodes in the node "
                  f"B-tree, {len(unlisted)} of them listed in no folder"),
        "detail": {
            "source": source_path, "kind": pst.kind, "layout": pst.layout.name,
            "encryption": pst.encryption, "header": pst.header.as_dict(),
            "store": store,
            "folders": [{"path": f.path, "nid": f.nid, "kind": f.kind,
                         "content_count": f.content_count} for f in folders],
            "messages_listed": len(listed), "node_census": census,
            "message_nodes_not_listed": len(unlisted),
            "message_nodes_not_listed_nids": [f"0x{n:X}" for n in unlisted[:50]],
            "not_recovered_note": ("message nodes not listed in any contents "
                                   "table are counted, not read; recovering "
                                   "deleted items is out of scope"),
            "problems": list(pst.problems) + folder_problems,
            "problems_suppressed": pst.suppressed_problems,
        },
        "row_ref_suffix": "store",
    })
    return rows
