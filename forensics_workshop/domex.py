# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""DOMEX — document and media exploitation over a disk image, stdlib only.

The parsers of Phase 1/2 answer *what is on this disk*. DOMEX answers the next
question an investigation actually asks: **of these files, which few matter,
and what do they say about who, where and when.** It reads the high-value
content types a case turns on — documents, images (with their EXIF and, above
all, their GPS), and email — pulls the metadata out of them, and lands every
result in the `artefacts` index as a timeline-ready row. That index is then the
corpus the hunt engine and the contact/geospatial views run over (§10): you
need parsed rows before you can hunt them.

**It reads through the same read-only door as everything else.** DOMEX never
opens evidence for writing and never extracts a file to disk. It reads a file's
bytes straight out of the NTFS volume (`diskimage.open_ntfs` → the blocker's
`O_RDONLY` handle), parses the metadata in memory, and writes only rows to the
case index and lines to the custody log. So there is no working-copy step and
no new writer to declare — DOMEX is a reader that happens to understand file
formats.

**Every value keeps the measured/authored line this project draws elsewhere.**
A row's `at_utc` is the file system's modified time — a *measured* UTC from the
volume. The times a document or camera wrote about *itself* (an EXIF capture
time with no zone, a PDF creation date) are authored values: they are kept in
`detail`, named with their epoch, and never quietly promoted into the UTC
column. The one authored time that IS honestly UTC is a GPS timestamp, which
the EXIF specification defines as UTC; it is carried in the `geo` block.

**What is parsed natively here** (no third party, FORENSICS_PLAN.md §1.1):

    images     JPEG (APP1) and TIFF EXIF, including the full GPS IFD —
               latitude, longitude, altitude and the UTC GPS timestamp.
    documents  OOXML (docx/xlsx/pptx) core+app properties, OpenDocument
               meta.xml, and a PDF /Info scan. Author, title, the created
               and modified times, the producing application.
    email      EML (one RFC 822 message) and mbox (many), by header:
               from/to/cc/subject/date/message-id and attachment names.

**What is catalogued but not yet deep-read**, honestly and by name: legacy OLE2
documents (.doc/.xls SummaryInformation is a property-set decode, a later
step), Outlook PST/OST (a large native parser of its own), and HEIF images
(EXIF lives in a `meta` box; JPEG/TIFF cover the overwhelming majority today).
Each is recorded with a note saying why its content was not mined, never
guessed at.
"""

from __future__ import annotations

import io
import json
import re
import struct
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from . import diskimage as _disk
from . import filetype
from . import index as _index
from .errors import Cancelled, EvidenceError, FileSystemError
from .timeutil import decode, iso, utc_now

PARSER_VERSION = 1

#: How much of a file DOMEX reads. Metadata lives near a file's start (EXIF in
#: the first APP1, an OOXML/PDF document is opened whole from a buffer), so a
#: generous but bounded cap keeps a 60 GB image tractable while catching every
#: real camera and office document. A file larger than the cap is catalogued
#: and its content left unread, with a note — never truncated and guessed at.
HEAD_BYTES = filetype.HEAD_BYTES          # for type identification
IMAGE_CAP = 4 << 20                       # EXIF/APP1 fits comfortably
DOCUMENT_CAP = 128 << 20                  # a zip/pdf must be opened whole
EMAIL_CAP = 256 << 20                     # an mbox streamed message by message
MAX_EMAIL_MESSAGES = 20000

#: filetype `family` → the DOMEX category a row is filed under. A handful of
#: type_ids override their family (an Outlook store is a "document" by family
#: but an email corpus to us).
_FAMILY_CATEGORY = {
    "image": "image", "document": "document", "archive": "archive",
    "database": "database", "audio": "media", "video": "media",
    "executable": "program", "font": "font", "system": "system",
    "crypto": "crypto", "disk": "disk",
}
_TYPE_CATEGORY = {"pst": "email"}

#: Categories DOMEX mines for metadata by default. Everything else is still
#: type-identified and catalogued, but not opened for content.
DEFAULT_CATEGORIES = ("image", "document", "email")
CATEGORIES = ("image", "document", "email", "archive", "database", "media",
              "program", "font", "system", "crypto", "disk", "other")


# ===========================================================================
# EXIF / TIFF — the crown jewel: images, and their GPS
# ===========================================================================

#: TIFF field type -> (struct code, byte size). Only the types EXIF uses.
_TIFF_TYPES = {1: ("B", 1), 2: ("s", 1), 3: ("H", 2), 4: ("I", 4),
               5: ("II", 8), 7: ("B", 1), 9: ("i", 4), 10: ("ii", 8)}

_IFD0_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software",
              0x0112: "orientation", 0x0132: "datetime"}
_EXIF_TAGS = {0x9003: "datetime_original", 0x9004: "datetime_digitized",
              0xA002: "pixel_x", 0xA003: "pixel_y", 0x8827: "iso",
              0x829A: "exposure_time", 0x920A: "focal_length"}
_GPS_TAGS = {1: "lat_ref", 2: "lat", 3: "lon_ref", 4: "lon", 5: "alt_ref",
             6: "alt", 7: "time", 29: "datestamp", 9: "status", 16: "img_dir_ref",
             17: "img_dir"}
_TAG_EXIF_IFD = 0x8769
_TAG_GPS_IFD = 0x8825
_MAX_IFD_ENTRIES = 256


def _tiff_values(buf: bytes, order: str, entry_off: int):
    """The decoded values of one 12-byte IFD entry, bounds-checked to `buf`.

    Returns (tag, [values]) or (tag, None) when the entry points outside the
    buffer — DOMEX reads a bounded head, so a value stored far into a large
    TIFF may simply not be present, which is reported, never invented.
    """
    tag, ftype, count = struct.unpack_from(order + "HHI", buf, entry_off)
    spec = _TIFF_TYPES.get(ftype)
    if spec is None or count > (1 << 20):
        return tag, None
    code, size = spec
    total = size * count
    data_off = entry_off + 8 if total <= 4 else \
        struct.unpack_from(order + "I", buf, entry_off + 8)[0]
    if data_off + total > len(buf) or data_off < 0:
        return tag, None
    if ftype in (2, 7):                       # ASCII / UNDEFINED: raw bytes
        raw = buf[data_off:data_off + total]
        if ftype == 2:
            return tag, [raw.split(b"\x00", 1)[0].decode("ascii", "replace")]
        return tag, [raw]
    if ftype in (5, 10):                      # RATIONAL / SRATIONAL: num/den
        out = []
        for i in range(count):
            num, den = struct.unpack_from(order + code, buf, data_off + i * 8)
            out.append((num, den))
        return tag, out
    return tag, list(struct.unpack_from(order + code * count, buf, data_off))


def _read_ifd(buf: bytes, order: str, offset: int, tags: dict) -> dict:
    """Decode the tags of interest from one IFD. Unknown tags are ignored;
    the two sub-IFD pointers (EXIF, GPS) are returned under their raw tag."""
    out: dict = {}
    if offset <= 0 or offset + 2 > len(buf):
        return out
    (count,) = struct.unpack_from(order + "H", buf, offset)
    count = min(count, _MAX_IFD_ENTRIES)
    for i in range(count):
        entry_off = offset + 2 + i * 12
        if entry_off + 12 > len(buf):
            break
        tag, values = _tiff_values(buf, order, entry_off)
        if values is None:
            continue
        if tag in (_TAG_EXIF_IFD, _TAG_GPS_IFD):
            out[tag] = values[0]
        elif tag in tags:
            out[tags[tag]] = values
    return out


def _rational(values, index=0):
    try:
        num, den = values[index]
        return num / den if den else None
    except (TypeError, ValueError, IndexError):
        return None


def _dms_to_degrees(values, ref) -> float | None:
    """[(deg),(min),(sec)] rationals + a N/S/E/W ref -> signed degrees."""
    if not values or len(values) < 3:
        return None
    parts = [_rational(values, i) for i in range(3)]
    if any(p is None for p in parts):
        return None
    deg = parts[0] + parts[1] / 60 + parts[2] / 3600
    if (ref or "").upper() in ("S", "W"):
        deg = -deg
    return round(deg, 7)


def _gps_datetime_utc(gps: dict) -> str | None:
    """GPSDateStamp ('YYYY:MM:DD') + GPSTimeStamp (h,m,s rationals) -> UTC ISO.
    The EXIF spec defines both as UTC, so this is an honest UTC value."""
    date = gps.get("datestamp")
    time = gps.get("time")
    if not date or not time:
        return None
    ds = date[0] if isinstance(date, list) else date
    try:
        y, mo, d = (int(x) for x in str(ds).split(":"))
        h = int(_rational(time, 0) or 0)
        mi = int(_rational(time, 1) or 0)
        sec = _rational(time, 2) or 0
        base = datetime(y, mo, d, tzinfo=timezone.utc)
        return iso(base + timedelta(hours=h, minutes=mi, seconds=sec))
    except (ValueError, TypeError, OverflowError):
        return None


def read_exif(data: bytes) -> dict | None:
    """EXIF/GPS from JPEG (APP1) or TIFF bytes. None if there is no EXIF.

    A `geo` block is present only when a real latitude AND longitude decoded.
    Every value here is *authored by the camera*; the caller keeps the file
    system's measured time as the row's UTC and treats these as content.
    """
    tiff = _tiff_from_jpeg(data) if data[:2] == b"\xff\xd8" else \
        (data if data[:4] in (b"II*\x00", b"MM\x00*") else None)
    if tiff is None or len(tiff) < 8:
        return None
    order = "<" if tiff[:2] == b"II" else ">"
    magic, ifd0 = struct.unpack_from(order + "HI", tiff, 2)
    if magic != 42:
        return None

    info: dict = {}
    ifd0_fields = _read_ifd(tiff, order, ifd0, _IFD0_TAGS)
    for key in ("make", "model", "software", "datetime"):
        if key in ifd0_fields:
            info[key] = _clean(ifd0_fields[key][0])
    if "orientation" in ifd0_fields:
        info["orientation"] = ifd0_fields["orientation"][0]

    if _TAG_EXIF_IFD in ifd0_fields:
        exif = _read_ifd(tiff, order, ifd0_fields[_TAG_EXIF_IFD], _EXIF_TAGS)
        for key in ("datetime_original", "datetime_digitized"):
            if key in exif:
                info[key] = _clean(exif[key][0])
        for key in ("pixel_x", "pixel_y", "iso"):
            if key in exif:
                info[key] = exif[key][0]

    if _TAG_GPS_IFD in ifd0_fields:
        graw = _read_ifd(tiff, order, ifd0_fields[_TAG_GPS_IFD], _GPS_TAGS)
        lat = _dms_to_degrees(graw.get("lat"), _first(graw.get("lat_ref")))
        lon = _dms_to_degrees(graw.get("lon"), _first(graw.get("lon_ref")))
        if lat is not None and lon is not None:
            geo = {"lat": lat, "lon": lon}
            alt = _rational(graw.get("alt"), 0)
            if alt is not None:
                below = bool(_first(graw.get("alt_ref")))
                geo["alt_m"] = round(-alt if below else alt, 2)
            ts = _gps_datetime_utc(graw)
            if ts:
                geo["ts_utc"] = ts
            info["geo"] = geo
    return info or None


def _tiff_from_jpeg(data: bytes) -> bytes | None:
    """The TIFF block inside a JPEG APP1 'Exif\\x00\\x00' segment."""
    pos = 2
    n = len(data)
    while pos + 4 <= n and data[pos] == 0xFF:
        marker = data[pos + 1]
        if marker in (0xD8, 0xD9) or 0xD0 <= marker <= 0xD7:
            pos += 2
            continue
        if marker == 0xDA:                    # start of scan: no more metadata
            break
        (seg_len,) = struct.unpack_from(">H", data, pos + 2)
        seg = data[pos + 4: pos + 2 + seg_len]
        if marker == 0xE1 and seg[:6] == b"Exif\x00\x00":
            return seg[6:]
        pos += 2 + seg_len
    return None


def _first(values):
    return values[0] if isinstance(values, list) and values else values


def _clean(value) -> str:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", "replace")
    return str(value).replace("\x00", "").strip()


# ===========================================================================
# Documents — OOXML, OpenDocument, PDF
# ===========================================================================

_W3C = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
                  r"(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")


def _w3cdtf_utc(text: str) -> str | None:
    """W3C/ISO-8601 datetime (OOXML/ODF write these) -> UTC ISO, or None."""
    if not text:
        return None
    m = _W3C.match(text.strip())
    if not m:
        return None
    y, mo, d, h, mi, s = (int(m.group(i)) for i in range(1, 7))
    tz = m.group(7)
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        tz = tz.replace(":", "")
        dt -= sign * timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
    return iso(dt)


def _xml_text(blob: bytes, *tags: str) -> str:
    """The text of the first of `tags` present, namespace-insensitively."""
    for tag in tags:
        m = re.search(rb"<(?:\w+:)?" + tag.encode() + rb"[^>]*>([^<]*)</",
                      blob, re.IGNORECASE)
        if m:
            return _clean(m.group(1))
    return ""


def _ooxml_props(zf: zipfile.ZipFile) -> dict:
    props: dict = {}
    names = {n.lower(): n for n in zf.namelist()}
    core_name = names.get("docprops/core.xml")
    if core_name:
        core = zf.read(core_name)
        props["author"] = _xml_text(core, "creator")
        props["last_modified_by"] = _xml_text(core, "lastModifiedBy")
        props["title"] = _xml_text(core, "title")
        props["subject"] = _xml_text(core, "subject")
        props["keywords"] = _xml_text(core, "keywords")
        props["revision"] = _xml_text(core, "revision")
        props["created_raw"] = _xml_text(core, "created")
        props["modified_raw"] = _xml_text(core, "modified")
    app_name = names.get("docprops/app.xml")
    if app_name:
        app = zf.read(app_name)
        props["application"] = _xml_text(app, "Application")
        props["company"] = _xml_text(app, "Company")
        props["total_time_min"] = _xml_text(app, "TotalTime")
    return {k: v for k, v in props.items() if v}


def _odf_props(zf: zipfile.ZipFile) -> dict:
    names = {n.lower(): n for n in zf.namelist()}
    meta_name = names.get("meta.xml")
    if not meta_name:
        return {}
    meta = zf.read(meta_name)
    props = {
        "author": _xml_text(meta, "initial-creator", "creator"),
        "last_modified_by": _xml_text(meta, "creator"),
        "title": _xml_text(meta, "title"),
        "subject": _xml_text(meta, "subject"),
        "keywords": _xml_text(meta, "keyword"),
        "application": _xml_text(meta, "generator"),
        "created_raw": _xml_text(meta, "creation-date"),
        "modified_raw": _xml_text(meta, "date"),
    }
    return {k: v for k, v in props.items() if v}


_PDF_STR = r"\(((?:[^()\\]|\\.)*)\)|<([0-9A-Fa-f\s]+)>"
_PDF_FIELDS = ("Author", "Title", "Subject", "Creator", "Producer",
               "CreationDate", "ModDate", "Keywords")


_PDF_ESCAPES = {"n": 10, "r": 13, "t": 9, "b": 8, "f": 12,
                "(": 0x28, ")": 0x29, "\\": 0x5C}


def _pdf_unescape(text: str) -> bytes:
    """The bytes of a PDF literal string: `\\ddd` octal, the named escapes, a
    backslash-newline line continuation, and raw bytes (latin-1 chars) passed
    through. A real /Info author is often octal-escaped UTF-16, which the old
    `\\(.)->\\1` collapse turned into digits — this returns the real bytes."""
    out = bytearray()
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n:
            nxt = text[i + 1]
            if nxt in "01234567":
                j, digits = i + 1, ""
                while j < n and len(digits) < 3 and text[j] in "01234567":
                    digits += text[j]
                    j += 1
                out.append(int(digits, 8) & 0xFF)
                i = j
                continue
            if nxt in _PDF_ESCAPES:
                out.append(_PDF_ESCAPES[nxt])
            elif nxt in ("\n", "\r"):
                pass                          # a line continuation: drop it
            else:
                out.append(ord(nxt) & 0xFF)
            i += 2
            continue
        out.append(ord(ch) & 0xFF)
        i += 1
    return bytes(out)


def _decode_pdf_bytes(raw: bytes) -> str:
    """UTF-16 when the BOM says so (PDF text strings are PDFDocEncoding or
    UTF-16BE), latin-1 otherwise — which covers the ASCII range PDFDocEncoding
    shares with it."""
    if raw[:2] in (b"\xfe\xff", b"\xff\xfe"):
        return _clean(raw.decode("utf-16", "replace"))
    return _clean(raw.decode("latin-1", "replace"))


def _pdf_string(match: "re.Match") -> str:
    literal, hexstr = match.group(1), match.group(2)
    if literal is not None:
        return _decode_pdf_bytes(_pdf_unescape(literal))
    try:
        return _decode_pdf_bytes(bytes.fromhex(re.sub(r"\s", "", hexstr)))
    except ValueError:
        return ""


def _pdf_date_utc(text: str) -> str | None:
    """A PDF date string 'D:YYYYMMDDHHmmSS+HH'mm'' -> UTC ISO, or None."""
    m = re.match(r"D?:?\s*(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
                 r"([Zz+-])?(\d{2})?'?(\d{2})?", text or "")
    if not m:
        return None
    y = int(m.group(1))
    mo, d, h, mi, s = (int(m.group(i) or (1 if i in (2, 3) else 0))
                       for i in range(2, 7))
    try:
        dt = datetime(y, mo, d, h, mi, s, tzinfo=timezone.utc)
    except ValueError:
        return None
    sign, oh, om = m.group(7), m.group(8), m.group(9)
    if sign in ("+", "-") and oh:
        off = timedelta(hours=int(oh), minutes=int(om or 0))
        dt -= off if sign == "+" else -off
    return iso(dt)


def _pdf_info(data: bytes) -> dict:
    """A pragmatic /Info scan. PDF's cross-reference machinery is heavy and,
    for the Info dictionary, unnecessary: the fields sit as plain object
    strings in the file. This is a documented HEURISTIC — the row's basis
    says so — not a full PDF parse, and it never touches page content."""
    window = data if len(data) < (8 << 20) else data[:2 << 20] + data[-2 << 20:]
    props: dict = {}
    for field_name in _PDF_FIELDS:
        m = re.search(rb"/" + field_name.encode() + rb"\s*(" +
                      _PDF_STR.encode() + rb")", window)
        if not m:
            continue
        sm = re.match(_PDF_STR, m.group(1).decode("latin-1"))
        if sm:
            props[field_name.lower()] = _pdf_string(sm)
    m = re.search(rb"/(Encrypt)\b", window)
    if m:
        props["encrypted"] = True
    return {k: v for k, v in props.items() if v}


def read_document_props(data: bytes, type_id: str) -> dict | None:
    """Author/title/dates/application for a document. `created`/`modified`
    are honest UTC where the format wrote a zone; the raw string is kept too.
    Returns a dict (possibly with only a `note`) or None if unreadable."""
    if type_id in ("docx", "xlsx", "pptx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                props = _ooxml_props(zf)
        except (zipfile.BadZipFile, OSError, KeyError):
            return {"note": "OOXML container could not be opened"}
        return _finish_doc(props)
    if type_id in ("odt", "ods", "odp", "epub"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                props = _odf_props(zf)
        except (zipfile.BadZipFile, OSError, KeyError):
            return {"note": "OpenDocument container could not be opened"}
        return _finish_doc(props)
    if type_id == "pdf":
        props = _pdf_info(data)
        for key in ("creationdate", "moddate"):
            if key in props:
                props[key + "_raw"] = props.pop(key)
        out = {"created_utc": _pdf_date_utc(props.get("creationdate_raw", "")),
               "modified_utc": _pdf_date_utc(props.get("moddate_raw", "")),
               "basis": "pdf-info-scan (heuristic)"}
        out.update(props)
        return {k: v for k, v in out.items() if v}
    if type_id == "ole2":
        return {"note": "legacy OLE2 document — SummaryInformation property-set "
                        "decode is a later step; catalogued by type only"}
    return None


def _finish_doc(props: dict) -> dict:
    props["created_utc"] = _w3cdtf_utc(props.get("created_raw", ""))
    props["modified_utc"] = _w3cdtf_utc(props.get("modified_raw", ""))
    return {k: v for k, v in props.items() if v}


# ===========================================================================
# Email — EML (one) and mbox (many)
# ===========================================================================

def _decode_header(raw) -> str:
    from email.header import decode_header, make_header
    if raw is None:
        return ""
    try:
        return _clean(str(make_header(decode_header(str(raw)))))
    except (ValueError, LookupError):
        return _clean(str(raw))


def _message_row(msg, index: int) -> dict:
    from email.utils import parsedate_to_datetime
    date_raw = msg.get("Date", "")
    at_utc = None
    try:
        dt = parsedate_to_datetime(date_raw) if date_raw else None
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            at_utc = iso(dt)
    except (TypeError, ValueError):
        at_utc = None
    attachments = []
    try:
        for part in msg.walk():
            fn = part.get_filename()
            if fn:
                attachments.append(_decode_header(fn))
    except (AttributeError, TypeError):
        pass
    return {
        "artefact": "email", "at_utc": at_utc, "at_raw": None,
        "at_epoch": "rfc2822" if at_utc else None,
        "from": _decode_header(msg.get("From", "")),
        "to": _decode_header(msg.get("To", "")),
        "cc": _decode_header(msg.get("Cc", "")),
        "subject": _decode_header(msg.get("Subject", "")),
        "message_id": _clean(msg.get("Message-ID", "")),
        "date_raw": _clean(date_raw),
        "attachments": attachments,
        "row_ref_suffix": f"msg{index}",
    }


def _split_mbox(data: bytes):
    """Yield the bytes of each message in an mbox. Messages begin at a line
    starting with 'From ' (the mbox separator)."""
    start = 0
    n = len(data)
    sep = re.compile(rb"(?:^|\n)From .*\n")
    count = 0
    for m in sep.finditer(data):
        if m.start() == 0 and start == 0:
            start = m.end()
            continue
        chunk = data[start:m.start()].strip(b"\r\n")
        if chunk:
            yield chunk
            count += 1
            if count >= MAX_EMAIL_MESSAGES:
                return
        start = m.end()
    if start < n:
        tail = data[start:].strip(b"\r\n")
        if tail:
            yield tail


def read_email_messages(data: bytes, kind: str) -> list[dict]:
    """Parsed header rows from an EML (one message) or mbox (many)."""
    from email.parser import BytesParser
    from email.policy import default as _default_policy
    parser = BytesParser(policy=_default_policy)
    rows = []
    if kind == "mbox":
        for i, chunk in enumerate(_split_mbox(data)):
            try:
                rows.append(_message_row(parser.parsebytes(chunk), i))
            except (ValueError, IndexError, TypeError):
                continue
    else:                                     # eml / emlx
        try:
            rows.append(_message_row(parser.parsebytes(data), 0))
        except (ValueError, IndexError, TypeError):
            pass
    return rows


def _sniff_email(name: str, head: bytes) -> str | None:
    """Return 'mbox' or 'eml' if `name`/`head` look like mail, else None."""
    ext = filetype.declared_extension(name)
    looks_mbox = head[:5] == b"From " or b"\nFrom " in head[:4096]
    header_re = re.compile(rb"(?im)^(from|to|subject|date|message-id):")
    has_headers = bool(header_re.search(head[:4096]))
    if ext in ("mbox", "mbx"):
        return "mbox"
    if ext in ("eml", "emlx"):
        return "eml"
    if looks_mbox and has_headers:
        return "mbox"
    if has_headers and head[:2] not in (b"\xff\xd8", b"PK", b"%P"):
        # header-shaped text with no binary signature: a loose .eml
        return "eml"
    return None


# ===========================================================================
# Classification
# ===========================================================================

def classify(type_result, name: str) -> str:
    """The DOMEX category of a typed file."""
    if type_result.type_id in _TYPE_CATEGORY:
        return _TYPE_CATEGORY[type_result.type_id]
    return _FAMILY_CATEGORY.get(type_result.family, "other")


# ===========================================================================
# Orchestration — walk one NTFS volume, mine the high-value files
# ===========================================================================

@dataclass
class DomexSummary:
    evidence_id: str
    volume: int
    run_id: str
    state: str
    categories: list = field(default_factory=list)
    files_seen: int = 0
    files_read: int = 0
    files_skipped_size: int = 0
    rows: int = 0
    by_category: dict = field(default_factory=dict)
    by_artefact: dict = field(default_factory=dict)
    geotagged: int = 0
    problems: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _candidate_entries(case, evidence_id, volume, path_prefix):
    """(record, sequence, in_use, name, path, path_status, size, si_modified,
    si_created, data_flags) for every non-directory file, largest paths first
    so a scoped run is predictable. Requires the volume to be NTFS-parsed."""
    where = ["evidence_id = ?", "volume = ?", "is_dir = 0", "size > 0"]
    params = [evidence_id, volume]
    if path_prefix:
        where.append("path LIKE ?")
        params.append(path_prefix.replace("\\", "/").rstrip("/") + "%")
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM ntfs_entries WHERE " + clause, params
        ).fetchone()[0]
        if total == 0 and not path_prefix:
            has = conn.execute("SELECT COUNT(*) FROM ntfs_entries WHERE "
                               "evidence_id = ? AND volume = ?",
                               (evidence_id, volume)).fetchone()[0]
            if has == 0:
                raise EvidenceError(
                    f"{evidence_id} volume {volume} has no parsed MFT entries. "
                    "DOMEX reads the files the NTFS pass found, so run `ntfs` "
                    "on this volume first.")
        rows = conn.execute(
            "SELECT record, sequence, in_use, name, path, path_status, size, "
            "si_modified, si_created, data_flags FROM ntfs_entries WHERE "
            + clause + " ORDER BY record", params).fetchall()
    return [dict(r) for r in rows]


def _read_bytes(vol, record, cap):
    """Up to `cap` bytes of an entry's main stream, and its true size. Returns
    (data, size, note): note is set when the stream could not be read or the
    file is larger than the cap (so it was left unread)."""
    e = vol.entry(record)
    if e is None:
        return b"", 0, "record is empty"
    s = e.stream("")
    if s is None:
        return b"", 0, "no unnamed data stream"
    size = s.data_size
    try:
        vol.refuse_unreadable(s)
    except FileSystemError as exc:
        return b"", size, str(exc)
    if size > cap:
        return b"", size, f"file is {size:,} bytes, over the {cap:,}-byte cap"
    try:
        return vol.read_stream(s, 0, cap), size, ""
    except FileSystemError as exc:
        return b"", size, str(exc)


def _row_common(entry, category, tr, size, read_note):
    """The provenance every DOMEX row carries, whatever its category."""
    return {
        "volume_record": entry["record"],
        "sequence": entry["sequence"],
        "in_use": bool(entry["in_use"]),
        "path": entry["path"],
        "path_status": entry["path_status"],
        "size": size,
        "declared_size": entry["size"],
        "type_id": tr.type_id,
        "type_label": tr.label,
        "type_basis": tr.basis,
        "type_note": tr.note,
        "ext_mismatch": tr.ext_mismatch,
        "category": category,
        "deleted": not entry["in_use"],
        "read_note": read_note,
    }


def _mtime_utc(entry) -> tuple[str | None, int | None]:
    """The measured file-system time to sort a row by: modified, else created.
    Returns (utc_iso, raw_filetime)."""
    for col in ("si_modified", "si_created"):
        raw = entry.get(col)
        got = decode(raw, "filetime")
        if got:
            return got, raw
    return None, None


def analyse_volume(case, evidence_id: str, volume: int, *,
                   categories=DEFAULT_CATEGORIES, path_prefix: str = "",
                   limit: int = 0, max_file_mb: int = 512,
                   progress=None, should_cancel=None) -> DomexSummary:
    """Type every eligible file on one NTFS volume, mine the target categories
    for metadata, and land the results in the `artefacts` index."""
    categories = tuple(categories) or DEFAULT_CATEGORIES
    cap_ceiling = max_file_mb << 20
    summary = DomexSummary(evidence_id, volume, uuid.uuid4().hex[:12],
                           "running", categories=list(categories),
                           started_at=utc_now())
    _disk.volume_row(case, evidence_id, volume)     # exists? decoded? raises if not
    entries = _candidate_entries(case, evidence_id, volume, path_prefix)
    run_id = summary.run_id

    source, vol, _row = _disk.open_ntfs(case, evidence_id, volume)
    _start_run(case, evidence_id, run_id, volume,
               {"categories": list(categories), "path_prefix": path_prefix,
                "limit": limit})
    case.custody.record(
        "domex.started", actor=case.actor(), target=f"{evidence_id}:v{volume}",
        detail={"run_id": run_id, "categories": list(categories),
                "candidates": len(entries), "path_prefix": path_prefix,
                "parser_version": PARSER_VERSION})
    batch: list = []
    try:
        _clear_volume(case, evidence_id, volume)
        for n, entry in enumerate(entries, 1):
            if should_cancel is not None and should_cancel():
                raise Cancelled("DOMEX cancelled")
            if progress is not None and n % 200 == 0:
                progress(f"{n} of {len(entries)} files, {summary.rows} rows")
            summary.files_seen += 1
            head, _size, head_note = _read_bytes(vol, entry["record"], HEAD_BYTES)
            if not head:
                if head_note and "cap" not in head_note:
                    summary.problems.append(
                        f"{entry['path'] or entry['name']}: {head_note}")
                continue
            tr = filetype.identify(head, name=entry["name"], size=entry["size"])
            category = classify(tr, entry["name"])
            mail_kind = _sniff_email(entry["name"], head) \
                if category in ("other", "document", "email") else None
            if mail_kind:
                category = "email"
            summary.by_category[category] = summary.by_category.get(category, 0) + 1
            if category not in categories:
                continue
            rows = _mine(vol, entry, tr, category, mail_kind, cap_ceiling,
                         summary)
            for r in rows:
                batch.append(_to_db_row(run_id, evidence_id, volume, entry, r))
                summary.rows += 1
                summary.by_artefact[r["artefact"]] = \
                    summary.by_artefact.get(r["artefact"], 0) + 1
                if r.get("detail", {}).get("geo"):
                    summary.geotagged += 1
            if len(batch) >= 500:
                _store(case, batch)
                batch = []
            if limit and summary.rows >= limit:
                break
        _store(case, batch)
        summary.state = "completed"
    except Cancelled:
        _store(case, batch)
        summary.state = "cancelled"
    except BaseException:
        summary.state = "failed"
        raise
    finally:
        source.close()
        summary.finished_at = utc_now()
        _finish_run(case, run_id, summary.state, summary.as_dict())
        case.custody.record(
            f"domex.{summary.state}", actor=case.actor(),
            target=f"{evidence_id}:v{volume}",
            detail=dict(summary.as_dict(), run_id=run_id))
    return summary


def _start_run(case, evidence_id, run_id, volume, settings) -> None:
    """Record this DOMEX pass in the shared `runs` table, so the pipeline (and
    a re-run) can tell a volume was mined even when it yielded no rows."""
    with _index.session(case.root) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO runs (run_id, evidence_id, kind, volume, "
            "started_at, state, settings_json) VALUES (?, ?, 'domex', ?, ?, "
            "'running', ?)",
            (run_id, evidence_id, volume, utc_now(),
             json.dumps(settings, default=str)))


def _finish_run(case, run_id, state, summary) -> None:
    with _index.session(case.root) as conn:
        conn.execute("UPDATE runs SET finished_at = ?, state = ?, summary_json "
                     "= ? WHERE run_id = ?",
                     (utc_now(), state, json.dumps(summary, default=str), run_id))


def _mine(vol, entry, tr, category, mail_kind, cap_ceiling, summary) -> list:
    """Read and parse one file according to its category. Returns artefact
    row dicts (one per file, or one per message for mail)."""
    cap = {"image": IMAGE_CAP, "document": DOCUMENT_CAP,
           "email": EMAIL_CAP}.get(category, HEAD_BYTES)
    cap = min(cap, cap_ceiling)
    data, size, note = _read_bytes(vol, entry["record"], cap)
    at_utc, at_raw = _mtime_utc(entry)
    base_detail = _row_common(entry, category, tr, size, note)
    if not data:
        summary.files_skipped_size += bool(note and "cap" in note)
        # a catalogued row with no content: still useful on the timeline
        return [{"artefact": category, "at_utc": at_utc, "at_raw": at_raw,
                 "at_epoch": "filetime" if at_utc else None,
                 "title": entry["name"], "value": tr.label,
                 "detail": base_detail}]
    summary.files_read += 1

    if category == "image":
        info = None
        try:
            info = read_exif(data)
        except (struct.error, ValueError, IndexError):
            info = None
        detail = dict(base_detail, exif=info or {})
        value = tr.label
        if info and info.get("geo"):
            g = info["geo"]
            detail["geo"] = g
            value = f"GPS {g['lat']:.5f},{g['lon']:.5f}"
            if info.get("model"):
                value += f" · {info['model']}"
        elif info and info.get("model"):
            value = f"{info.get('make', '')} {info['model']}".strip()
        return [{"artefact": "image", "at_utc": at_utc, "at_raw": at_raw,
                 "at_epoch": "filetime" if at_utc else None,
                 "title": entry["name"], "value": value, "detail": detail}]

    if category == "document":
        props = read_document_props(data, tr.type_id) or {}
        detail = dict(base_detail, doc=props)
        value = props.get("title") or props.get("author") or tr.label
        # a document's own created time is authored; keep the fs time as UTC
        return [{"artefact": "document", "at_utc": at_utc, "at_raw": at_raw,
                 "at_epoch": "filetime" if at_utc else None,
                 "title": entry["name"], "value": value, "detail": detail}]

    if category == "email":
        if tr.type_id == "pst":
            return [{"artefact": "email", "at_utc": at_utc, "at_raw": at_raw,
                     "at_epoch": "filetime" if at_utc else None,
                     "title": entry["name"],
                     "value": "Outlook store (PST/OST) — detected, not yet parsed",
                     "detail": dict(base_detail,
                                    note="native PST/OST parsing is a later step")}]
        rows = read_email_messages(data, mail_kind or "eml")
        if not rows:
            return [{"artefact": "email", "at_utc": at_utc, "at_raw": at_raw,
                     "at_epoch": "filetime" if at_utc else None,
                     "title": entry["name"], "value": tr.label,
                     "detail": dict(base_detail, note="no messages parsed")}]
        out = []
        for r in rows:
            detail = dict(base_detail, email={
                k: r[k] for k in ("from", "to", "cc", "subject", "message_id",
                                  "date_raw", "attachments")})
            detail["message_ref"] = r["row_ref_suffix"]
            value = f"{r['from']} → {r['to']}: {r['subject']}".strip(" →:")
            out.append({"artefact": "email",
                        "at_utc": r["at_utc"] or at_utc,
                        "at_raw": None if r["at_utc"] else at_raw,
                        "at_epoch": r["at_epoch"] or ("filetime" if at_utc else None),
                        "title": r["subject"] or entry["name"],
                        "value": value or tr.label, "detail": detail,
                        "row_ref_suffix": r["row_ref_suffix"]})
        return out

    return [{"artefact": category, "at_utc": at_utc, "at_raw": at_raw,
             "at_epoch": "filetime" if at_utc else None,
             "title": entry["name"], "value": tr.label, "detail": base_detail}]


def _to_db_row(run_id, evidence_id, volume, entry, r) -> tuple:
    suffix = r.get("row_ref_suffix")
    row_ref = f"v{volume}:mft{entry['record']}"
    if suffix:
        row_ref += f":{suffix}"
    return (run_id, evidence_id, entry.get("path") or entry["name"], None,
            r["artefact"], r["at_utc"],
            r["at_raw"] if isinstance(r["at_raw"], int) else None, r["at_epoch"],
            None, None, None, None, r["title"],
            r["value"], json.dumps(r["detail"], ensure_ascii=False, default=str),
            "domex-native", row_ref)


def _store(case, batch) -> None:
    if not batch:
        return
    with _index.session(case.root) as conn:
        conn.executemany(
            "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
            "source_sha256, parser, artefact, at_utc, at_raw, at_epoch, "
            "browser, browser_basis, profile, url, title, value, detail_json, "
            "provenance, row_ref) VALUES (?, ?, ?, ?, 'domex', ?, ?, ?, ?, ?, "
            "?, ?, ?, ?, ?, ?, ?, ?)", batch)


def _clear_volume(case, evidence_id, volume) -> None:
    """Drop this volume's prior DOMEX rows so a re-run is idempotent."""
    with _index.session(case.root) as conn:
        conn.execute("DELETE FROM artefacts WHERE evidence_id = ? AND "
                     "parser = 'domex' AND row_ref LIKE ?",
                     (evidence_id, f"v{volume}:%"))


ARTEFACT_KINDS = ("image", "document", "email", "archive", "database", "media")


def list_domex(case, evidence_id: str, *, artefact: str = "",
               geo_only: bool = False, search: str = "", limit: int = 200,
               offset: int = 0) -> tuple[list[dict], int]:
    where = ["evidence_id = ?", "parser = 'domex'"]
    params: list = [evidence_id]
    if artefact:
        where.append("artefact = ?")
        params.append(artefact)
    if geo_only:
        where.append("detail_json LIKE ?")
        params.append('%"geo":%')
    if search:
        where.append("(value LIKE ? OR title LIKE ? OR detail_json LIKE ?)")
        params.extend([f"%{search}%"] * 3)
    clause = " AND ".join(where)
    with _index.session(case.root) as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM artefacts WHERE {clause}",
                             params).fetchone()[0]
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM artefacts WHERE {clause} "
            "ORDER BY at_utc IS NULL, at_utc, id LIMIT ? OFFSET ?",
            [*params, int(limit), int(offset)])]
    return rows, total
