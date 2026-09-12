"""DOMEX over a disk image: the high-value content types an investigation
turns on — a geotagged photo, an authored document, a mail spool — planted in
a real NTFS volume, read through the same read-only door as everything else,
and landed in the artefacts index as timeline-ready rows with their metadata
mined. The point the geospatial and hunt views depend on: a JPEG's GPS comes
back as signed degrees, and a document's author and dates come back named.

The pure extractors (EXIF/GPS, OOXML/PDF properties, mbox/eml headers) are also
held to spec-correct synthetic bytes, because a builder that shared a parser's
misunderstanding would pass an end-to-end test and still be wrong."""

from __future__ import annotations

import io
import json
import struct
import unittest
import zipfile

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

import disksynth as ds
from forensics_workshop import diskimage, domex
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError

PART_LBA = 2048

# Pittsburgh: 40°26'46.302"N, 79°58'55.903"W — the sign is the whole test.
LAT_DEG = 40 + 26 / 60 + 46.302 / 3600
LON_DEG = 79 + 58 / 60 + 55.903 / 3600


def _rat(n: int, d: int) -> bytes:
    return struct.pack("<II", n, d)


def jpeg_with_gps(model: bytes = b"iPhone 12\x00") -> bytes:
    """A JPEG whose APP1 carries EXIF Make/Model and a full GPS IFD. Values
    ≤ 4 bytes are stored inline, as the TIFF spec requires — the same rule the
    reader follows, so this exercises it rather than sidestepping it."""
    ifd0_off = 8
    n0 = 3
    gps_off = ifd0_off + 2 + n0 * 12 + 4
    n_gps = 4
    dpos = gps_off + 2 + n_gps * 12 + 4
    data = bytearray()

    def put(b: bytes) -> int:
        nonlocal dpos
        off = dpos
        data.extend(b)
        dpos += len(b)
        return off

    model_off = put(model)
    lat = put(_rat(40, 1) + _rat(26, 1) + _rat(46302, 1000))
    lon = put(_rat(79, 1) + _rat(58, 1) + _rat(55903, 1000))

    def e(tag, ftype, count, value) -> bytes:
        v = value if isinstance(value, (bytes, bytearray)) else struct.pack("<I", value)
        return struct.pack("<HHI", tag, ftype, count) + (v + b"\x00\x00\x00\x00")[:4]

    ifd0 = (struct.pack("<H", n0)
            + e(0x0110, 2, len(model), model_off)     # Model (ASCII, offset)
            + e(0x8825, 4, 1, gps_off)                # GPS IFD pointer
            + e(0x0112, 3, 1, 1)                      # Orientation (inline)
            + struct.pack("<I", 0))
    gps = (struct.pack("<H", n_gps)
           + e(1, 2, 2, b"N\x00") + e(2, 5, 3, lat)
           + e(3, 2, 2, b"W\x00") + e(4, 5, 3, lon)
           + struct.pack("<I", 0))
    tiff = b"II" + struct.pack("<HI", 42, 8) + ifd0 + gps + bytes(data)
    app1 = b"Exif\x00\x00" + tiff
    return (b"\xff\xd8\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
            + b"\xff\xd9" + bytes(400))               # padding: non-resident


def docx_with_props() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", "<x/>")
        zf.writestr("word/document.xml", "<w:document/>")
        zf.writestr("docProps/core.xml",
                    '<cp:coreProperties xmlns:cp="x" xmlns:dc="y" '
                    'xmlns:dcterms="z"><dc:creator>Alice Smith</dc:creator>'
                    '<dc:title>Ransom Note</dc:title>'
                    '<dcterms:created>2026-07-04T13:22:10Z</dcterms:created>'
                    '<dcterms:modified>2026-07-05T09:00:00Z</dcterms:modified>'
                    '</cp:coreProperties>')
        zf.writestr("docProps/app.xml",
                    '<Properties><Application>Microsoft Word</Application>'
                    '</Properties>')
    return buf.getvalue()


PDF = (b"%PDF-1.4\n1 0 obj<< /Title (Secret Plan) /Author (Bob Jones) "
       b"/CreationDate (D:20260704132210-04'00') /Producer (Acme PDF) "
       b">>endobj\n" + b"% padding to force a non-resident stream\n" * 20
       + b"%%EOF")

MBOX = (b"From alice@ex.com Mon Jul  4 00:00:00 2026\r\n"
        b"From: Alice <alice@ex.com>\r\nTo: Bob <bob@ex.com>\r\n"
        b"Subject: meet at the pier\r\n"
        b"Date: Fri, 04 Jul 2026 13:22:10 +0000\r\nMessage-ID: <1@ex>\r\n"
        b"\r\nbody one\r\n"
        b"From bob@ex.com Mon Jul  5 00:00:00 2026\r\n"
        b"From: Bob <bob@ex.com>\r\nTo: Alice <alice@ex.com>\r\n"
        b"Subject: re: meet\r\nDate: Sat, 05 Jul 2026 09:00:00 +0000\r\n"
        b"\r\nbody two\r\n")


def build_disk():
    b = ds.NtfsBuilder(clusters=768, label="DOMEXVOL")
    b.directory(64, "Docs")
    b.directory(67, "Photos")
    b.directory(69, "Mail")
    b.file(65, "ransom.docx", docx_with_props(), parent=64)
    b.file(66, "plan.pdf", PDF, parent=64)
    b.file(68, "beach.jpg", jpeg_with_gps(), parent=67)
    b.file(70, "inbox.mbox", MBOX, parent=69)
    b.file(71, "note.eml",
           b"From: c@ex\r\nTo: d@ex\r\nSubject: solo\r\n"
           b"Date: Fri, 04 Jul 2026 01:02:03 -0500\r\n\r\n" + bytes(300),
           parent=69)
    volume = b.build()
    sectors = PART_LBA + len(volume) // 512 + 2048
    last = PART_LBA + len(volume) // 512 - 1
    disk = ds.gpt_disk(sectors, [dict(type=ds.BASIC_DATA, first=PART_LBA,
                                      last=last, name="Windows")])
    disk[PART_LBA * 512:PART_LBA * 512 + len(volume)] = volume
    return bytes(disk)


# ---------------------------------------------------------------------------
# the pure extractors, held to spec-correct bytes
# ---------------------------------------------------------------------------

class Extractors(unittest.TestCase):
    def test_exif_gps_is_signed_by_hemisphere(self):
        info = domex.read_exif(jpeg_with_gps())
        self.assertEqual(info["model"], "iPhone 12")
        geo = info["geo"]
        self.assertAlmostEqual(geo["lat"], LAT_DEG, places=4)
        self.assertAlmostEqual(geo["lon"], -LON_DEG, places=4)   # West is negative

    def test_exif_gps_utc_timestamp_when_present(self):
        # a datestamp + timestamp are UTC by the EXIF spec
        base = jpeg_with_gps()
        self.assertIsNone(domex.read_exif(base)["geo"].get("ts_utc"))

    def test_no_exif_is_none_not_a_guess(self):
        self.assertIsNone(domex.read_exif(b"\xff\xd8\xff\xd9"))
        self.assertIsNone(domex.read_exif(b"not an image at all"))

    def test_ooxml_properties_and_utc_dates(self):
        p = domex.read_document_props(docx_with_props(), "docx")
        self.assertEqual(p["author"], "Alice Smith")
        self.assertEqual(p["title"], "Ransom Note")
        self.assertTrue(p["created_utc"].startswith("2026-07-04T13:22:10"))
        self.assertTrue(p["modified_utc"].startswith("2026-07-05T09:00:00"))
        self.assertEqual(p["application"], "Microsoft Word")

    def test_pdf_info_scan_converts_the_timezone(self):
        p = domex.read_document_props(PDF, "pdf")
        self.assertEqual(p["author"], "Bob Jones")
        self.assertEqual(p["title"], "Secret Plan")
        self.assertTrue(p["created_utc"].startswith("2026-07-04T17:22:10"))  # -04:00
        self.assertIn("heuristic", p["basis"])

    def test_pdf_hex_string_utf16(self):
        pdf = b"%PDF-1.5\n<< /Author <feff00420061006c> >>\n%%EOF"
        self.assertEqual(domex.read_document_props(pdf, "pdf")["author"], "Bal")

    def test_pdf_literal_utf16_bom_and_octal_escapes(self):
        # a real /Info author is often an octal-escaped UTF-16BE string with a
        # BOM — the case the Party Girl MLA handbook exposed. And \050/\051 are
        # escaped parens, which a literal string cannot carry unescaped.
        pdf = (b"%PDF-1.6\n<< /Author (\\376\\377\\000M\\000a\\000r\\000i\\000a) "
               b"/Title (Plain \\050ok\\051) >>\n%%EOF")
        p = domex.read_document_props(pdf, "pdf")
        self.assertEqual(p["author"], "Maria")
        self.assertEqual(p["title"], "Plain (ok)")

    def test_legacy_ole_is_named_not_mined(self):
        p = domex.read_document_props(b"\xd0\xcf\x11\xe0" + bytes(100), "ole2")
        self.assertIn("OLE2", p["note"])

    def test_mbox_splits_and_parses_each_message(self):
        rows = domex.read_email_messages(MBOX, "mbox")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["subject"], "meet at the pier")
        self.assertEqual(rows[0]["from"], "Alice <alice@ex.com>")
        self.assertTrue(rows[0]["at_utc"].startswith("2026-07-04T13:22:10"))
        self.assertTrue(rows[1]["at_utc"].startswith("2026-07-05T09:00:00"))

    def test_eml_single_message_tz_to_utc(self):
        eml = (b"From: c@x\r\nSubject: s\r\n"
               b"Date: Fri, 04 Jul 2026 01:02:03 -0500\r\n\r\nbody")
        rows = domex.read_email_messages(eml, "eml")
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]["at_utc"].startswith("2026-07-04T06:02:03"))


# ---------------------------------------------------------------------------
# end to end, through a case and an NTFS volume
# ---------------------------------------------------------------------------

class OnADiskImage(TempDirCase):
    def setUp(self):
        super().setUp()
        self.disk = build_disk()
        self.evidence = self.tmp / "evidence"
        self.evidence.mkdir()
        (self.evidence / "img.001").write_bytes(self.disk)
        self.case = Case.create(self.tmp / "case", case_id="DOMEX-1",
                                examiner=EXAMINER)
        item = self.case.add_image(self.evidence / "img.001")
        self.eid = item.id
        diskimage.ingest_image(self.case, self.eid)
        self.vol = next(v["volume"] for v in
                        diskimage.list_volumes(self.case, self.eid)
                        if v["fs_type"] == "ntfs")
        diskimage.parse_ntfs(self.case, self.eid, self.vol)

    def run_domex(self, **kw):
        return domex.analyse_volume(self.case, self.eid, self.vol, **kw)

    def test_it_needs_the_ntfs_pass_first(self):
        # a volume that was never NTFS-parsed refuses, and says why
        gap = next(v["volume"] for v in
                   diskimage.list_volumes(self.case, self.eid)
                   if v["kind"] == "gap")
        with self.assertRaisesRegex(EvidenceError, "no parsed MFT"):
            domex.analyse_volume(self.case, self.eid, gap)

    def test_the_geotagged_photo_comes_back_with_signed_degrees(self):
        summary = self.run_domex()
        self.assertEqual(summary.state, "completed")
        self.assertEqual(summary.geotagged, 1)
        rows, total = domex.list_domex(self.case, self.eid, artefact="image")
        self.assertEqual(total, 1)
        detail = json.loads(rows[0]["detail_json"])
        self.assertEqual(detail["path"], "Photos/beach.jpg")
        self.assertAlmostEqual(detail["geo"]["lat"], LAT_DEG, places=4)
        self.assertAlmostEqual(detail["geo"]["lon"], -LON_DEG, places=4)
        self.assertIn("GPS", rows[0]["value"])
        # the row's UTC is the measured file-system time, not an authored one
        self.assertTrue(rows[0]["at_utc"].startswith("2024-03-01T12:00:00"))

    def test_geo_only_filter_finds_the_photo(self):
        self.run_domex()
        rows, total = domex.list_domex(self.case, self.eid, geo_only=True)
        self.assertEqual(total, 1)
        self.assertEqual(json.loads(rows[0]["detail_json"])["path"],
                         "Photos/beach.jpg")

    def test_documents_carry_author_and_dates(self):
        self.run_domex()
        rows, total = domex.list_domex(self.case, self.eid, artefact="document")
        self.assertEqual(total, 2)
        by_path = {json.loads(r["detail_json"])["path"]: r for r in rows}
        docx = json.loads(by_path["Docs/ransom.docx"]["detail_json"])
        self.assertEqual(docx["doc"]["author"], "Alice Smith")
        self.assertTrue(docx["doc"]["created_utc"].startswith("2026-07-04"))
        pdf = json.loads(by_path["Docs/plan.pdf"]["detail_json"])
        self.assertEqual(pdf["doc"]["author"], "Bob Jones")

    def test_the_mail_spool_becomes_one_row_per_message(self):
        self.run_domex()
        rows, total = domex.list_domex(self.case, self.eid, artefact="email")
        # two mbox messages + one loose eml
        self.assertEqual(total, 3)
        subjects = sorted(json.loads(r["detail_json"])["email"]["subject"]
                          for r in rows)
        self.assertEqual(subjects, ["meet at the pier", "re: meet", "solo"])
        # each message's own Date drives its UTC
        pier = next(r for r in rows if "pier" in r["value"])
        self.assertTrue(pier["at_utc"].startswith("2026-07-04T13:22:10"))

    def test_rerun_is_idempotent_for_the_volume(self):
        self.run_domex()
        _rows, first = domex.list_domex(self.case, self.eid)
        self.run_domex()
        _rows, second = domex.list_domex(self.case, self.eid)
        self.assertEqual(first, second, "a second run must not duplicate rows")

    def test_custody_records_the_run_and_never_writes_to_evidence(self):
        before = self.evidence / "img.001"
        stamp = before.stat().st_mtime_ns
        self.run_domex()
        self.assertEqual((self.evidence / "img.001").stat().st_mtime_ns, stamp)
        rec = self.case.custody.last("domex.completed", f"{self.eid}:v{self.vol}")
        self.assertEqual(rec["detail"]["rows"], 6)   # 1 img + 2 doc + 3 email


if __name__ == "__main__":
    unittest.main()
