"""Type identification: bytes decide, names are compared, weak never cries wolf."""

from __future__ import annotations

import io
import os
import struct
import unittest

import synth  # noqa: F401  (path set up by _support)
from _support import TempDirCase  # noqa: F401

from forensics_workshop import filetype
from forensics_workshop.filetype import identify


def pad(data: bytes, n: int = 512) -> bytes:
    return data + b"\x00" * max(0, n - len(data))


class Signatures(unittest.TestCase):
    def check(self, head, type_id, *, name="", basis=None, confidence=None,
              mismatch=None, reader=None):
        r = identify(head, name=name, size=len(head), reader=reader)
        self.assertEqual(r.type_id, type_id, r)
        if basis is not None:
            self.assertEqual(r.basis, basis, r)
        if confidence is not None:
            self.assertEqual(r.confidence, confidence, r)
        if mismatch is not None:
            self.assertEqual(r.ext_mismatch, mismatch, r)
        return r

    def test_common_formats(self):
        self.check(synth.JPEG, "jpeg", name="a.jpg", mismatch=False)
        self.check(synth.PNG, "png", name="a.png")
        self.check(synth.PDF, "pdf", name="a.pdf")
        self.check(pad(b"SQLite format 3\x00"), "sqlite", name="History")
        self.check(pad(b"regf"), "regf", name="NTUSER.DAT", mismatch=False)
        self.check(pad(b"ElfFile\x00"), "evtx", name="System.evtx")
        self.check(pad(b"\x00\x00\x00\x00SCCA"), "prefetch", name="X.pf")
        self.check(pad(b"MAM\x04"), "prefetch", name="X.pf")
        self.check(pad(b"EVF\x09\x0d\x0a\xff\x00"), "ewf", name="disk.E01",
                   mismatch=False)
        self.check(pad(b"\xeb\x58\x90-FVE-FS-"), "bitlocker")
        self.check(pad(b"\xeb\x52\x90NTFS    "), "ntfs")

    def test_offsets_deep_in_the_head(self):
        tar = bytearray(1024)
        tar[257:262] = b"ustar"
        self.check(bytes(tar), "tar", name="x.tar")
        iso = bytearray(40000)
        iso[32769:32774] = b"CD001"
        self.check(bytes(iso), "iso9660", name="disk.iso")

    def test_ooxml_and_odf_are_refined_from_the_container(self):
        docx = synth.docx_bytes()
        self.check(docx, "docx", name="a.docx", basis="signature+container",
                   reader=io.BytesIO(docx))
        self.check(docx, "docx", name="a.docx", basis="signature+container",
                   reader=None)                       # local headers only
        self.check(synth.odt_bytes(), "odt", name="a.odt")

    def test_a_plain_zip_named_jpg_is_a_mismatch(self):
        z = synth.plain_zip_bytes()
        self.check(z, "zip", name="vacation.jpg", mismatch=True,
                   reader=io.BytesIO(z))

    def test_pe_exe_dll_and_bare_mz(self):
        self.check(synth.pe_bytes(), "pe", name="setup.exe")
        self.check(synth.pe_bytes(dll=True), "pe-dll", name="x.dll")
        bare = pad(b"MZ" + b"\x00" * 58 + struct.pack("<I", 4000))
        r = self.check(bare, "mz", confidence="weak")
        self.assertFalse(identify(bare, name="thing.txt").ext_mismatch,
                         "a weak MZ never raises a mismatch")

    def test_riff_and_ftyp_forms(self):
        self.check(pad(b"RIFF\x00\x00\x00\x00WAVEfmt "), "wav", name="a.wav")
        self.check(pad(b"RIFF\x00\x00\x00\x00WEBPVP8 "), "webp")
        self.check(pad(b"\x00\x00\x00\x18ftypheic"), "heic", name="IMG.HEIC",
                   mismatch=False)
        self.check(pad(b"\x00\x00\x00\x18ftypisom"), "mp4", name="clip.mp4")
        self.check(pad(b"\x00\x00\x00\x18ftypqt  "), "mov", name="clip.mov")

    def test_cafebabe_is_disambiguated(self):
        self.check(pad(b"\xca\xfe\xba\xbe\x00\x00\x00\x02"), "macho-fat")
        self.check(pad(b"\xca\xfe\xba\xbe\x00\x00\x00\x34"), "java-class")

    def test_ole_subtype_from_directory_names(self):
        self.check(synth.ole_doc_bytes(), "doc", name="old.doc")
        bare = pad(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 4096)
        r = self.check(bare, "ole2", name="unknown.bin", mismatch=True)
        self.assertIn("sub-type unknown", r.note)

    def test_weak_signatures_never_flag_a_mismatch(self):
        r = self.check(pad(b"BM" + os.urandom(200)), "bmp", name="holiday.jpg",
                       confidence="weak")
        self.assertFalse(r.ext_mismatch)
        mbr = bytearray(512)
        mbr[510:512] = b"\x55\xaa"
        self.assertFalse(identify(bytes(mbr), name="notes.txt").ext_mismatch)

    def test_the_extension_is_never_the_basis(self):
        r = identify(os.urandom(1024), name="report.pdf")
        self.assertEqual(r.type_id, "unknown")
        self.assertEqual(r.declared_ext, "pdf")
        self.assertFalse(r.ext_mismatch, "unknown is not a strong claim")

    def test_high_entropy_unknown_says_what_it_cannot_tell(self):
        r = identify(os.urandom(8192), name="container.bin")
        self.assertGreater(r.head_entropy, 7.5)
        self.assertIn("compressed, encrypted or random", r.note)

    def test_text_heuristics(self):
        self.check(b"hello world\n" * 20, "text", basis="heuristic",
                   confidence="weak")
        self.check(b'<?xml version="1.0"?><a/>' + b" " * 300, "xml")
        self.check(b"<!DOCTYPE html><html></html>" + b" " * 300, "html")
        self.check("é".encode() * 200 + b"\xc3", "text")   # cut multibyte tail
        self.check(b"\xff\xfeh\x00i\x00" * 50, "text-utf16")

    def test_empty(self):
        r = identify(b"", name="empty.txt", size=0)
        self.assertEqual(r.type_id, "empty")
        self.assertFalse(r.ext_mismatch)

    def test_wal_sidecar(self):
        self.check(pad(b"\x37\x7f\x06\x82"), "sqlite-wal", name="History-wal",
                   mismatch=False)

    def test_declared_extension(self):
        self.assertEqual(filetype.declared_extension("a/b/Report.PDF"), "pdf")
        self.assertEqual(filetype.declared_extension(".bashrc"), "")
        self.assertEqual(filetype.declared_extension("History"), "")
        self.assertEqual(filetype.declared_extension("x.tar.gz"), "gz")

    def test_the_table_is_well_formed(self):
        for sig in filetype.SIGNATURES:
            self.assertIn(sig.confidence, ("strong", "weak"), sig)
            self.assertTrue(sig.magic, sig)
            self.assertLess(sig.offset + len(sig.magic), filetype.HEAD_BYTES,
                            f"{sig.type_id} is beyond what the ingest keeps")
            self.assertTrue(all(e == e.lower() for e in sig.extensions), sig)


if __name__ == "__main__":
    unittest.main()
