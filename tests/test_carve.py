"""Carving: every format measured by its own structure, and honest about the rest."""

from __future__ import annotations

import random
import unittest

import _support  # noqa: F401
import disksynth as ds
from forensics_workshop import carve


class Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


def noise(n: int, seed: int) -> bytes:
    rng = random.Random(seed)
    out = bytearray(rng.getrandbits(8) for _ in range(n))
    return bytes(out)


def disk_with(files: dict, *, gap: int = 3, seed: int = 1):
    """Files at sector boundaries with `gap` sectors of noise between them.
    Returns (bytes, {name: (offset, length)})."""
    out = bytearray(noise(4096, seed))
    where = {}
    for i, (name, blob) in enumerate(files.items()):
        out += bytes(-len(out) % 512)
        where[name] = (len(out), len(blob))
        out += blob
        out += noise(-len(out) % 512 + gap * 512, seed + i + 1)
    return bytes(out), where


def run(data, **kw):
    reader = Bytes(data)
    return [c for c in carve.carve_regions(reader, [(0, len(data))], **kw)]


class EveryFormat(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = ds.carved_corpus()
        cls.data, cls.where = disk_with(cls.files)
        cls.found = {c.offset: c for c in run(cls.data)}

    def test_each_file_is_found_at_its_offset_with_its_exact_length(self):
        expect_type = {"png": "png", "jpeg": "jpeg", "gif": "gif", "bmp": "bmp",
                       "pdf": "pdf", "zip": "zip", "sqlite": "sqlite", "wav": "wav",
                       "ole2": "ole2", "pe": "pe", "mp4": "mp4", "gzip": "gzip",
                       "7z": "7z", "docx": "docx"}
        for name, (offset, length) in self.where.items():
            with self.subTest(name):
                c = self.found.get(offset)
                self.assertIsNotNone(c, f"{name} not found at {offset}")
                self.assertEqual(c.type_id, expect_type[name])
                self.assertEqual(c.length, length, c.note)
                self.assertEqual(c.status, "complete", c.note)
                self.assertIn(c.basis, ("structure", "footer"))

    def test_nothing_but_the_planted_files_is_claimed_complete(self):
        planted = {o for o, _l in self.where.values()}
        extra = [c for c in self.found.values()
                 if c.offset not in planted and c.status == "complete"]
        self.assertEqual(extra, [], "noise produced a 'complete' candidate")

    def test_the_basis_names_what_was_checked(self):
        png = self.found[self.where["png"][0]]
        self.assertIn("CRC", png.note)
        zipc = self.found[self.where["zip"][0]]
        self.assertIn("end-of-central-directory", zipc.note)
        pdf = self.found[self.where["pdf"][0]]
        self.assertEqual(pdf.basis, "footer")


class Honesty(unittest.TestCase):
    def test_a_png_overwritten_part_way_is_truncated_where_the_crc_fails(self):
        png = ds.png_file(40, 40)
        damaged = png[:60] + noise(len(png) - 60, 9)
        data, where = disk_with({"png": damaged})
        c = next(c for c in run(data, types=["png"]) if c.offset == where["png"][0])
        self.assertEqual(c.status, "truncated")
        self.assertLess(c.length, len(png))
        self.assertIn("CRC", c.note)

    def test_a_jpeg_with_no_end_is_capped_not_complete(self):
        jpeg = ds.jpeg_file()[:-2]                          # no EOI
        data = bytes(512) + jpeg + bytes(512) * 4
        found = run(data, types=["jpeg"])
        self.assertEqual(len(found), 1)
        self.assertIn(found[0].status, ("capped", "truncated"))
        self.assertNotEqual(found[0].status, "complete")

    def test_a_region_boundary_is_never_crossed_as_complete(self):
        sqlite = ds.sqlite_file()
        data = bytes(1024) + sqlite
        reader = Bytes(data)
        inside = list(carve.carve_regions(reader, [(0, 1024 + len(sqlite) // 2)],
                                          types=["sqlite"]))
        self.assertEqual(inside[0].status, "truncated")
        whole = list(carve.carve_regions(reader, [(0, len(data))], types=["sqlite"]))
        self.assertEqual((whole[0].status, whole[0].length), ("complete", len(sqlite)))

    def test_every_byte_mode_finds_an_embedded_file_and_marks_it_nested(self):
        inner = ds.png_file()
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("photo.png", inner)
        blob = buf.getvalue()
        data = bytes(512) + blob + bytes(-len(blob) % 512 + 512)
        aligned = run(data)
        self.assertEqual([c.type_id for c in aligned], ["zip"])
        deep = run(data, aligned=1)
        types = {c.type_id: c for c in deep}
        self.assertIn("png", types)
        self.assertEqual(types["png"].nested_in, 512)

    def test_a_pdf_with_an_incremental_update_runs_to_its_last_eof(self):
        pdf = ds.pdf_file(updates=2)
        data, where = disk_with({"pdf": pdf})
        c = next(c for c in run(data, types=["pdf"]) if c.offset == where["pdf"][0])
        self.assertEqual(c.length, len(pdf))

    def test_mz_in_noise_is_not_an_executable(self):
        data = bytearray(noise(64 * 512, 3))
        for i in range(0, len(data), 512):
            data[i:i + 2] = b"MZ"
        self.assertEqual(run(bytes(data), types=["pe"]), [])

    def test_only_the_types_asked_for(self):
        data, where = disk_with({"png": ds.png_file(), "gif": ds.gif_file()})
        self.assertEqual({c.type_id for c in run(data, types=["gif"])}, {"gif"})
        with self.assertRaises(Exception):
            run(data, types=["nonsense"])


if __name__ == "__main__":
    unittest.main()
