"""Prefetch: SCCA versions 17–31, MAM (LZXPRESS Huffman) decompression,
damage reported beside the result, and measurement-worded rows."""

from __future__ import annotations

import glob
import json
import os
import struct
import sys
import unittest

import _support  # noqa: F401
import prefetchsynth as ps
from forensics_workshop import prefetch, timeutil
from forensics_workshop.errors import FileSystemError

#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples"
FILES = [("\\VOLUME{01d1}\\WINDOWS\\SYSTEM32\\NTDLL.DLL", (1234, 5)),
         ("\\VOLUME{01d1}\\WINDOWS\\SYSTEM32\\NOTEPAD.EXE", (98765, 2)),
         ("\\VOLUME{01d1}\\USERS\\ANALYST\\DESKTOP\\NOTES.TXT", (0, 0))]
VOLUMES = [("\\VOLUME{01d1a2b3c4d5e6f7-1234ABCD}", 0x1234ABCD, ps.T_VOL,
            ["\\VOLUME{01d1}\\WINDOWS", "\\VOLUME{01d1}\\WINDOWS\\SYSTEM32"],
            [(1234, 5), (98765, 2)])]
RUNS = [ps.T_RUN - i * 36_000_000_000 for i in range(8)]   # an hour apart


class Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


def build(version, **kw):
    kw.setdefault("files", FILES)
    kw.setdefault("volumes", VOLUMES)
    kw.setdefault("run_times", RUNS if version >= 26 else RUNS[:1])
    return ps.build_scca(version, **kw)


class Versions(unittest.TestCase):
    def check(self, version, variant=2):
        p = prefetch.parse_prefetch(build(version, variant=variant),
                                    file_name="NOTEPAD.EXE-D8414F97.pf")
        self.assertEqual(p["version"], version)
        self.assertEqual(p["problems"], [])
        self.assertEqual(p["executable"], "NOTEPAD.EXE")
        self.assertEqual(p["prefetch_hash"], "D8414F97")
        self.assertTrue(p["hash_matches_file_name"])
        self.assertEqual(p["run_count"], 7)
        slots = 8 if version >= 26 else 1
        self.assertEqual(p["last_run_slots"], slots)
        self.assertEqual([r["raw"] for r in p["last_run_times"]], RUNS[:slots])
        first = p["last_run_times"][0]
        self.assertEqual((first["epoch"], first["utc"]),
                         ("filetime", "2020-01-01T01:00:00.000000Z"))
        self.assertEqual([f["name"] for f in p["files"]], [n for n, _ in FILES])
        if version == 17:
            self.assertNotIn("file_reference", p["files"][0])
        else:
            self.assertEqual(p["files"][0]["file_reference"],
                             {"entry": 1234, "sequence": 5})
            self.assertIsNone(p["files"][2]["file_reference"])
        vol = p["volumes"][0]
        self.assertEqual(vol["device_path"], VOLUMES[0][0])
        self.assertEqual((vol["serial"], vol["serial_short"]),
                         ("1234ABCD", "1234-ABCD"))
        self.assertEqual(vol["created"], {"raw": ps.T_VOL, "epoch": "filetime",
                                          "utc": timeutil.decode(ps.T_VOL, "filetime")})
        self.assertEqual(vol["directories"], VOLUMES[0][3])
        self.assertEqual(vol["file_references"]["count"], 2)
        self.assertEqual(vol["file_references"]["references"][1],
                         {"entry": 98765, "sequence": 2})
        return p

    def test_version_17_xp(self):
        self.check(17)

    def test_version_23_vista_7(self):
        self.check(23)

    def test_version_26_eight_run_times(self):
        self.check(26)

    def test_version_30_both_layouts_are_told_apart_and_named(self):
        self.assertIn("variant 1", self.check(30, variant=1)["layout"])
        self.assertIn("variant 2", self.check(30, variant=2)["layout"])

    def test_version_31_uses_the_variant_2_layout(self):
        p = self.check(31)
        self.assertIn("version 31", p["layout"])

    def test_unset_run_slots_are_not_invented(self):
        p = prefetch.parse_prefetch(build(26, run_times=RUNS[:3]))
        self.assertEqual(len(p["last_run_times"]), 3)

    def test_hash_compared_with_the_file_name_only_when_given(self):
        data = build(23)
        self.assertIsNone(prefetch.parse_prefetch(data)["hash_matches_file_name"])
        p = prefetch.parse_prefetch(data, file_name=r"C:\x\NOTEPAD.EXE-00000001.pf")
        self.assertFalse(p["hash_matches_file_name"])
        self.assertEqual(p["hash_in_file_name"], "00000001")

    def test_a_reader_object_is_accepted(self):
        p = prefetch.parse_prefetch(Bytes(build(23)))
        self.assertEqual(p["executable"], "NOTEPAD.EXE")


class Mam(unittest.TestCase):
    def test_compressed_and_plain_parse_identically(self):
        plain = build(30)
        packed = ps.mam(plain)
        a = prefetch.parse_prefetch(plain)
        b = prefetch.parse_prefetch(packed)
        self.assertTrue(b["compressed"])
        self.assertEqual(b["compression"]["decoder"], "pure-python")
        for key in ("executable", "run_count", "last_run_times", "files",
                    "volumes", "prefetch_hash"):
            self.assertEqual(a[key], b[key], key)

    def test_several_64k_blocks_and_long_matches(self):
        files = [(f"\\VOLUME{{01d1}}\\PROGRAM FILES\\APP\\MODULE{i:05d}.DLL", (i, 1))
                 for i in range(2400)]
        plain = build(30, files=files)
        self.assertGreater(len(plain), 3 * 65536)
        out, info = prefetch.decompress_mam(ps.mam(plain))
        self.assertEqual(out, plain)
        self.assertGreaterEqual(info["blocks"], 4)
        zeros = bytes(300_000)
        got, _ = prefetch.lzxpress_huffman_decompress(
            ps.lzxpress_huffman_compress(zeros), len(zeros))
        self.assertEqual(got, zeros)

    def test_literal_only_and_text_streams(self):
        for data in (bytes(range(256)) * 3, b"prefetch " * 1000, b"\x41"):
            comp = ps.lzxpress_huffman_compress(data)
            self.assertEqual(prefetch.lzxpress_huffman_decompress(comp, len(data))[0],
                             data)

    def test_truncated_compressed_data_is_refused_with_a_reason(self):
        packed = ps.mam(build(30, files=FILES * 40))
        with self.assertRaises(FileSystemError) as cm:
            prefetch.parse_prefetch(packed[:len(packed) // 3])
        self.assertTrue("truncated" in str(cm.exception)
                        or "damaged" in str(cm.exception))

    def test_an_empty_huffman_table_is_refused(self):
        bad = b"MAM\x04" + struct.pack("<I", 1000) + bytes(300)
        with self.assertRaises(FileSystemError) as cm:
            prefetch.parse_prefetch(bad)
        self.assertIn("Huffman table", str(cm.exception))

    def test_an_over_full_huffman_table_is_refused(self):
        bad = b"MAM\x04" + struct.pack("<I", 1000) + bytes([0x11] * 256) + bytes(8)
        with self.assertRaises(FileSystemError) as cm:
            prefetch.parse_prefetch(bad)
        self.assertIn("over-fill", str(cm.exception))

    def test_unknown_mam_method_is_refused(self):
        bad = b"MAM\x03" + struct.pack("<I", 100) + bytes(100)
        with self.assertRaises(FileSystemError) as cm:
            prefetch.parse_prefetch(bad)
        self.assertIn("method 3", str(cm.exception))

    def test_checksum_variant_is_read_and_says_it_was_not_verified(self):
        plain = build(30)
        body = ps.lzxpress_huffman_compress(plain)
        data = b"MAM\x84" + struct.pack("<II", len(plain), 0xDEADBEEF) + body
        p = prefetch.parse_prefetch(data)
        self.assertTrue(p["compression"]["has_checksum"])
        self.assertEqual(p["compression"]["checksum"], 0xDEADBEEF)
        self.assertIn("not verified", prefetch.__doc__)

    def test_native_path_is_windows_only_and_falls_back(self):
        packed = ps.mam(build(30))
        out, info = prefetch.decompress_mam(packed, native=True)
        self.assertEqual(out, build(30))
        check = prefetch.native_cross_check(packed)
        if sys.platform != "win32":
            self.assertEqual(info["decoder"], "pure-python")
            self.assertTrue(info["native_unavailable"])
            self.assertFalse(check["available"])
            self.assertIsNone(check["agree"])

    @unittest.skipUnless(sys.platform == "win32",
                         "ntdll's RtlDecompressBufferEx exists only on Windows")
    def test_native_and_pure_decoders_agree_on_windows(self):
        packed = ps.mam(build(30, files=FILES * 400))
        check = prefetch.native_cross_check(packed)
        self.assertTrue(check["available"], check)
        self.assertTrue(check["agree"])


class Damage(unittest.TestCase):
    def test_not_prefetch_is_refused(self):
        for data in (b"", b"hello world" * 10, bytes(84),
                     struct.pack("<I4s", 23, b"SCCX") + bytes(200)):
            with self.assertRaises(FileSystemError):
                prefetch.parse_prefetch(data)

    def test_unknown_version_is_refused_not_guessed(self):
        data = bytearray(build(30))
        struct.pack_into("<I", data, 0, 29)
        with self.assertRaises(FileSystemError) as cm:
            prefetch.parse_prefetch(bytes(data))
        self.assertIn("29", str(cm.exception))

    def test_size_mismatch_and_overlong_arrays_are_reported(self):
        data = bytearray(build(26))
        struct.pack_into("<I", data, 12, len(data) + 100)
        struct.pack_into("<I", data, 84 + 4, 10_000)      # metrics count
        p = prefetch.parse_prefetch(bytes(data))
        text = " ".join(p["problems"])
        self.assertIn("declares", text)
        self.assertIn("file-metrics array", text)
        self.assertEqual(p["executable"], "NOTEPAD.EXE")

    def test_cut_off_directory_strings_are_reported_not_raised(self):
        data = build(23)
        p = prefetch.parse_prefetch(data[:-20])
        self.assertTrue(any("directory strings" in x or "declares" in x
                            for x in p["problems"]))

    def test_oversized_input_is_refused(self):
        class Huge:
            size = prefetch.MAX_INPUT + 1

            def read_at(self, o, n):
                raise AssertionError("must not be read")
        with self.assertRaises(FileSystemError):
            prefetch.parse_prefetch(Huge())


class Rows(unittest.TestCase):
    def test_one_row_per_stored_run_and_a_summary(self):
        p = prefetch.parse_prefetch(build(30), file_name="NOTEPAD.EXE-D8414F97.pf")
        rows = prefetch.to_rows(p, source_path="Windows/Prefetch/NOTEPAD.EXE-D8414F97.pf")
        runs = [r for r in rows if r["artefact"] == "prefetch-run"]
        summary = [r for r in rows if r["artefact"] == "prefetch"]
        self.assertEqual(len(runs), 8)
        self.assertEqual(len(summary), 1)
        self.assertEqual(runs[0]["at_raw"], RUNS[0])
        self.assertEqual(runs[0]["at_epoch"], "filetime")
        self.assertEqual(runs[0]["at_utc"], "2020-01-01T01:00:00.000000Z")
        self.assertTrue(runs[0]["value"].startswith(
            "Prefetch records 7 runs of NOTEPAD.EXE"))
        self.assertIsNone(summary[0]["at_utc"])
        self.assertEqual(len(summary[0]["detail"]["referenced_files"]), 3)
        suffixes = [r["row_ref_suffix"] for r in rows]
        self.assertEqual(len(suffixes), len(set(suffixes)))
        keys = {"artefact", "at_utc", "at_raw", "at_epoch", "title", "value",
                "detail", "row_ref_suffix"}
        for r in rows:
            self.assertEqual(set(r), keys)
            json.dumps(r)
            self.assertNotIn("user ran", r["value"].lower())
            self.assertNotIn("executed", r["value"].lower())


class RealSamples(unittest.TestCase):
    """Real files (not shipped) read from the container's sample folder and
    compared with values libscca (pyscca) produced for the same files."""

    def setUp(self):
        self.files = sorted(set(
            glob.glob(SAMPLES + "/repos/ez_Prefetch/Prefetch.Test/TestFiles/*/*.pf")
            + glob.glob(SAMPLES + "/repos/plaso/test_data/winprefetch/*.pf")
            + glob.glob(SAMPLES + "/prefetch/*.pf")))
        if not self.files:
            self.skipTest(f"no real prefetch samples under {SAMPLES} (they are "
                          "downloaded for validation only and never shipped)")

    def test_every_sample_parses_or_is_refused_cleanly(self):
        parsed = 0
        for path in self.files:
            with open(path, "rb") as fh:
                data = fh.read()
            try:
                p = prefetch.parse_prefetch(data, file_name=os.path.basename(path))
            except FileSystemError:
                self.assertIn("Bad", path)
                continue
            parsed += 1
            self.assertEqual(p["problems"], [], path)
            self.assertTrue(p["hash_matches_file_name"], path)
            json.dumps(prefetch.to_rows(p, source_path=path))
        self.assertGreater(parsed, 0)

    def test_known_values(self):
        known = {
            "Win10/CALC.EXE-3FBEF7FD.pf": (30, "CALC.EXE", 2, 63),
            "Win10/DEVENV.EXE-854D7862.pf": (30, "DEVENV.EXE", 54, 403),
            "Win7/PING.EXE-B29F6629.pf": (23, "PING.EXE", 14, 27),
            "XPPro/VERCLSID.EXE-3667BD89.pf": (17, "VERCLSID.EXE", 11, 63),
            "AM_DELTA_PATCH_1.443.990.0.EX-7037CF86.pf":
                (31, "AM_DELTA_PATCH_1.443.990.0.EX", 1, 18),
        }
        for tail, want in known.items():
            hits = [f for f in self.files if f.endswith(tail)]
            if not hits:
                continue
            with open(hits[0], "rb") as fh:
                p = prefetch.parse_prefetch(fh.read())
            self.assertEqual((p["version"], p["executable"], p["run_count"],
                              p["file_count"]), want, tail)


if __name__ == "__main__":
    unittest.main()
