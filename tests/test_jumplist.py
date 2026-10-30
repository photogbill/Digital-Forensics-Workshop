"""Jump lists: the compound-file reader, DestList v1/v3/v4, the join to
shortcut streams, deleted-entry recovery, custom destinations, and rows."""

from __future__ import annotations

import glob
import json
import os
import struct
import unittest

import _support  # noqa: F401
import jumplistsynth as js
import shelllinksynth as ls
from forensics_workshop import jumplist
from forensics_workshop.errors import FileSystemError

#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples"
EXPLORER = "f01b4d95cf55d32a.automaticDestinations-ms"


def lnk_to(path: str, mft=(500, 3)) -> bytes:
    folder, _, name = path.rpartition("\\")
    ids = ls.id_list(ls.item_root(), ls.item_volume("C:\\"),
                     ls.item_file(name[:8].upper(), name, mft=mft))
    return ls.build_lnk(ids=ids, link_info=ls.link_info_local(path),
                        extra=[ls.tracker()])


class CompoundFile(unittest.TestCase):
    def test_v3_mini_and_regular_streams_and_a_storage(self):
        big = bytes(range(256)) * 30
        data, _ = js.build_cfb([("small", b"tiny" * 10), ("big", big)],
                               storage=("Sub", [("inner", b"in" * 100)]))
        cf = jumplist.CompoundFile(data)
        self.assertEqual((cf.version, cf.sector_size), (3, 512))
        got = {e.path: cf.read(e) for e in cf.streams()}
        self.assertEqual(got, {"small": b"tiny" * 10, "big": big,
                               "Sub/inner": b"in" * 100})
        self.assertEqual(cf.problems, [])

    def test_v4_with_4096_byte_sectors(self):
        data, _ = js.build_cfb([("a", b"x" * 100), ("b", b"y" * 9000)], version=4)
        cf = jumplist.CompoundFile(data)
        self.assertEqual((cf.version, cf.sector_size), (4, 4096))
        self.assertEqual(cf.read(cf.find("b")), b"y" * 9000)

    def test_fat_sectors_listed_through_a_difat_sector(self):
        data, lay = js.build_cfb([("big", b"D" * 20000)], min_fat_sectors=115)
        self.assertEqual(lay["n_difat"], 1)
        cf = jumplist.CompoundFile(data)
        self.assertEqual(cf.read(cf.find("big")), b"D" * 20000)
        self.assertEqual(cf.problems, [])

    def test_a_broken_and_a_looping_chain_are_reported(self):
        data, lay = js.build_cfb([("big", b"Q" * 5000)])
        ss = lay["sector_size"]
        start = lay["streams"]["big"]
        fat_at = (lay["fat_first"] + 1) * ss
        broken = bytearray(data)
        struct.pack_into("<I", broken, fat_at + 4 * (start + 2), 0x00FFFFF0)
        cf = jumplist.CompoundFile(bytes(broken))
        problems: list = []
        self.assertEqual(len(cf.read(cf.find("big"), problems)), 3 * ss)
        self.assertTrue(any("outside the allocation table" in p for p in problems))
        loop = bytearray(data)
        struct.pack_into("<I", loop, fat_at + 4 * (start + 2), start)
        cf = jumplist.CompoundFile(bytes(loop))
        problems = []
        cf.read(cf.find("big"), problems)
        self.assertTrue(any("loops back" in p for p in problems))

    def test_not_a_compound_file_is_refused(self):
        with self.assertRaises(FileSystemError):
            jumplist.CompoundFile(b"PK\x03\x04" + bytes(600))
        data, _ = js.build_cfb([("a", b"1")])
        bad = bytearray(data)
        struct.pack_into("<H", bad, 28, 0xFEFF)
        with self.assertRaises(FileSystemError):
            jumplist.CompoundFile(bytes(bad))


class DestList(unittest.TestCase):
    def test_version_1_windows_7(self):
        raw = js.destlist(1, [js.destlist_entry(1, 1, "C:\\a.txt", pin=0),
                              js.destlist_entry(1, 2, "C:\\b.txt")])
        d = jumplist.parse_destlist(raw)
        self.assertEqual(d["problems"], [])
        a, b = d["entries"]
        self.assertEqual((a["entry_number"], a["path"], a["pinned"], a["pin_status"]),
                         (1, "C:\\a.txt", True, 0))
        self.assertFalse(b["pinned"])
        self.assertIsNone(a["access_count"])
        self.assertEqual(a["hostname"], "WORKSTATION7")
        self.assertEqual(a["last_modified"]["raw"], ls.T_WRITE)
        self.assertEqual(a["last_modified"]["epoch"], "filetime")
        self.assertEqual(a["droid_file"]["mac"], "00:0c:29:aa:bb:cc")

    def test_versions_3_and_4_with_counter_and_property_store(self):
        for version in (3, 4):
            store = js.property_store_blob("remembered title")
            raw = js.destlist(version, [
                js.destlist_entry(version, 10, "C:\\x.docx", count=5, store=store),
                js.destlist_entry(version, 11, "C:\\y.docx", count=2)])
            d = jumplist.parse_destlist(raw)
            self.assertEqual(d["problems"], [], version)
            x, y = d["entries"]
            self.assertEqual((x["entry_number"], x["access_count"]), (10, 5))
            self.assertEqual(x["property_store"][0]["properties"][0]["value"],
                             "remembered title")
            self.assertEqual((y["path"], y["access_count"]), ("C:\\y.docx", 2))

    def test_a_path_that_runs_off_the_stream_is_reported(self):
        raw = js.destlist(3, [js.destlist_entry(3, 1, "C:\\a.txt"),
                              js.destlist_entry(3, 2, "C:\\long-path.txt")])
        d = jumplist.parse_destlist(raw[:-12])
        self.assertEqual(len(d["entries"]), 1)
        self.assertTrue(any("runs past the end" in p for p in d["problems"]))

    def test_an_empty_stream_is_an_empty_list(self):
        d = jumplist.parse_destlist(b"")
        self.assertEqual((d["entries"], d["problems"], d["empty"]), ([], [], True))


class Automatic(unittest.TestCase):
    def build(self, **kw):
        dl = js.destlist(3, [
            js.destlist_entry(3, 1, "C:\\Cases\\one.txt", pin=0, count=4),
            js.destlist_entry(3, 10, "C:\\Cases\\ten.txt", count=1),
            js.destlist_entry(3, 12, "C:\\Cases\\gone.txt")])
        streams = [("DestList", dl), ("1", lnk_to("C:\\Cases\\one.txt", (101, 1))),
                   ("a", lnk_to("C:\\Cases\\ten.txt", (110, 2))),
                   ("b", lnk_to("C:\\Cases\\stray.txt"))]
        data, _ = js.build_cfb(streams, **kw)
        return jumplist.parse_automatic(data, file_name=EXPLORER)

    def test_destlist_joined_to_streams_by_hex_entry_number(self):
        p = self.build()
        self.assertEqual(p["app_id"], "f01b4d95cf55d32a")
        self.assertIn("Windows Explorer", p["app_name"])
        one, ten, gone = p["entries"]
        self.assertEqual((one["stream"], one["lnk"]["target_path"]),
                         ("1", "C:\\Cases\\one.txt"))
        self.assertEqual(one["lnk"]["target_mft"]["entry"], 101)
        self.assertEqual((ten["stream"], ten["destlist"]["access_count"]), ("a", 1))
        self.assertIsNone(gone["stream"])
        self.assertTrue(any("no stream named 'c'" in x for x in p["problems"]))
        self.assertEqual([o["stream"] for o in p["orphan_streams"]], ["b"])
        self.assertEqual(p["recovered"], [])

    def test_unlinked_directory_entries_and_free_sectors_are_recovered_and_flagged(self):
        p = self.build(unlinked=[("d", lnk_to("C:\\Cases\\deleted.txt"))],
                       free_mini_blobs=[lnk_to("C:\\Cases\\carved.txt")],
                       free_blobs=[lnk_to("C:\\Cases\\carved-big.txt") + bytes(5000)])
        rec = {r["lnk"]["target_path"]: r for r in p["recovered"]}
        self.assertEqual(set(rec), {"C:\\Cases\\deleted.txt", "C:\\Cases\\carved.txt",
                                    "C:\\Cases\\carved-big.txt"})
        self.assertTrue(all(r["recovered"] for r in rec.values()))
        self.assertIn("not linked from the root", rec["C:\\Cases\\deleted.txt"]["how"])
        self.assertIn("free mini-sector", rec["C:\\Cases\\carved.txt"]["how"])
        self.assertIn("free sector", rec["C:\\Cases\\carved-big.txt"]["how"])

    def test_unknown_app_id_stays_hex_and_dispatch_by_content(self):
        data, _ = js.build_cfb([("DestList", js.destlist(4, []))])
        p = jumplist.parse_jumplist(data, file_name="00aa11bb22cc33dd.automaticDestinations-ms")
        self.assertEqual((p["format"], p["app_id"], p["app_name"]),
                         ("automaticDestinations", "00aa11bb22cc33dd", None))

    def test_rows(self):
        p = self.build(unlinked=[("d", lnk_to("C:\\Cases\\deleted.txt"))])
        rows = jumplist.to_rows(p, source_path="Recent/AutomaticDestinations/" + EXPLORER)
        self.assertTrue(all(r["artefact"] == "jumplist-entry" for r in rows))
        timed = [r for r in rows if r["at_utc"]]
        self.assertEqual(len(timed), 3)
        self.assertEqual(timed[0]["at_raw"], ls.T_WRITE)
        self.assertEqual(timed[0]["at_epoch"], "filetime")
        self.assertIn("DestList entry 1 records C:\\Cases\\one.txt", timed[0]["value"])
        self.assertIn("pinned (position 0)", timed[0]["value"])
        recovered = [r for r in rows if r["detail"].get("recovered")]
        self.assertEqual(len(recovered), 1)
        self.assertIn("recovered", recovered[0]["title"])
        self.assertEqual(len({r["row_ref_suffix"] for r in rows}), len(rows))
        for r in rows:
            json.dumps(r)


class Custom(unittest.TestCase):
    def test_categories_are_read_where_the_structure_holds(self):
        data = js.custom_file([
            js.custom_category(0, name="Pinned sites",
                               links=[lnk_to("C:\\a.html"), lnk_to("C:\\b.html")]),
            js.custom_category(1, ident=2),
            js.custom_category(2, links=[lnk_to("C:\\Windows\\notepad.exe")])])
        p = jumplist.parse_jumplist(data, file_name="5d696d521de238c3.customDestinations-ms")
        self.assertEqual(p["app_name"], "Google Chrome")
        self.assertEqual([(c["name"], c["entries"]) for c in p["categories"]],
                         [("Pinned sites", 2), ("Recent", 0), ("Tasks", 1)])
        self.assertEqual([l["lnk"]["target_path"] for l in p["links"]],
                         ["C:\\a.html", "C:\\b.html", "C:\\Windows\\notepad.exe"])
        self.assertEqual((p["skipped"], p["problems"]), ([], []))
        rows = jumplist.to_rows(p, source_path="x.customDestinations-ms")
        self.assertEqual(len(rows), 3)
        self.assertIn("Pinned sites", rows[0]["value"])

    def test_a_damaged_category_falls_back_to_the_signature_and_reports_skips(self):
        good = js.custom_category(0, name="Recent work",
                                  links=[lnk_to("C:\\one.txt")])
        bad = bytearray(js.custom_category(0, name="Damaged",
                                           links=[lnk_to("C:\\two.txt"),
                                                  lnk_to("C:\\three.txt")]))
        struct.pack_into("<I", bad, 0, 7)            # undocumented category type
        data = js.custom_file([good, bytes(bad)])
        p = jumplist.parse_custom(data)
        self.assertEqual([l["lnk"]["target_path"] for l in p["links"]],
                         ["C:\\one.txt", "C:\\two.txt", "C:\\three.txt"])
        self.assertEqual([l["how"] for l in p["links"]],
                         ["category structure", "signature scan", "signature scan"])
        self.assertTrue(p["problems"])
        self.assertTrue(p["skipped"])
        self.assertTrue(all(s["length"] > 0 for s in p["skipped"]))

    def test_something_else_is_refused(self):
        with self.assertRaises(FileSystemError):
            jumplist.parse_custom(b"QUFBQUFBQUFB" * 50)


class RealSamples(unittest.TestCase):
    """Real jump lists (not shipped) from the container's sample folder;
    the expected counts were cross-checked with olefile, libolecf + the
    dtformats DestList definitions, and liblnk."""

    def setUp(self):
        self.files = [f for f in sorted(set(
            glob.glob(SAMPLES + "/repos/**/*Destinations-ms", recursive=True)
            + glob.glob(SAMPLES + "/jumplist/*Destinations-ms")))
            if "/.git/" not in f and os.path.isfile(f)]
        if not self.files:
            self.skipTest(f"no real jump-list samples under {SAMPLES} "
                          "(downloaded for validation only, never shipped)")

    def parse(self, tail):
        hits = [f for f in self.files if f.endswith(tail)]
        if not hits:
            self.skipTest(f"{tail} is not in the sample folder")
        with open(hits[0], "rb") as fh:
            return jumplist.parse_jumplist(fh.read(), file_name=os.path.basename(hits[0]))

    def test_every_sample_parses_or_is_refused_cleanly(self):
        for path in self.files:
            with open(path, "rb") as fh:
                data = fh.read()
            try:
                p = jumplist.parse_jumplist(data, file_name=os.path.basename(path))
            except FileSystemError:
                self.assertIn("lnkparse3/tests/raw", path)   # base64 text, not a file
                continue
            json.dumps(jumplist.to_rows(p, source_path=path))

    def test_known_values(self):
        p = self.parse("Win10/f01b4d95cf55d32a.automaticDestinations-ms")
        self.assertEqual((p["destlist_header"]["version"], len(p["entries"])), (3, 9))
        p = self.parse("dtformats/test_data/1b4dd67f29cb1962.automaticDestinations-ms")
        self.assertEqual((p["destlist_header"]["version"], len(p["entries"])), (1, 7))
        p = self.parse("velociraptor_5f7b5f1e01b83767.automaticDestinations-ms")
        self.assertEqual((p["destlist_header"]["version"], len(p["entries"])), (4, 8))
        p = self.parse("368d807282ccde9d.customDestinations-ms")
        self.assertEqual([c["name"] for c in p["categories"]],
                         ["My Category 1", "Frequent", "Tasks", "My Category 2", "Recent"])
        self.assertEqual(len(p["links"]), 3)


if __name__ == "__main__":
    unittest.main()
