"""Shell links: header, ID list, LinkInfo, strings, extra blocks, damage,
and measurement-worded rows — on links built from [MS-SHLLINK]."""

from __future__ import annotations

import glob
import json
import os
import struct
import unittest

import _support  # noqa: F401
import shelllinksynth as ls
from forensics_workshop import shelllink, timeutil
from forensics_workshop.errors import FileSystemError

#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples"


class Bytes:
    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)

    def read_at(self, offset, length):
        return self.data[offset:offset + length]


class Header(unittest.TestCase):
    def setUp(self):
        self.p = shelllink.parse_lnk(ls.sample_lnk())

    def test_header_fields_and_times_raw_beside_decoded(self):
        h = self.p["header"]
        self.assertIn("HasTargetIDList", h["flag_names"])
        self.assertIn("IsUnicode", h["flag_names"])
        self.assertEqual(h["attribute_names"], ["ARCHIVE"])
        self.assertEqual(h["times"]["target_created"],
                         {"raw": ls.T_CREATE, "epoch": "filetime",
                          "utc": "2020-01-01T00:00:00.000000Z"})
        self.assertEqual(h["times"]["target_accessed"]["utc"],
                         timeutil.decode(ls.T_ACCESS, "filetime"))
        self.assertEqual(h["file_size"], 4096)
        self.assertEqual(h["show_command_name"], "SW_SHOWNORMAL")
        self.assertEqual(h["hotkey"], {"raw": 0x0641, "key": 0x41,
                                       "modifiers": ["CTRL", "ALT"]})
        self.assertEqual(self.p["problems"], [])
        self.assertEqual(self.p["consumed"], self.p["size"])

    def test_not_a_shortcut_is_refused(self):
        good = ls.sample_lnk()
        for bad in (b"", good[:60], b"\x4d\x00\x00\x00" + good[4:],
                    good[:4] + bytes(16) + good[20:]):
            with self.assertRaises(FileSystemError):
                shelllink.parse_lnk(bad)

    def test_a_reader_object_is_accepted(self):
        self.assertEqual(shelllink.parse_lnk(Bytes(ls.sample_lnk()))["target_path"],
                         "C:\\Users\\report final.docx")


class IdList(unittest.TestCase):
    def setUp(self):
        self.p = shelllink.parse_lnk(ls.sample_lnk())
        self.items = self.p["id_list"]["items"]

    def test_items_and_path(self):
        self.assertEqual([i["kind"] for i in self.items],
                         ["root", "volume", "file_entry", "file_entry"])
        self.assertEqual(self.items[0]["folder"], "My Computer")
        self.assertEqual(self.p["id_list"]["path"],
                         "My Computer\\C:\\Users\\report final.docx")

    def test_file_entry_extension_long_name_and_mft_reference(self):
        last = self.items[-1]
        self.assertEqual(last["primary_name"], "REPORT~1.DOC")
        self.assertEqual(last["name"], "report final.docx")
        self.assertEqual(last["extension"]["mft"], {"entry": 91234, "sequence": 7})
        self.assertEqual(self.p["target_mft"]["entry"], 91234)
        self.assertIn("0xBEEF0004", self.p["target_mft"]["source"])

    def test_dos_times_are_labelled_without_a_zone_and_never_as_utc(self):
        m = self.items[-1]["modified"]
        self.assertEqual(m["value"], "2020-01-01T01:00:00")
        self.assertEqual(m["epoch"], "dos_datetime")
        self.assertEqual(m["zone"], "not stated in the format")
        self.assertNotIn("utc", m)
        self.assertEqual(self.items[-1]["extension"]["created"]["value"],
                         "2020-01-01T00:00:00")

    def test_unterminated_unicode_primary_name_is_bounded_by_the_extension(self):
        item = ls.item_file("Échantill", "Échantillons d'images", mft=(77, 3),
                            unicode_primary=True, terminate_primary=False)
        data = ls.build_lnk(ids=ls.id_list(ls.item_root(), ls.item_volume(), item))
        last = shelllink.parse_lnk(data)["id_list"]["items"][-1]
        self.assertEqual(last["primary_name"], "Échantill")
        self.assertEqual(last["name"], "Échantillons d'images")
        self.assertEqual(last["extension"]["mft"], {"entry": 77, "sequence": 3})

    def test_an_item_that_overruns_the_list_is_reported(self):
        ids = bytearray(ls.id_list(ls.item_root(), ls.item_volume()))
        struct.pack_into("<H", ids, 2 + 20, 400)        # volume item size
        p = shelllink.parse_lnk(ls.build_lnk(ids=bytes(ids)))
        self.assertTrue(any("do not fit" in x for x in p["problems"]))
        self.assertEqual(len(p["id_list"]["items"]), 1)


class LinkInfoAndStrings(unittest.TestCase):
    def test_local_volume(self):
        p = shelllink.parse_lnk(ls.sample_lnk())
        li = p["link_info"]
        self.assertEqual(li["volume"]["drive_type_name"], "DRIVE_FIXED")
        self.assertEqual(li["volume"]["serial_short"], "1234-ABCD")
        self.assertEqual(li["volume"]["label"], "SYSTEM")
        self.assertEqual(li["local_base_path_unicode"], "C:\\Users\\report final.docx")
        self.assertEqual(p["target_path_source"], "link_info.local_base_path")
        self.assertEqual(p["strings"], {"relative_path": "..\\report final.docx",
                                        "working_dir": "C:\\Users",
                                        "arguments": "/safe"})
        self.assertEqual(p["string_lengths"]["arguments"], {"declared": 5, "read": 5})

    def test_network_share(self):
        p = shelllink.parse_lnk(ls.build_lnk(
            link_info=ls.link_info_network("\\\\FILESRV\\CASES", "2024\\notes.txt")))
        self.assertEqual(p["link_info"]["network"]["net_name"], "\\\\FILESRV\\CASES")
        self.assertEqual(p["link_info"]["network"]["device_name"], "Z:")
        self.assertEqual(p["target_path"], "\\\\FILESRV\\CASES\\2024\\notes.txt")

    def test_ansi_strings_are_decoded_and_the_code_page_assumption_noted(self):
        p = shelllink.parse_lnk(ls.build_lnk(strings={"name": "Café notes"},
                                             unicode=False))
        self.assertEqual(p["strings"]["name"], "Café notes")
        self.assertTrue(any("cp1252" in n for n in p["notes"]))

    def test_unpaired_surrogates_are_escaped_not_replaced(self):
        raw = "a\ud800b".encode("utf-16-le", "surrogatepass")
        data = bytearray(ls.build_lnk(strings={"arguments": "aXb"}))
        at = data.find("aXb".encode("utf-16-le"))
        data[at:at + 6] = raw
        self.assertEqual(shelllink.parse_lnk(bytes(data))["strings"]["arguments"],
                         "a\\ud800b")

    def test_overlong_working_dir_is_reread_with_the_260_limit_and_noted(self):
        hidden = "C:\\Windows\\System32" + " " * 241
        data = ls.build_lnk(strings={"working_dir": (900, hidden),
                                     "arguments": "/c calc.exe",
                                     "icon_location": "shell32.dll"})
        p = shelllink.parse_lnk(data)
        self.assertEqual(p["strings"]["arguments"], "/c calc.exe")
        self.assertEqual(p["strings"]["icon_location"], "shell32.dll")
        self.assertEqual(p["string_lengths"]["working_dir"],
                         {"declared": 900, "read": 260})
        self.assertTrue(any("260-character limit" in n for n in p["notes"]))
        self.assertEqual(p["problems"], [])

    def test_a_long_description_that_fits_is_read_as_declared(self):
        text = "x" * 400
        p = shelllink.parse_lnk(ls.build_lnk(strings={"name": text}))
        self.assertEqual(p["strings"]["name"], text)
        self.assertFalse(any("260" in n for n in p["notes"]))


class ExtraData(unittest.TestCase):
    def setUp(self):
        self.p = shelllink.parse_lnk(ls.sample_lnk())
        self.by_kind = {b["kind"]: b for b in self.p["extra"]}

    def test_tracker_machine_and_droid_measurements(self):
        t = self.p["tracker"]
        self.assertEqual(t["machine_id"], "WORKSTATION7")
        d = t["droid_file"]
        self.assertEqual(d["uuid_version"], 1)
        self.assertEqual(d["mac"], "00:0c:29:aa:bb:cc")
        self.assertFalse(d["mac_is_random"])
        self.assertEqual(d["uuid_time_raw"], ls.UUID_TICKS)
        self.assertEqual(d["as_filetime"], ls.UUID_TICKS - shelllink.UUID_TO_FILETIME)
        self.assertEqual(d["utc"], "2021-05-31T04:00:00.000000Z")
        self.assertNotEqual(t["droid_volume"]["uuid_version"], 1)

    def test_a_random_node_is_flagged_and_a_non_v1_droid_has_no_mac(self):
        rnd = ls.droid_v1(node=0x030000000001)
        data = ls.build_lnk(extra=[ls.tracker(droid_file=rnd)])
        self.assertTrue(shelllink.parse_lnk(data)["tracker"]["droid_file"]["mac_is_random"])
        self.assertNotIn("mac", self.p["tracker"]["droid_volume"])

    def test_folder_blocks_environment_and_property_store(self):
        self.assertEqual(self.by_kind["special_folder"]["folder"], "System")
        self.assertEqual(self.by_kind["known_folder"]["folder"], "Documents")
        self.assertEqual(self.by_kind["environment"]["unicode"],
                         "%USERPROFILE%\\report final.docx")
        props = self.by_kind["property_store"]["stores"][0]["properties"]
        self.assertEqual(props[0]["value"], "report final.docx")
        self.assertEqual(props[1]["value"]["raw"], ls.T_WRITE)
        self.assertEqual(props[1]["value"]["epoch"], "filetime")
        self.assertEqual(props[2]["value"], 4096)

    def test_vista_id_list_block(self):
        data = ls.build_lnk(extra=[ls.vista_id_list(
            ls.item_root(), ls.item_volume("D:\\"),
            ls.item_file("EVID", "Evidence", directory=True))])
        blk = shelllink.parse_lnk(data)["extra"][0]
        self.assertEqual(blk["path"], "My Computer\\D:\\Evidence")

    def test_unknown_block_is_listed_and_trailing_bytes_reported(self):
        odd = struct.pack("<II", 12, 0xA00000FF) + b"zzzz"
        data = ls.build_lnk(extra=[odd]) + b"APPENDED"
        p = shelllink.parse_lnk(data)
        self.assertEqual(p["extra"][0]["kind"], "unknown")
        self.assertEqual(p["trailing_bytes"], 8)
        self.assertTrue(any("follow the terminal block" in n for n in p["notes"]))
        self.assertEqual(p["consumed"], len(data) - 8)


class Truncation(unittest.TestCase):
    def test_every_cut_parses_and_reports(self):
        full = ls.sample_lnk()
        for cut in range(76, len(full)):
            p = shelllink.parse_lnk(full[:cut])
            self.assertTrue(p["problems"], f"cut at {cut} reported nothing")
            json.dumps(p)

    def test_missing_terminal_block_is_reported(self):
        p = shelllink.parse_lnk(ls.build_lnk(extra=[ls.tracker()], terminal=False))
        self.assertTrue(any("no terminal block" in x for x in p["problems"]))
        self.assertEqual(p["tracker"]["machine_id"], "WORKSTATION7")

    def test_overlong_extra_block_is_reported(self):
        blk = bytearray(ls.tracker())
        struct.pack_into("<I", blk, 0, 4000)
        p = shelllink.parse_lnk(ls.build_lnk(extra=[bytes(blk)]))
        self.assertTrue(any("do not fit" in x for x in p["problems"]))


class Rows(unittest.TestCase):
    def test_one_row_per_target_time(self):
        p = shelllink.parse_lnk(ls.sample_lnk())
        rows = shelllink.to_rows(p, source_path="Users/a/Recent/report final.docx.lnk")
        self.assertEqual([r["artefact"] for r in rows], ["lnk"] * 3)
        self.assertEqual([r["at_raw"] for r in rows],
                         [ls.T_CREATE, ls.T_ACCESS, ls.T_WRITE])
        self.assertEqual({r["at_epoch"] for r in rows}, {"filetime"})
        self.assertIn("records its target's write time", rows[2]["value"])
        self.assertEqual(rows[0]["detail"]["target_mft"]["entry"], 91234)
        self.assertEqual(len({r["row_ref_suffix"] for r in rows}), 3)
        keys = {"artefact", "at_utc", "at_raw", "at_epoch", "title", "value",
                "detail", "row_ref_suffix"}
        for r in rows:
            self.assertEqual(set(r), keys)
            json.dumps(r)

    def test_no_times_gives_one_untimed_row(self):
        p = shelllink.parse_lnk(ls.build_lnk(times=(0, 0, 0),
                                             strings={"relative_path": "a.txt"}))
        rows = shelllink.to_rows(p, source_path="x.lnk")
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["at_utc"])
        self.assertIsNone(rows[0]["at_raw"])


class RealSamples(unittest.TestCase):
    """Real shortcuts (not shipped) from the container's sample folder;
    expected values were produced by liblnk (pylnk) for the same files."""

    def setUp(self):
        self.files = [f for f in sorted(
            glob.glob(SAMPLES + "/repos/ez_Lnk/Lnk.Test/TestFiles/**/*", recursive=True)
            + glob.glob(SAMPLES + "/shelllink/**/*.lnk", recursive=True)
            + glob.glob(SAMPLES + "/repos/plaso/test_data/*.lnk"))
            if os.path.isfile(f)]
        if not self.files:
            self.skipTest(f"no real shortcut samples under {SAMPLES} (downloaded "
                          "for validation only and never shipped)")

    def test_every_sample_parses_or_is_refused_cleanly(self):
        ok = 0
        for path in self.files:
            with open(path, "rb") as fh:
                data = fh.read()
            try:
                p = shelllink.parse_lnk(data)
            except FileSystemError:
                continue
            ok += 1
            json.dumps(shelllink.to_rows(p, source_path=path))
        self.assertGreater(ok, 0)

    def test_known_values(self):
        hits = [f for f in self.files if f.endswith("plaso/test_data/example.lnk")]
        if not hits:
            self.skipTest("plaso's example.lnk is not in the sample folder")
        with open(hits[0], "rb") as fh:
            p = shelllink.parse_lnk(fh.read())
        self.assertEqual(p["tracker"]["machine_id"], "win-tj9qcsjkags")
        self.assertEqual(p["tracker"]["droid_file"]["guid"],
                         "846ee3bb-7039-11de-9d20-001d09fa5a1c")
        self.assertEqual(p["header"]["times"]["target_modified"]["raw"],
                         128920091582200000)


if __name__ == "__main__":
    unittest.main()
