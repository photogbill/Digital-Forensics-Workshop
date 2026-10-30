"""Registry hives: the regf structures, damage read around, deleted records,
and the artefact extractors — on hives built from the format documentation
(`regsynth.py`), plus an optional pass over real public sample hives."""

from __future__ import annotations

import json
import struct
import os
import unittest
from pathlib import Path

import _support  # noqa: F401
import regsynth as rs
from forensics_workshop import registry, timeutil
from forensics_workshop.errors import FileSystemError

ROW_KEYS = {"artefact", "at_utc", "at_raw", "at_epoch", "title", "value",
            "detail", "row_ref_suffix"}
#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = Path(os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples") / "registry" / "hives"


class Reader:
    """The `image.Region` interface: `.size` and `.read_at`."""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.reads = 0

    def read_at(self, offset, length):
        self.reads += 1
        return self.data[offset:offset + length]


def hive_of(builder: rs.HiveBuilder, name="", **kw) -> registry.Hive:
    return registry.open_hive(builder.build(**kw), name)


def rows_of(hive, path="C:/Windows/System32/config/TEST", **kw):
    rows = registry.to_rows(hive, source_path=path, **kw)
    for r in rows:
        assert set(r) == ROW_KEYS, set(r) ^ ROW_KEYS
    return rows


def by_kind(rows, kind):
    return [r for r in rows if r["artefact"] == kind]


# ---------------------------------------------------------------------------
# base block
# ---------------------------------------------------------------------------

class BaseBlock(unittest.TestCase):
    def test_a_file_that_is_not_a_hive_is_refused_with_a_sentence(self):
        with self.assertRaises(FileSystemError) as cm:
            registry.open_hive(b"MZ" + bytes(5000), "notepad.exe")
        self.assertIn("not a Windows registry hive", str(cm.exception))
        with self.assertRaises(FileSystemError) as cm:
            registry.open_hive(rs.HiveBuilder().build()[:1000], "cut")
        self.assertIn("truncated", str(cm.exception))

    def test_header_fields_and_checksum(self):
        b = rs.HiveBuilder(minor=6)
        b.root.key("A")
        h = hive_of(b, written=rs.T0 + 5)
        self.assertEqual((h.header.major, h.header.minor), (1, 6))
        self.assertTrue(h.header.checksum_ok)
        self.assertFalse(h.header.dirty)
        self.assertEqual(h.header.last_written, timeutil.decode(rs.T0 + 5, "filetime"))
        self.assertIn("config\\TEST", h.header.file_name)
        self.assertEqual(h.problems, [])

    def test_a_dirty_hive_says_so_first_and_is_still_read(self):
        b = rs.HiveBuilder()
        b.root.key("Software").sz("x", "y")
        h = hive_of(b, primary=10, secondary=9)
        self.assertTrue(h.header.dirty)
        self.assertIn("DIRTY HIVE", h.problems[0])
        self.assertIn(".LOG1", h.problems[0])
        self.assertIn("NOT applied", h.problems[0])
        self.assertEqual(h.find("Software").value("x").data, "y")
        row = rows_of(h)[0]
        self.assertEqual(row["artefact"], "registry-hive")
        self.assertIn("DIRTY", row["value"])

    def test_a_bad_checksum_is_reported_not_fatal(self):
        data = bytearray(rs.HiveBuilder().build())
        data[0x1FC] ^= 0xFF
        h = registry.open_hive(bytes(data))
        self.assertFalse(h.header.checksum_ok)
        self.assertTrue(any("checksum" in p for p in h.problems))

    def test_a_transaction_log_is_refused_with_the_remedy(self):
        log = bytearray(rs.HiveBuilder().build(file_type=6)[:4096])
        log += b"HvLE" + bytes(508)
        with self.assertRaises(FileSystemError) as cm:
            registry.open_hive(rs.resign(bytes(log)), "SYSTEM.LOG1")
        self.assertIn("transaction log", str(cm.exception))
        self.assertIn("primary hive", str(cm.exception))

    def test_reads_through_a_reader_object(self):
        b = rs.HiveBuilder()
        b.root.key("A").sz("v", "through a reader")
        reader = Reader(b.build())
        h = registry.open_hive(reader, "region")
        self.assertEqual(h.find("A").value("v").data, "through a reader")
        self.assertGreaterEqual(reader.reads, 1)


# ---------------------------------------------------------------------------
# keys, lists, values
# ---------------------------------------------------------------------------

class Structures(unittest.TestCase):
    def test_every_subkey_list_form_gives_the_same_tree(self):
        trees = []
        for kind in ("lf", "lh", "li", "ri"):
            b = rs.HiveBuilder(list_kind=kind, ri_chunk=2)
            for i in range(9):
                b.root.key(f"K{i}", written=rs.T0 + i).key("Child").dword("n", i)
            h = hive_of(b)
            self.assertEqual(h.problems, [], kind)
            trees.append([(k.path, k.last_written_raw) for k in h.walk()])
        self.assertTrue(all(t == trees[0] for t in trees))
        self.assertEqual(len(trees[0]), 1 + 9 * 2)

    def test_names_ascii_and_utf16_class_name_and_lookup_is_case_insensitive(self):
        b = rs.HiveBuilder()
        k = b.root.key("ControlSet001", class_name="SomeClass")
        k.key("Ключ").sz("Значение", "текст", utf16_name=True)
        k.key("Latin\xe9")
        h = hive_of(b)
        cs = h.find("controlset001")
        self.assertEqual(cs.name, "ControlSet001")
        self.assertEqual(cs.class_name, "SomeClass")
        self.assertIsNotNone(cs.subkey("ключ"))
        self.assertEqual(h.find("ControlSet001\\Ключ").value("значение").data, "текст")
        self.assertEqual(cs.subkey("LATINÉ").name, "Latin\xe9")
        self.assertIn("COMP_NAME", cs.flag_names)
        self.assertNotIn("COMP_NAME", cs.subkey("Ключ").flag_names)

    def test_paths_find_and_the_root_name(self):
        b = rs.HiveBuilder("CMI-CreateHive{X}")
        b.root.path("A\\B\\C").sz("v", "deep")
        h = hive_of(b)
        c = h.find("A\\B\\C")
        self.assertEqual(c.path, "A\\B\\C")
        self.assertIs(h.find("CMI-CreateHive{X}\\A\\B\\C").offset, c.offset)
        self.assertIsNone(h.find("A\\Nope"))
        self.assertEqual(h.root.path, "")
        self.assertEqual(h.key_count(), 4)

    def test_value_types(self):
        b = rs.HiveBuilder()
        k = b.root.key("V")
        k.value("sz", rs.REG_SZ, rs.sz("hello") + b"GARBAGE\x00")
        k.value("expand", rs.REG_EXPAND_SZ, rs.sz("%SystemRoot%\\x"))
        k.value("multi", rs.REG_MULTI_SZ, rs.multi_sz(["one", "two", "three"]))
        k.value("le", rs.REG_DWORD, rs.dword(0x12345678))
        k.value("be", rs.REG_DWORD_BIG_ENDIAN, rs.dword_be(0x12345678))
        k.value("q", rs.REG_QWORD, rs.qword(1 << 40))
        k.value("bin", rs.REG_BINARY, bytes(range(20)))
        k.value("none", rs.REG_NONE, b"\x01\x02\x03\x04\x05\x06")
        k.value("link", rs.REG_LINK, "\\Registry\\Machine\\X".encode("utf-16-le"))
        k.value("devprop", 0xFFFF0010, rs.qword(rs.T0))
        k.value("", rs.REG_SZ, rs.sz("default"))
        v = hive_of(b).find("V")
        self.assertEqual(v.value("sz").data, "hello")
        self.assertEqual(v.value("expand").data, "%SystemRoot%\\x")
        self.assertEqual(v.value("multi").data, ["one", "two", "three"])
        self.assertEqual(v.value("le").data, 0x12345678)
        self.assertEqual(v.value("be").data, 0x12345678)
        self.assertEqual(v.value("q").data, 1 << 40)
        self.assertEqual(v.value("bin").data, bytes(range(20)))
        self.assertEqual(v.value("none").data, b"\x01\x02\x03\x04\x05\x06")
        self.assertEqual(v.value("link").data, "\\Registry\\Machine\\X")
        dev = v.value("devprop")
        self.assertEqual(dev.raw, rs.qword(rs.T0))
        self.assertEqual(dev.type_name, "DEVPROP_TYPE 0x0010")
        self.assertEqual(v.value("(default)").data, "default")
        self.assertEqual(v.value("").name, "")

    def test_inline_data_of_four_bytes_or_fewer(self):
        b = rs.HiveBuilder()
        k = b.root.key("I")
        k.dword("d", 7).binary("two", b"\xAB\xCD").binary("empty", b"")
        v = hive_of(b).find("I")
        self.assertTrue(v.value("d").inline)
        self.assertEqual(v.value("d").data, 7)
        self.assertEqual(v.value("two").raw, b"\xAB\xCD")
        self.assertEqual(v.value("empty").raw, b"")

    def test_big_data_over_16344_bytes_is_reassembled_from_db_segments(self):
        blob = bytes((i * 7) % 251 for i in range(50_000))
        b = rs.HiveBuilder(minor=5)
        b.root.key("Big").binary("blob", blob)
        h = hive_of(b)
        self.assertEqual(h.find("Big").value("blob").raw, blob)
        self.assertEqual(h.problems, [])

    def test_security_record_owner(self):
        b = rs.HiveBuilder()
        b.root.key("S")
        sec = hive_of(b).find("S").security()
        self.assertEqual(sec["owner_sid"], "S-1-5-32-544")


# ---------------------------------------------------------------------------
# damage
# ---------------------------------------------------------------------------

def _poke(data: bytes, off: int, fmt: str, *vals) -> bytes:
    out = bytearray(data)
    struct.pack_into(fmt, out, off, *vals)
    return bytes(out)


class Damage(unittest.TestCase):
    def setUp(self):
        self.b = rs.HiveBuilder()
        r = self.b.root
        for name in ("Alpha", "Bravo", "Charlie"):
            r.key(name).sz("v", name.lower()).binary("blob", bytes(64))
        self.data = self.b.build()

    def test_a_value_whose_data_points_outside_the_file_is_kept_and_reported(self):
        vk = self.b.value_offsets[("Bravo", "blob")]
        data = _poke(self.data, 4096 + vk + 4 + 8, "<I", 0x7FFFFFF0)
        h = registry.open_hive(data)
        v = h.find("Bravo").value("blob")
        self.assertEqual(v.raw, b"")
        self.assertTrue(v.problems)
        self.assertTrue(any("Bravo" in p and "blob" in p for p in h.problems))
        self.assertEqual(h.find("Bravo").value("v").data, "bravo")

    def test_a_broken_key_cell_costs_that_key_only(self):
        nk = self.b.offsets["Bravo"]
        data = bytearray(self.data)
        data[4096 + nk + 4:4096 + nk + 6] = b"XX"
        h = registry.open_hive(bytes(data))
        self.assertEqual([k.name for k in h.root.subkeys()], ["Alpha", "Charlie"])
        self.assertTrue(any("not a key node" in p for p in h.problems))
        self.assertTrue(any("records 3 subkeys; 2 could be read" in p
                            for p in h.problems))

    def test_an_impossible_cell_size_is_reported(self):
        nk = self.b.offsets["Charlie"]
        data = _poke(self.data, 4096 + nk, "<i", -3)
        h = registry.open_hive(data)
        self.assertIsNone(h.find("Charlie"))
        self.assertTrue(any("impossible size" in p for p in h.problems))

    def test_a_loop_in_the_tree_is_reported_and_not_followed(self):
        b = rs.HiveBuilder(list_kind="li")
        b.root.key("A").key("B")
        data = b.build()
        h0 = registry.open_hive(data)
        b_key = h0.find("A\\B")
        # B's subkey list becomes A's list, which names B: B is its own child
        li_off = h0.find("A").subkey_list_offset
        data = _poke(data, 4096 + li_off + 4, "<2sHI", b"li", 1, b_key.offset)
        data = _poke(data, 4096 + b_key.offset + 4 + 0x14, "<I", 1)
        data = _poke(data, 4096 + b_key.offset + 4 + 0x1C, "<I", li_off)
        h = registry.open_hive(data)
        paths = [k.path for k in h.walk()]
        self.assertLess(len(paths), 10)
        self.assertTrue(any("reached twice" in p for p in h.problems), h.problems)

    def test_a_zeroed_hive_bin_is_skipped_and_later_bins_are_still_read(self):
        b = rs.HiveBuilder()
        for i in range(60):
            b.root.key(f"Key{i:02d}").binary("pad", bytes(300))
        data = bytearray(b.build())
        # zero the second hive bin entirely
        second = 4096 + 4096
        size = struct.unpack_from("<I", data, second + 8)[0]
        data[second:second + size] = bytes(size)
        h = registry.open_hive(bytes(data))
        self.assertTrue(any("hold no valid hive bin" in p for p in h.problems))
        found = [k.name for k in h.root.subkeys()]
        self.assertGreater(len(found), 10)
        self.assertLess(len(found), 60)

    def test_a_truncated_file_is_reported(self):
        b = rs.HiveBuilder()
        for i in range(40):
            b.root.key(f"K{i}").binary("pad", bytes(400))
        data = b.build()
        h = registry.open_hive(data[:len(data) - 4096])
        self.assertTrue(any("truncated" in p for p in h.problems))

    def test_a_referenced_cell_marked_free_is_read_and_flagged(self):
        vk = self.b.value_offsets[("Alpha", "v")]
        size = struct.unpack_from("<i", self.data, 4096 + vk)[0]
        data = _poke(self.data, 4096 + vk, "<i", -size)
        h = registry.open_hive(data)
        self.assertEqual(h.find("Alpha").value("v").data, "alpha")
        self.assertTrue(any("marked FREE" in p for p in h.problems))


# ---------------------------------------------------------------------------
# deleted records
# ---------------------------------------------------------------------------

class Deleted(unittest.TestCase):
    def test_deleted_key_and_value_are_recovered_from_free_cells(self):
        b = rs.HiveBuilder()
        run = b.root.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        run.sz("Keep", "C:\\ok.exe")
        run.sz("Evil", "C:\\Users\\x\\evil.exe", deleted=True)
        gone = b.root.path("Software").key("Tool", deleted=True,
                                           written=rs.T0 + rs.HOUR)
        gone.sz("InstallPath", "C:\\Tool")
        h = hive_of(b)
        self.assertEqual([v.name for v in h.find(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run").values()], ["Keep"])
        found = h.recover_deleted()
        keys = {k.path: k for k in found["keys"]}
        self.assertIn("Software\\Tool", keys)
        k = keys["Software\\Tool"]
        self.assertTrue(k.deleted)
        self.assertEqual(k.recovered_from, "free cell")
        self.assertFalse(k.live_twin)
        self.assertEqual(k.last_written_raw, rs.T0 + rs.HOUR)
        self.assertEqual(k.value("InstallPath").data, "C:\\Tool")
        vals = {v.name: (v, parent) for v, parent in found["values"]}
        self.assertEqual(vals["Evil"][0].data, "C:\\Users\\x\\evil.exe")
        self.assertTrue(vals["Evil"][0].deleted)
        self.assertEqual(vals["Evil"][0].recovered_from, "free cell")
        self.assertEqual(vals["InstallPath"][1], "Software\\Tool")
        self.assertEqual(h.problems, [])
        rows = rows_of(h)
        dk = by_kind(rows, "registry-deleted-key")
        self.assertEqual([r["value"] for r in dk], ["Software\\Tool"])
        self.assertTrue(dk[0]["detail"]["deleted"])
        self.assertEqual(dk[0]["at_raw"], rs.T0 + rs.HOUR)
        dv = {r["detail"]["name"]: r for r in by_kind(rows, "registry-deleted-value")}
        self.assertIn("evil.exe", dv["Evil"]["value"])

    def test_a_clean_hive_recovers_nothing(self):
        b = rs.HiveBuilder()
        for i in range(30):
            b.root.key(f"K{i}").sz("v", "x" * i)
        found = hive_of(b).recover_deleted()
        self.assertEqual((found["keys"], found["values"]), ([], []))


# ---------------------------------------------------------------------------
# transaction logs
# ---------------------------------------------------------------------------

def _two_versions():
    """The same hive before and after a write: v2 adds a key and grows."""
    def build(extra):
        b = rs.HiveBuilder()
        run = b.root.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        run.sz("Keep", "C:\\ok.exe")
        if extra:
            run.sz("Late", "C:\\late.exe")
            for i in range(30):
                b.root.key(f"New{i:02d}").binary("pad", bytes(500))
        return b.build(primary=11, secondary=10) if not extra else b.build(primary=11, secondary=11)
    return build(False), build(True)


class TransactionLogs(unittest.TestCase):
    def test_marvin32_two_separately_written_forms_agree(self):
        """The real proof is RealSamples: every hash in Windows-written logs
        validates. Here the engine's form is checked against regsynth's,
        which handles the tail bytes differently, across every tail length."""
        for n in range(0, 13):
            data = bytes(range(7, 7 + n))
            self.assertEqual(registry.marvin32(data), rs.marvin32(data), n)

    def test_a_dirty_hive_is_reconstructed_in_memory_from_its_log(self):
        old, new = _two_versions()
        log = rs.new_format_log(old, new, base_seq=10, first_seq=10, entries=3)
        plain = registry.open_hive(old, "NTUSER.DAT")
        self.assertIsNone(plain.find("New05"))
        h = registry.open_hive(old, "NTUSER.DAT", logs={"NTUSER.DAT.LOG1": log})
        self.assertTrue(h.recovery["applied"])
        self.assertEqual((h.recovery["entries"], h.recovery["first_sequence"],
                          h.recovery["last_sequence"]), (3, 10, 12))
        self.assertEqual(h.recovery["logs_used"], ["NTUSER.DAT.LOG1"])
        self.assertIn("TRANSACTION LOGS APPLIED", h.problems[0])
        self.assertEqual(len(h.problems), 1, h.problems)
        self.assertEqual(h.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                         .value("Late").data, "C:\\late.exe")
        self.assertIsNotNone(h.find("New29"))
        self.assertEqual(h.recovery["original_base_block"]["secondary_sequence"], 10)
        row = rows_of(h, "NTUSER.DAT")[0]
        self.assertIn("transaction logs applied", row["value"])
        self.assertEqual(old, plain._data)          # the input is never altered

    def test_entries_after_a_failed_hash_are_not_used(self):
        old, new = _two_versions()
        log = bytearray(rs.new_format_log(old, new, base_seq=10, first_seq=10, entries=3))
        second = 512 + struct.unpack_from("<I", log, 512 + 4)[0]
        log[second + 100] ^= 0xFF                          # damage entry 11's pages
        h = registry.open_hive(old, "x", logs=[bytes(log)])
        self.assertEqual((h.recovery["entries"], h.recovery["last_sequence"]), (1, 10))
        self.assertTrue(any("hash check" in p for p in h.recovery["log_problems"]["log 1"]))

    def test_stale_logs_and_clean_hives_are_left_alone_with_the_reason(self):
        old, new = _two_versions()
        stale = rs.new_format_log(old, new, base_seq=4, first_seq=4)
        h = registry.open_hive(old, "x", logs={"old.LOG2": stale})
        self.assertFalse(h.recovery["applied"])
        self.assertIn("DIRTY HIVE", h.problems[0])
        self.assertIn("not used", h.problems[0])
        self.assertIn("older than the hive", h.recovery["log_problems"]["old.LOG2"][0])
        clean = registry.open_hive(new, "x", logs={"a.LOG1": stale})
        self.assertFalse(clean.recovery["applied"])
        self.assertIn("not dirty", clean.recovery["reason"])
        self.assertFalse(clean.header.dirty)


# ---------------------------------------------------------------------------
# hive kind
# ---------------------------------------------------------------------------

class Kind(unittest.TestCase):
    def kind(self, build, file_name=""):
        b = rs.HiveBuilder()
        build(b.root)
        return registry.hive_kind(hive_of(b), file_name)

    def test_by_content(self):
        self.assertEqual(self.kind(lambda r: (r.key("Select"), r.key("ControlSet001"))), "SYSTEM")
        self.assertEqual(self.kind(lambda r: (r.key("Microsoft"), r.key("Classes"), r.key("Policies"))), "SOFTWARE")
        self.assertEqual(self.kind(lambda r: r.path("SAM\\Domains\\Account")), "SAM")
        self.assertEqual(self.kind(lambda r: (r.key("Policy"), r.key("RXACT"), r.key("SAM"))), "SECURITY")
        self.assertEqual(self.kind(lambda r: (r.key("Software"), r.key("Control Panel"), r.key("Environment"))), "NTUSER")
        self.assertEqual(self.kind(lambda r: (r.key("Local Settings"), r.key("CLSID"), r.key(".txt"))), "USRCLASS")
        self.assertEqual(self.kind(lambda r: r.path("Root\\InventoryApplicationFile")), "AMCACHE")

    def test_by_file_name_when_content_says_nothing(self):
        self.assertEqual(self.kind(lambda r: r.key("X"), "NTUSER.DAT"), "NTUSER")
        self.assertEqual(self.kind(lambda r: r.key("X"), "Amcache.hve"), "AMCACHE")
        self.assertEqual(self.kind(lambda r: r.key("X"), "UsrClass.dat"), "USRCLASS")
        self.assertEqual(self.kind(lambda r: r.key("X"), "BCD"), "unknown")


# ---------------------------------------------------------------------------
# extractors
# ---------------------------------------------------------------------------

USB_DEV = "Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26"
PROPS = "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}"


def system_hive(shim: bytes, *, current=2):
    b = rs.HiveBuilder()
    r = b.root
    r.key("Select").dword("Current", current).dword("Default", current) \
        .dword("LastKnownGood", 1).dword("Failed", 0)
    r.path("ControlSet001\\Control\\ComputerName\\ComputerName").sz("ComputerName", "OLD-NAME")
    cs = r.key("ControlSet002")
    cs.path("Control\\ComputerName\\ComputerName").sz("ComputerName", "WKS-01")
    cs.path("Control\\TimeZoneInformation").sz("TimeZoneKeyName", "Eastern Standard Time") \
        .dword("Bias", 300).dword("ActiveTimeBias", 240).dword("DaylightBias", -60)
    inst = cs.path(f"Enum\\USBSTOR\\{USB_DEV}\\4C530001230101115&0", written=rs.T0 + 50)
    inst.sz("FriendlyName", "SanDisk Cruzer USB Device")
    for pid, t in (("0064", rs.T0), ("0066", rs.T0 + rs.HOUR), ("0067", rs.T0 + 2 * rs.HOUR)):
        inst.path(f"{PROPS}\\{pid}").value("", 0xFFFF0010, rs.qword(t))
    cs.path(f"Enum\\USBSTOR\\{USB_DEV}\\7&2a2f6b3&0&_&0").sz("FriendlyName", "No serial")
    cs.path("Enum\\USB\\VID_0781&PID_5530\\4C530001230101115").sz("Service", "USBSTOR")
    md = r.key("MountedDevices")
    md.binary("\\DosDevices\\E:", struct.pack("<IQ", 0xA1B2C3D4, 1048576))
    md.binary("\\DosDevices\\C:", b"DMIO:ID:" + rs.guid_le("{11111111-2222-3333-4444-555555555555}"))
    md.binary("\\??\\Volume{aaaa}", "_??_USBSTOR#Disk&Ven_SanDisk#4C530001230101115&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}".encode("utf-16-le"))
    cs.path("Control\\Session Manager\\AppCompatCache").binary("AppCompatCache", shim)
    svc = cs.path("Services\\EvilSvc", written=rs.T0 + 99)
    svc.value("ImagePath", rs.REG_EXPAND_SZ, rs.sz("%SystemRoot%\\evil.exe")).dword("Start", 2).dword("Type", 0x10)
    svc.key("Parameters").value("ServiceDll", rs.REG_EXPAND_SZ, rs.sz("C:\\evil.dll"))
    cs.path("Services\\NoImage")                           # no service values: no row
    itf = cs.path("Services\\Tcpip\\Parameters\\Interfaces\\{AAAA}")
    itf.dword("EnableDHCP", 1).sz("DhcpIPAddress", "192.168.1.50").dword("LeaseObtainedTime", 1_600_000_000)
    return hive_of(b, "SYSTEM")


class SystemExtractors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        shim = rs.shim_win10([("C:\\Windows\\notepad.exe", rs.T0 - 10, b"\x01\x02"),
                              ("C:\\Tools\\x.exe", rs.T0 - 20, b"")])
        cls.hive = system_hive(shim)
        cls.rows = rows_of(cls.hive, "Windows/System32/config/SYSTEM", deleted=False)

    def test_current_control_set_comes_from_select(self):
        self.assertEqual(self.hive.control_set()[0], "ControlSet002")
        self.assertEqual(self.hive.find("CurrentControlSet\\Control\\ComputerName\\ComputerName")
                         .value("ComputerName").data, "WKS-01")
        self.assertEqual([r["value"] for r in by_kind(self.rows, "computer-name")], ["WKS-01"])

    def test_time_zone_biases_are_signed(self):
        tz = by_kind(self.rows, "timezone")[0]["detail"]
        self.assertEqual((tz["bias_minutes"], tz["active_time_bias_minutes"],
                          tz["daylight_bias_minutes"]), (300, 240, -60))
        self.assertIsNone(by_kind(self.rows, "timezone")[0]["at_utc"])

    def test_usbstor_devices_their_property_times_and_generated_serials(self):
        devs = {r["detail"]["serial"]: r for r in by_kind(self.rows, "usbstor-device")}
        real = devs["4C530001230101115&0"]
        self.assertEqual(real["detail"]["vendor"], "SanDisk")
        self.assertEqual(real["detail"]["product"], "Cruzer")
        self.assertFalse(real["detail"]["serial_is_windows_generated"])
        self.assertEqual(real["at_raw"], rs.T0 + 50)
        self.assertEqual(real["detail"]["time_basis"], "key")
        self.assertEqual(set(real["detail"]["times"]), {"first install", "last arrival", "last removal"})
        self.assertTrue(devs["7&2a2f6b3&0&_&0"]["detail"]["serial_is_windows_generated"])
        times = {r["detail"]["event"]: r for r in by_kind(self.rows, "usbstor-time")}
        self.assertEqual(times["last removal"]["at_raw"], rs.T0 + 2 * rs.HOUR)
        self.assertEqual(times["last removal"]["detail"]["time_basis"], "entry")
        usb = by_kind(self.rows, "usb-device")[0]["detail"]
        self.assertEqual((usb["vid"], usb["pid"]), ("0781", "5530"))

    def test_mounted_devices_three_forms(self):
        md = {r["detail"]["name"]: r["detail"] for r in by_kind(self.rows, "mounted-device")}
        self.assertEqual(md["\\DosDevices\\E:"]["disk_signature"], "A1B2C3D4")
        self.assertEqual(md["\\DosDevices\\E:"]["partition_offset"], 1048576)
        self.assertEqual(md["\\DosDevices\\C:"]["partition_guid"], "{11111111-2222-3333-4444-555555555555}")
        self.assertEqual(md["\\??\\Volume{aaaa}"]["instance"], "4C530001230101115&0")

    def test_shimcache_win10_entries_in_order_with_the_execution_caveat(self):
        shim = by_kind(self.rows, "shimcache")
        self.assertEqual([r["value"] for r in shim], ["C:\\Windows\\notepad.exe", "C:\\Tools\\x.exe"])
        self.assertEqual(shim[0]["at_raw"], rs.T0 - 10)
        self.assertEqual(shim[0]["detail"]["format"], "Windows 10/11")
        self.assertEqual(shim[0]["detail"]["position"], 0)
        self.assertIn("NOT proof of execution", shim[0]["detail"]["note"])
        self.assertEqual(shim[0]["detail"]["data_head_hex"], "0102")

    def test_services_and_interfaces(self):
        svc = {r["detail"]["name"]: r for r in by_kind(self.rows, "service")}
        self.assertNotIn("NoImage", svc)
        e = svc["EvilSvc"]["detail"]
        self.assertEqual((e["image_path"], e["start_name"], e["type_name"], e["service_dll"]),
                         ("%SystemRoot%\\evil.exe", "Automatic", "own process", "C:\\evil.dll"))
        self.assertEqual(svc["EvilSvc"]["at_raw"], rs.T0 + 99)
        itf = by_kind(self.rows, "network-interface")[0]
        self.assertEqual(itf["detail"]["dhcp_ip_address"], "192.168.1.50")
        self.assertEqual((itf["at_raw"], itf["at_epoch"]), (1_600_000_000, "unix_s"))


class ShimCacheFormats(unittest.TestCase):
    def test_win7_64bit(self):
        blob = rs.shim_win7_64([("\\??\\C:\\a.exe", rs.T0, 2), ("\\??\\C:\\b.exe", rs.T0 + 1, 0)])
        out = registry.parse_shimcache(blob)
        self.assertEqual(out["format"], "Windows 7 / Server 2008 R2 (64-bit)")
        self.assertEqual([(e["path"], e["last_modified_raw"], e["insert_flags"]) for e in out["entries"]],
                         [("\\??\\C:\\a.exe", rs.T0, 2), ("\\??\\C:\\b.exe", rs.T0 + 1, 0)])
        self.assertEqual(out["problems"], [])

    def test_win81(self):
        out = registry.parse_shimcache(rs.shim_win81([("SYSVOL\\Windows\\x.exe", 0xF3, rs.T0)]))
        self.assertEqual(out["format"], "Windows 8.1")
        e = out["entries"][0]
        self.assertEqual((e["path"], e["insert_flags"], e["last_modified_raw"]),
                         ("SYSVOL\\Windows\\x.exe", 0xF3, rs.T0))

    def test_win10_older_header_and_damage(self):
        out = registry.parse_shimcache(rs.shim_win10([("C:\\a", 5, b"")], header=0x30))
        self.assertEqual(out["entries"][0]["path"], "C:\\a")
        cut = rs.shim_win10([("C:\\a", 5, b""), ("C:\\b", 6, b"")])[:-6]
        out = registry.parse_shimcache(cut)
        self.assertEqual(len(out["entries"]), 1)
        self.assertTrue(out["problems"])
        self.assertIn("not decoded", registry.parse_shimcache(struct.pack("<II", 0xDEADBEEF, 0))["problems"][0])


def software_hive():
    b = rs.HiveBuilder()
    r = b.root
    r.key("Classes")
    cv = r.path("Microsoft\\Windows NT\\CurrentVersion")
    cv.sz("ProductName", "Windows 10 Pro").sz("CurrentBuild", "19045").sz("DisplayVersion", "22H2")
    cv.dword("InstallDate", 1_650_000_000).value("InstallTime", rs.REG_QWORD, rs.qword(rs.T0 + 7))
    app = r.path("Microsoft\\Windows\\CurrentVersion\\Uninstall\\{APP}", written=rs.T0 + 3)
    app.sz("DisplayName", "7-Zip").sz("InstallDate", "20240101").sz("Publisher", "Igor Pavlov")
    r.path("WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Old").sz("DisplayName", "Old 32-bit")
    r.path("Microsoft\\Windows\\CurrentVersion\\Run").sz("Updater", "C:\\u.exe /bg")
    nl = r.path("Microsoft\\Windows NT\\CurrentVersion\\NetworkList")
    prof = nl.path("Profiles\\{PROF-1}", written=rs.T0 + 11)
    prof.sz("ProfileName", "CoffeeShopWiFi").dword("Category", 0).dword("NameType", 0x47)
    prof.binary("DateCreated", rs.systemtime(2023, 5, 1, 9, 30, 0))
    prof.binary("DateLastConnected", rs.systemtime(2023, 6, 2, 18, 5, 9, 250))
    sig = nl.path("Signatures\\Unmanaged\\ABC123")
    sig.sz("ProfileGuid", "{PROF-1}").binary("DefaultGatewayMac", bytes.fromhex("001122aabbcc"))
    pl = r.path("Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21-1-2-3-1001")
    pl.value("ProfileImagePath", rs.REG_EXPAND_SZ, rs.sz("C:\\Users\\alice"))
    load = rs.T0 + 5 * rs.HOUR
    pl.dword("LocalProfileLoadTimeHigh", load >> 32).dword("LocalProfileLoadTimeLow", load & 0xFFFFFFFF)
    return hive_of(b, "SOFTWARE")


class SoftwareExtractors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = rows_of(software_hive(), "C:/Windows/System32/config/SOFTWARE", deleted=False)

    def test_os_version_prefers_the_filetime_install_time(self):
        os_ = by_kind(self.rows, "os-version")[0]
        self.assertEqual((os_["at_raw"], os_["at_epoch"]), (rs.T0 + 7, "filetime"))
        self.assertIn("Windows 10 Pro build 19045", os_["value"])
        self.assertEqual(os_["detail"]["install_date"]["epoch"], "unix_s")

    def test_uninstall_and_run(self):
        progs = {r["detail"]["display_name"]: r for r in by_kind(self.rows, "installed-program")}
        self.assertEqual(progs["7-Zip"]["at_raw"], rs.T0 + 3)
        self.assertEqual(progs["7-Zip"]["detail"]["install_date_text"], "20240101")
        self.assertTrue(progs["Old 32-bit"]["detail"]["wow6432"])
        run = by_kind(self.rows, "autorun")[0]
        self.assertEqual(run["detail"]["command"], "C:\\u.exe /bg")
        self.assertIsNone(run["at_utc"])
        self.assertEqual(run["detail"]["time_basis"], "none")

    def test_network_profile_local_times_are_labelled_and_never_utc(self):
        p = by_kind(self.rows, "network-profile")[0]
        d = p["detail"]
        self.assertEqual(d["date_last_connected_local"]["value"], "2023-06-02T18:05:09.250")
        self.assertIn("zone not recorded", d["date_last_connected_local"]["zone"])
        self.assertEqual(p["at_raw"], rs.T0 + 11)          # the key, not the SYSTEMTIME
        self.assertNotIn("2023", p["at_utc"])
        self.assertIn("LOCAL TIME", p["value"])
        self.assertEqual(d["signatures"][0]["default_gateway_mac"], "00-11-22-AA-BB-CC")
        self.assertEqual((d["category"], d["name_type_name"]), ("Public", "wireless"))

    def test_profile_list_with_its_split_load_time(self):
        prof = by_kind(self.rows, "user-profile")[0]
        self.assertEqual(prof["detail"]["profile_image_path"], "C:\\Users\\alice")
        t = by_kind(self.rows, "user-profile-time")[0]
        self.assertEqual((t["at_raw"], t["detail"]["event"]), (rs.T0 + 5 * rs.HOUR, "load"))


EXPL = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
EXE_GUID = "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}"


def ntuser_hive():
    b = rs.HiveBuilder()
    r = b.root
    r.key("Control Panel")
    r.key("Environment")
    ua = r.path(f"{EXPL}\\UserAssist\\{EXE_GUID}\\Count")
    ua.binary(rs.rot13("{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"),
              rs.userassist72(5, 3, 60000, rs.T0 + 1))
    ua.binary(rs.rot13("C:\\old\\xp.exe"), rs.userassist16(9, rs.T0 + 2))
    ua.binary(rs.rot13("UEME_CTLSESSION"), bytes(1612))
    rd = r.path(f"{EXPL}\\RecentDocs", written=rs.T0 + 30)
    rd.binary("0", rs.sz("older.docx") + rs.item_file("older.lnk", directory=False))
    rd.binary("1", rs.sz("newest.pdf") + rs.item_file("newest.lnk", directory=False))
    rd.binary("MRUListEx", rs.mru_list_ex([1, 0]))
    rd.key(".pdf").binary("0", rs.sz("newest.pdf")).binary("MRUListEx", rs.mru_list_ex([0]))
    r.path(f"{EXPL}\\TypedPaths").sz("url1", "C:\\Secret").sz("url2", "\\\\server\\share")
    r.path("Software\\Microsoft\\Internet Explorer\\TypedURLs").sz("url1", "http://example.test/")
    r.path("Software\\Microsoft\\Internet Explorer\\TypedURLsTime").binary("url1", rs.qword(rs.T0 + 40))
    run = r.path(f"{EXPL}\\RunMRU")
    run.sz("a", "cmd\\1").sz("b", "regedit\\1").sz("MRUList", "ba")
    ww = r.path(f"{EXPL}\\WordWheelQuery")
    ww.binary("0", rs.sz("password")).binary("MRUListEx", rs.mru_list_ex([0]))
    mycomp = rs.item_root("{20D04FE0-3AEA-1069-A2D8-08002B30309D}")
    path_pidl = rs.pidl(mycomp, rs.item_volume("C"), rs.item_file("Users"),
                        rs.item_file("report.xlsx", directory=False))
    osm = r.path(f"{EXPL}\\ComDlg32\\OpenSavePidlMRU\\xlsx")
    osm.binary("0", path_pidl).binary("MRUListEx", rs.mru_list_ex([0]))
    lv = r.path(f"{EXPL}\\ComDlg32\\LastVisitedPidlMRU")
    lv.binary("0", rs.sz("EXCEL.EXE") + rs.pidl(mycomp, rs.item_volume("C"), rs.item_file("Users")))
    lv.binary("MRUListEx", rs.mru_list_ex([0]))
    r.path("Software\\Microsoft\\Windows\\CurrentVersion\\Run").sz("Sync", "C:\\sync.exe")
    return hive_of(b, "NTUSER.DAT")


class NtuserExtractors(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = rows_of(ntuser_hive(), "C:/Users/alice/NTUSER.DAT", deleted=False)

    def test_userassist_rot13_and_both_record_formats(self):
        ua = {r["detail"]["name"]: r for r in by_kind(self.rows, "userassist")}
        cmd = ua["{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe"]
        self.assertEqual(cmd["detail"]["known_folder"], "System32")
        self.assertEqual(cmd["detail"]["guid_meaning"], "executables")
        rec = cmd["detail"]["record"]
        self.assertEqual((rec["run_count"], rec["focus_count"], rec["focus_time_ms"]), (5, 3, 60000))
        self.assertEqual((cmd["at_raw"], cmd["at_epoch"]), (rs.T0 + 1, "filetime"))
        self.assertIn("5 runs", cmd["value"])
        xp = ua["C:\\old\\xp.exe"]
        self.assertEqual(xp["detail"]["record"]["format"], "Windows XP (16 bytes)")
        self.assertEqual(xp["at_raw"], rs.T0 + 2)
        self.assertIsNone(ua["UEME_CTLSESSION"]["detail"]["record"])

    def test_recentdocs_order_and_time_only_on_the_most_recent(self):
        rd = [r for r in by_kind(self.rows, "recentdocs") if r["detail"]["list_key"] == "RecentDocs"]
        by_pos = {r["detail"]["mru_position"]: r for r in rd}
        self.assertEqual(by_pos[0]["value"], "newest.pdf")
        self.assertEqual(by_pos[0]["at_raw"], rs.T0 + 30)
        self.assertEqual(by_pos[0]["detail"]["time_basis"], "key-mru-0")
        self.assertEqual(by_pos[1]["value"], "older.docx")
        self.assertIsNone(by_pos[1]["at_utc"])
        self.assertEqual(by_pos[1]["detail"]["time_basis"], "none")
        self.assertEqual(len(by_kind(self.rows, "recentdocs")), 3)

    def test_typed_paths_urls_runmru_wordwheel(self):
        tp = {r["value"]: r for r in by_kind(self.rows, "typed-path")}
        self.assertEqual(tp["C:\\Secret"]["detail"]["time_basis"], "key-mru-0")
        self.assertIsNone(tp["\\\\server\\share"]["at_utc"])
        tu = by_kind(self.rows, "typed-url")[0]
        self.assertEqual((tu["at_raw"], tu["detail"]["time_basis"]), (rs.T0 + 40, "entry"))
        runs = {r["value"]: r["detail"]["mru_position"] for r in by_kind(self.rows, "runmru")}
        self.assertEqual(runs, {"regedit": 0, "cmd": 1})
        self.assertEqual([r["value"] for r in by_kind(self.rows, "wordwheelquery")], ["password"])

    def test_comdlg32_paths_from_shell_item_lists(self):
        os_ = by_kind(self.rows, "opensave-mru")[0]
        self.assertEqual(os_["value"], "My Computer\\C:\\Users\\report.xlsx")
        lv = by_kind(self.rows, "lastvisited-mru")[0]
        self.assertEqual((lv["detail"]["program"], lv["detail"]["folder"]),
                         ("EXCEL.EXE", "My Computer\\C:\\Users"))

    def test_run_key(self):
        self.assertEqual([r["detail"]["command"] for r in by_kind(self.rows, "autorun")], ["C:\\sync.exe"])


class ShellBags(unittest.TestCase):
    def setUp(self):
        b = rs.HiveBuilder()
        r = b.root
        r.key("CLSID")
        r.key(".txt")
        bag = r.path("Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU", written=rs.T0)
        bag.binary("0", rs.item_root("{20D04FE0-3AEA-1069-A2D8-08002B30309D}") + b"\0\0")
        bag.binary("MRUListEx", rs.mru_list_ex([0]))
        n0 = bag.key("0", written=rs.T0 + 1)
        n0.binary("0", rs.item_volume("E") + b"\0\0").binary("MRUListEx", rs.mru_list_ex([0]))
        n00 = n0.key("0", written=rs.T0 + 2)
        self.mod = rs.dos_datetime(2023, 7, 4, 13, 22, 10)
        n00.binary("0", rs.item_file("Exfil Staging", modified=self.mod, mft=(4242, 3)) + b"\0\0")
        n00.binary("1", rs.item_property_view("wsl$") + b"\0\0")
        n00.binary("MRUListEx", rs.mru_list_ex([1, 0]))
        n00.key("0", written=rs.T0 + 3).dword("NodeSlot", 7)
        self.hive = hive_of(b, "UsrClass.dat")

    def test_bagmru_tree_to_paths_with_node_times_and_unzoned_dos_dates(self):
        rows = rows_of(self.hive, "C:/Users/alice/AppData/Local/Microsoft/Windows/UsrClass.dat", deleted=False)
        sb = {r["value"]: r for r in by_kind(rows, "shellbag")}
        self.assertIn("My Computer", sb)
        self.assertIn("My Computer\\E:\\", sb)
        leaf = sb["My Computer\\E:\\Exfil Staging"]
        self.assertEqual((leaf["at_raw"], leaf["detail"]["time_basis"]), (rs.T0 + 3, "key"))
        item = leaf["detail"]["item"]
        self.assertEqual((item["mft_record"], item["mft_sequence"]), (4242, 3))
        self.assertEqual(item["modified"]["value"], "2023-07-04T13:22:10")
        self.assertIn("zone not recorded", item["modified"]["zone"])
        self.assertEqual(leaf["detail"]["node_slot"], 7)
        pv = sb["My Computer\\E:\\wsl$"]
        self.assertEqual(pv["detail"]["mru_position"], 0)
        self.assertIsNone(pv["at_utc"])                 # no child key: no time
        self.assertIn("property view", pv["detail"]["item"]["kind"])


class ShellItems(unittest.TestCase):
    def test_types(self):
        self.assertEqual(registry.shell_item(rs.item_root("{645FF040-5081-101B-9F08-00AA002F954E}"))["name"],
                         "Recycle Bin")
        self.assertEqual(registry.shell_item(rs.item_volume("D"))["name"], "D:\\")
        f = registry.shell_item(rs.item_file("Ünïcode name.txt", directory=False, short="UNICOD~1.TXT"))
        self.assertEqual((f["kind"], f["name"], f["short_name"]), ("file", "Ünïcode name.txt", "UNICOD~1.TXT"))
        net = b"\x00\xc3\x01\x85\\\\host\\share\x00Plan 9 Network Provider\x00"
        net = struct.pack("<H", 2 + len(net) - 1) + net[1:]
        n = registry.shell_item(net)
        self.assertEqual((n["kind"], n["name"], n["description"]),
                         ("network location", "\\\\host\\share", "Plan 9 Network Provider"))
        cat = struct.pack("<HBBII", 12, 0x01, 0, 0x39DE2184, 5)
        self.assertEqual(registry.shell_item(cat)["name"], "System and Security")
        vol = rs.item_volume("D")
        emb = struct.pack("<HBBHI", 10 + len(vol), 0x1F, 0, 0, 0xF5A6B710) + vol
        self.assertEqual(registry.shell_item(emb)["name"], "D:\\")
        self.assertEqual(registry.shell_item(b"\x05\x00\x99\x00\x00")["kind"], "unparsed item type 0x99")

    def test_a_cut_item_list_says_where(self):
        items, problems = registry.shell_item_list(rs.item_volume("C") + b"\x50\x00\x31")
        self.assertEqual(len(items), 1)
        self.assertTrue(problems)


class SamAndAmcache(unittest.TestCase):
    def test_sam_users(self):
        b = rs.HiveBuilder()
        users = b.root.path("SAM\\Domains\\Account\\Users")
        u = users.key("000003E9", written=rs.T0 + 8)
        u.binary("F", rs.sam_f(last_logon=rs.T0 + 1, pw_set=rs.T0 - rs.HOUR, failed=rs.T0 + 2,
                               rid=1001, acb=0x211, bad=2, logons=17))
        u.binary("V", rs.sam_v("alice", "Alice Example"))
        users.path("Names\\alice").value("", 1001, b"")
        rows = rows_of(hive_of(b, "SAM"), "config/SAM", deleted=False)
        user = by_kind(rows, "sam-user")[0]
        d = user["detail"]
        self.assertEqual((d["rid"], d["username"], d["username_from"]), (1001, "alice", "Names subkey"))
        self.assertEqual(d["v_value_names"]["full_name"], "Alice Example")
        self.assertEqual((d["f"]["logon_count"], d["f"]["failed_logon_count"]), (17, 2))
        self.assertEqual(d["f"]["acb_flag_names"], ["disabled", "normal account", "password does not expire"])
        self.assertTrue(d["account_never_expires"])
        times = {r["detail"]["event"]: r["at_raw"] for r in by_kind(rows, "sam-user-time")}
        self.assertEqual(times, {"last logon": rs.T0 + 1, "password last set": rs.T0 - rs.HOUR,
                                 "last failed logon": rs.T0 + 2})

    def test_amcache_inventory_application_file(self):
        b = rs.HiveBuilder()
        inv = b.root.path("Root\\InventoryApplicationFile")
        e = inv.key("evil.exe|abc", written=rs.T0 + 4)
        e.sz("LowerCaseLongPath", "c:\\users\\x\\evil.exe").sz("FileId", "0000" + "ab" * 20)
        e.value("Size", rs.REG_QWORD, rs.qword(123456)).sz("LinkDate", "01/02/2020 03:04:05")
        old = inv.key("early|1")
        old.sz("LowerCaseLongPath", "c:\\a.exe").sz("FileId", "0000" + "cd" * 20).sz("Size", "0x7fac0")
        rows = {r["detail"]["path"]: r for r in by_kind(rows_of(hive_of(b), "x/Amcache.hve", deleted=False),
                                                        "amcache-file")}
        ev = rows["c:\\users\\x\\evil.exe"]
        self.assertEqual(ev["detail"]["sha1"], "ab" * 20)
        self.assertEqual(ev["detail"]["size"], 123456)
        self.assertEqual(ev["detail"]["link_date_text"], "01/02/2020 03:04:05")
        self.assertEqual(ev["at_raw"], rs.T0 + 4)
        self.assertIn("not by itself proof", ev["detail"]["note"])
        self.assertEqual(rows["c:\\a.exe"]["detail"]["size"], 0x7FAC0)


# ---------------------------------------------------------------------------
# the row contract
# ---------------------------------------------------------------------------

class RowContract(unittest.TestCase):
    def test_every_row_keeps_the_house_rules(self):
        shim = rs.shim_win10([("C:\\x.exe", rs.T0, b"")])
        for hive, path in ((system_hive(shim), "SYSTEM"), (software_hive(), "SOFTWARE"),
                           (ntuser_hive(), "NTUSER.DAT")):
            rows = rows_of(hive, path)
            json.dumps(rows)
            refs = [r["row_ref_suffix"] for r in rows]
            self.assertEqual(len(refs), len(set(refs)), path)
            for r in rows:
                self.assertIn("time_basis", r["detail"])
                if r["at_epoch"]:
                    self.assertIsInstance(r["at_raw"], int)
                    self.assertEqual(r["at_utc"], timeutil.decode(r["at_raw"], r["at_epoch"]))
                else:
                    self.assertIsNone(r["at_utc"])
                    self.assertIsNone(r["at_raw"])
                self.assertNotIn("\n", r["value"])

    def test_rows_are_stable_between_runs(self):
        a = rows_of(ntuser_hive(), "NTUSER.DAT")
        b = rows_of(ntuser_hive(), "NTUSER.DAT")
        self.assertEqual([r["row_ref_suffix"] for r in a], [r["row_ref_suffix"] for r in b])

    def test_a_failing_extractor_costs_only_its_own_rows(self):
        b = rs.HiveBuilder()
        r = b.root
        r.key("Control Panel")
        r.path(f"{EXPL}\\RunMRU").sz("a", "cmd\\1").sz("MRUList", "a")
        r.path(f"{EXPL}\\TypedPaths").sz("url1", "C:\\x")
        h = hive_of(b, "NTUSER.DAT")
        original = registry._userassist_rows

        def boom(hive, rows):
            raise ValueError("synthetic failure")
        registry._userassist_rows = boom
        try:
            ua = registry.EXPLORER + "\\UserAssist"
            r.path(ua)
            rows = rows_of(h, "NTUSER.DAT")
        finally:
            registry._userassist_rows = original
        self.assertTrue(by_kind(rows, "runmru"))
        self.assertTrue(by_kind(rows, "typed-path"))
        self.assertTrue(any("UserAssist" in p and "synthetic failure" in p for p in h.problems))


# ---------------------------------------------------------------------------
# real hives (optional)
# ---------------------------------------------------------------------------

#: key counts measured on these files by hivex 1.3.23 (python3-hivex) and
#: matched by this parser, key for key, timestamp for timestamp and value
#: byte for value byte (validation run, 2026-10-29).
HIVEX_KEY_COUNTS = {"SYSTEM": 30756, "SOFTWARE": 117488, "NTUSER.DAT": 1812,
                    "UsrClass.dat": 6205, "SAM": 65, "SECURITY": 100,
                    "amcache.hve": 2105, "SYSTEM_WIN_10_1709": 43211,
                    "NTUSER_BAGMRU.DAT": 6279}


@unittest.skipUnless(SAMPLES.is_dir(), "public sample hives (regipy's test data) are not "
                     f"present at {SAMPLES}; they are downloaded for validation only and "
                     "never copied into tests/")
class RealSamples(unittest.TestCase):
    def open(self, name):
        path = SAMPLES / name
        if not path.is_file():
            self.skipTest(f"{name} not downloaded")
        return registry.open_hive(path.read_bytes(), name)

    def test_key_counts_match_hivex(self):
        for name, count in HIVEX_KEY_COUNTS.items():
            with self.subTest(name=name):
                self.assertEqual(self.open(name).key_count(), count)

    def test_kinds_and_some_measurements(self):
        h = self.open("SAM")
        self.assertEqual(registry.hive_kind(h, "SAM"), "SAM")
        names = sorted(r["detail"]["username"] for r in by_kind(rows_of(h, "SAM"), "sam-user"))
        self.assertEqual(names, ["Administrator", "Guest", "Preston"])
        h = self.open("SYSTEM")
        shim = by_kind(rows_of(h, "SYSTEM", deleted=False), "shimcache")
        self.assertEqual(len(shim), 660)
        self.assertEqual(shim[0]["detail"]["format"], "Windows 7 / Server 2008 R2 (32-bit)")

    def test_transaction_log_replay_gives_a_consistent_hive(self):
        """Key counts of the reconstructions, confirmed by hivex walking the
        same reconstructed bytes with no error (validation run, 2026-10-29)."""
        for hive, logs, keys in (("SYSTEM_B", ("SYSTEM_B.LOG1", "SYSTEM_B.LOG2"), 35595),
                                 ("UsrClass.dat", ("UsrClass.dat.LOG1", "UsrClass.dat.LOG2"), 6238),
                                 ("transactions_NTUSER.DAT", ("transactions_ntuser.dat.log1",
                                                              "transactions_ntuser.dat.log2"), 3105)):
            with self.subTest(hive=hive):
                if not all((SAMPLES / n).is_file() for n in (hive,) + logs):
                    self.skipTest("sample logs not downloaded")
                for n in logs:
                    _base, entries, problems = registry.log_entries((SAMPLES / n).read_bytes())
                    self.assertTrue(entries)
                    self.assertEqual(problems, [], n)      # every Marvin32 hash checks
                h = registry.open_hive((SAMPLES / hive).read_bytes(), hive,
                                       logs={n: (SAMPLES / n).read_bytes() for n in logs})
                self.assertTrue(h.recovery["applied"])
                self.assertEqual(h.key_count(), keys)
                self.assertEqual(h.problems[1:], [])

    def test_a_damaged_hive_is_read_around(self):
        h = self.open("corrupted_system_hive")
        self.assertTrue(any("hold no valid hive bin" in p for p in h.problems))
        self.assertGreater(h.key_count(), 1000)


if __name__ == "__main__":
    unittest.main()
