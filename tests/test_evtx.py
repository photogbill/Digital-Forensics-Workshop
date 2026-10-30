"""Windows XML Event Logs: header, chunks, records, Binary XML, damage, rows."""

from __future__ import annotations

import json
import os
import struct
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

import _support  # noqa: F401
import evtxsynth as xs
from evtxsynth import (E, Sub, CharRef, EntityRef, CData, PI, Nested, Event,
                       ChunkWriter)
from forensics_workshop import evtx, timeutil
from forensics_workshop.errors import FileSystemError

#: Third-party samples are never copied into tests/ (their licences are
#: unchecked). Point DFW_SAMPLES at a folder holding them to run the
#: optional comparisons; without it those tests skip and say so.
SAMPLES = Path(os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples") / "evtx"
DIRTY, FULL = 0x1, 0x2


class Counting:
    """A reader that records every read, to prove the walk is chunk-sized."""

    def __init__(self, data):
        self.data = bytes(data)
        self.size = len(self.data)
        self.reads = []

    def read_at(self, offset, length):
        self.reads.append((offset, length))
        return self.data[offset:offset + length]


def walk(data, **kw):
    log = evtx.open_evtx(data)
    return log, list(log.records(**kw))


def security(record_id, event_id, data, **kw):
    return Event("Microsoft-Windows-Security-Auditing", event_id, record_id,
                 data=data, **kw)


class FileHeader(unittest.TestCase):
    def test_fields_flags_and_checksum(self):
        data = xs.build([xs.chunk_of([xs.logon_4624(1)])], flags=DIRTY | FULL,
                        next_record_id=2, minor=2)
        log = evtx.open_evtx(data)
        h = log.header
        self.assertTrue(h.signature_ok and h.checksum_ok)
        self.assertTrue(h.dirty and h.full)
        self.assertEqual(h.flag_names(), ["DIRTY", "FULL"])
        self.assertEqual((h.chunk_count, h.next_record_id), (1, 2))
        self.assertEqual(h.as_dict()["version"], "3.2")
        self.assertFalse(h.wrapped)
        self.assertTrue(any("DIRTY" in p for p in log.problems))

    def test_a_checksum_mismatch_is_reported_and_reading_goes_on(self):
        data = bytearray(xs.build([xs.chunk_of([xs.logon_4624(1)])]))
        data[60] ^= 0xFF                    # inside the checksummed 120 bytes
        log, recs = walk(bytes(data))
        self.assertFalse(log.header.checksum_ok)
        self.assertTrue(any("file header checksum" in p for p in log.problems))
        self.assertEqual([r.record_id for r in recs], [1])

    def test_a_wrapped_log_is_not_damage(self):
        data = xs.build([xs.chunk_of([xs.logon_4624(1)]),
                         xs.chunk_of([xs.logon_4624(2)])],
                        first_chunk=1, last_chunk=0)
        log, recs = walk(data)
        self.assertTrue(log.header.wrapped)
        self.assertEqual(log.problems, [])
        self.assertEqual(len(recs), 2)

    def test_what_is_not_a_log_is_refused_with_a_sentence(self):
        with self.assertRaises(FileSystemError) as cm:
            evtx.open_evtx(b"\x00" * 100)
        self.assertIn("too short", str(cm.exception))
        evt = bytearray(80000)
        evt[0:8] = b"\x30\x00\x00\x00LfLe"     # a legacy .evt header
        with self.assertRaises(FileSystemError) as cm:
            evtx.open_evtx(bytes(evt))
        self.assertIn(".evt", str(cm.exception))


class Chunks(unittest.TestCase):
    def test_chunk_and_record_checksums_are_checked(self):
        good = xs.build([xs.chunk_of([xs.logon_4624(1, user="alice")])])
        log, _recs = walk(good)
        self.assertTrue(log.chunk_reports[0].header_checksum_ok)
        self.assertTrue(log.chunk_reports[0].records_checksum_ok)

        data = bytearray(good)
        at = data.index("alice".encode("utf-16-le"))
        data[at] = ord("A")                  # alter a record, not its CRC
        data[4096 + 60] ^= 0x55              # alter the chunk header
        log, recs = walk(bytes(data))
        rep = log.chunk_reports[0]
        self.assertFalse(rep.records_checksum_ok)
        self.assertFalse(rep.header_checksum_ok)
        self.assertEqual(sum("checksum does not match" in p for p in log.problems), 2)
        # what the record now says is still read, beside the report
        self.assertEqual(recs[0].as_dict()["event_data"]["TargetUserName"], "Alice")

    def test_a_chunk_without_signature_is_reported_scanned_and_passed(self):
        c0 = bytearray(xs.chunk_of([xs.logon_4624(1), xs.logon_4624(2)]))
        c0[0:8] = b"XXXXXXXX"
        data = xs.build([bytes(c0), xs.chunk_of([xs.logon_4624(3)])])
        log, recs = walk(data)
        self.assertEqual(log.chunk_reports[0].status, "no-signature")
        self.assertTrue(any("ElfChnk" in p for p in log.problems))
        by_id = {r.record_id: r for r in recs}
        self.assertEqual(sorted(by_id), [1, 2, 3])
        self.assertTrue(by_id[1].recovered and by_id[2].recovered)
        self.assertEqual(by_id[1].found_by, "scan-bad-chunk")
        self.assertFalse(by_id[3].recovered)
        self.assertEqual(by_id[2].as_dict()["event_id"], 4624)

    def test_unused_zero_chunks_are_not_damage_but_a_counted_one_is(self):
        empty = bytes(xs.CHUNK)
        log, recs = walk(xs.build([xs.chunk_of([xs.logon_4624(1)]), empty],
                                  chunk_count=1))
        self.assertEqual(log.chunk_reports[1].status, "empty")
        self.assertEqual(log.problems, [])
        log, recs = walk(xs.build([xs.chunk_of([xs.logon_4624(1)]), empty]))
        self.assertTrue(any("all zeroes" in p for p in log.problems))

    def test_chunks_past_the_header_count_are_read_as_live(self):
        data = xs.build([xs.chunk_of([xs.logon_4624(1)]),
                         xs.chunk_of([xs.logon_4624(2)])],
                        chunk_count=1, flags=DIRTY)
        log, recs = walk(data)
        self.assertEqual([(r.record_id, r.found_by, r.recovered) for r in recs],
                         [(1, "chunk", False), (2, "unlisted-chunk", False)])
        self.assertFalse(log.chunk_reports[1].listed)

    def test_records_are_read_one_chunk_at_a_time(self):
        chunks = [xs.chunk_of([xs.logon_4624(10 * i + j) for j in range(3)])
                  for i in range(4)]
        reader = Counting(xs.build(chunks))
        log = evtx.open_evtx(reader)
        it = log.records()
        first = next(it)
        self.assertEqual(first.record_id, 0)
        self.assertEqual(max(n for _o, n in reader.reads), xs.CHUNK)
        self.assertEqual(len([r for r in reader.reads if r[1] == xs.CHUNK]), 1)
        rest = list(it)
        self.assertEqual(len(rest), 11)
        self.assertEqual(max(n for _o, n in reader.reads), xs.CHUNK)


class Records(unittest.TestCase):
    def setUp(self):
        ev = xs.logon_4624(7, time=xs.T0)
        ev.user_sid = "S-1-5-21-111-222-333-500"
        ev.activity = "{11111111-2222-3333-4444-555555555555}"
        ev.written = xs.T0 + 5
        self.log, self.recs = walk(xs.build([xs.chunk_of([ev])]))
        self.rec = self.recs[0]

    def test_header_identifier_and_written_time(self):
        r = self.rec
        self.assertEqual((r.record_id, r.written_raw), (7, xs.T0 + 5))
        self.assertEqual(r.written_utc, timeutil.decode(xs.T0 + 5, "filetime"))
        self.assertEqual(r.offset, 4096 + 512)
        self.assertEqual(r.found_by, "chunk")
        self.assertEqual(r.problems, [])

    def test_system_fields(self):
        d = self.rec.as_dict()
        self.assertEqual(d["event_id"], 4624)
        self.assertIsNone(d["event_qualifiers"])
        self.assertEqual((d["version"], d["level"], d["task"], d["opcode"]),
                         (0, 0, 12544, 0))
        self.assertEqual(d["keywords"], "0x8020000000000000")
        self.assertEqual(d["provider_name"], "Microsoft-Windows-Security-Auditing")
        self.assertEqual(d["provider_guid"], xs.SECURITY_GUID)
        self.assertEqual((d["channel"], d["computer"]), ("Security", "WS01.corp.example"))
        self.assertEqual(d["user_sid"], "S-1-5-21-111-222-333-500")
        self.assertEqual((d["process_id"], d["thread_id"]), (636, 700))
        self.assertEqual(d["activity_id"], "{11111111-2222-3333-4444-555555555555}")
        self.assertEqual(d["event_record_id"], 7)
        self.assertEqual(d["time_created_raw"], xs.T0)
        self.assertEqual(d["time_created_utc"], "2024-05-06T07:20:00.123456Z")
        self.assertEqual(d["time_created_text"], "2024-05-06T07:20:00.1234567Z")
        self.assertEqual(d["epoch"], "filetime")
        json.dumps(d)

    def test_event_data_by_name(self):
        ed = self.rec.as_dict()["event_data"]
        self.assertEqual(ed["TargetUserName"], "alice")
        self.assertEqual(ed["LogonType"], "10")
        self.assertEqual(ed["SubjectLogonId"], "0x3e7")
        self.assertEqual(ed["TargetUserSid"], "S-1-5-21-1-2-3-1104")
        self.assertEqual(self.rec.as_dict()["event_data_source"], "EventData")

    def test_xml_rendering(self):
        x = self.rec.xml()
        root = ET.fromstring(x)
        ns = "{" + xs.NS + "}"
        self.assertEqual(root.tag, ns + "Event")
        self.assertEqual(root.find(f"{ns}System/{ns}EventID").text, "4624")
        self.assertEqual(root.find(f"{ns}System/{ns}TimeCreated").get("SystemTime"),
                         "2024-05-06T07:20:00.1234567Z")
        data = {d.get("Name"): d.text for d in root.iter(ns + "Data")}
        self.assertEqual(data["IpAddress"], "10.0.0.5")
        self.assertIn('<Data Name="LogonType">10</Data>', x)

    def test_optional_null_attributes_are_omitted(self):
        log, recs = walk(xs.build([xs.chunk_of([xs.logon_4624(1)])]))
        x = recs[0].xml()
        self.assertIn("<Correlation/>", x)
        self.assertIn("<Security/>", x)
        self.assertNotIn("Qualifiers", x)
        self.assertIsNone(recs[0].as_dict()["user_sid"])

    def test_qualifiers_are_kept_apart_from_the_event_id(self):
        ev = Event("Service Control Manager", 7045, 3, channel="System",
                   guid=None, qualifiers=16384, data=[
                       ("ServiceName", xs.v_str("evil")),
                       ("ImagePath", xs.v_str("C:\\x.exe"))])
        log, recs = walk(xs.build([xs.chunk_of([ev])]))
        d = recs[0].as_dict()
        self.assertEqual((d["event_id"], d["event_qualifiers"]), (7045, 16384))
        self.assertIn('<EventID Qualifiers="16384">7045</EventID>', recs[0].xml())

    def test_escaping(self):
        ev = security(1, 4688, [("CommandLine", xs.v_str('cmd /c "a & b" <x>'))])
        log, recs = walk(xs.build([xs.chunk_of([ev])]))
        x = recs[0].xml()
        self.assertIn("cmd /c \"a &amp; b\" &lt;x&gt;", x)
        self.assertEqual(ET.fromstring(x).find(".//{%s}Data" % xs.NS).text,
                         'cmd /c "a & b" <x>')
        self.assertEqual(recs[0].as_dict()["event_data"]["CommandLine"],
                         'cmd /c "a & b" <x>')

    def test_event_record_id_mismatch_is_reported(self):
        ev = xs.logon_4624(5)
        ev.event_record_id = 6
        log, recs = walk(xs.build([xs.chunk_of([ev])]))
        recs[0].as_dict()
        self.assertTrue(any("EventRecordID is 6" in p for p in recs[0].problems))


class ValueTypes(unittest.TestCase):
    def test_every_value_type_is_rendered(self):
        nested_tree = E("Inner", [("Kind", [Sub(0, 0x01)])], [Sub(1, 0x08)])
        values = [
            ("Null", xs.v_null()),
            ("Str", xs.v_str("héllo")),
            ("Ansi", xs.v_ansi("café")),
            ("I8", xs.v_int(0x03, -5)), ("U8", xs.v_int(0x04, 250)),
            ("I16", xs.v_int(0x05, -300)), ("U16", xs.v_int(0x06, 65000)),
            ("I32", xs.v_int(0x07, -70000)), ("U32", xs.v_int(0x08, 4000000000)),
            ("I64", xs.v_int(0x09, -(2 ** 40))), ("U64", xs.v_int(0x0A, 2 ** 63 + 5)),
            ("R32", xs.v_real32(1.5)), ("R64", xs.v_real64(-2.25)),
            ("BoolT", xs.v_bool(1)), ("BoolF", xs.v_bool(0)), ("BoolOdd", xs.v_bool(16)),
            ("Bin", xs.v_binary(b"\x01\xab\xff")),
            ("Guid", xs.v_guid("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}")),
            ("Size4", xs.v_sizet(0x1234, 4)), ("Size8", xs.v_sizet(0xABCDEF, 8)),
            ("FT", xs.v_filetime(xs.T0)),
            ("ST", xs.v_systemtime(2024, 5, 1, 6, 7, 8, 9, 123)),
            ("Sid", xs.v_sid("S-1-5-21-10-20-30-500")),
            ("H32", xs.v_int(0x14, 0x3E7)), ("H64", xs.v_int(0x15, 0x8020000000000000)),
            ("Nest", Nested(nested_tree, [xs.v_str("k"), xs.v_int(0x08, 42)],
                            key="inner")),
            ("Direct", Nested(E("Plain", [("A", ["b"])], ["text"]), direct=True)),
            ("Handle", (0x20, b"\x01\x02\x03\x04")),
        ]
        ev = Event("Test-Provider", 1, 1, channel="Test", data=values)
        log, recs = walk(xs.build([xs.chunk_of([ev])]))
        rec = recs[0]
        ed = rec.as_dict()["event_data"]
        expect = {
            "Null": None, "Str": "héllo", "Ansi": "café", "I8": "-5", "U8": "250",
            "I16": "-300", "U16": "65000", "I32": "-70000", "U32": "4000000000",
            "I64": str(-(2 ** 40)), "U64": str(2 ** 63 + 5), "R32": "1.5",
            "R64": "-2.25", "BoolT": "true", "BoolF": "false", "BoolOdd": "16",
            "Bin": "01ABFF", "Guid": "{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}",
            "Size4": "0x1234", "Size8": "0xabcdef",
            "FT": "2024-05-06T07:20:00.1234567Z",
            "ST": "2024-05-06T07:08:09.123",          # no zone: never claimed UTC
            "Sid": "S-1-5-21-10-20-30-500", "H32": "0x3e7",
            "H64": "0x8020000000000000", "Handle": "01020304",
        }
        for key, want in expect.items():
            self.assertEqual(ed[key], want, key)
        x = rec.xml()
        self.assertIn('<Data Name="Nest"><Inner Kind="k">42</Inner></Data>', x)
        self.assertIn('<Data Name="Direct"><Plain A="b">text</Plain></Data>', x)
        self.assertEqual(ed["Nest"], None)          # element content, no text
        self.assertTrue(any("EvtHandle" in p for p in rec.problems))
        ET.fromstring(x)

    def test_arrays_repeat_their_element_per_item(self):
        ev = Event("Test-Provider", 2, 1, channel="Test", data=[
            (None, xs.v_str_array(["one", "two", "three"])),
            ("Nums", xs.v_u16_array([1, 2])),
            ("Empty", (0x81, b""))])
        log, recs = walk(xs.build([xs.chunk_of([ev])]))
        ed = recs[0].as_dict()["event_data"]
        self.assertEqual([ed["Data_1"], ed["Data_2"], ed["Data_3"]],
                         ["one", "two", "three"])
        self.assertEqual((ed["Nums"], ed["Nums_2"]), ("1", "2"))
        self.assertEqual(ed["Empty"], "")
        self.assertIn('<Data Name="Nums">1</Data><Data Name="Nums">2</Data>',
                      recs[0].xml())

    def test_references_cdata_and_processing_instructions(self):
        tree = E("Event", [("xmlns", [xs.NS])], [
            xs.system_element(),
            E("EventData", [], [
                E("Data", [("Name", ["Mixed"])],
                  ["a", CharRef(65), EntityRef("amp"), "b"]),
                E("Data", [("Name", ["Code"])], [CData("x < y")]),
                E("Data", [("Name", ["Proc"])], [PI("target", "k=v")])])])
        c = ChunkWriter()
        values = xs._system_values(Event("Test-Provider", 3, 1, channel="Test"))
        c.record(1, xs.T0, "refs", tree, values)
        log, recs = walk(xs.build([c.finish()]))
        x = recs[0].xml()
        self.assertIn('<Data Name="Mixed">a&#65;&amp;b</Data>', x)
        self.assertIn("<![CDATA[x < y]]>", x)
        self.assertIn("<?target k=v?>", x)
        ed = recs[0].as_dict()["event_data"]
        self.assertEqual(ed["Mixed"], "aA&b")
        self.assertEqual(ed["Code"], "x < y")


class Templates(unittest.TestCase):
    def test_a_template_is_defined_once_per_chunk_and_referenced_after(self):
        c = ChunkWriter()
        a = xs.add_event(c, xs.logon_4624(1, user="alice"))
        b = xs.add_event(c, xs.logon_4624(2, user="bob"))
        size_a, size_b = c.records[0][1], c.records[1][1]
        self.assertLess(size_b, size_a - 200)       # b points back at a's definition
        c2 = ChunkWriter()
        xs.add_event(c2, xs.logon_4624(3, user="carol"))
        log, recs = walk(xs.build([c.finish(), c2.finish()]))
        self.assertEqual([r.as_dict()["event_data"]["TargetUserName"] for r in recs],
                         ["alice", "bob", "carol"])
        self.assertEqual(recs[0].xml().replace("alice", "bob")
                         .replace("<EventRecordID>1<", "<EventRecordID>2<"),
                         recs[1].xml())
        self.assertTrue(a < b)

    def test_a_reference_to_another_chunks_template_is_not_trusted(self):
        # chunk 0: record 1 defines template T (4624 shape) at offset X.
        # chunk 1: record 2 defines a DIFFERENT template at the same offset;
        # record 3 is chunk 0's second-use bytes for T, pointing at X.
        c0 = ChunkWriter()
        xs.add_event(c0, xs.logon_4624(1))
        xs.add_event(c0, xs.logon_4624(9))
        start, size, _ = c0.records[1]
        reference = bytearray(c0.buf[start:start + size])
        c1 = ChunkWriter()
        xs.add_event(c1, security(2, 4688, [("NewProcessName", xs.v_str("x"))]))
        self.assertEqual(c1.records[0][0], c0.records[0][0])
        struct.pack_into("<Q", reference, 8, 3)
        c1.buf += reference
        c1.records.append((c1.records[0][0] + c1.records[0][1], size, 3))
        log, recs = walk(xs.build([c0.finish(), c1.finish()]))
        by_id = {r.record_id: r for r in recs}
        self.assertTrue(by_id[9].readable)
        self.assertFalse(by_id[3].readable)
        self.assertTrue(any("not the one this record names" in p
                            for p in by_id[3].problems))


class Damage(unittest.TestCase):
    def test_a_torn_record_is_reported_and_the_rest_of_the_chunk_recovered(self):
        c = ChunkWriter()
        for i in (1, 2, 3):
            xs.add_event(c, xs.logon_4624(i, user=f"u{i}"))
        chunk = bytearray(c.finish())
        start, size, _ = c.records[1]
        struct.pack_into("<I", chunk, start + size - 4, 0)   # size copy torn
        data = xs.build([bytes(chunk), xs.chunk_of([xs.logon_4624(4)])])
        log, recs = walk(data)
        got = [(r.record_id, r.found_by, r.recovered) for r in recs]
        self.assertEqual(got, [(1, "chunk", False), (2, "chunk", False),
                               (3, "scan-after-damage", True),
                               (4, "chunk", False)])
        self.assertTrue(any("copy of its size" in p for p in recs[1].problems))
        self.assertEqual(recs[2].as_dict()["event_data"]["TargetUserName"], "u3")
        self.assertTrue(any("Record 2" in p for p in log.problems))

    def test_records_in_unused_space_are_recovered_and_flagged(self):
        c = ChunkWriter()
        for i in (1, 2, 3):
            xs.add_event(c, xs.logon_4624(i, user=f"u{i}"))
        log, recs = walk(xs.build([c.finish(live=2)]))
        got = [(r.record_id, r.found_by, r.recovered) for r in recs]
        self.assertEqual(got, [(1, "chunk", False), (2, "chunk", False),
                               (3, "chunk-slack", True)])
        self.assertEqual(recs[2].as_dict()["event_data"]["TargetUserName"], "u3")
        self.assertTrue(recs[2].as_dict()["recovered"])
        self.assertEqual(log.chunk_reports[0].recovered, 1)
        self.assertEqual([r.record_id for r in walk(
            xs.build([c.finish(live=2)]), recovered=False)[1]], [1, 2])

    def test_record_shaped_junk_in_unused_space_is_counted_not_listed(self):
        c = ChunkWriter()
        xs.add_event(c, xs.logon_4624(1))
        chunk = bytearray(c.finish())
        junk = (b"**\0\0" + struct.pack("<I", 64) + struct.pack("<QQ", 77, xs.T0)
                + b"\x0f\x01\x01\x00\x0c\x01" + b"\xee" * 30 + struct.pack("<I", 64))
        self.assertEqual(len(junk), 64)
        at = 0x8000
        chunk[at:at + len(junk)] = junk
        log, recs = walk(xs.build([bytes(chunk)]))
        self.assertEqual([r.record_id for r in recs], [1])
        self.assertEqual(log.problem_counts.get("slack-unreadable"), 1)

    def test_a_recovered_record_naming_reused_space_is_not_listed(self):
        # chunk x: record 1 defines the names; record 2 (another template)
        # refers back to some of them. In chunk y the same space was reused
        # by a shorter, differently shaped record 3, and record 2's bytes
        # survive in y's unused space at their old offset.
        x = ChunkWriter()
        xs.add_event(x, xs.logon_4624(1))
        xs.add_event(x, security(2, 4688, [("NewProcessName", xs.v_str("evil.exe"))]))
        start, size, _ = x.records[1]
        stale = bytes(x.buf[start:start + size])
        bare = E("Event", [("xmlns", [xs.NS])], [E("System", [], [
            E("Provider", [("Name", ["EventLog"])]),
            E("EventID", [], [Sub(0, 0x06)])])])
        y = ChunkWriter()
        y.record(3, xs.T0, "bare", bare, [xs.v_int(0x06, 6005)])
        self.assertLess(len(y.buf), start)
        y.buf += bytes(start - len(y.buf)) + stale
        y.records.append((start, size, 2))
        log, recs = walk(xs.build([y.finish(live=1)]))
        self.assertEqual([r.record_id for r in recs], [3])
        self.assertEqual(log.problem_counts.get("slack-unreadable"), 1)
        self.assertTrue(any("could not be read" in p
                            for p in log.chunk_reports[0].problems))
        # control: in its own chunk's unused space the same bytes are read
        log, recs = walk(xs.build([x.finish(live=1)]))
        self.assertEqual([(r.record_id, r.recovered) for r in recs],
                         [(1, False), (2, True)])
        self.assertEqual(recs[1].as_dict()["event_data"]["NewProcessName"], "evil.exe")

    def test_unreadable_binary_xml_is_reported_and_the_record_kept(self):
        c = ChunkWriter()
        xs.add_event(c, xs.logon_4624(1))
        xs.add_event(c, xs.logon_4624(2))
        chunk = bytearray(c.finish())
        start = c.records[0][0]
        chunk[start + 24 + 4] = 0x17        # the template-instance token
        log, recs = walk(xs.build([bytes(chunk)]))
        self.assertEqual([r.record_id for r in recs], [1, 2])
        self.assertFalse(recs[0].readable)
        d = recs[0].as_dict()
        self.assertEqual((d["record_id"], d["written_raw"], d["event_id"]),
                         (1, xs.T0, None))
        self.assertTrue(any("Binary XML could not be read" in p for p in d["problems"]))
        # record 2 needed record 1's template definition, which is intact
        self.assertEqual(recs[1].as_dict()["event_id"], 4624)

    def test_a_file_cut_inside_a_chunk_is_scanned(self):
        data = xs.build([xs.chunk_of([xs.logon_4624(1)]),
                         xs.chunk_of([xs.logon_4624(2), xs.logon_4624(3)])])
        cut = data[:4096 + xs.CHUNK + 3400]     # record 2 whole, record 3 cut
        log, recs = walk(cut)
        self.assertEqual([(r.record_id, r.found_by) for r in recs],
                         [(1, "chunk"), (2, "scan-partial-chunk")])
        self.assertTrue(any("partial chunk" in p for p in log.problems))
        self.assertTrue(any("truncated" in p for p in log.problems))


def _log_with(events, **kw):
    return evtx.open_evtx(xs.build([xs.chunk_of(events)], **kw))


class Rows(unittest.TestCase):
    def test_only_catalogued_events_become_rows(self):
        cleared = Event("Microsoft-Windows-Eventlog", 1102, 4, guid=None,
                        userdata=E("LogFileCleared",
                                   [("xmlns", ["http://manifests.microsoft.com/win/2004/08/windows/eventlog"])],
                                   [E("SubjectUserSid", [], [Sub(xs.N_SYSTEM, 0x13)]),
                                    E("SubjectUserName", [], [Sub(xs.N_SYSTEM + 1, 0x01)]),
                                    E("SubjectDomainName", [], [Sub(xs.N_SYSTEM + 2, 0x01)]),
                                    E("SubjectLogonId", [], [Sub(xs.N_SYSTEM + 3, 0x15)])]),
                        userdata_values=[xs.v_sid("S-1-5-21-1-2-3-500"),
                                         xs.v_str("mallory"), xs.v_str("CORP"),
                                         xs.v_int(0x15, 0x55)])
        events = [
            xs.logon_4624(1),
            security(2, 4688, [("SubjectUserName", xs.v_str("alice")),
                               ("SubjectDomainName", xs.v_str("CORP")),
                               ("NewProcessName", xs.v_str("C:\\Windows\\System32\\cmd.exe")),
                               ("CommandLine", xs.v_str("cmd /c whoami")),
                               ("ParentProcessName", xs.v_str("C:\\Windows\\explorer.exe"))]),
            security(3, 5379, [("TargetName", xs.v_str("x"))]),     # not catalogued
            cleared,
        ]
        log = _log_with(events)
        rows = evtx.to_rows(log, source_path="Windows/System32/winevt/Logs/Security.evtx")
        self.assertEqual([r["artefact"] for r in rows],
                         ["evtx_logon", "evtx_process_created", "evtx_log_cleared"])
        logon, proc, clear = rows
        self.assertEqual((logon["at_raw"], logon["at_epoch"]), (xs.T0, "filetime"))
        self.assertEqual(logon["at_utc"], timeutil.decode(xs.T0, "filetime"))
        self.assertIn("logon type 10 (RemoteInteractive)", logon["value"])
        self.assertIn("CORP\\alice from 10.0.0.5", logon["value"])
        self.assertEqual(logon["detail"]["fields"]["source_ip"], "10.0.0.5")
        self.assertEqual(logon["detail"]["derived"]["logon_type_name"], "RemoteInteractive")
        self.assertIn("cmd /c whoami", proc["value"])
        self.assertIn("cleared by CORP\\mallory", clear["value"])
        self.assertEqual(clear["detail"]["fields"]["subject_sid"], "S-1-5-21-1-2-3-500")
        refs = [r["row_ref_suffix"] for r in rows]
        self.assertEqual(len(set(refs)), len(refs))
        for r in rows:
            self.assertEqual(set(r), {"artefact", "at_utc", "at_raw", "at_epoch",
                                      "title", "value", "detail", "row_ref_suffix"})
            json.dumps(r)
            self.assertNotIn("\n", r["value"])

    def test_failed_logon_status_codes_are_named_beside_the_code(self):
        ev = security(1, 4625, [("TargetUserName", xs.v_str("admin")),
                                ("TargetDomainName", xs.v_str("CORP")),
                                ("Status", xs.v_int(0x14, 0xC000006D)),
                                ("SubStatus", xs.v_int(0x14, 0xC000006A)),
                                ("LogonType", xs.v_int(0x08, 3)),
                                ("IpAddress", xs.v_str("203.0.113.9"))])
        row = evtx.to_rows(_log_with([ev]), source_path="S.evtx")[0]
        self.assertEqual(row["detail"]["fields"]["sub_status"], "0xc000006a")
        self.assertEqual(row["detail"]["derived"]["sub_status_name"],
                         "STATUS_WRONG_PASSWORD")
        self.assertIn("0xc000006a (STATUS_WRONG_PASSWORD)", row["value"])

    def test_scheduled_task_command_is_read_from_the_task_xml(self):
        task = ("<?xml version=\"1.0\"?><Task><Actions><Exec><Command>C:\\tmp\\a.exe"
                "</Command><Arguments>-q</Arguments></Exec></Actions></Task>")
        ev = security(1, 4698, [("SubjectUserName", xs.v_str("bob")),
                                ("TaskName", xs.v_str("\\Updater")),
                                ("TaskContent", xs.v_str(task))])
        row = evtx.to_rows(_log_with([ev]), source_path="S.evtx")[0]
        self.assertEqual(row["artefact"], "evtx_scheduled_task")
        self.assertEqual(row["detail"]["derived"]["task_command"], "C:\\tmp\\a.exe")
        self.assertIn("C:\\tmp\\a.exe -q", row["value"])

    def test_long_script_blocks_are_cut_and_say_so(self):
        text = "Write-Host 'x'\n" * 2000
        ev = Event("Microsoft-Windows-PowerShell", 4104, 1,
                   channel="Microsoft-Windows-PowerShell/Operational", data=[
                       ("MessageNumber", xs.v_int(0x08, 1)),
                       ("MessageTotal", xs.v_int(0x08, 1)),
                       ("ScriptBlockText", xs.v_str(text)),
                       ("ScriptBlockId", xs.v_guid("{0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9}")),
                       ("Path", xs.v_str(""))])
        row = evtx.to_rows(_log_with([ev]), source_path="PS.evtx")[0]
        kept = row["detail"]["fields"]["script_block_text"]
        self.assertEqual(len(kept), evtx.FIELD_LIMITS["script_block_text"])
        self.assertEqual(row["detail"]["truncated"]["script_block_text"], len(text))
        self.assertLessEqual(len(row["value"]), 400)

    def test_channel_hint_and_written_time_fallback(self):
        tree = E("Event", [("xmlns", [xs.NS])], [E("System", [], [
            E("Provider", [("Name", ["EventLog"])]),
            E("EventID", [], [Sub(0, 0x06)])])])
        c = ChunkWriter()
        c.record(1, xs.T0 + 99, "bare", tree, [xs.v_int(0x06, 6005)])
        log = evtx.open_evtx(xs.build([c.finish()]))
        row = evtx.to_rows(log, source_path="System.evtx", channel_hint="System")[0]
        self.assertEqual(row["artefact"], "evtx_system_power")
        self.assertEqual((row["detail"]["channel"], row["detail"]["channel_from"]),
                         ("System", "hint"))
        self.assertEqual(row["at_raw"], xs.T0 + 99)
        self.assertEqual(row["detail"]["time_source"], "record written time")

    def test_a_recovered_copy_of_a_live_event_is_folded_not_doubled(self):
        c0 = ChunkWriter()
        xs.add_event(c0, xs.logon_4624(1, user="alice"))
        xs.add_event(c0, xs.logon_4624(2, user="bob"))       # slack in chunk 0
        xs.add_event(c0, xs.logon_4624(5, user="eve"))       # slack, no twin
        c1 = ChunkWriter()
        xs.add_event(c1, xs.logon_4624(2, user="bob"))       # live in chunk 1
        log = evtx.open_evtx(xs.build([c0.finish(live=1), c1.finish()]))
        rows = evtx.to_rows(log, source_path="S.evtx")
        got = sorted((r["detail"]["record_id"], r["detail"]["recovered"]) for r in rows)
        self.assertEqual(got, [(1, False), (2, False), (5, True)])
        bob = next(r for r in rows if r["detail"]["record_id"] == 2)
        self.assertEqual(len(bob["detail"]["recovered_copies"]), 1)
        eve = next(r for r in rows if r["detail"]["record_id"] == 5)
        self.assertTrue(eve["value"].startswith("[recovered] "))
        self.assertEqual(eve["detail"]["found_by"], "chunk-slack")

    def test_the_catalogue_can_be_extended(self):
        key = ("test-provider", 77)
        evtx.CATALOGUE[key] = {"artefact": "evtx_custom", "title": "Custom (77)",
                               "summary": "custom {thing}",
                               "fields": {"thing": "Thing"}, "channel": "Test"}
        try:
            ev = Event("Test-Provider", 77, 1, channel="Test",
                       data=[("Thing", xs.v_str("widget"))])
            rows = evtx.to_rows(_log_with([ev]), source_path="T.evtx")
            self.assertEqual([(r["artefact"], r["value"]) for r in rows],
                             [("evtx_custom", "custom widget")])
        finally:
            del evtx.CATALOGUE[key]

    def test_record_dicts_are_accepted_too(self):
        log = _log_with([xs.logon_4624(1)])
        dicts = [r.as_dict() for r in log.records()]
        self.assertEqual(len(evtx.to_rows(dicts, source_path="S.evtx")), 1)


class Summary(unittest.TestCase):
    def test_counts_per_provider_and_event_id(self):
        c = ChunkWriter()
        for i in range(5):
            xs.add_event(c, xs.logon_4624(i + 1, time=xs.T0 + i * 10_000_000))
        xs.add_event(c, security(6, 4672, [("SubjectUserName", xs.v_str("a"))]))
        xs.add_event(c, xs.logon_4624(7))                    # left in slack
        s = evtx.summary(evtx.open_evtx(xs.build([c.finish(live=6)])))
        self.assertEqual((s["records"], s["recovered"], s["unreadable"]), (6, 1, 0))
        top = s["counts"][0]
        self.assertEqual((top["provider"], top["event_id"], top["count"],
                          top["recovered"]),
                         ("Microsoft-Windows-Security-Auditing", 4624, 5, 1))
        self.assertEqual(top["first_raw"], xs.T0)
        self.assertEqual(top["last_raw"], xs.T0 + 4 * 10_000_000)
        self.assertEqual(top["last_utc"], timeutil.decode(top["last_raw"], "filetime"))
        self.assertTrue(top["catalogued"])
        self.assertEqual(s["counts"][1]["event_id"], 4672)
        json.dumps(s)


@unittest.skipUnless(SAMPLES.is_dir(),
                     "real .evtx samples are not downloaded here "
                     f"({SAMPLES}); they are never shipped with the engine")
class RealSamples(unittest.TestCase):
    """Optional: logs from github.com/omerbenamram/evtx (samples/) and
    github.com/sbousseaden/EVTX-ATTACK-SAMPLES, read from the examiner's
    scratch folder. Licences unchecked, so they are not in the repository."""

    def _files(self):
        files = sorted(SAMPLES.rglob("*.evtx"))
        if not files:
            self.skipTest("no .evtx files under the samples folder")
        return files

    def test_every_sample_is_read_without_an_unreadable_live_record(self):
        damaged = {"2-vss_0-Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx",
                   "2-vss_0-Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx",
                   "sample_with_a_bad_chunk_magic.evtx"}
        for path in self._files()[:400]:
            if os.path.getsize(path) > 8 << 20:
                continue                        # keep the suite quick
            log = evtx.open_evtx(path.read_bytes())
            for rec in log.records():
                if not rec.recovered and path.name not in damaged:
                    self.assertTrue(rec.readable, f"{path.name} {rec.record_id}")
                rec.as_dict()

    def test_against_pyevtx_rs_when_it_is_installed(self):
        try:
            import evtx as rs  # noqa: F401  (container-only, never shipped)
        except ImportError:
            self.skipTest("pyevtx-rs (pip install evtx) is not installed")
        import re
        if not hasattr(rs, "PyEvtxParser"):
            self.skipTest("the importable 'evtx' is not pyevtx-rs")
        checked = 0
        for path in self._files():
            if os.path.getsize(path) > 8 << 20:
                continue
            try:
                theirs = {r["event_record_id"]: r for r in rs.PyEvtxParser(str(path)).records()
                          if isinstance(r, dict)}
            except Exception:                               # they stop at damage
                continue
            ours = {r.record_id: r for r in evtx.open_evtx(path.read_bytes()).records()
                    if not r.recovered}
            self.assertEqual(set(theirs), set(ours), path.name)
            for rid, r in theirs.items():
                m = re.search(r"<EventID[^>]*>(\d+)</EventID>", r["data"])
                if m:
                    self.assertEqual(ours[rid].as_dict()["event_id"], int(m.group(1)))
                checked += 1
        self.assertGreater(checked, 0)


if __name__ == "__main__":
    unittest.main()
