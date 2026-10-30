"""Outlook PST/OST: spec samples, every NDB/LTP layer, damage, and real files.

Known answers come from the sample dumps printed in [MS-PST] §3 (header,
B-tree pages, SLBLOCK, the message store's Heap-on-Node and the root folder's
hierarchy Table Context). Whole files come from `pstsynth`, a writer built
from the specification, in all three layouts (ANSI, Unicode, Unicode 4 KB)
and all three encodings. Real Outlook files are read when they are present
under $DFW_SAMPLES/pst (never shipped here; their licences are
unchecked), and compared with pypff (libpff) when that is installed.
"""

from __future__ import annotations

import json
import os
import struct
import unittest

import _support  # noqa: F401
import pstsynth as ps
from forensics_workshop import pst, timeutil
from forensics_workshop.errors import FileSystemError

SAMPLES = os.path.join(os.environ.get("DFW_SAMPLES") or "/nonexistent-dfw-samples", "pst", "files")

# --- [MS-PST] §3 sample dumps (offset, 16 bytes per row; omitted rows are zero)

HEADER = """
00000000 2142444E0EA99A37534D170013000101
00000010 5C070000D07B990B0400000001000000
00000020 54020000000000004500000000040000
00000030 00040000040400000040000002000100
00000040 04040000000400000004000000800000
00000050 00040000000400000004000000040000
00000060 04040000040400000404000000040000
00000070 00040000000400000004000000040000
00000080 00040000000400000004000000040000
00000090 00040000000400000004000000040000
000000A0 00040000000400000F04000000000000
000000B0 000000000000000000249F0000000000
000000C0 00449B000000000040F2120000000000
000000D0 00000000000000004B02000000000000
000000E0 00529000000000005302000000000000
000000F0 000A9000000000000200000000000000
00000100 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000110 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000120 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000130 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000140 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000150 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000160 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000170 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000180 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000190 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001A0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001B0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001C0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001D0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001E0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
000001F0 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
00000200 800100003414000000000000D683D21F
"""
INTERMEDIATE_PAGE = """
00008200 21000000000000000502000000000000
00008210 007E0000000000000F06000000000000
00008220 41010000000000000070000000000000
00008230 2280000000000000FD00000000000000
00008240 00840000000000000000000000000000
000083E0 00000000000000000314180100000000
000083F0 8181068064B1E8020602000000000000
"""
NBT_PAGE = """
00007000 0F060000000000000C00000000000000
00007010 00000000000000000000000002000000
00007020 10060000000000001000000000000000
00007030 00000000000000000000000002000000
00007040 2B060000000000003000000000000000
00007050 00000000000000000000000002000000
00007060 4C060000000000001C00000000000000
00007070 00000000000000000000000002000000
00007080 71060000000000001800000000000000
00007090 00000000000000000000000002000000
000070A0 92060000000000001400000000000000
000070B0 00000000000000000000000002000000
000070C0 B6060000000000002400000000000000
000070D0 00000000000000000000000002000000
000070E0 D7060000000000002800000000000000
000070F0 00000000000000000000000002000000
00007100 F8060000000000002C00000000000000
00007110 00000000000000000000000002000000
00007120 010C0000000000004800000000000000
00007130 00000000000000000000000002000000
00007140 22800000000000005400000000000000
00007150 00000000000000002201000002000000
00007160 2D800000000000000400000000000000
00007170 00000000000000000000000002000000
00007180 2E800000000000000800000000000000
00007190 00000000000000000000000002000000
000071A0 2F800000000000000C00000000000000
000071B0 00000000000000000000000002000000
000071C0 42800000000000006400000000000000
000071D0 00000000000000002201000002000000
000071E0 00000000000000000E0F200000000000
000071F0 81816B704919C2396B00000000000000
"""
# printed in §3.5 as a "leaf" BBT page, but its cLevel byte is 1: the
# entries are BTENTRYs, and it is read as such
BBT_PAGE = """
00900200 68110000000000000B02000000000000
00900210 00287C0000000000B011000000000000
00900220 0C020000000000000008800000000000
00900230 F8110000000000000D02000000000000
00900240 000A8000000000004012000000000000
00900250 0F0200000000000000E6830000000000
00900260 88120000000000001002000000000000
00900270 00C6870000000000D012000000000000
00900280 110200000000000000C8870000000000
00900290 18130000000000001202000000000000
009002A0 00A68B00000000008613000000000000
009002B0 440200000000000000FC8F0000000000
009003E0 00000000000000000814180100000000
009003F0 8080D6002FA0F6A14602000000000000
"""
SLBLOCK = """
00594D80 02000100000000007F81000000000000
00594D90 80130000000000000000000000000000
00594DB0 20005F5E505ED4D98613000000000000
"""
STORE_HN = """
00004800 EC00ECBC2000000000000000B5020600
00004810 40000000340E0201A0000000380E0300
00004820 00000000F90F02016000000001301F00
00004830 80000000DF35030089000000E0350201
00004840 C0000000E335020100010000E7350201
00004850 E000000033660B0001000000FA660300
00004860 0D000E00FF67030000000000229DB50A
00004870 DCD9944385DE90AEB07D127055004E00
00004880 490043004F0044004500310001000000
00004890 F55EF6669569CC4C83D1D87398990285
000048A0 0100000000000000229DB50ADCD99443
000048B0 85DE90AEB07D12702280000000000000
000048C0 229DB50ADCD9944385DE90AEB07D1270
000048D0 4280000000000000229DB50ADCD99443
000048E0 85DE90AEB07D12706280000008000000
000048F0 0C0014006C007C008C00A400BC00D400
00004900 EC00
"""
ROOT_HIERARCHY_TC = """
00004A00 BC01EC7C4000000000000000B5040400
00004A10 600000007C0D34003400350037002000
00004A20 000080000000000000000201300E1400
00004A30 04061400330E180008070201340E2000
00004A40 04080300380E240004091F0001300800
00004A50 0402030002360C000403030003361000
00004A60 04040B000A36340001051F0013362800
00004A70 040A030035662C00040B030036663000
00004A80 040C0300F267000004000300F3670400
00004A90 04012322000002000000228000000000
00004AA0 00004280000001000000228000000E00
00004AB0 0000A000000000000000000000000000
00004AD0 000000000000000000000000000001FC
00004AE0 004280000006000000C0000000000000
00004B10 000000000000FC00232200000B000000
00004B20 E0000000000000000000000000000000
00004B40 00000000000000000000000000FC0054
00004B50 006F00700020006F0066002000500065
00004B60 00720073006F006E0061006C00200046
00004B70 006F006C006400650072007300530065
00004B80 006100720063006800200052006F006F
00004B90 0074005300500041004D002000530065
00004BA0 006100720063006800200046006F006C
00004BB0 00640065007200200032000007000000
00004BC0 0C0014009200AA004F017D019301BB01
"""


def dump(text: str, base: int, size: int | None = None) -> bytes:
    rows = [line.split() for line in text.strip().splitlines()]
    end = max(int(o, 16) + len(h) // 2 for o, h in rows) - base
    buf = bytearray(max(end, size or 0))
    for o, h in rows:
        at = int(o, 16) - base
        buf[at:at + len(h) // 2] = bytes.fromhex(h)
    return bytes(buf)


class Counting:
    """A reader that reports a large size and counts what is read."""

    def __init__(self, data: bytes, size: int | None = None) -> None:
        self.data = data
        self.size = size or len(data)
        self.read_bytes = 0
        self.max_offset = 0

    def read_at(self, offset: int, length: int) -> bytes:
        self.read_bytes += length
        self.max_offset = max(self.max_offset, offset + length)
        chunk = self.data[offset:offset + length]
        if offset + length > len(self.data) and offset < self.size:
            chunk += bytes(min(self.size, offset + length) - max(offset, len(self.data)))
        return chunk


# ---------------------------------------------------------------------------

class SpecSamples(unittest.TestCase):
    """The sample structures printed in [MS-PST] §3 read with no problem
    and to the values the specification annotates."""

    def test_sample_header(self):
        header, layout, problems = pst.parse_header(dump(HEADER, 0, 564))
        self.assertEqual(problems, [])                 # both CRCs verify
        self.assertIs(layout, pst.UNICODE)
        self.assertEqual((header.version, header.client_version, header.crypt_method),
                         (23, 19, 1))
        self.assertEqual(header.nbt, (0x24B, 0x905200))
        self.assertEqual(header.bbt, (0x253, 0x900A00))
        self.assertEqual((header.file_eof, header.amap_last, header.bid_next_b,
                          header.bid_next_p, header.unique),
                         (0x9F2400, 0x9B4400, 0x1434, 0x254, 0x45))
        self.assertEqual((header.crc_partial_stored, header.crc_full_stored),
                         (0x379AA90E, 0x1FD283D6))

    def test_sample_pages_verify(self):
        cases = ((INTERMEDIATE_PAGE, 0x8200, 0x206, pst.PTYPE_NBT, 1, 3),
                 (NBT_PAGE, 0x7000, 0x6B, pst.PTYPE_NBT, 0, 14),
                 (BBT_PAGE, 0x900200, 0x246, pst.PTYPE_BBT, 1, 8))
        for text, ib, bid, ptype, level, count in cases:
            (got_level, entries), problems = pst.parse_bt_page(
                dump(text, ib, 512), ib, bid, ptype, pst.UNICODE)
            self.assertEqual(problems, [], hex(ib))
            self.assertEqual((got_level, len(entries)), (level, count))
        (_lvl, entries), _p = pst.parse_bt_page(dump(INTERMEDIATE_PAGE, 0x8200, 512),
                                                0x8200, 0x206, pst.PTYPE_NBT, pst.UNICODE)
        self.assertEqual(entries[2], (0x8022, 0xFD, 0x8400))
        (_lvl, entries), _p = pst.parse_bt_page(dump(NBT_PAGE, 0x7000, 512), 0x7000,
                                                0x6B, pst.PTYPE_NBT, pst.UNICODE)
        self.assertEqual(entries[10], pst.NodeEntry(0x8022, 0x54, 0, 0x122))

    def test_a_damaged_sample_page_is_reported_and_still_read(self):
        raw = bytearray(dump(NBT_PAGE, 0x7000, 512))
        raw[0x10] ^= 0xFF                       # inside an entry's padding
        result, problems = pst.parse_bt_page(bytes(raw), 0x7000, 0x6B,
                                             pst.PTYPE_NBT, pst.UNICODE)
        self.assertEqual(len(result[1]), 14)
        self.assertTrue(any("CRC mismatch" in p for p in problems), problems)
        moved, problems = pst.parse_bt_page(dump(NBT_PAGE, 0x7000, 512), 0x7200,
                                            0x6B, pst.PTYPE_NBT, pst.UNICODE)
        self.assertTrue(any("signature" in p for p in problems), problems)
        wrong, problems = pst.parse_bt_page(dump(NBT_PAGE, 0x7000, 512), 0x7000,
                                            0x6B, pst.PTYPE_BBT, pst.UNICODE)
        self.assertIsNone(wrong)
        self.assertTrue(any("is not a block B-tree page" in p for p in problems))

    def test_sample_slblock_trailer(self):
        raw = dump(SLBLOCK, 0x594D80, 64)
        inflated, problems = pst.check_block(raw, 0x594D80, 0x1386, 0x20, pst.UNICODE)
        self.assertEqual((inflated, problems), (0x20, []))
        btype, level, count = struct.unpack_from("<BBH", raw, 0)
        self.assertEqual((btype, level, count), (2, 0, 1))
        self.assertEqual(struct.unpack_from("<QQQ", raw, 8), (0x817F, 0x1380, 0))

    def test_sample_message_store_pc(self):
        problems: list = []
        heap = pst.heap_from_bytes([dump(STORE_HN, 0x4800)], problems=problems)
        pc = pst.PropertyContext(heap)
        self.assertEqual(pc.text(0x3001), "UNICODE1")
        self.assertEqual(pc.get(0x0FF9), bytes.fromhex("229DB50ADCD9944385DE90AEB07D1270"))
        self.assertEqual(struct.unpack_from("<I", pc.get(0x35E0), 20)[0], 0x8022)
        self.assertEqual(struct.unpack_from("<I", pc.get(0x35E3), 20)[0], 0x8062)
        self.assertEqual((pc.get(0x35DF), pc.get(0x67FF), pc.get(0x0E38)), (0x89, 0, 0))
        self.assertIs(pc.get(0x6633), True)
        self.assertEqual(len(pc.get(0x0E34)), 24)
        self.assertEqual(problems, [])

    def test_sample_root_hierarchy_tc(self):
        problems: list = []
        tc = pst.TableContext(pst.heap_from_bytes([dump(ROOT_HIERARCHY_TC, 0x4A00)],
                                                  problems=problems))
        self.assertEqual(len(tc.columns), 13)
        rows = list(tc.rows())
        self.assertEqual([(hex(r), v[0x3001]) for r, v in rows],
                         [("0x8022", "Top of Personal Folders"),
                          ("0x8042", "Search Root"),
                          ("0x2223", "SPAM Search Folder 2")])
        self.assertEqual([v[0x360A] for _r, v in rows], [True, False, False])
        self.assertIs(rows[0][1][0x0E30], pst.MISSING)   # its CEB bit is clear
        self.assertEqual(problems, [])


class Primitives(unittest.TestCase):
    def test_crc_is_the_specification_algorithm(self):
        for data in (b"", b"a", b"123456789", bytes(range(256)) * 9):
            self.assertEqual(pst.crc32(data), ps.spec_crc(data))
        self.assertEqual(pst.crc32(b""), 0)

    def test_signature(self):
        self.assertEqual(pst.signature(0x8200, 0x206), 0x8006)
        self.assertEqual(pst.signature(0x900200, 0x246), 0x00D6)

    def test_permutation_table_is_the_published_one(self):
        self.assertEqual(list(pst._ENC_R[:8]), [65, 54, 19, 98, 168, 33, 110, 187])
        self.assertEqual(list(pst._ENC_S[:8]), [20, 83, 15, 86, 179, 200, 122, 156])
        self.assertEqual(list(pst._ENC_I[-8:]), [237, 154, 100, 63, 193, 108, 249, 236])
        self.assertTrue(all(pst._ENC_I[pst._ENC_R[i]] == i for i in range(256)))
        self.assertTrue(all(pst._ENC_S[pst._ENC_S[i]] == i for i in range(256)))
        data = bytes(range(256)) * 3
        self.assertEqual(pst.decode_permute(pst.encode_permute(data)), data)

    def test_cyclic_is_symmetric_and_matches_the_spec_pseudocode(self):
        data = b"The cyclic cipher is keyed by the BID." * 20
        for key in (0x4, 0x12345678, 0xFFFFFFFC):
            enc = pst.cyclic(data, key)
            self.assertEqual(enc, ps.spec_cyclic(data, key))
            self.assertNotEqual(enc, data)
            self.assertEqual(pst.cyclic(enc, key), data)

    def test_codepages(self):
        self.assertEqual(pst.codec_for(1252), "cp1252")
        self.assertEqual(pst.codec_for(65001), "utf-8")
        self.assertEqual(pst.codec_for(28592), "iso8859_2")
        self.assertIsNone(pst.codec_for(99999))

    def test_compressed_rtf(self):
        rtf = b"{\\rtf1\\ansi\\ansicpg1252 Hello\\par}"
        self.assertEqual(pst.decompress_rtf(ps.rtf_stream(rtf)), rtf)
        self.assertEqual(pst.decompress_rtf(ps.rtf_stream(rtf, compressed=False)), rtf)
        # one reference into the preloaded dictionary, then the end marker
        body = bytes([0x03, 0x00, 0x09, 0x0D, 0xA0])
        stream = struct.pack("<IIII", len(body) + 12, 11, 0x75465A4C,
                             ps.spec_crc(body)) + body
        self.assertEqual(pst.decompress_rtf(stream), b"{\\rtf1\\ansi")
        bad = bytearray(ps.rtf_stream(rtf))
        bad[-3] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            pst.decompress_rtf(bytes(bad))

    def test_text_reducers(self):
        self.assertEqual(pst.rtf_to_text(b"{\\rtf1{\\fonttbl{\\f0 Arial;}}Hi \\'e9\\par "
                                         b"x\\u8364?y}").strip(), "Hi \u00e9\nx\u20acy")
        self.assertEqual(" ".join(pst.html_to_text(
            "<head><title>t</title></head><p>a<b>b</b></p><script>x</script>").split()),
            "ab")


class Header(unittest.TestCase):
    def test_not_a_pst(self):
        with self.assertRaisesRegex(FileSystemError, "!BDN"):
            pst.open_pst(b"MZ" + bytes(1000))

    def test_unknown_version(self):
        data = bytearray(ps.standard()[0])
        struct.pack_into("<H", data, 10, 5)
        with self.assertRaisesRegex(FileSystemError, "version 5"):
            pst.open_pst(bytes(data))

    def test_wip_and_unknown_encoding_are_refused(self):
        for crypt, words in ((0x10, "Windows Information Protection"),
                             (0x07, "not one")):
            data = bytearray(ps.standard()[0])
            data[513] = crypt
            with self.assertRaisesRegex(FileSystemError, words):
                pst.open_pst(bytes(data))

    def test_header_crc_damage_is_reported_not_fatal(self):
        data = bytearray(ps.standard()[0])
        data[16] ^= 0x55                                # dwReserved1
        p = pst.open_pst(bytes(data))
        self.assertTrue(any("partial CRC" in x for x in p.problems))
        self.assertTrue(any("full CRC" in x for x in p.problems))
        self.assertEqual(len(list(p.iter_folders())), 5)

    def test_layouts_and_kinds(self):
        for layout, crypt, kind, name in (("unicode", 0, "pst-unicode", "unicode"),
                                          ("ansi", 1, "pst-ansi", "ansi"),
                                          ("unicode-4k", 2, "pst-unicode", "unicode-4k")):
            p = pst.open_pst(ps.standard(layout, crypt)[0])
            self.assertEqual((p.kind, p.layout.name, p.encryption, p.problems),
                             (kind, name, pst.CRYPT_NAMES[crypt], []))
        b = ps.Builder("unicode-4k", client=b"SO")
        b.store()
        b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER)
        self.assertEqual(pst.open_pst(b.build()).kind, "ost")

    def test_truncated_file(self):
        data = ps.standard()[0]
        with self.assertRaisesRegex(FileSystemError, "root page"):
            pst.open_pst(data[:len(data) - 600])
        padded = ps.standard()[1].build(pad_to=len(data) + 4096)
        p = pst.open_pst(padded)                        # header records a bigger file
        self.assertTrue(any("truncated" in x for x in p.problems), p.problems)


# ---------------------------------------------------------------------------

STANDARD = {(layout, crypt): ps.standard(layout, crypt, compress=(layout == "unicode-4k"))
            for layout in ("unicode", "ansi", "unicode-4k") for crypt in (0, 1, 2)}


class Messaging(unittest.TestCase):
    """The standard synthetic store, read the same in every layout/encoding."""

    def each(self):
        for (layout, crypt), (data, _b, facts) in STANDARD.items():
            yield f"{layout}/{crypt}", pst.open_pst(data), facts

    def test_folder_tree(self):
        for label, p, facts in self.each():
            with self.subTest(label):
                paths = [(f.path, f.kind) for f in p.iter_folders()]
                self.assertEqual(paths, [("/", "normal"),
                                         ("/Top of Personal Folders", "normal"),
                                         ("/Top of Personal Folders/Inbox", "normal"),
                                         ("/Top of Personal Folders/Sent Items", "normal"),
                                         ("/Finder", "search")])
                inbox = p.folder(facts["inbox"])
                self.assertEqual((inbox.content_count, inbox.container_class),
                                 (2, "IPF.Note"))
                self.assertEqual(list(p.messages(p.folder(facts["search"]))), [])
                self.assertEqual(p.store["display_name"], "Synthetic Store")
                self.assertEqual(p.store["ipm_subtree_nid"], facts["top"])
                for f in p.iter_folders():
                    self.assertEqual(f.problems, [], f.path)

    def test_message_headers(self):
        for label, p, facts in self.each():
            with self.subTest(label):
                m = p.message(facts["m1"])
                self.assertEqual(m.folder_path, "/Top of Personal Folders/Inbox")
                self.assertEqual((m.subject, m.subject_prefix_length),
                                 ("RE: Quarterly figures", 4))
                self.assertEqual(m.sender, "Alice Example <alice@example.com>")
                self.assertEqual(m.sender_email, "/O=EXAMPLE/CN=ALICE")
                self.assertEqual([(r.kind, r.name, r.address) for r in m.recipients],
                                 [("to", "Bob Example", "bob@example.com"),
                                  ("cc", "Carol Example", "carol@example.com"),
                                  ("bcc", "Dan Hidden", "dan@example.com")])
                self.assertEqual(m.client_submit_time, ps.T0)
                self.assertEqual(m.delivery_time, ps.T0 + 600_000_000)
                self.assertEqual(timeutil.decode(m.client_submit_time, "filetime"),
                                 "2019-04-17T18:40:00.000000Z")
                self.assertEqual(m.internet_message_id, "<q1@example.com>")
                self.assertIn("Date: Mon, 4 Feb 2019", m.transport_headers)
                self.assertEqual((m.body_kind, m.body_excerpt),
                                 ("plain", "Quarterly figures attached.\n\nRegards,\nAlice"))
                self.assertEqual(m.problems, [])

    def test_attachments(self):
        for label, p, facts in self.each():
            with self.subTest(label):
                m = p.message(facts["m1"])
                self.assertEqual([(a.filename, a.method_name, a.data_type) for a in m.attachments],
                                 [("figures.bin", "by-value", "binary"),
                                  ("small.txt", "by-value", "binary"),
                                  ("forwarded", "embedded-message", "object")])
                self.assertEqual(m.attachments[0].mime_type, "application/octet-stream")
                self.assertEqual(p.read_attachment(m, 0), facts["big"])
                self.assertEqual(p.read_attachment(m, 1), b"small attachment\r\n")
                self.assertEqual(b"".join(p.attachment_chunks(m, 0)), facts["big"])
                with self.assertRaisesRegex(FileSystemError, "embedded message"):
                    p.read_attachment(m, 2)
                with self.assertRaisesRegex(FileSystemError, "no attachment 7"):
                    p.read_attachment(m, 7)
                inner = p.embedded_message(m, 2)
                self.assertEqual((inner.subject, inner.sender, inner.addressed("to"),
                                  inner.body_excerpt, inner.embedded),
                                 ("Inner message", "Eve <eve@example.com>",
                                  "Alice Example <alice@example.com>", "inner body", True))

    def test_ole_storage_attachment_reads_the_stored_object(self):
        b = ps.Builder("unicode", 2)
        b.store()
        inbox = ps.nid(0x402, 2)
        b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER, children=[(inbox, "Inbox")])
        obj_nid = ps.nid(0x7FF, pst.NID_TYPE_LTP)
        storage = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + bytes(5000)
        blocks, subs = b.message_parts(subject="ole", recipients=[])
        att_blocks, att_subs = b.pc({0x3705: (pst.PT_LONG, 6), 0x3001: (pst.PT_UNICODE, "Picture"),
                                     0x3701: (pst.PT_OBJECT, (obj_nid, len(storage)))})
        att_nid = ps.nid(0x400, pst.NID_TYPE_ATTACHMENT)
        tb, ts = b.tc([0x37050003], [(att_nid, {0x37050003: 6})])
        subs += [(att_nid, b.blocks_tree(att_blocks),
                  b.subnode_tree(list(att_subs) + [(obj_nid, b.data_tree(storage), 0)])),
                 (0x671, b.blocks_tree(tb), b.subnode_tree(ts))]
        msg = ps.nid(0x10000, 4)
        b.node(msg, b.blocks_tree(blocks), b.subnode_tree(subs), inbox)
        b.folder(inbox, "Inbox", pst.NID_ROOT_FOLDER, messages=[(msg, "ole")])
        p = pst.open_pst(b.build())
        m = p.message(msg)
        self.assertEqual((m.attachments[0].method_name, m.attachments[0].data_type,
                          m.attachments[0].display_name), ("ole-storage", "object", "Picture"))
        self.assertEqual(p.read_attachment(m, 0), storage)

    def test_rtf_and_html_bodies_and_string8(self):
        for label, p, facts in self.each():
            with self.subTest(label):
                m2 = p.message(facts["m2"])
                self.assertEqual(m2.body_kind, "rtf")
                self.assertEqual(p.body(m2), ("rtf", facts["rtf"]))
                self.assertIn("Hello RTF world", m2.body_excerpt)
                self.assertTrue(m2.body_excerpt.startswith("[RTF body reduced to text"))
                m3 = p.message(facts["m3"])
                self.assertEqual((m3.subject, m3.codepage), ("Résumé", "cp1252"))
                self.assertEqual(m3.addressed("to"), "Zoë Recipient <zoe@example.com>")
                self.assertEqual(m3.body_kind, "html")
                self.assertIn("Hello HTML\n\nLine two", m3.body_excerpt)
                self.assertNotIn("p{}", m3.body_excerpt)


class Ndb(unittest.TestCase):
    def test_deep_btrees_are_walked_and_searched(self):
        b = ps.standard()[1]
        b.nbt_leaf_cap = b.bbt_leaf_cap = 3
        p = pst.open_pst(b.build())
        levels = {lvl for _t, _ib, lvl in b.page_offsets}
        self.assertGreaterEqual(max(levels), 2)
        nodes = list(p.iter_nodes())
        self.assertEqual(len(nodes), len(b.nodes))
        for nid in b.nodes:
            self.assertEqual(p.node(nid).nid, nid)
        self.assertIsNone(p.node(0x7FFFFFE4))
        for bid in b.blocks:
            self.assertEqual(p.block_entry(bid).ib, b.offsets[bid][0])
        self.assertEqual(len([m for _f, m in p.iter_messages()]), 3)
        self.assertEqual(p.problems, [])

    def test_xxblock_data_tree(self):
        for layout in ("unicode", "ansi"):
            b = ps.Builder(layout, 1)
            chunks = [bytes([i]) * 1000 for i in range(5)]
            leaves = [b.block(c) for c in chunks]
            fmt = "<Q" if b.unicode else "<I"
            x1 = b.block(struct.pack("<BBHI", 1, 1, 2, 2000) +
                         b"".join(struct.pack(fmt, x) for x in leaves[:2]), internal=True)
            x2 = b.block(struct.pack("<BBHI", 1, 1, 3, 3000) +
                         b"".join(struct.pack(fmt, x) for x in leaves[2:]), internal=True)
            xx = b.block(struct.pack("<BBHI", 1, 2, 2, 5000) +
                         struct.pack(fmt, x1) + struct.pack(fmt, x2), internal=True)
            bad = b.block(struct.pack("<BBHI", 1, 1, 2, 9999) +
                          b"".join(struct.pack(fmt, x) for x in leaves[:2]), internal=True)
            b.store()
            b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER)
            p = pst.open_pst(b.build())
            self.assertEqual(p.node_bytes(xx), b"".join(chunks))
            sink: list = []
            self.assertEqual(p.node_bytes(bad, sink), b"".join(chunks[:2]))
            self.assertTrue(any("records 9999" in s for s in sink), sink)

    def test_siblock_subnode_tree(self):
        for layout in ("unicode", "ansi"):
            b = ps.Builder(layout)
            entries = [(ps.nid(0x100 + i, pst.NID_TYPE_LTP), b.block(bytes([i]) * 10), 0)
                       for i in range(7)]
            top = b.subnode_tree(entries, per_block=2)
            b.store()
            b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER)
            p = pst.open_pst(b.build())
            self.assertEqual(p.block(top)[1], 1)            # an SIBLOCK
            subs = p.subnodes(top)
            self.assertEqual(sorted(subs), [e[0] for e in entries])
            self.assertEqual(p.block(subs[entries[3][0]][0]), bytes([3]) * 10)

    def test_block_damage_is_reported_on_the_message_and_read_around(self):
        data, b, facts = ps.standard("unicode", 1)
        p0 = pst.open_pst(data)
        m = p0.message(facts["m1"])
        att = m.attachments[0]
        first = next(iter(pst.open_pst(data).subnodes(att._bid_sub).values()))[0]
        leaf = pst.open_pst(data).block(first)
        bid = struct.unpack_from("<Q", leaf, 8)[0] if first & 2 else first
        ib, cb = b.offsets[bid]
        damaged = bytearray(data)
        damaged[ib + 10] ^= 0xFF
        p = pst.open_pst(bytes(damaged))
        m = p.message(facts["m1"])
        content = p.read_attachment(m, 0)
        self.assertEqual(len(content), len(facts["big"]))
        self.assertNotEqual(content, facts["big"])
        self.assertTrue(any("CRC mismatch" in x for x in m.attachments[0].problems),
                        m.attachments[0].problems)
        again = p.message(facts["m1"])                  # a cached block still reports
        p.read_attachment(again, 0)
        self.assertTrue(any("CRC mismatch" in x for x in again.attachments[0].problems))

    def test_missing_block_and_unreadable_node(self):
        data, b, facts = ps.standard()
        b2 = ps.standard()[1]
        b2.message(ps.nid(0x10009, 4), facts["inbox"], subject="x")
        b2.nodes[ps.nid(0x10009, 4)] = (0x7FFFFC, 0, facts["inbox"])
        p = pst.open_pst(b2.build())
        m = p.message(ps.nid(0x10009, 4))
        self.assertTrue(any("not in the block B-tree" in x for x in m.problems), m.problems)
        self.assertTrue(any("missing or unreadable" in x for x in m.problems), m.problems)

    def test_a_wrong_page_type_loses_only_what_is_below_it(self):
        b = ps.standard()[1]
        b.nbt_leaf_cap = 4
        data = bytearray(b.build())
        leaves = [ib for t, ib, lvl in b.page_offsets if t == 0x81 and lvl == 0]
        victim = leaves[-1]
        data[victim + 496] = 0x84                       # ptype: an AMap page
        p = pst.open_pst(bytes(data))
        readable = list(p.iter_nodes())
        self.assertTrue(any("is not a node B-tree page" in x for x in p.problems),
                        p.problems)
        lost = len(b.nodes) - 4 * (len(leaves) - 1)
        self.assertEqual(len(readable), len(b.nodes) - lost)
        self.assertEqual(p.store["display_name"], "Synthetic Store")

    def test_streaming_reads_only_what_it_needs(self):
        data, b, _facts = ps.standard()
        big = 8 << 30
        reader = Counting(b.build(pad_to=big), size=big)
        p = pst.open_pst(reader)
        rows = pst.to_rows(p, source_path="E:/big.pst")
        self.assertEqual(len(rows), 4)
        self.assertLess(reader.read_bytes, 4 * len(data))
        self.assertLess(reader.max_offset, len(data) + 4096)


class Ltp(unittest.TestCase):
    def node_pc(self, layout, props, **kw):
        b = ps.Builder(layout)
        b.store()
        b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER)
        blocks, subs = b.pc(props, **kw)
        b.node_from(ps.nid(0x900, 1), blocks, subs)
        p = pst.open_pst(b.build())
        return p, p.node_pc(ps.nid(0x900, 1), "test PC"), len(blocks)

    def test_bth_index_levels(self):
        props = {0x6000 + i: (pst.PT_LONG, i * 3) for i in range(40)}
        for layout in ("unicode", "ansi", "unicode-4k"):
            _p, pc, _n = self.node_pc(layout, props, leaf_cap=3)
            self.assertEqual({k: pc.get(k) for k in props}, {k: v for k, (_t, v) in props.items()})

    def test_multi_block_heap_and_subnode_values(self):
        long_text = "x" * 3000
        props = {0x6100 + i: (pst.PT_UNICODE, f"{i}" + long_text[:1700]) for i in range(8)}
        props[0x6200] = (pst.PT_UNICODE, "big " * 2500)            # > 3580 bytes
        props[0x6201] = (pst.PT_BINARY, bytes(range(256)) * 40)
        for layout in ("unicode", "ansi", "unicode-4k"):
            p, pc, nblocks = self.node_pc(layout, props)
            self.assertGreater(nblocks, 1)
            for pid, (_t, value) in props.items():
                self.assertEqual(pc.get(pid), value, hex(pid))
            self.assertEqual(pc.text(0x6200, limit=10), "big big bi")

    def test_value_types(self):
        props = {0x6300: (pst.PT_I2, -2), 0x6301: (pst.PT_BOOLEAN, True),
                 0x6302: (pst.PT_I8, -(1 << 40)), 0x6303: (pst.PT_DOUBLE, 2.5),
                 0x6304: (pst.PT_SYSTIME, ps.T0), 0x6305: (pst.PT_CLSID, bytes(range(16))),
                 0x6306: (0x1003, [1, 2, 3]), 0x6307: (0x101F, ["a", "bc", ""]),
                 0x6308: (0x1102, [b"\x01", b"\x02\x03"]), 0x6309: (pst.PT_UNICODE, ""),
                 0x630A: (pst.PT_STRING8, "caf\xe9")}
        _p, pc, _n = self.node_pc("unicode", props)
        self.assertEqual(pc.get(0x6300), -2)
        self.assertIs(pc.get(0x6301), True)
        self.assertEqual(pc.get(0x6302), -(1 << 40))
        self.assertEqual(pc.get(0x6303), 2.5)
        self.assertEqual(pc.get(0x6304), ps.T0)
        self.assertEqual(pc.get(0x6305), "03020100-0504-0706-0809-0a0b0c0d0e0f")
        self.assertEqual(pc.get(0x6306), [1, 2, 3])
        self.assertEqual(pc.get(0x6307), ["a", "bc", ""])
        self.assertEqual(pc.get(0x6308), [b"\x01", b"\x02\x03"])
        self.assertEqual((pc.get(0x6309), pc.get(0x630A)), ("", "café"))
        self.assertIsNone(pc.get(0x7777))

    def test_row_matrix_in_a_subnode_across_blocks(self):
        cols = [0x60000014 + (i << 16) for i in range(10)] + [0x3001001F]
        rows = [(0x200004 + 32 * i, {**{c: i * 1000 + k for k, c in enumerate(cols[:10])},
                                     0x3001001F: f"row {i}"})
                for i in range(250)]
        for layout in ("unicode", "ansi", "unicode-4k"):
            b = ps.Builder(layout)
            b.store()
            b.folder(pst.NID_ROOT_FOLDER, "", pst.NID_ROOT_FOLDER)
            blocks, subs = b.tc(cols, rows, force_subnode=True)
            b.node_from(ps.nid(0x901, 0x0E), blocks, subs)
            p = pst.open_pst(b.build())
            problems: list = []
            tc = p.node_tc(ps.nid(0x901, 0x0E), "wide table", problems)
            self.assertGreater(len(list(tc._matrix_blocks())), 2)
            got = list(tc.rows())
            self.assertEqual([r for r, _v in got], [r for r, _v in rows])
            self.assertEqual(got[200][1][0x6005], 200 * 1000 + 5)
            self.assertEqual(got[249][1][0x3001], "row 249")
            self.assertEqual(problems, [])

    def test_damaged_heap_is_reported(self):
        heap = bytearray(dump(STORE_HN, 0x4800))
        heap[2] = 0x00                                   # bSig
        with self.assertRaisesRegex(pst._Unreadable, "not a heap"):
            pst.heap_from_bytes([bytes(heap)])
        problems: list = []
        pc = pst.PropertyContext(pst.heap_from_bytes([dump(STORE_HN, 0x4800)],
                                                     problems=problems))
        pc.props[0x7000] = (pst.PT_UNICODE, 0x3E0)      # an HID past the page map
        self.assertIsNone(pc.get(0x7000))
        self.assertTrue(any("allocation 31" in x for x in problems), problems)


class Rows(unittest.TestCase):
    def test_row_shape_and_times(self):
        data, b, facts = STANDARD[("unicode", 1)]
        rows = pst.to_rows(pst.open_pst(data), source_path="C:/x/Outlook.pst")
        keys = {"artefact", "at_utc", "at_raw", "at_epoch", "title", "value",
                "detail", "row_ref_suffix"}
        for row in rows:
            self.assertEqual(set(row), keys)
            json.dumps(row)
        self.assertEqual(len({r["row_ref_suffix"] for r in rows}), len(rows))
        mail = {r["detail"]["nid"]: r for r in rows if r["artefact"] == "email"}
        r1, r2 = mail[facts["m1"]], mail[facts["m2"]]
        self.assertEqual((r1["at_raw"], r1["at_epoch"], r1["detail"]["time_basis"]),
                         (ps.T0, "filetime", "client-submit-time"))
        self.assertEqual(r1["at_utc"], timeutil.decode(ps.T0, "filetime"))
        self.assertEqual((r2["at_raw"], r2["detail"]["time_basis"]),
                         (ps.T0 + 10**10, "delivery-time"))
        email = r1["detail"]["email"]
        self.assertEqual(email["from"], "Alice Example <alice@example.com>")
        self.assertEqual(email["to"], "Bob Example <bob@example.com>")
        self.assertEqual(email["cc"], "Carol Example <carol@example.com>")
        self.assertEqual(email["date_raw"], "Mon, 4 Feb 2019 10:00:00 +0000")
        self.assertEqual(email["attachments"], ["figures.bin", "small.txt", "forwarded"])
        self.assertEqual(r1["detail"]["folder"], "/Top of Personal Folders/Inbox")
        self.assertEqual(r1["detail"]["bcc"], "Dan Hidden <dan@example.com>")
        self.assertEqual(r1["row_ref_suffix"], f"nid{facts['m1']:x}")
        store = [r for r in rows if r["artefact"] == "email-store"][0]
        self.assertEqual(store["detail"]["messages_listed"], 3)
        self.assertEqual(store["detail"]["message_nodes_not_listed"], 0)
        self.assertEqual(store["detail"]["encryption"], "permute")

    def test_non_mail_items_unlisted_nodes_and_long_bodies(self):
        b = ps.standard()[1]
        inbox = ps.nid(0x402, 2)
        contacts = ps.nid(0x405, 2)
        b.message(ps.nid(0x10005, 4), contacts, subject="Jane Contact",
                  cls="IPM.Contact", recipients=None)
        b.folder(contacts, "Contacts", ps.nid(0x401, 2),
                 messages=[(ps.nid(0x10005, 4), "Jane Contact")])
        b.message(ps.nid(0x10007, 4), inbox, subject="orphan", body="z")
        b.message(ps.nid(0x10008, 4), contacts, subject="long", body="w" * 10000,
                  recipients=None)
        b.folder(contacts, "Contacts", ps.nid(0x401, 2),
                 messages=[(ps.nid(0x10005, 4), "Jane Contact"),
                           (ps.nid(0x10008, 4), "long")])
        top_children = [(ps.nid(0x402, 2), "Inbox"), (ps.nid(0x403, 2), "Sent Items"),
                        (contacts, "Contacts")]
        b.folder(ps.nid(0x401, 2), "Top of Personal Folders", pst.NID_ROOT_FOLDER,
                 children=top_children)
        p = pst.open_pst(b.build())
        rows = pst.to_rows(p, source_path="x.pst")
        kinds = {r["title"]: r["artefact"] for r in rows}
        self.assertEqual(kinds["Jane Contact"], "pst-item")
        self.assertEqual(kinds["long"], "email")
        long_row = [r for r in rows if r["title"] == "long"][0]
        self.assertEqual(len(long_row["detail"]["body_excerpt"]), pst.EXCERPT)
        self.assertIsNone(long_row["at_utc"])
        store = [r for r in rows if r["artefact"] == "email-store"][0]["detail"]
        self.assertEqual(store["message_nodes_not_listed"], 1)
        self.assertEqual(store["message_nodes_not_listed_nids"],
                         [f"0x{ps.nid(0x10007, 4):X}"])

    def test_content_count_disagreement_is_noted(self):
        b = ps.standard()[1]
        facts = ps.standard()[2]
        b.folder(facts["sent"], "Sent Items", facts["top"],
                 messages=[(facts["m3"], "Résumé")], content_count=5)
        p = pst.open_pst(b.build())
        sent = p.folder(facts["sent"])
        list(p.messages(sent))
        self.assertTrue(any("records 5 items" in x for x in sent.problems), sent.problems)


# ---------------------------------------------------------------------------

def _sample(test, name):
    path = os.path.join(SAMPLES, name)
    if not os.path.exists(path):
        raise unittest.SkipTest(f"real sample {name} is not present under {SAMPLES} "
                                "(downloaded for validation only, never shipped)")

    class FileReader:
        def __init__(self) -> None:
            self.f = open(path, "rb")
            self.f.seek(0, 2)
            self.size = self.f.tell()

        def read_at(self, offset, length):
            self.f.seek(offset)
            return self.f.read(length)

    reader = FileReader()
    test.addCleanup(reader.f.close)
    return reader


class RealSamples(unittest.TestCase):
    """Counts confirmed against pypff and readpst when this was written."""

    EXPECTED = {  # name: (kind, layout, encryption, folders, messages, attachments)
        "enron.pst": ("pst-unicode", "unicode", "permute", 11, 71, 70),
        "aspose-test.pst": ("pst-unicode", "unicode", "permute", 25, 193, 196),
        "example-2013.ost": ("ost", "unicode-4k", "none", 46, 3, 0),
        "mtnman1965@outlook.com.ost": ("ost", "unicode-4k", "none", 60, 214, 11),
        "pstextractortest@outlook.com.ost": ("ost", "unicode-4k", "none", 57, 183, 34),
        "aspose-SampleOstFile.ost": ("ost", "unicode", "permute", 45, 92, 39),
    }

    def test_counts(self):
        for name, expected in self.EXPECTED.items():
            with self.subTest(name=name):
                reader = _sample(self, name)
                p = pst.open_pst(reader)
                folders = list(p.iter_folders())
                msgs = [m for f in folders for m in p.messages(f)]
                self.assertEqual((p.kind, p.layout.name, p.encryption, len(folders),
                                  len(msgs), sum(len(m.attachments) for m in msgs)),
                                 expected)
                self.assertEqual(p.problems, [])
                self.assertEqual([m.problems for m in msgs if m.problems], [])
                rows = pst.to_rows(p, source_path=name)
                self.assertEqual(len(rows), len(msgs) + 1)

    def test_against_pypff(self):
        try:
            import pypff  # noqa: F401  (container-only validation dependency)
        except ImportError:
            raise unittest.SkipTest("pypff (libpff) is not installed here")
        for name in ("enron.pst", "pstextractortest@outlook.com.ost"):
            with self.subTest(name=name):
                reader = _sample(self, name)
                f = pypff.file()
                f.open(os.path.join(SAMPLES, name))
                theirs = {}

                def walk(folder):
                    for i in range(folder.number_of_sub_folders):
                        sub = folder.get_sub_folder(i)
                        for j in range(sub.number_of_sub_messages):
                            m = sub.get_sub_message(j)
                            rs = m.get_record_set(0)
                            subj = rs.get_entry_by_type(0x0037)
                            sent = rs.get_entry_by_type(0x0039)
                            theirs[m.identifier] = (
                                (subj.data_as_string if subj else "") or "",
                                sent.data_as_integer if sent else None)
                        walk(sub)
                walk(f.get_root_folder())
                p = pst.open_pst(reader)
                ours = {m.nid: (m.subject, m.client_submit_time)
                        for _f, m in p.iter_messages()}
                strip = {k: ((s[2:] if s[:1] == "\x01" else s), t)
                         for k, (s, t) in theirs.items()}
                self.assertEqual(ours, strip)


if __name__ == "__main__":
    unittest.main()
