"""A small Outlook data file writer, built from [MS-PST], for the test suite.

It writes what a reader needs and nothing more: a HEADER with both CRCs,
a block B-tree and node B-tree of real BTPAGEs (several levels when asked),
blocks with BLOCKTRAILERs (CRC, signature, BID), XBLOCK data trees, SLBLOCK
and SIBLOCK subnode trees, Heap-on-Node with HNPAGEMAPs (several heap
blocks when the data needs them), BTree-on-Heap (with index levels when
asked), Property Contexts and Table Contexts (Row Matrix in the heap or in
a subnode data tree), and the messaging objects on top. AMaps, PMaps, the
density list, templates and the name-to-ID map are not written: an
Outlook would refuse the result, a reader that follows the B-trees does not
need them.

The CRC and the cyclic cipher are written out again here from the
specification's pseudo-code rather than imported, so the reader is not
checked against itself. The permutation table is taken from the module;
the test suite checks it against rows quoted from [MS-PST] §5.1.
"""

from __future__ import annotations

import struct
import zlib

import _support  # noqa: F401
from forensics_workshop import pst as _pst

T0 = 132_000_000_000_000_000         # a FILETIME in 2019

_CRC_TABLE = []
for _n in range(256):
    _c = _n
    for _ in range(8):
        _c = (_c >> 1) ^ 0xEDB88320 if _c & 1 else _c >> 1
    _CRC_TABLE.append(_c)


def spec_crc(data: bytes) -> int:
    """[MS-PST] §5.3 ComputeCRC, byte at a time, seed 0, no inversion."""
    crc = 0
    for b in data:
        crc = _CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def spec_sig(ib: int, bid: int) -> int:
    ib ^= bid
    return ((ib >> 16) ^ ib) & 0xFFFF


def spec_cyclic(data: bytes, key: int) -> bytes:
    """[MS-PST] §5.2 CryptCyclic, as written there."""
    r, s, i_tab = _pst._ENC_R, _pst._ENC_S, _pst._ENC_I
    w = (key ^ (key >> 16)) & 0xFFFF
    out = bytearray()
    for b in data:
        b = (b + (w & 0xFF)) & 0xFF
        b = r[b]
        b = (b + (w >> 8)) & 0xFF
        b = s[b]
        b = (b - (w >> 8)) & 0xFF
        b = i_tab[b]
        b = (b - (w & 0xFF)) & 0xFF
        out.append(b)
        w = (w + 1) & 0xFFFF
    return bytes(out)


def rtf_stream(rtf: bytes, *, compressed: bool = True) -> bytes:
    """A PidTagRtfCompressed value ([MS-OXRTFCP]): LZFu of literals plus the
    end marker, or MELA (stored)."""
    if not compressed:
        return struct.pack("<IIII", len(rtf) + 12, len(rtf), 0x414C454D, 0) + rtf
    body = bytearray()
    pos, write = 0, 207
    while True:
        chunk = rtf[pos:pos + 8]
        if len(chunk) == 8:
            body.append(0)
            body += chunk
            pos += 8
            write = (write + 8) & 0xFFF
            continue
        control = 1 << len(chunk)                 # the end-marker reference
        body.append(control)
        body += chunk
        write = (write + len(chunk)) & 0xFFF
        body += struct.pack(">H", write << 4)
        break
    return struct.pack("<IIII", len(body) + 12, len(rtf), 0x75465A4C,
                       spec_crc(bytes(body))) + bytes(body)


def nid(index: int, nid_type: int) -> int:
    return (index << 5) | nid_type


def entryid(uid: bytes, target: int) -> bytes:
    return b"\x00" * 4 + uid + struct.pack("<I", target)


# ---------------------------------------------------------------------------

class HeapWriter:
    """Heap-on-Node allocations, split over blocks as they fill."""

    def __init__(self, b: "Builder", client_sig: int) -> None:
        self.b, self.sig = b, client_sig
        self.blocks: list = [[]]
        self.used = [12]

    def hid(self, block: int, index: int) -> int:
        if self.b.four_k:
            return (block << 19) | (index << 5)
        return (block << 16) | (index << 5)

    def alloc(self, data: bytes) -> int:
        assert len(data) <= 3580, "heap items are at most 3580 bytes"
        i = len(self.blocks) - 1
        need = self.used[i] + len(data) + 1 + 4 + 2 * (len(self.blocks[i]) + 2)
        if need > self.b.max_data and self.blocks[i]:
            self.blocks.append([])
            self.used.append(2)
            i += 1
        self.blocks[i].append(bytes(data))
        self.used[i] += len(data)
        return self.hid(i, len(self.blocks[i]))

    def serialize(self, user_root: int) -> list:
        out = []
        for i, items in enumerate(self.blocks):
            head = 12 if i == 0 else 2
            body = bytearray(head)
            offsets = [head]
            for item in items:
                body += item
                offsets.append(len(body))
            if len(body) % 2:
                body.append(0)
            ibm = len(body)
            body += struct.pack("<HH", len(items), 0)
            body += struct.pack(f"<{len(offsets)}H", *offsets)
            if i == 0:
                struct.pack_into("<HBBII", body, 0, ibm, 0xEC, self.sig, user_root, 0)
            else:
                struct.pack_into("<H", body, 0, ibm)
            out.append(bytes(body))
        return out


def bth(heap: HeapWriter, cb_key: int, cb_ent: int, records: list,
        leaf_cap: int | None = None) -> int:
    """A BTH over sorted (key bytes, data bytes); returns the BTHHEADER HID."""
    if not records:
        return heap.alloc(struct.pack("<BBBBI", 0xB5, cb_key, cb_ent, 0, 0))
    size = cb_key + cb_ent
    cap = leaf_cap or (3580 // size)
    level = [(records[i][0], b"".join(k + d for k, d in records[i:i + cap]))
             for i in range(0, len(records), cap)]
    level = [(k, heap.alloc(blob)) for k, blob in level]
    depth = 0
    while len(level) > 1:
        depth += 1
        icap = leaf_cap or (3580 // (cb_key + 4))
        nxt = []
        for i in range(0, len(level), icap):
            group = level[i:i + icap]
            blob = b"".join(k + struct.pack("<I", h) for k, h in group)
            nxt.append((group[0][0], heap.alloc(blob)))
        level = nxt
    return heap.alloc(struct.pack("<BBBBI", 0xB5, cb_key, cb_ent, depth, level[0][1]))


def encode_value(ptype: int, value, codepage: str = "cp1252") -> bytes:
    P = _pst
    if ptype & P.MV_FLAG:
        base = ptype & ~P.MV_FLAG
        items = [encode_value(base, v, codepage) for v in value]
        if base in P.FIXED_SIZE:
            return b"".join(items)
        head = 4 + 4 * len(items)
        offs, pos = [], head
        for it in items:
            offs.append(pos)
            pos += len(it)
        return struct.pack(f"<I{len(items)}I", len(items), *offs) + b"".join(items)
    if ptype == P.PT_UNICODE:
        return value.encode("utf-16-le")
    if ptype == P.PT_STRING8:
        return value.encode(codepage)
    if ptype == P.PT_BINARY:
        return bytes(value)
    if ptype == P.PT_LONG:
        return struct.pack("<i", value)
    if ptype == P.PT_I2:
        return struct.pack("<h", value)
    if ptype == P.PT_BOOLEAN:
        return b"\x01" if value else b"\x00"
    if ptype in (P.PT_SYSTIME,):
        return struct.pack("<Q", value)
    if ptype in (P.PT_I8, P.PT_CURRENCY):
        return struct.pack("<q", value)
    if ptype in (P.PT_DOUBLE, P.PT_APPTIME):
        return struct.pack("<d", value)
    if ptype == P.PT_CLSID:
        return bytes(value)
    raise ValueError(f"no encoder for 0x{ptype:04X}")


class Builder:
    """Collects blocks and nodes; `build()` lays out the file."""

    def __init__(self, layout: str = "unicode", crypt: int = 0, *,
                 compress: bool = False, encode_first: bool = True,
                 client: bytes = b"SM",
                 nbt_leaf_cap: int | None = None,
                 bbt_leaf_cap: int | None = None) -> None:
        self.layout = layout
        self.unicode = layout != "ansi"
        self.four_k = layout == "unicode-4k"
        self.crypt, self.compress, self.client = crypt, compress, client
        self.encode_first = encode_first
        self.max_data = 8192 - (12 if not self.unicode else 16)
        self.blocks: dict = {}           # bid -> (raw data, internal)
        self.nodes: dict = {}            # nid -> (bid_data, bid_sub, parent)
        self.next_bid = 4
        self.next_ltp = 0x100
        self.nbt_leaf_cap, self.bbt_leaf_cap = nbt_leaf_cap, bbt_leaf_cap
        self.offsets: dict = {}          # bid -> (ib, cb on disk)
        self.page_offsets: list = []     # (ptype, ib, level)
        self.uid = bytes(range(0x10, 0x20))

    # -- NDB --------------------------------------------------------------------

    def block(self, data: bytes, internal: bool = False) -> int:
        bid = self.next_bid | (2 if internal else 0)
        self.next_bid += 4
        self.blocks[bid] = (bytes(data), internal)
        return bid

    def data_tree(self, data: bytes) -> int:
        chunks = [data[i:i + self.max_data]
                  for i in range(0, len(data), self.max_data)] or [b""]
        return self.blocks_tree(chunks)

    def blocks_tree(self, chunks: list) -> int:
        if len(chunks) == 1:
            return self.block(chunks[0])
        idsz = 8 if self.unicode else 4
        per = (self.max_data - 8) // idsz
        fmt = "<Q" if self.unicode else "<I"
        xblocks = []
        for i in range(0, len(chunks), per):
            group = chunks[i:i + per]
            bids = [self.block(c) for c in group]
            body = struct.pack("<BBHI", 1, 1, len(bids), sum(len(c) for c in group))
            body += b"".join(struct.pack(fmt, b) for b in bids)
            xblocks.append((self.block(body, internal=True), sum(len(c) for c in group)))
        if len(xblocks) == 1:
            return xblocks[0][0]
        body = struct.pack("<BBHI", 1, 2, len(xblocks), sum(n for _b, n in xblocks))
        body += b"".join(struct.pack(fmt, b) for b, _n in xblocks)
        return self.block(body, internal=True)

    def subnode_tree(self, entries: list, per_block: int | None = None) -> int:
        """entries: [(nid, bid_data, bid_sub)]. SIBLOCK over SLBLOCKs when
        there are more than `per_block` entries."""
        if not entries:
            return 0
        entries = sorted(entries)
        u = self.unicode
        fmt, pad = ("<QQQ", b"\x00" * 4) if u else ("<III", b"")
        per = per_block or ((self.max_data - 8) // (24 if u else 12))
        leaves = []
        for i in range(0, len(entries), per):
            group = entries[i:i + per]
            body = struct.pack("<BBH", 2, 0, len(group)) + pad
            body += b"".join(struct.pack(fmt, *e) for e in group)
            leaves.append((group[0][0], self.block(body, internal=True)))
        if len(leaves) == 1:
            return leaves[0][1]
        body = struct.pack("<BBH", 2, 1, len(leaves)) + pad
        body += b"".join(struct.pack("<QQ" if u else "<II", k, b) for k, b in leaves)
        return self.block(body, internal=True)

    def node(self, node_nid: int, bid_data: int, bid_sub: int = 0, parent: int = 0):
        self.nodes[node_nid] = (bid_data, bid_sub, parent)

    def ltp_nid(self) -> int:
        self.next_ltp += 1
        return nid(self.next_ltp, _pst.NID_TYPE_LTP)

    # -- LTP --------------------------------------------------------------------

    def pc(self, props: dict, *, leaf_cap: int | None = None,
           codepage: str = "cp1252") -> tuple:
        """props {pid: (ptype, value)} -> (heap blocks, subnode entries)."""
        P = _pst
        heap = HeapWriter(self, P.BTYPE_PC)
        subs = []
        records = []
        for pid in sorted(props):
            ptype, value = props[pid]
            if ptype == P.PT_OBJECT:              # value: (nid, size)
                hnid = heap.alloc(struct.pack("<II", *value))
            else:
                raw = encode_value(ptype, value, codepage)
                size = P.FIXED_SIZE.get(ptype)
                if size is not None and not ptype & P.MV_FLAG and size <= 4:
                    hnid = int.from_bytes(raw.ljust(4, b"\x00"), "little")
                elif len(raw) <= 3580:
                    hnid = heap.alloc(raw)
                else:
                    hnid = self.ltp_nid()
                    subs.append((hnid, self.data_tree(raw), 0))
            records.append((struct.pack("<H", pid), struct.pack("<HI", ptype, hnid)))
        root = bth(heap, 2, 6, records, leaf_cap=leaf_cap)
        return heap.serialize(root), subs

    def tc(self, columns: list, rows: list, *, force_subnode: bool = False,
           codepage: str = "cp1252") -> tuple:
        """columns: [tag]; rows: [(row id, {tag: value})] -> (blocks, subs)."""
        P = _pst
        tags = [0x67F20003, 0x67F30003] + [t for t in columns
                                           if t not in (0x67F20003, 0x67F30003)]

        def width(tag):
            size = P.FIXED_SIZE.get(tag & 0xFFFF)
            if size is None or tag & P.MV_FLAG or size > 8:
                return 4
            return size

        order = tags[:2] + sorted(tags[2:], key=lambda t: -width(t))
        layout, pos, ib = {}, 0, [0, 0, 0, 0]
        for t in order:
            layout[t] = pos
            pos += width(t)
            if width(t) >= 4:
                ib[0] = pos
        ib[0] = ib[0] or pos
        ib[1] = ib[0] + sum(width(t) for t in order if width(t) == 2)
        ib[2] = ib[1] + sum(width(t) for t in order if width(t) == 1)
        ib[3] = ib[2] + (len(order) + 7) // 8
        row_size = ib[3]
        ibit = {t: i for i, t in enumerate(order)}
        heap = HeapWriter(self, P.BTYPE_TC)
        subs = []
        matrix = []
        for index, (row_id, values) in enumerate(rows):
            row = bytearray(row_size)
            vals = dict(values)
            vals[0x67F20003] = row_id
            vals.setdefault(0x67F30003, index)
            for t in order:
                if t not in vals:
                    continue
                ptype = t & 0xFFFF
                raw = encode_value(ptype, vals[t], codepage)
                if width(t) == 4 and (P.FIXED_SIZE.get(ptype) is None or
                                      ptype & P.MV_FLAG or P.FIXED_SIZE[ptype] > 8):
                    if len(raw) <= 3580:
                        raw = struct.pack("<I", heap.alloc(raw))
                    else:
                        sub = self.ltp_nid()
                        subs.append((sub, self.data_tree(raw), 0))
                        raw = struct.pack("<I", sub)
                row[layout[t]:layout[t] + width(t)] = raw[:width(t)].ljust(width(t), b"\0")
                bit = ibit[t]
                row[ib[2] + bit // 8] |= 1 << (7 - bit % 8)
            matrix.append(bytes(row))
        hnid_rows = 0
        if matrix:
            blob = b"".join(matrix)
            if len(blob) <= 3580 and not force_subnode:
                hnid_rows = heap.alloc(blob)
            else:
                per = self.max_data // row_size
                chunks = [b"".join(matrix[i:i + per]) for i in range(0, len(matrix), per)]
                hnid_rows = self.ltp_nid()
                subs.append((hnid_rows, self.blocks_tree(chunks), 0))
        idx_fmt = "<I" if self.unicode else "<H"
        index_records = sorted((struct.pack("<I", rid), struct.pack(idx_fmt, i))
                               for i, (rid, _v) in enumerate(rows))
        hid_index = bth(heap, 4, 4 if self.unicode else 2, index_records)
        coldesc = b"".join(struct.pack("<IHBB", t, layout[t], width(t), ibit[t])
                           for t in sorted(order))
        info = struct.pack("<BB4HIII", 0x7C, len(order), *ib, hid_index,
                           hnid_rows, 0) + coldesc
        root = heap.alloc(info)
        return heap.serialize(root), subs

    def node_from(self, node_nid: int, heap_blocks: list, subs: list,
                  parent: int = 0, extra_subs: list = ()) -> None:
        all_subs = list(subs) + list(extra_subs)
        self.node(node_nid, self.blocks_tree(heap_blocks),
                  self.subnode_tree(all_subs), parent)

    # -- messaging ----------------------------------------------------------------

    def store(self, name: str = "Synthetic Store", ipm: int = nid(0x401, 2),
              password_crc: int = 0) -> None:
        props = {0x3001: (0x001F, name), 0x0FF9: (0x0102, self.uid),
                 0x35E0: (0x0102, entryid(self.uid, ipm))}
        if password_crc:
            props[0x67FF] = (0x0003, password_crc)
        blocks, subs = self.pc(props)
        self.node_from(_pst.NID_MESSAGE_STORE, blocks, subs)

    def folder(self, folder_nid: int, name: str, parent: int, *,
               children: list = (), messages: list = (), search: bool = False,
               content_count: int | None = None, force_subnode: bool = False,
               container_class: str | None = None) -> None:
        props = {0x3001: (0x001F, name),
                 0x3602: (0x0003, len(messages) if content_count is None
                          else content_count),
                 0x3603: (0x0003, 0), 0x360A: (0x000B, bool(children))}
        if container_class:
            props[0x3613] = (0x001F, container_class)
        blocks, subs = self.pc(props)
        self.node_from(folder_nid, blocks, subs, parent)
        if search:
            return
        base = folder_nid & ~0x1F
        rows = [(c, {0x3001001F: n}) for c, n in children]
        blocks, subs = self.tc([0x3001001F, 0x36020003], rows)
        self.node_from(base | 0x0D, blocks, subs, 0)
        rows = [(m, {0x0037001F: s}) for m, s in messages]
        blocks, subs = self.tc([0x0037001F, 0x0E060040], rows,
                               force_subnode=force_subnode)
        self.node_from(base | 0x0E, blocks, subs, 0)
        blocks, subs = self.tc([0x001A001F], [])
        self.node_from(base | 0x0F, blocks, subs, 0)

    def message_parts(self, *, subject: str = "", sender=("", "", ""),
                      recipients: list = (), attachments: list = (),
                      submit: int | None = None, delivery: int | None = None,
                      created: int | None = None, body: str | None = None,
                      html: bytes | None = None, rtf: bytes | None = None,
                      headers: str = "", message_id: str = "",
                      cls: str = "IPM.Note", string8: bool = False,
                      codepage: int | None = None, extra: dict | None = None,
                      flags: int | None = None) -> tuple:
        """(heap blocks, subnode entries) of a Message object."""
        P = _pst
        st = P.PT_STRING8 if string8 else P.PT_UNICODE
        cpname = _pst.codec_for(codepage) if codepage else "cp1252"
        props = {0x001A: (st, cls), 0x0037: (st, subject),
                 0x0E07: (P.PT_LONG, flags if flags is not None else
                          (0x10 if attachments else 0)),
                 0x0E08: (P.PT_LONG, 1234)}
        name, email, smtp = sender
        if name:
            props[0x0C1A] = (st, name)
        if email:
            props[0x0C1F] = (st, email)
            props[0x0C1E] = (st, "SMTP")
        if smtp:
            props[0x5D01] = (st, smtp)
        for pid, val in ((0x0039, submit), (0x0E06, delivery), (0x3007, created)):
            if val is not None:
                props[pid] = (P.PT_SYSTIME, val)
        if body is not None:
            props[0x1000] = (st, body)
        if html is not None:
            props[0x1013] = (P.PT_BINARY, html)
        if rtf is not None:
            props[0x1009] = (P.PT_BINARY, rtf)
        if headers:
            props[0x007D] = (st, headers)
        if message_id:
            props[0x1035] = (st, message_id)
        if codepage:
            props[0x3FFD] = (P.PT_LONG, codepage)
        props.update(extra or {})
        blocks, subs = self.pc(props, codepage=cpname)
        subs = list(subs)
        if recipients is not None:
            rows = []
            for k, (rtype, rname, remail, rsmtp) in enumerate(recipients):
                vals = {0x0C150003: rtype, 0x3001001F: rname, 0x3003001F: remail,
                        0x3002001F: "SMTP"}
                if rsmtp:
                    vals[0x39FE001F] = rsmtp
                rows.append((k, vals))
            rb, rs = self.tc([0x0C150003, 0x3001001F, 0x3003001F, 0x3002001F,
                              0x39FE001F], rows)
            subs.append((0x692, self.blocks_tree(rb), self.subnode_tree(rs)))
        if attachments:
            rows = []
            for k, att in enumerate(attachments):
                att_nid = nid(0x400 + k, P.NID_TYPE_ATTACHMENT)
                fname, data, method = att["name"], att.get("data", b""), att.get("method", 1)
                aprops = {0x3707: (P.PT_UNICODE, fname),
                          0x3704: (P.PT_UNICODE, fname[:8]),
                          0x3705: (P.PT_LONG, method),
                          0x0E20: (P.PT_LONG, len(data) + 200),
                          0x370B: (P.PT_LONG, -1)}
                if att.get("mime"):
                    aprops[0x370E] = (P.PT_UNICODE, att["mime"])
                inner_subs = []
                if att.get("embedded") is not None:
                    inner_nid = nid(0x700 + k, P.NID_TYPE_NORMAL_MESSAGE)
                    eblocks, esubs = self.message_parts(**att["embedded"])
                    inner_subs.append((inner_nid, self.blocks_tree(eblocks),
                                       self.subnode_tree(esubs)))
                    aprops[0x3701] = (P.PT_OBJECT, (inner_nid, 999))
                else:
                    aprops[0x3701] = (P.PT_BINARY, data)
                ab, asubs = self.pc(aprops)
                subs.append((att_nid, self.blocks_tree(ab),
                             self.subnode_tree(list(asubs) + inner_subs)))
                rows.append((att_nid, {0x3704001F: fname[:8],
                                       0x0E200003: len(data) + 200,
                                       0x37050003: method}))
            tb, ts = self.tc([0x3704001F, 0x0E200003, 0x37050003, 0x370B0003], rows)
            subs.append((0x671, self.blocks_tree(tb), self.subnode_tree(ts)))
        return blocks, subs

    def message(self, msg_nid: int, folder_nid: int, **kw) -> None:
        blocks, subs = self.message_parts(**kw)
        self.node(msg_nid, self.blocks_tree(blocks), self.subnode_tree(subs),
                  folder_nid)

    # -- layout -------------------------------------------------------------------

    def _encode(self, bid: int, data: bytes) -> bytes:
        if bid & 2:
            return data
        if self.crypt == 1:
            return bytes(data).translate(_pst._ENC_R)
        if self.crypt == 2:
            return spec_cyclic(data, bid & 0xFFFFFFFF)
        return data

    def _page(self, ptype: int, level: int, entries: list, ib: int, bid: int) -> bytes:
        u = self.unicode
        if self.four_k:
            size, area, span = 4096, 4056, 4072
        else:
            size, area, span = 512, (488 if u else 496), (496 if u else 500)
        if level:
            fmt = "<QQQ" if u else "<III"
        elif ptype == 0x80:
            fmt = "<QQHHI" if u else "<IIHH"
        else:
            fmt = "<QQQII" if u else "<IIII"
        cb = struct.calcsize(fmt)
        page = bytearray(size)
        for i, e in enumerate(entries):
            struct.pack_into(fmt, page, i * cb, *e)
        if self.four_k:
            struct.pack_into("<HHBB", page, area, len(entries), area // cb, cb, level)
        else:
            struct.pack_into("<BBBB", page, area, len(entries), area // cb, cb, level)
        sig = spec_sig(ib, bid)
        crc = spec_crc(bytes(page[:span]))
        if u:
            struct.pack_into("<BBHIQ", page, span, ptype, ptype, sig, crc, bid)
        else:
            struct.pack_into("<BBHII", page, span, ptype, ptype, sig, bid, crc)
        return bytes(page)

    def build(self, *, pad_to: int | None = None) -> bytes:
        u, k4 = self.unicode, self.four_k
        self.offsets, self.page_offsets = {}, []
        trailer = 24 if k4 else (16 if u else 12)
        align = 512 if k4 else 64
        page_size = 4096 if k4 else 512
        out = bytearray(0x4400)
        bbt = []
        for bid in sorted(self.blocks):
            data, internal = self.blocks[bid]
            inflated = len(data)
            if k4 and self.compress and not internal and len(data) > 64:
                if self.encode_first:            # what libpff expects
                    stored = zlib.compress(self._encode(bid, data))
                else:
                    stored = self._encode(bid, zlib.compress(data))
            else:
                stored = self._encode(bid, data)
            ib = len(out)
            size = -(-(len(stored) + trailer) // align) * align
            blk = bytearray(size)
            blk[:len(stored)] = stored
            sig, crc = spec_sig(ib, bid), spec_crc(stored)
            if k4:
                struct.pack_into("<HHIQHHI", blk, size - trailer, len(stored), sig,
                                 crc, bid, 2, inflated, 0)
            elif u:
                struct.pack_into("<HHIQ", blk, size - trailer, len(stored), sig, crc, bid)
            else:
                struct.pack_into("<HHII", blk, size - trailer, len(stored), sig, bid, crc)
            out += blk
            self.offsets[bid] = (ib, len(stored))
            bbt.append((bid, ib, len(stored)))
        if len(out) % page_size:
            out += bytes(page_size - len(out) % page_size)
        next_page_bid = [1]

        def tree(ptype, leaf_entries, leaf_cap):
            entry_size = (24 if ptype == 0x80 else 32) if u else (12 if ptype == 0x80 else 16)
            area = 4056 if k4 else (488 if u else 496)
            cap = leaf_cap or area // entry_size
            icap = leaf_cap or area // (24 if u else 12)
            level, lvl = [], 0
            for i in range(0, len(leaf_entries), cap):
                group = leaf_entries[i:i + cap]
                ib, bid = len(out), next_page_bid[0]
                next_page_bid[0] += 1
                out.extend(self._page(ptype, 0, group, ib, bid))
                self.page_offsets.append((ptype, ib, 0))
                level.append((group[0][0], bid, ib))
            while len(level) > 1:
                lvl += 1
                nxt = []
                for i in range(0, len(level), icap):
                    group = level[i:i + icap]
                    ib, bid = len(out), next_page_bid[0]
                    next_page_bid[0] += 1
                    out.extend(self._page(ptype, lvl, group, ib, bid))
                    self.page_offsets.append((ptype, ib, lvl))
                    nxt.append((group[0][0], bid, ib))
                level = nxt
            return level[0][1], level[0][2]

        bbt_entries = [((b, ib, cb, 2, 0) if u else (b, ib, cb, 2)) for b, ib, cb in bbt]
        bbt_root = tree(0x80, bbt_entries, self.bbt_leaf_cap)
        nbt_entries = [((n, bd, bs, p, 0) if u else (n, bd, bs, p))
                       for n, (bd, bs, p) in sorted(self.nodes.items())]
        nbt_root = tree(0x81, nbt_entries, self.nbt_leaf_cap)
        eof = max(len(out), pad_to or 0)
        version = 36 if k4 else (23 if u else 14)
        if u:
            hdr = bytearray(564)
            hdr[0:4] = b"!BDN"
            struct.pack_into("<2sHHBBII", hdr, 8, self.client, version, 19, 1, 1, 0, 0)
            struct.pack_into("<QQI", hdr, 24, 0, next_page_bid[0], 7)
            struct.pack_into("<IQQQQQQQQBBH", hdr, 180, 0, eof, 0, 0, 0,
                             nbt_root[0], nbt_root[1], bbt_root[0], bbt_root[1], 2, 0, 0)
            hdr[256:512] = b"\xff" * 256
            hdr[512], hdr[513] = 0x80, self.crypt
            struct.pack_into("<Q", hdr, 516, self.next_bid)
            struct.pack_into("<I", hdr, 4, spec_crc(bytes(hdr[8:8 + 471])))
            struct.pack_into("<I", hdr, 524, spec_crc(bytes(hdr[8:8 + 516])))
        else:
            hdr = bytearray(512)
            hdr[0:4] = b"!BDN"
            struct.pack_into("<2sHHBBII", hdr, 8, self.client, version, 19, 1, 1, 0, 0)
            struct.pack_into("<III", hdr, 24, self.next_bid, next_page_bid[0], 7)
            struct.pack_into("<IIIIIIIIIBBH", hdr, 164, 0, eof, 0, 0, 0,
                             nbt_root[0], nbt_root[1], bbt_root[0], bbt_root[1], 2, 0, 0)
            hdr[204:460] = b"\xff" * 256
            hdr[460], hdr[461] = 0x80, self.crypt
            struct.pack_into("<I", hdr, 4, spec_crc(bytes(hdr[8:8 + 471])))
        out[:len(hdr)] = hdr
        return bytes(out)


def standard(layout: str = "unicode", crypt: int = 0, **kw) -> tuple:
    """A small store: root, Top of Personal Folders, Inbox (two messages:
    one with recipients, a large attachment and an embedded message; one
    RTF-only), Sent Items (one HTML-only message, String8 strings) and a
    search folder. Returns (bytes, builder, facts)."""
    P = _pst
    b = Builder(layout, crypt, **kw)
    root, top = P.NID_ROOT_FOLDER, nid(0x401, 2)
    inbox, sent, search = nid(0x402, 2), nid(0x403, 2), nid(0x404, 3)
    m1, m2, m3 = nid(0x10000, 4), nid(0x10001, 4), nid(0x10002, 4)
    big = bytes((i * 7 + 3) & 0xFF for i in range(20000))      # > 2 data blocks
    rtf = b"{\\rtf1\\ansi\\ansicpg1252 Hello \\b RTF\\b0  world\\par second}"
    b.store()
    b.folder(root, "", root, children=[(top, "Top of Personal Folders"),
                                    (search, "Finder")])
    b.folder(top, "Top of Personal Folders", root,
             children=[(inbox, "Inbox"), (sent, "Sent Items")])
    b.folder(inbox, "Inbox", top, messages=[(m1, "RE: Quarterly"), (m2, "Notice")],
             container_class="IPF.Note")
    b.folder(sent, "Sent Items", top, messages=[(m3, "Résumé")])
    b.folder(search, "Finder", root, search=True)
    b.message(m1, inbox, subject="\x01\x05RE: Quarterly figures",
              sender=("Alice Example", "/O=EXAMPLE/CN=ALICE", "alice@example.com"),
              recipients=[(1, "Bob Example", "bob@example.com", ""),
                          (2, "Carol Example", "carol@example.com", ""),
                          (3, "Dan Hidden", "dan@example.com", "")],
              attachments=[{"name": "figures.bin", "data": big,
                            "mime": "application/octet-stream"},
                           {"name": "small.txt", "data": b"small attachment\r\n"},
                           {"name": "forwarded", "method": 5,
                            "embedded": dict(subject="Inner message",
                                             sender=("Eve", "eve@example.com", ""),
                                             recipients=[(1, "Alice Example",
                                                          "alice@example.com", "")],
                                             body="inner body", submit=T0 - 10**9)}],
              submit=T0, delivery=T0 + 600_000_000, created=T0 + 600_000_001,
              body="Quarterly figures attached.\r\n\r\nRegards,\r\nAlice",
              headers="Received: from mx\r\nDate: Mon, 4 Feb 2019 10:00:00 +0000\r\n"
                      "Subject: RE: Quarterly figures\r\n",
              message_id="<q1@example.com>")
    b.message(m2, inbox, subject="Notice", sender=("System", "", ""),
              recipients=[(1, "Alice Example", "alice@example.com", "")],
              delivery=T0 + 10**10, rtf=rtf_stream(rtf))
    b.message(m3, sent, subject="Résumé", sender=("Alice Example", "alice@example.com", ""),
              recipients=[(1, "Zoë Recipient", "zoe@example.com", "")],
              submit=T0 + 2 * 10**10, delivery=T0 + 2 * 10**10 + 5,
              html=b"<html><head><style>p{}</style></head><body><p>Hello "
                   b"<b>HTML</b></p><p>Line two</p></body></html>",
              string8=True, codepage=1252)
    facts = {"root": root, "top": top, "inbox": inbox, "sent": sent,
             "search": search, "m1": m1, "m2": m2, "m3": m3, "big": big, "rtf": rtf}
    return b.build(), b, facts
