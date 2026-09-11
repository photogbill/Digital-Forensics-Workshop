"""Synthetic disks, volumes and journals, built byte by byte — never real evidence.

The same rule as `synth.py`: every structure here has a known shape and a
known story, and nothing is committed. These builders follow the published
layouts (MBR, UEFI GPT, NTFS boot sector / FILE records / attributes / data
runs, USN_RECORD_V2/V3/V4) so the parsers can be tested where no disk tools
exist — on Windows, in CI, anywhere.

**A builder that shares a parser's misunderstanding would pass everything.**
That is why `test_real_tools.py` exists: on a machine with ntfs-3g, sfdisk and
sgdisk it builds REAL volumes and partition tables with those tools and
checks the parsers against them. What only these builders can make — deleted
parents whose records were reused, set-by-hand timestamps, torn records,
attribute lists, a change journal — is kept to the documented layouts.
"""

from __future__ import annotations

import gzip
import io
import sqlite3
import struct
import tempfile
import uuid
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path

SECTOR = 512
CLUSTER = 4096
RECORD = 1024
EPOCH_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)


def filetime(dt: datetime, ticks: int = 0) -> int:
    """A FILETIME for `dt` (whole seconds) plus `ticks` of 100 ns."""
    return int((dt - EPOCH_1601).total_seconds()) * 10_000_000 + ticks


T0 = filetime(datetime(2024, 3, 1, 12, 0, 0, tzinfo=timezone.utc), 1234567)


def align(n: int, to: int = 8) -> int:
    return (n + to - 1) // to * to


def crc32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


# ---------------------------------------------------------------------------
# partition tables
# ---------------------------------------------------------------------------

def mbr_sector(entries, disk_id: int = 0x1234ABCD) -> bytearray:
    """entries: [(status, type, start_lba, sectors)] — up to four."""
    sector = bytearray(SECTOR)
    struct.pack_into("<I", sector, 0x1B8, disk_id)
    for i, (status, ptype, start, count) in enumerate(entries):
        base = 0x1BE + 16 * i
        sector[base] = status
        sector[base + 4] = ptype
        struct.pack_into("<II", sector, base + 8, start, count)
    sector[510:512] = b"\x55\xaa"
    return sector


def guid_bytes(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


BASIC_DATA = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
LINUX_FS = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
EFI_SYSTEM = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def gpt_disk(sectors: int, partitions, *, ss: int = SECTOR,
             disk_guid: str = "11111111-2222-3333-4444-555555555555",
             protective: bool = True) -> bytearray:
    """A whole GPT disk. partitions: [dict(type, guid, first, last, name,
    attrs)] with LBAs in `ss`-byte sectors."""
    disk = bytearray(sectors * ss)
    count, esize = 128, 128
    array = bytearray(count * esize)
    for i, p in enumerate(partitions):
        e = bytearray(esize)
        e[0:16] = guid_bytes(p["type"])
        e[16:32] = guid_bytes(p.get("guid", str(uuid.UUID(int=i + 1))))
        struct.pack_into("<QQQ", e, 32, p["first"], p["last"], p.get("attrs", 0))
        name = p.get("name", "").encode("utf-16-le")[:72]
        e[56:56 + len(name)] = name
        array[i * esize:(i + 1) * esize] = e
    array_sectors = -(-len(array) // ss)
    last_lba = sectors - 1
    first_usable = 2 + array_sectors
    last_usable = last_lba - 1 - array_sectors

    def header(current, backup, entries_lba):
        h = bytearray(ss)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", h, 8, 0x00010000, 92, 0, 0, current,
                         backup, first_usable, last_usable)
        h[56:72] = guid_bytes(disk_guid)
        struct.pack_into("<QIII", h, 72, entries_lba, count, esize, crc32(array))
        struct.pack_into("<I", h, 16, crc32(bytes(h[:92])))
        return h

    if protective:
        disk[0:SECTOR] = mbr_sector([(0, 0xEE, 1, min(sectors - 1, 0xFFFFFFFF))])
    disk[ss:2 * ss] = header(1, last_lba, 2)
    disk[2 * ss:2 * ss + len(array)] = array
    backup_entries = last_lba - array_sectors
    disk[backup_entries * ss:backup_entries * ss + len(array)] = array
    disk[last_lba * ss:(last_lba + 1) * ss] = header(last_lba, 1, backup_entries)
    return disk


# ---------------------------------------------------------------------------
# NTFS
# ---------------------------------------------------------------------------

def encode_runs(runs) -> bytes:
    """[(lcn or None, clusters)] → a data run list, offsets relative."""
    out = bytearray()
    prev = 0
    for lcn, count in runs:
        length = count.to_bytes(max(1, (count.bit_length() + 7) // 8), "little")
        if lcn is None:
            out.append(len(length))
            out += length
            continue
        delta = lcn - prev
        size = 1
        while not -(1 << (8 * size - 1)) <= delta < (1 << (8 * size - 1)):
            size += 1
        out.append(len(length) | (size << 4))
        out += length + delta.to_bytes(size, "little", signed=True)
        prev = lcn
    out.append(0)
    return bytes(out)


def resident(atype: int, value: bytes, name: str = "", aid: int = 0,
             flags: int = 0) -> bytes:
    nb = name.encode("utf-16-le")
    name_off = 0x18
    value_off = align(name_off + len(nb))
    total = align(value_off + len(value))
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, atype, total, 0, len(name), name_off,
                     flags, aid)
    struct.pack_into("<IHBB", a, 16, len(value), value_off, 0, 0)
    a[name_off:name_off + len(nb)] = nb
    a[value_off:value_off + len(value)] = value
    return bytes(a)


def nonresident(atype: int, runs, size: int, *, name: str = "", aid: int = 0,
                flags: int = 0, init: int | None = None, start_vcn: int = 0,
                alloc: int | None = None) -> bytes:
    nb = name.encode("utf-16-le")
    run_bytes = encode_runs(runs)
    clusters = sum(n for _l, n in runs)
    name_off = 0x40
    runs_off = align(name_off + len(nb))
    total = align(runs_off + len(run_bytes))
    a = bytearray(total)
    struct.pack_into("<IIBBHHH", a, 0, atype, total, 1, len(name), name_off,
                     flags, aid)
    struct.pack_into("<QQHH", a, 16, start_vcn, start_vcn + clusters - 1,
                     runs_off, 0)
    alloc = clusters * CLUSTER if alloc is None else alloc
    struct.pack_into("<QQQ", a, 40, alloc, size, size if init is None else init)
    a[name_off:name_off + len(nb)] = nb
    a[runs_off:runs_off + len(run_bytes)] = run_bytes
    return bytes(a)


def si_value(times, attrs: int = 0x20) -> bytes:
    created, modified, changed, accessed = times
    v = bytearray(72)
    struct.pack_into("<QQQQI", v, 0, created, modified, changed, accessed, attrs)
    return bytes(v)


def fn_value(parent: int, parent_seq: int, name: str, times, *, size: int = 0,
             ns: int = 1, flags: int = 0x20) -> bytes:
    nb = name.encode("utf-16-le")
    v = bytearray(66 + len(nb))
    struct.pack_into("<Q", v, 0, parent | (parent_seq << 48))
    struct.pack_into("<QQQQQQI", v, 8, *times, align(size, CLUSTER), size, flags)
    v[64] = len(name)
    v[65] = ns
    v[66:] = nb
    return bytes(v)


def record_bytes(number: int, attrs, *, seq: int = 1, flags: int = 1,
                 links: int = 1, base_ref: int = 0, torn: bool = False,
                 lsn: int = 0x1000, usn_value: int = 0x0005) -> bytes:
    rec = bytearray(RECORD)
    rec[0:4] = b"FILE"
    struct.pack_into("<HH", rec, 4, 0x30, 3)
    struct.pack_into("<QHHHH", rec, 8, lsn, seq, links, 0x38, flags)
    body = b"".join(attrs) + b"\xff\xff\xff\xff\x00\x00\x00\x00"
    used = 0x38 + len(body)
    if used > RECORD - 8:
        raise ValueError(f"record {number} is too full ({used} bytes)")
    struct.pack_into("<IIQHHI", rec, 24, used, RECORD, base_ref, 16, 0, number)
    rec[0x38:0x38 + len(body)] = body
    usn = struct.pack("<H", usn_value)
    rec[0x30:0x32] = usn
    for i in (1, 2):
        pos = i * SECTOR - 2
        rec[0x30 + 2 * i:0x32 + 2 * i] = rec[pos:pos + 2]
        rec[pos:pos + 2] = usn
    if torn:
        rec[RECORD - 2:RECORD] = b"\x00\x00" if usn != b"\x00\x00" else b"\x01\x01"
    return bytes(rec)


class NtfsBuilder:
    """A small NTFS volume: 4 KiB clusters, 1 KiB records, 512-byte sectors.

    Only what a reader of the MFT needs is present — boot sector and its
    backup, $MFT (with its $BITMAP), $MFTMirr, $Volume, the root, $Bitmap,
    $Extend — plus whatever a test adds. There is no $LogFile and no
    directory index: the parser rebuilds paths from $FILE_NAME, not indexes.
    """

    def __init__(self, clusters: int = 1024, *, label: str = "SYNTH",
                 mft_records: int = 128, serial: int = 0x0123456789ABCDEF):
        self.clusters = clusters
        self.image = bytearray(clusters * CLUSTER)
        self.used = bytearray(clusters)             # one byte per cluster
        self.label = label
        self.serial = serial
        self.mft_records = mft_records
        self.mft_lcn = 4
        self.mft_clusters = -(-mft_records * RECORD // CLUSTER)
        self.mirr_lcn = 2
        self.bitmap_lcn = self.mft_lcn + self.mft_clusters
        self.bitmap_clusters = -(-((clusters + 7) // 8) // CLUSTER)
        for lcn in [0, self.mirr_lcn, *range(self.mft_lcn, self.mft_lcn + self.mft_clusters),
                    *range(self.bitmap_lcn, self.bitmap_lcn + self.bitmap_clusters)]:
            self.used[lcn] = 1
        self.next_free = self.bitmap_lcn + self.bitmap_clusters + 8
        self.records: dict[int, bytes] = {}
        self.seqs: dict[int, int] = {5: 5, 11: 11}
        t = (T0, T0, T0, T0)
        self._system(5, ".", 5, directory=True, seq=5, times=t)
        self._system(11, "$Extend", 5, directory=True, seq=11, times=t)
        vol_attrs = [resident(0x10, si_value(t, 0x06)),
                     resident(0x30, fn_value(5, 5, "$Volume", t, ns=3), aid=1),
                     resident(0x60, label.encode("utf-16-le"), aid=2),
                     resident(0x70, bytes(8) + bytes([3, 1]) + b"\x00\x00", aid=3)]
        self.records[3] = record_bytes(3, vol_attrs, seq=3)
        self.seqs[3] = 3

    # -- allocation --------------------------------------------------------
    def alloc(self, count: int) -> int:
        lcn = self.next_free
        if lcn + count > self.clusters:
            raise ValueError("synthetic volume is full")
        for i in range(count):
            self.used[lcn + i] = 1
        self.next_free += count
        return lcn

    def write(self, lcn: int, data: bytes) -> None:
        self.image[lcn * CLUSTER:lcn * CLUSTER + len(data)] = data

    def _system(self, number, name, parent, *, directory=False, seq=1, times=None):
        t = times or (T0, T0, T0, T0)
        attrs = [resident(0x10, si_value(t, 0x06)),
                 resident(0x30, fn_value(parent, self.seqs.get(parent, parent),
                                         name, t, ns=3), aid=1)]
        self.records[number] = record_bytes(number, attrs, seq=seq,
                                            flags=1 | (2 if directory else 0))
        self.seqs[number] = seq

    # -- files ---------------------------------------------------------------
    def directory(self, number: int, name: str, parent: int = 5, *,
                  seq: int = 1, in_use: bool = True, parent_seq: int | None = None,
                  times=None) -> None:
        t = times or (T0, T0, T0, T0)
        pseq = self.seqs.get(parent, 1) if parent_seq is None else parent_seq
        attrs = [resident(0x10, si_value(t, 0x10)),
                 resident(0x30, fn_value(parent, pseq, name, t, flags=0x10000000),
                          aid=1)]
        self.records[number] = record_bytes(number, attrs, seq=seq,
                                            flags=(1 if in_use else 0) | 2)
        self.seqs[number] = seq

    def file(self, number: int, name: str, data: bytes = b"", parent: int = 5, *,
             seq: int = 1, in_use: bool = True, parent_seq: int | None = None,
             si_times=None, fn_times=None, ads: dict | None = None,
             resident_data: bool | None = None, data_flags: int = 0,
             fragments: int = 1, extra_names=(), torn: bool = False,
             free_clusters: bool = False) -> list:
        """Add a file; returns its runs [(lcn, clusters)] ([] if resident)."""
        si_t = si_times or (T0, T0, T0, T0)
        fn_t = fn_times or si_t
        pseq = self.seqs.get(parent, 1) if parent_seq is None else parent_seq
        attrs = [resident(0x10, si_value(si_t)),
                 resident(0x30, fn_value(parent, pseq, name, fn_t, size=len(data)),
                          aid=1)]
        for i, (p, ps, nm, ns) in enumerate(extra_names):
            attrs.append(resident(0x30, fn_value(p, ps, nm, fn_t, ns=ns), aid=10 + i))
        runs: list = []
        small = len(data) <= 256 if resident_data is None else resident_data
        if small:
            attrs.append(resident(0x80, data, aid=2, flags=data_flags))
        else:
            need = -(-len(data) // CLUSTER)
            pieces = [need // fragments + (1 if i < need % fragments else 0)
                      for i in range(fragments)]
            pos = 0
            for count in pieces:
                if not count:
                    continue
                lcn = self.alloc(count)
                self.next_free += 3                     # leave a gap: fragments
                self.write(lcn, data[pos:pos + count * CLUSTER])
                pos += count * CLUSTER
                runs.append((lcn, count))
            attrs.append(nonresident(0x80, runs, len(data), aid=2,
                                     flags=data_flags))
            if free_clusters:
                for lcn, count in runs:
                    for i in range(count):
                        self.used[lcn + i] = 0
        for i, (stream, value) in enumerate((ads or {}).items()):
            attrs.append(resident(0x80, value, name=stream, aid=3 + i))
        self.records[number] = record_bytes(number, attrs, seq=seq,
                                            flags=1 if in_use else 0, torn=torn)
        self.seqs[number] = seq
        return runs

    def _check_number(self, number: int) -> None:
        if not 0 <= number < self.mft_records:
            raise ValueError(f"record {number} is outside this builder's "
                             f"{self.mft_records}-record MFT")

    def raw(self, number: int, attrs, **kw) -> None:
        self._check_number(number)
        self.records[number] = record_bytes(number, attrs, **kw)
        self.seqs[number] = kw.get("seq", 1)

    def journal(self, number: int, records: list, *, sparse_clusters: int = 8,
                version: int = 2) -> list:
        """$Extend\\$UsnJrnl with a sparse $J. `records` are dicts of
        file/parent (record, seq), time, reasons, name. Returns the records
        as written, each with its offset (which is also its USN)."""
        page = bytearray()
        pages = bytearray()
        written = []
        base = sparse_clusters * CLUSTER
        for r in records:
            offset = base + len(pages) + len(page)
            blob = (usn_v3 if version == 3 else usn_v2)(
                offset, r["file"], r["parent"], r["time"], r["reasons"], r["name"])
            if len(page) + len(blob) > CLUSTER:
                pages += page + bytes(CLUSTER - len(page))
                page = bytearray()
                offset = base + len(pages)
                blob = (usn_v3 if version == 3 else usn_v2)(
                    offset, r["file"], r["parent"], r["time"], r["reasons"],
                    r["name"])
            page += blob
            written.append(dict(r, offset=offset, usn=offset))
        data_size = base + len(pages) + len(page)
        pages += page + bytes(-len(page) % CLUSTER)
        count = len(pages) // CLUSTER
        lcn = self.alloc(count)
        self.write(lcn, bytes(pages))
        t = (T0, T0, T0, T0)
        attrs = [resident(0x10, si_value(t, 0x26)),
                 resident(0x30, fn_value(11, 11, "$UsnJrnl", t, ns=3), aid=1),
                 nonresident(0x80, [(None, sparse_clusters), (lcn, count)],
                             data_size, name="$J", aid=2, flags=0x8000),
                 resident(0x80, bytes(32), name="$Max", aid=3)]
        self.records[number] = record_bytes(number, attrs, seq=1)
        self.seqs[number] = 1
        return written

    # -- output --------------------------------------------------------------
    def build(self) -> bytes:
        total_sectors = self.clusters * (CLUSTER // SECTOR) - 1
        boot = bytearray(SECTOR)
        boot[0:3] = b"\xeb\x52\x90"
        boot[3:11] = b"NTFS    "
        struct.pack_into("<HB", boot, 0x0B, SECTOR, CLUSTER // SECTOR)
        boot[0x15] = 0xF8
        struct.pack_into("<QQQ", boot, 0x28, total_sectors, self.mft_lcn,
                         self.mirr_lcn)
        struct.pack_into("<b", boot, 0x40, -10)
        struct.pack_into("<b", boot, 0x44, 1)
        struct.pack_into("<Q", boot, 0x48, self.serial)
        boot[510:512] = b"\x55\xaa"
        img = self.image
        img[0:SECTOR] = boot
        img[total_sectors * SECTOR:total_sectors * SECTOR + SECTOR] = boot
        t = (T0, T0, T0, T0)
        mft_bitmap = bytearray(-(-self.mft_records // 8))
        for n in [0, 3, 5, 6, 11, *self.records]:
            rec = self.records.get(n)
            if n in (0, 6) or (rec and struct.unpack_from("<H", rec, 22)[0] & 1):
                mft_bitmap[n >> 3] |= 1 << (n & 7)
        rec0 = [resident(0x10, si_value(t, 0x06)),
                resident(0x30, fn_value(5, 5, "$MFT", t, ns=3), aid=1),
                nonresident(0x80, [(self.mft_lcn, self.mft_clusters)],
                            self.mft_records * RECORD, aid=2),
                resident(0xB0, bytes(mft_bitmap) + bytes(-len(mft_bitmap) % 8),
                         aid=3)]
        self.records[0] = record_bytes(0, rec0, seq=1)
        bitmap = bytearray((self.clusters + 7) // 8)
        for lcn, used in enumerate(self.used):
            if used:
                bitmap[lcn >> 3] |= 1 << (lcn & 7)
        rec6 = [resident(0x10, si_value(t, 0x06)),
                resident(0x30, fn_value(5, 5, "$Bitmap", t, ns=3), aid=1),
                nonresident(0x80, [(self.bitmap_lcn, self.bitmap_clusters)],
                            len(bitmap), aid=2)]
        self.records[6] = record_bytes(6, rec6, seq=6)
        self.write(self.bitmap_lcn, bytes(bitmap))
        for n, rec in self.records.items():
            at = self.mft_lcn * CLUSTER + n * RECORD
            img[at:at + RECORD] = rec
        for n in range(4):
            if n in self.records:
                at = self.mirr_lcn * CLUSTER + n * RECORD
                img[at:at + RECORD] = self.records[n]
        return bytes(img)

    @staticmethod
    def record_offset(number: int, mft_lcn: int = 4) -> int:
        return mft_lcn * CLUSTER + number * RECORD


# ---------------------------------------------------------------------------
# USN records
# ---------------------------------------------------------------------------

def usn_v2(usn: int, file_ref, parent_ref, ts: int, reasons: int, name: str,
           attrs: int = 0x20) -> bytes:
    nb = name.encode("utf-16-le")
    length = align(0x3C + len(nb))
    b = bytearray(length)
    fr = file_ref[0] | (file_ref[1] << 48)
    pr = parent_ref[0] | (parent_ref[1] << 48)
    struct.pack_into("<IHHQQqqIIIIHH", b, 0, length, 2, 0, fr, pr, usn, ts,
                     reasons, 0, 0, attrs, len(nb), 0x3C)
    b[0x3C:0x3C + len(nb)] = nb
    return bytes(b)


def usn_v3(usn: int, file_ref, parent_ref, ts: int, reasons: int, name: str,
           attrs: int = 0x20) -> bytes:
    nb = name.encode("utf-16-le")
    length = align(0x4C + len(nb))
    b = bytearray(length)
    struct.pack_into("<IHH", b, 0, length, 3, 0)
    struct.pack_into("<QQ", b, 8, file_ref[0] | (file_ref[1] << 48), 0)
    struct.pack_into("<QQ", b, 24, parent_ref[0] | (parent_ref[1] << 48), 0)
    struct.pack_into("<qqIIIIHH", b, 40, usn, ts, reasons, 0, 0, attrs,
                     len(nb), 0x4C)
    b[0x4C:0x4C + len(nb)] = nb
    return bytes(b)


def usn_v4(usn: int, file_ref, parent_ref, reasons: int, extents) -> bytes:
    length = align(0x40 + 16 * len(extents))
    b = bytearray(length)
    struct.pack_into("<IHH", b, 0, length, 4, 0)
    struct.pack_into("<QQ", b, 8, file_ref[0] | (file_ref[1] << 48), 0)
    struct.pack_into("<QQ", b, 24, parent_ref[0] | (parent_ref[1] << 48), 0)
    struct.pack_into("<qIIIHH", b, 40, usn, reasons, 0, 0, len(extents), 16)
    for i, (off, n) in enumerate(extents):
        struct.pack_into("<qq", b, 0x40 + 16 * i, off, n)
    return bytes(b)


# ---------------------------------------------------------------------------
# small, VALID files of each carved format
# ---------------------------------------------------------------------------

def png_file(width: int = 4, height: int = 3) -> bytes:
    def chunk(kind, data):
        return (struct.pack(">I", len(data)) + kind + data
                + struct.pack(">I", crc32(kind + data)))
    raw = b"".join(b"\x00" + bytes([(x * 40) % 256 for x in range(width * 3)])
                   for _ in range(height))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw))
            + chunk(b"tEXt", b"Comment\x00synthetic")
            + chunk(b"IEND", b""))


def jpeg_file(scan: bytes = b"\x12\x34\xff\x00\x56\xff\xd3\x78" * 20,
              progressive: bool = False) -> bytes:
    """Markers and lengths are real; the entropy data is not decodable."""
    def seg(code, payload):
        return bytes([0xFF, code]) + struct.pack(">H", len(payload) + 2) + payload
    out = b"\xff\xd8" + seg(0xE0, b"JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")
    out += seg(0xDB, bytes(65))
    out += seg(0xC0, b"\x08\x00\x10\x00\x10\x01\x01\x11\x00")
    out += seg(0xC4, bytes(20))
    out += seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + scan
    if progressive:
        out += seg(0xC4, bytes(20)) + seg(0xDA, b"\x01\x01\x00\x00\x3f\x00") + scan
    return out + b"\xff\xd9"


def gif_file() -> bytes:
    return (b"GIF89a" + struct.pack("<HHBBB", 2, 2, 0x80, 0, 0) + bytes(6)
            + b"\x21\xf9\x04\x00\x00\x00\x00\x00"
            + b"\x2c" + struct.pack("<HHHHB", 0, 0, 2, 2, 0)
            + b"\x02\x02\x44\x01\x00" + b"\x3b")


def bmp_file(width: int = 4, height: int = 4) -> bytes:
    pixels = bytes(align(width * 3, 4) * height)
    size = 54 + len(pixels)
    return (b"BM" + struct.pack("<IHHI", size, 0, 0, 54)
            + struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0,
                          len(pixels), 2835, 2835, 0, 0) + pixels)


def pdf_file(updates: int = 0) -> bytes:
    body = (b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 2\n"
            b"trailer\n<< /Root 1 0 R >>\nstartxref\n9\n%%EOF\n")
    for i in range(updates):
        body += (f"{i + 2} 0 obj\n<< /Update {i} >>\nendobj\nxref\n"
                 "trailer\n<<>>\nstartxref\n9\n%%EOF\n").encode()
    return body


def zip_file() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("inside.txt", "carved from unallocated space " * 20)
        zf.writestr("more/second.txt", "second entry")
    return buf.getvalue()


def docx_file() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def sqlite_file() -> bytes:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "c.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE t (a TEXT)")
        conn.executemany("INSERT INTO t VALUES (?)", [("row %d" % i,) for i in range(300)])
        conn.commit()
        conn.close()
        return path.read_bytes()


def wav_file(samples: int = 400) -> bytes:
    data = bytes(samples * 2)
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    body = b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmt + b"data" + \
        struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def ole_file() -> bytes:
    """A minimal compound file: header, one FAT sector, one directory sector."""
    ss = 512
    head = bytearray(ss)
    head[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    struct.pack_into("<HHHHH", head, 0x18, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", head, 0x2C, 1)              # FAT sectors
    struct.pack_into("<I", head, 0x30, 1)              # first directory sector
    struct.pack_into("<I", head, 0x38, 4096)
    struct.pack_into("<IIII", head, 0x3C, 0xFFFFFFFE, 0, 0xFFFFFFFE, 0)
    for i in range(109):
        struct.pack_into("<I", head, 0x4C + 4 * i, 0 if i == 0 else 0xFFFFFFFF)
    fat = bytearray(b"\xff" * ss)
    struct.pack_into("<II", fat, 0, 0xFFFFFFFD, 0xFFFFFFFE)
    directory = bytearray(ss)
    name = "Root Entry".encode("utf-16-le") + b"\x00\x00"
    directory[0:len(name)] = name
    struct.pack_into("<HBB", directory, 64, len(name), 5, 1)
    return bytes(head + fat + directory)


def pe_file() -> bytes:
    out = bytearray(0x400)
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, 0x80)
    out[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", out, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    struct.pack_into("<H", out, 0x98, 0x10B)
    sec = 0x98 + 0xE0
    out[sec:sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", out, sec + 8, 0x100, 0x1000, 0x200, 0x200)
    return bytes(out)


def mp4_file() -> bytes:
    ftyp = struct.pack(">I4s4sI4s4s", 24, b"ftyp", b"isom", 0x200, b"isom", b"mp41")
    moov = struct.pack(">I4s", 16, b"moov") + bytes(8)
    mdat = struct.pack(">I4s", 108, b"mdat") + bytes(100)
    return ftyp + moov + mdat


def gzip_file() -> bytes:
    return gzip.compress(b"compressed evidence " * 400, mtime=0)


def sevenzip_file() -> bytes:
    payload = b"\x00" * 40
    next_header = b"\x01\x04\x06\x00"
    start = struct.pack("<QQI", len(payload), len(next_header), crc32(next_header))
    return (b"7z\xbc\xaf\x27\x1c\x00\x04" + struct.pack("<I", crc32(start))
            + start + payload + next_header)


def carved_corpus() -> dict:
    return {"png": png_file(), "jpeg": jpeg_file(), "gif": gif_file(),
            "bmp": bmp_file(), "pdf": pdf_file(updates=1), "zip": zip_file(),
            "sqlite": sqlite_file(), "wav": wav_file(), "ole2": ole_file(),
            "pe": pe_file(), "mp4": mp4_file(), "gzip": gzip_file(),
            "7z": sevenzip_file(), "docx": docx_file()}
