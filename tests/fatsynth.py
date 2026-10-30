"""FAT12/16/32 and exFAT volumes built from the specifications, for test_fat.

Written from Microsoft's "FAT: General Overview of On-Disk Format" (fatgen103)
and the "exFAT File System Specification", independently of the parser: the
checksums, the long-name layout, the entry sets and the boot regions are
spelt out again here, so a misreading in `fat.py` is not mirrored. The real
tools in test_fat.RealTools hold both to what mkfs.vfat, mtools and
fsck.exfat do.

Every builder keeps what it wrote (cluster lists, the volume offset of each
directory entry) so a test can corrupt one structure and know where it is.
"""

from __future__ import annotations

import math
import struct

SECTOR = 512
EOC32 = 0x0FFFFFFF


def dos_date(y: int, m: int, d: int) -> int:
    return (y - 1980) << 9 | m << 5 | d


def dos_time(h: int, mi: int, s: int) -> int:
    return h << 11 | mi << 5 | s // 2


#: 2024-05-01 13:22:10 local — the default time on every entry built here
D0, T0 = dos_date(2024, 5, 1), dos_time(13, 22, 10)


def sfn(base: str, ext: str = "") -> bytes:
    """An 8.3 name field: 8 + 3 bytes, space padded."""
    return base.encode("cp437").ljust(8, b" ") + ext.encode("cp437").ljust(3, b" ")


def sfn_sum(name11: bytes) -> int:
    total = 0
    for b in name11:
        total = ((total >> 1) | ((total & 1) << 7)) + b & 0xFF
    return total


def lfn_slots(long_name: str, checksum: int) -> list[bytes]:
    """Long-name slots in PHYSICAL order (last part first, 0x40 on it)."""
    units = list(struct.unpack(f"<{len(long_name.encode('utf-16-le')) // 2}H",
                               long_name.encode("utf-16-le")))
    parts = math.ceil(len(units) / 13)
    if len(units) % 13:
        units.append(0)
    units += [0xFFFF] * (parts * 13 - len(units))
    out = []
    for n in range(parts, 0, -1):
        chunk = units[(n - 1) * 13:n * 13]
        slot = bytearray(32)
        slot[0] = n | (0x40 if n == parts else 0)
        struct.pack_into("<5H", slot, 1, *chunk[0:5])
        slot[11] = 0x0F
        slot[13] = checksum
        struct.pack_into("<6H", slot, 14, *chunk[5:11])
        struct.pack_into("<2H", slot, 28, *chunk[11:13])
        out.append(bytes(slot))
    return out


def sfn_slot(name11: bytes, *, attr: int = 0x20, cluster: int = 0, size: int = 0,
             ntres: int = 0, cdate: int = D0, ctime: int = T0, tenth: int = 0,
             adate: int = D0, mdate: int = D0, mtime: int = T0) -> bytes:
    slot = bytearray(32)
    slot[0:11] = name11
    struct.pack_into("<BBBHHHHHHHI", slot, 11, attr, ntres, tenth, ctime, cdate,
                     adate, cluster >> 16, mtime, mdate, cluster & 0xFFFF, size)
    return bytes(slot)


class _Dir:
    def __init__(self, clusters, region=None):
        self.clusters = clusters          # None for the FAT12/16 root
        self.region = region              # (offset, bytes) for the fixed root
        self.slots: list[bytearray] = []
        self.index: dict = {}             # name -> (first slot, sfn slot)


class FatImage:
    """A FAT12/16/32 volume. `sectors` and `spc` decide the cluster count,
    and the cluster count — as the specification says — decides the type."""

    def __init__(self, fat_type: str = "FAT16", *, sectors: int | None = None,
                 spc: int | None = None, bps: int = SECTOR, nfats: int = 2,
                 root_entries: int | None = None, label: str = "SYNTHVOL",
                 serial: int = 0x2024ABCD, oem: bytes = b"MSWIN4.1") -> None:
        defaults = {"FAT12": (4096, 4), "FAT16": (32768, 4), "FAT32": (70000, 1)}
        d_sectors, d_spc = defaults[fat_type]
        self.fat_type = fat_type
        self.bps, self.spc, self.nfats = bps, spc or d_spc, nfats
        self.total = sectors or d_sectors
        self.rsvd = 32 if fat_type == "FAT32" else 1
        self.root_entries = 0 if fat_type == "FAT32" else (root_entries or 512)
        self.root_secs = (self.root_entries * 32 + bps - 1) // bps
        bits = {"FAT12": 12, "FAT16": 16, "FAT32": 32}[fat_type]
        fatsz = 1
        while True:
            count = (self.total - self.rsvd - nfats * fatsz - self.root_secs) // self.spc
            need = math.ceil((count + 2) * bits / 8 / bps)
            if need <= fatsz:
                break
            fatsz = need
        self.fatsz, self.count = fatsz, count
        self.first_data = self.rsvd + nfats * fatsz + self.root_secs
        self.label, self.serial, self.oem = label, serial, oem
        self.fat: dict[int, int] = {}
        self.content: dict[int, bytes] = {}
        self.next = 2
        self.eoc = {"FAT12": 0xFFF, "FAT16": 0xFFFF, "FAT32": EOC32}[fat_type]
        if fat_type == "FAT32":
            root = self.alloc(1)
            self.root = _Dir(root)
        else:
            self.root = _Dir(None, self.root_dir_offset)
        self.dirs = {"": self.root}
        self.root.slots.append(bytearray(sfn_slot(sfn(label.ljust(11)[:8],
                                                      label.ljust(11)[8:11]),
                                                  attr=0x08)))
        self.backup_boot = 6
        self.fsinfo_free: int | None = None

    # -- geometry ---------------------------------------------------------------
    @property
    def cluster_size(self) -> int:
        return self.bps * self.spc

    @property
    def root_dir_offset(self) -> int:
        return (self.rsvd + self.nfats * self.fatsz) * self.bps

    def cluster_offset(self, c: int) -> int:
        return (self.first_data + (c - 2) * self.spc) * self.bps

    def slot_offset(self, d: _Dir, index: int) -> int:
        if d.clusters is None:
            return d.region + index * 32
        per = self.cluster_size // 32
        return self.cluster_offset(d.clusters[index // per]) + index % per * 32

    # -- allocation -------------------------------------------------------------
    def alloc(self, n: int, *, at: int | None = None) -> list[int]:
        start = self.next if at is None else at
        clusters = list(range(start, start + n))
        if at is None:
            self.next += n
        self.link(clusters)
        return clusters

    def link(self, clusters) -> None:
        for a, b in zip(clusters, clusters[1:]):
            self.fat[a] = b
        if clusters:
            self.fat[clusters[-1]] = self.eoc

    # -- entries ------------------------------------------------------------------
    def _add(self, parent: str, name: str, slots: list[bytes]) -> int:
        d = self.dirs[parent]
        first = len(d.slots)
        d.slots.extend(bytearray(s) for s in slots)
        d.index[name] = (first, len(d.slots) - 1)
        return self.slot_offset(d, len(d.slots) - 1)

    def _name_slots(self, name11, long_name, **kw) -> list[bytes]:
        slots = lfn_slots(long_name, sfn_sum(name11)) if long_name else []
        return slots + [sfn_slot(name11, **kw)]

    def mkdir(self, parent: str, name11: bytes, long_name: str = "", *,
              clusters: int = 1, **kw) -> dict:
        cl = self.alloc(clusters)
        path = f"{parent}/{long_name or name11.decode().strip()}".lstrip("/")
        d = _Dir(cl)
        parent_cluster = 0 if parent == "" else self.dirs[parent].clusters[0]
        d.slots.append(bytearray(sfn_slot(b".          ", attr=0x10, cluster=cl[0])))
        d.slots.append(bytearray(sfn_slot(b"..         ", attr=0x10,
                                          cluster=parent_cluster)))
        self.dirs[path] = d
        off = self._add(parent, path, self._name_slots(
            name11, long_name, attr=0x10, cluster=cl[0], **kw))
        return {"path": path, "clusters": cl, "offset": off}

    def add_file(self, parent: str, name11: bytes, data: bytes, long_name: str = "",
                 *, clusters: list | None = None, attr: int = 0x20, **kw) -> dict:
        n = math.ceil(len(data) / self.cluster_size)
        if clusters is None:
            clusters = self.alloc(n)
        else:
            self.link(clusters)
        cs = self.cluster_size
        for i, c in enumerate(clusters):
            self.content[c] = data[i * cs:(i + 1) * cs]
        path = f"{parent}/{long_name or self.short(name11, kw.get('ntres', 0))}".lstrip("/")
        off = self._add(parent, path, self._name_slots(
            name11, long_name, attr=attr, cluster=clusters[0] if clusters else 0,
            size=len(data), **kw))
        return {"path": path, "clusters": clusters, "offset": off}

    @staticmethod
    def short(name11: bytes, ntres: int = 0) -> str:
        base, ext = name11[:8].decode("cp437").rstrip(), name11[8:].decode("cp437").rstrip()
        base = base.lower() if ntres & 0x08 else base
        ext = ext.lower() if ntres & 0x10 else ext
        return f"{base}.{ext}" if ext else base

    def raw_slots(self, parent: str, slots: list[bytes]) -> int:
        """Append arbitrary slots; returns the volume offset of the first."""
        d = self.dirs[parent]
        first = len(d.slots)
        d.slots.extend(bytearray(s) for s in slots)
        return self.slot_offset(d, first)

    def delete(self, path: str, *, keep_chain: bool = False) -> None:
        """As FAT deletes: 0xE5 over each slot's first byte, chain zeroed."""
        parent, _, _name = path.rpartition("/")
        d = self.dirs[parent]
        first, last = d.index[path]
        sl = d.slots[last]
        cluster = struct.unpack_from("<H", sl, 26)[0] | \
            (struct.unpack_from("<H", sl, 20)[0] << 16 if self.fat_type == "FAT32" else 0)
        for i in range(first, last + 1):
            d.slots[i][0] = 0xE5
        if keep_chain:
            return
        c = cluster
        seen = set()
        while 2 <= c < self.eoc - 7 and c not in seen:
            seen.add(c)
            nxt = self.fat.pop(c, 0)
            c = nxt

    # -- output ---------------------------------------------------------------------
    def boot_sector(self) -> bytearray:
        b = bytearray(self.bps)
        b[0:3] = b"\xeb\x3c\x90" if self.fat_type != "FAT32" else b"\xeb\x58\x90"
        b[3:11] = self.oem
        tot16 = self.total if self.total < 0x10000 and self.fat_type != "FAT32" else 0
        tot32 = 0 if tot16 else self.total
        struct.pack_into("<HBHBHHBHHHII", b, 11, self.bps, self.spc, self.rsvd,
                         self.nfats, self.root_entries, tot16, 0xF8,
                         0 if self.fat_type == "FAT32" else self.fatsz, 63, 255, 0,
                         tot32)
        label = self.label.encode().ljust(11)[:11]
        if self.fat_type == "FAT32":
            struct.pack_into("<IHHIHH", b, 36, self.fatsz, 0, 0, self.root.clusters[0],
                             1, self.backup_boot)
            b[64], b[66] = 0x80, 0x29
            struct.pack_into("<I", b, 67, self.serial)
            b[71:82] = label
            b[82:90] = b"FAT32   "
        else:
            b[36], b[38] = 0x80, 0x29
            struct.pack_into("<I", b, 39, self.serial)
            b[43:54] = label
            b[54:62] = self.fat_type.encode().ljust(8)
        b[510:512] = b"\x55\xaa"
        return b

    def fat_bytes(self) -> bytes:
        size = self.fatsz * self.bps
        out = bytearray(size)
        values = dict(self.fat)
        values[0] = {"FAT12": 0xFF8, "FAT16": 0xFFF8, "FAT32": 0x0FFFFFF8}[self.fat_type]
        values[1] = self.eoc
        for c, v in values.items():
            if self.fat_type == "FAT12":
                off = c + c // 2
                cur = out[off] | out[off + 1] << 8
                cur = (cur & 0x000F) | (v & 0xFFF) << 4 if c & 1 else \
                    (cur & 0xF000) | (v & 0xFFF)
                out[off], out[off + 1] = cur & 0xFF, cur >> 8
            elif self.fat_type == "FAT16":
                struct.pack_into("<H", out, 2 * c, v)
            else:
                struct.pack_into("<I", out, 4 * c, v)
        return bytes(out)

    def build(self) -> bytearray:
        img = bytearray(self.total * self.bps)
        boot = self.boot_sector()
        img[0:self.bps] = boot
        if self.fat_type == "FAT32":
            fsinfo = bytearray(self.bps)
            free = self.count - (len(self.fat))
            struct.pack_into("<I", fsinfo, 0, 0x41615252)
            struct.pack_into("<III", fsinfo, 484, 0x61417272,
                             free if self.fsinfo_free is None else self.fsinfo_free,
                             0xFFFFFFFF)
            struct.pack_into("<I", fsinfo, 508, 0xAA550000)
            img[self.bps:2 * self.bps] = fsinfo
            bk = self.backup_boot * self.bps
            img[bk:bk + self.bps] = boot
            img[bk + self.bps:bk + 2 * self.bps] = fsinfo
        fat = self.fat_bytes()
        for i in range(self.nfats):
            off = (self.rsvd + i * self.fatsz) * self.bps
            img[off:off + len(fat)] = fat
        for c, data in self.content.items():
            off = self.cluster_offset(c)
            img[off:off + len(data)] = data
        for d in self.dirs.values():
            for i, slot in enumerate(d.slots):
                off = self.slot_offset(d, i)
                img[off:off + 32] = slot
        return img


# ---------------------------------------------------------------------------
# exFAT
# ---------------------------------------------------------------------------

def boot_checksum(sectors: bytes) -> int:
    total = 0
    for i, b in enumerate(sectors):
        if i in (106, 107, 112):
            continue
        total = ((total >> 1) | ((total & 1) << 31)) + b & 0xFFFFFFFF
    return total


def table_checksum(data: bytes) -> int:
    total = 0
    for b in data:
        total = ((total >> 1) | ((total & 1) << 31)) + b & 0xFFFFFFFF
    return total


def set_checksum(entries: bytes) -> int:
    total = 0
    for i, b in enumerate(entries):
        if i in (2, 3):
            continue
        total = ((total >> 1) | ((total & 1) << 15)) + b & 0xFFFF
    return total


def upcase_table() -> bytes:
    """A compressed up-case table: identity except a-z → A-Z."""
    vals = [0xFFFF, 0x61]                      # 0x0000-0x0060 map to themselves
    vals += list(range(0x41, 0x5B))            # a-z
    vals += [0xFFFF, 0x10000 - 0x7B]           # the rest to themselves
    return struct.pack(f"<{len(vals)}H", *vals)


def upper(ch: int) -> int:
    return ch - 0x20 if 0x61 <= ch <= 0x7A else ch


def name_hash(name: str) -> int:
    total = 0
    raw = name.encode("utf-16-le")
    for i in range(0, len(raw), 2):
        u = upper(raw[i] | raw[i + 1] << 8)
        for b in (u & 0xFF, u >> 8):
            total = ((total >> 1) | ((total & 1) << 15)) + b & 0xFFFF
    return total


def exfat_stamp(y, mo, d, h, mi, s) -> int:
    return dos_date(y, mo, d) << 16 | dos_time(h, mi, s)


X0 = exfat_stamp(2024, 5, 1, 13, 22, 10)


class ExfatImage:
    """An exFAT volume: boot region + backup, one FAT, bitmap, up-case
    table and root directory, then whatever the test adds."""

    def __init__(self, *, sectors: int = 8192, spc_shift: int = 3,
                 label: str = "SYNTHX", serial: int = 0x5EED1234) -> None:
        self.bps = SECTOR
        self.spc = 1 << spc_shift
        self.spc_shift = spc_shift
        self.total = sectors
        self.fat_offset = 24
        guess = sectors // self.spc
        self.fat_length = math.ceil((guess + 2) * 4 / self.bps)
        heap = self.fat_offset + self.fat_length
        heap += -heap % self.spc
        self.heap = heap
        self.count = (sectors - heap) // self.spc
        self.serial, self.label = serial, label
        self.fat: dict[int, int] = {}
        self.used: set[int] = set()
        self.content: dict[int, bytes] = {}
        self.next = 2
        bm_bytes = math.ceil(self.count / 8)
        self.bitmap_clusters = self.alloc(math.ceil(bm_bytes / self.cluster_size),
                                          chained=True)
        self.bitmap_len = bm_bytes
        up = upcase_table()
        self.upcase = up
        self.upcase_clusters = self.alloc(1, chained=True)
        self.content[self.upcase_clusters[0]] = up
        self.root_clusters = self.alloc(2, chained=True)
        self.dirs = {"": {"clusters": self.root_clusters, "slots": [], "index": {}}}
        self.volume_flags = 0
        root = self.dirs[""]["slots"]
        e = bytearray(32)
        e[0] = 0x83
        e[1] = len(label)
        e[2:2 + 2 * len(label)] = label.encode("utf-16-le")
        root.append(e)
        e = bytearray(32)
        e[0] = 0x81
        struct.pack_into("<IQ", e, 20, self.bitmap_clusters[0], bm_bytes)
        root.append(e)
        e = bytearray(32)
        e[0] = 0x82
        struct.pack_into("<I", e, 4, table_checksum(up))
        struct.pack_into("<IQ", e, 20, self.upcase_clusters[0], len(up))
        root.append(e)

    @property
    def cluster_size(self) -> int:
        return self.bps * self.spc

    def cluster_offset(self, c: int) -> int:
        return (self.heap + (c - 2) * self.spc) * self.bps

    def alloc(self, n: int, *, chained: bool = True, at: int | None = None) -> list:
        start = self.next if at is None else at
        cl = list(range(start, start + n))
        if at is None:
            self.next += n
        self.used.update(cl)
        if chained:
            self.link(cl)
        return cl

    def link(self, cl) -> None:
        for a, b in zip(cl, cl[1:]):
            self.fat[a] = b
        if cl:
            self.fat[cl[-1]] = 0xFFFFFFFF

    def slot_offset(self, d: dict, index: int) -> int:
        per = self.cluster_size // 32
        return self.cluster_offset(d["clusters"][index // per]) + index % per * 32

    def entry_set(self, name: str, *, attrs: int, first: int, size: int,
                  vdl: int | None = None, nofatchain: bool = True,
                  times=(X0, X0, X0), tens=(0, 0), offsets=(0xF0, 0xF0, 0xF0),
                  bad_hash: bool = False) -> list[bytearray]:
        units = name.encode("utf-16-le")
        nn = math.ceil(len(name) / 15)
        f = bytearray(32)
        f[0], f[1] = 0x85, 1 + nn
        struct.pack_into("<H", f, 4, attrs)
        struct.pack_into("<III", f, 8, *times)
        f[20], f[21] = tens
        f[22], f[23], f[24] = offsets
        s = bytearray(32)
        s[0] = 0xC0
        s[1] = 0x01 | (0x02 if nofatchain else 0)
        s[3] = len(name)
        struct.pack_into("<H", s, 4, name_hash(name) ^ (0x5555 if bad_hash else 0))
        struct.pack_into("<Q", s, 8, size if vdl is None else vdl)
        struct.pack_into("<IQ", s, 20, first, size)
        out = [f, s]
        for k in range(nn):
            n_ = bytearray(32)
            n_[0] = 0xC1
            chunk = units[k * 30:(k + 1) * 30]
            n_[2:2 + len(chunk)] = chunk
            out.append(n_)
        struct.pack_into("<H", f, 2, set_checksum(b"".join(out)))
        return out

    def _place(self, parent: str, path: str, slots) -> int:
        d = self.dirs[parent]
        first = len(d["slots"])
        d["slots"].extend(slots)
        d["index"][path] = (first, len(d["slots"]))
        return self.slot_offset(d, first)

    def mkdir(self, parent: str, name: str, *, clusters: int = 1,
              nofatchain: bool = True, **kw) -> dict:
        cl = self.alloc(clusters, chained=not nofatchain)
        path = f"{parent}/{name}".lstrip("/")
        self.dirs[path] = {"clusters": cl, "slots": [], "index": {}}
        off = self._place(parent, path, self.entry_set(
            name, attrs=0x10, first=cl[0], size=clusters * self.cluster_size,
            nofatchain=nofatchain, **kw))
        return {"path": path, "clusters": cl, "offset": off}

    def add_file(self, parent: str, name: str, data: bytes, *,
                 clusters: list | None = None, nofatchain: bool | None = None,
                 vdl: int | None = None, **kw) -> dict:
        n = math.ceil(len(data) / self.cluster_size)
        if clusters is None:
            nofatchain = True if nofatchain is None else nofatchain
            clusters = self.alloc(n, chained=not nofatchain)
        else:
            nofatchain = False if nofatchain is None else nofatchain
            self.used.update(clusters)
            if not nofatchain:
                self.link(clusters)
        cs = self.cluster_size
        for i, c in enumerate(clusters):
            self.content[c] = data[i * cs:(i + 1) * cs]
        path = f"{parent}/{name}".lstrip("/")
        off = self._place(parent, path, self.entry_set(
            name, attrs=0x20, first=clusters[0] if clusters else 0,
            size=len(data), vdl=vdl, nofatchain=nofatchain, **kw))
        return {"path": path, "clusters": clusters, "offset": off}

    def delete(self, path: str, *, zero_fat: bool = False) -> None:
        """As exFAT deletes: InUse cleared on the set, bitmap bits cleared."""
        parent = path.rpartition("/")[0]
        d = self.dirs[parent]
        first, end = d["index"][path]
        stream = d["slots"][first + 1]
        c, size = struct.unpack_from("<IQ", stream, 20)
        nofat = stream[1] & 2
        n = math.ceil(size / self.cluster_size)
        cl = []
        if nofat:
            cl = list(range(c, c + n))
        else:
            while c in self.fat and len(cl) < n:
                cl.append(c)
                c = self.fat[c]
        for k in range(first, end):
            d["slots"][k][0] &= 0x7F
        self.used.difference_update(cl)
        if zero_fat:
            for c in cl:
                self.fat.pop(c, None)

    def boot_region(self) -> bytes:
        bps = self.bps
        reg = bytearray(12 * bps)
        b = reg
        b[0:3] = b"\xeb\x76\x90"
        b[3:11] = b"EXFAT   "
        struct.pack_into("<QQIIIIIIHHBBBBB", b, 64, 0, self.total, self.fat_offset,
                         self.fat_length, self.heap, self.count,
                         self.root_clusters[0], self.serial, 0x0100,
                         self.volume_flags, 9, self.spc_shift, 1, 0x80,
                         100 * len(self.used) // self.count)
        b[510:512] = b"\x55\xaa"
        for s in range(1, 9):
            reg[s * bps + bps - 4:s * bps + bps] = b"\x00\x00\x55\xaa"
        chk = boot_checksum(bytes(reg[:11 * bps]))
        reg[11 * bps:12 * bps] = struct.pack("<I", chk) * (bps // 4)
        return bytes(reg)

    def build(self) -> bytearray:
        img = bytearray(self.total * self.bps)
        reg = self.boot_region()
        img[0:len(reg)] = reg
        img[len(reg):2 * len(reg)] = reg
        fat = bytearray(self.fat_length * self.bps)
        struct.pack_into("<II", fat, 0, 0xFFFFFFF8, 0xFFFFFFFF)
        for c, v in self.fat.items():
            struct.pack_into("<I", fat, 4 * c, v)
        off = self.fat_offset * self.bps
        img[off:off + len(fat)] = fat
        bm = bytearray(self.bitmap_len)
        for c in self.used:
            bm[(c - 2) >> 3] |= 1 << ((c - 2) & 7)
        self.content[self.bitmap_clusters[0]] = bytes(bm)
        for c, data in self.content.items():
            o = self.cluster_offset(c)
            img[o:o + len(data)] = data
        for d in self.dirs.values():
            for i, slot in enumerate(d["slots"]):
                o = self.slot_offset(d, i)
                img[o:o + 32] = slot
        return img
