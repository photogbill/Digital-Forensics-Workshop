"""Prefetch files built from libyal's "Windows Prefetch File (PF) format",
and an LZXPRESS Huffman compressor written from [MS-XCA] section 2.1 so the
MAM path can be tested on data no Windows machine produced. Standard library
only; writes nothing to disk."""

from __future__ import annotations

import heapq
import struct

T_RUN = 132223140000000000          # 2020-01-01T01:00:00Z
T_VOL = 131000000000000000          # 2016-02-13T…Z
INFO_SIZE = {17: 68, 23: 156, 26: 220}
METRIC = {17: 20}
VOLUME = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}
TRACE = {17: 12, 23: 12, 26: 12, 30: 8, 31: 8}


def _utf16z(text: str) -> bytes:
    return text.encode("utf-16-le") + b"\0\0"


def build_scca(version: int, *, exe="NOTEPAD.EXE", prefetch_hash=0xD8414F97,
               run_count=7, run_times=(T_RUN,), files=(), volumes=(),
               variant=2, traces=2) -> bytes:
    """files: [(name, (mft_entry, seq))]; volumes: [(device, serial,
    created, [directories], [file refs])]."""
    if version in INFO_SIZE:
        info = INFO_SIZE[version]
    else:
        info = 220 if variant == 1 else 212
    msize = METRIC.get(version, 32)
    metrics_off = 84 + info
    names = b""
    name_offsets = []
    for name, _ref in files:
        name_offsets.append(len(names))
        names += _utf16z(name)
    trace_off = metrics_off + msize * len(files)
    names_off = trace_off + TRACE[version] * traces
    vols_off = names_off + len(names)
    vols_off += (-vols_off) % 8
    vsize = VOLUME[version]
    vol_entries = b""
    vol_data = b""
    data_base = vsize * len(volumes)
    for device, serial, created, dirs, refs in volumes:
        dev_off = data_base + len(vol_data)
        vol_data += _utf16z(device)
        if len(vol_data) % 8:
            vol_data += bytes(8 - len(vol_data) % 8)
        fref_off = data_base + len(vol_data)
        if version == 17:
            fref = struct.pack("<II", 1, len(refs))
        else:
            fref = struct.pack("<IIQ", 3, len(refs), 0)
        fref += b"".join(struct.pack("<Q", e | (s << 48)) for e, s in refs)
        vol_data += fref
        dir_off = data_base + len(vol_data)
        for d in dirs:
            vol_data += struct.pack("<H", len(d)) + _utf16z(d)
        entry = struct.pack("<IIQIIIII", dev_off, len(device), created, serial,
                            fref_off, len(fref), dir_off, len(dirs))
        vol_entries += entry.ljust(vsize, b"\0")
    vols = vol_entries + vol_data

    out = bytearray(vols_off + len(vols))
    struct.pack_into("<I4sII", out, 0, version, b"SCCA", 0x11, len(out))
    struct.pack_into("<60s", out, 16, exe.encode("utf-16-le")[:58])
    struct.pack_into("<II", out, 76, prefetch_hash, 0)
    struct.pack_into("<9I", out, 84, metrics_off, len(files), trace_off, traces,
                     names_off, len(names), vols_off, len(volumes), len(vols))
    if version == 17:
        struct.pack_into("<Q", out, 84 + 36, run_times[0] if run_times else 0)
        struct.pack_into("<I", out, 84 + 60, run_count)
    elif version == 23:
        struct.pack_into("<Q", out, 84 + 44, run_times[0] if run_times else 0)
        struct.pack_into("<I", out, 84 + 68, run_count)
    else:
        times = list(run_times)[:8] + [0] * (8 - min(8, len(run_times)))
        struct.pack_into("<8Q", out, 84 + 44, *times)
        at = 124 if (version == 26 or variant == 1) else 116
        struct.pack_into("<I", out, 84 + at, run_count)
    for i, (name, ref) in enumerate(files):
        base = metrics_off + i * msize
        chars = len(name)
        if version == 17:
            struct.pack_into("<5I", out, base, i, 1, name_offsets[i], chars, 0x200)
        else:
            mft = ref[0] | (ref[1] << 48)
            struct.pack_into("<6IQ", out, base, i, 1, 1, name_offsets[i], chars,
                             0x200, mft)
    out[names_off:names_off + len(names)] = names
    out[vols_off:vols_off + len(vols)] = vols
    return bytes(out)


# ---------------------------------------------------------------------------
# LZXPRESS Huffman compression ([MS-XCA] 2.1) — test-side only
# ---------------------------------------------------------------------------

def _tokens(data: bytes, max_len=65538, window=65535):
    """Greedy LZ77 with a 3-byte hash chain: [(literal) | (length, offset)]."""
    out = []
    heads: dict = {}
    i, n = 0, len(data)
    while i < n:
        best_len, best_off = 0, 0
        if i + 3 <= n:
            key = data[i:i + 3]
            for j in reversed(heads.get(key, [])[-16:]):
                if i - j > window:
                    break
                length = 3
                limit = min(max_len, n - i)
                while length < limit and data[j + length] == data[i + length]:
                    length += 1
                if length > best_len:
                    best_len, best_off = length, i - j
                    if length == limit:
                        break
        if best_len >= 3:
            out.append((best_len, best_off))
            step = best_len
        else:
            out.append(data[i])
            step = 1
        for k in range(i, min(i + step, n - 2)):
            heads.setdefault(data[k:k + 3], []).append(k)
        i += step
    return out


def _symbol(token) -> int:
    if isinstance(token, int):
        return token
    length, offset = token
    bits = offset.bit_length() - 1
    return 256 + (bits << 4) + min(length - 3, 15)


def _code_lengths(freq: dict) -> list:
    lengths = [0] * 512
    syms = [s for s, f in freq.items() if f]
    if len(syms) == 1:
        lengths[syms[0]] = 1
        lengths[0 if syms[0] else 1] = 1
        return lengths
    scale = dict(freq)
    while True:
        heap = [(f, s, None) for s, f in scale.items() if f]
        heapq.heapify(heap)
        counter = 1000
        parents = {}
        while len(heap) > 1:
            f1, a, _ = heapq.heappop(heap)
            f2, b, _ = heapq.heappop(heap)
            counter += 1
            parents[a] = counter
            parents[b] = counter
            heapq.heappush(heap, (f1 + f2, counter, None))
        depth_ok = True
        for s in syms:
            d, node = 0, s
            while node in parents:
                node = parents[node]
                d += 1
            lengths[s] = d
            if d > 15:
                depth_ok = False
        if depth_ok:
            return lengths
        scale = {s: (f >> 1) | 1 for s, f in scale.items() if f}


def _canonical(lengths: list) -> dict:
    codes, code = {}, 0
    for length in range(1, 16):
        for s in range(512):
            if lengths[s] == length:
                codes[s] = (code, length)
                code += 1
        code <<= 1
    return codes


class _Writer:
    """[MS-XCA] 2.1's bit writer: two 16-bit slots reserved ahead, extra
    length bytes written inline at the current output position."""

    def __init__(self, out: bytearray):
        self.out = out
        self.pos1 = len(out)
        self.pos2 = len(out) + 2
        out.extend(bytes(4))
        self.free = 16
        self.acc = 0

    def bits(self, n: int, value: int) -> None:
        if n == 0:
            return
        if self.free >= n:
            self.free -= n
            self.acc = (self.acc << n) | value
            return
        self.acc = (self.acc << self.free) | (value >> (n - self.free))
        n -= self.free
        struct.pack_into("<H", self.out, self.pos1, self.acc & 0xFFFF)
        self.pos1 = self.pos2
        self.pos2 = len(self.out)
        self.out.extend(b"\0\0")
        self.free = 16 - n
        self.acc = value & ((1 << n) - 1)

    def byte(self, b: int) -> None:
        self.out.append(b)

    def word(self, w: int) -> None:
        self.out.extend(struct.pack("<H", w))

    def flush(self) -> None:
        struct.pack_into("<H", self.out, self.pos1,
                         (self.acc << self.free) & 0xFFFF)
        struct.pack_into("<H", self.out, self.pos2, 0)


def lzxpress_huffman_compress(data: bytes) -> bytes:
    tokens = _tokens(data)
    blocks, current, produced, block_start = [], [], 0, 0
    for t in tokens:
        if produced >= block_start + 65536:
            blocks.append(current)
            current, block_start = [], produced
        current.append(t)
        produced += 1 if isinstance(t, int) else t[0]
    blocks.append(current)
    out = bytearray()
    for bi, block in enumerate(blocks):
        last = bi == len(blocks) - 1
        freq: dict = {}
        for t in block:
            s = _symbol(t)
            freq[s] = freq.get(s, 0) + 1
        if last:
            freq[256] = freq.get(256, 0) + 1
        lengths = _code_lengths(freq)
        out.extend(bytes((lengths[2 * i] | (lengths[2 * i + 1] << 4))
                         for i in range(256)))
        codes = _canonical(lengths)
        w = _Writer(out)
        for t in block:
            s = _symbol(t)
            code, n = codes[s]
            w.bits(n, code)
            if isinstance(t, int):
                continue
            length, offset = t
            extra = length - 3
            if extra >= 15:
                if extra - 15 < 255:
                    w.byte(extra - 15)
                else:
                    w.byte(255)
                    w.word(length - 3)
            bits = offset.bit_length() - 1
            w.bits(bits, offset - (1 << bits))
        if last:
            code, n = codes[256]
            w.bits(n, code)
        w.flush()
    return bytes(out)


def mam(data: bytes) -> bytes:
    return b"MAM\x04" + struct.pack("<I", len(data)) + lzxpress_huffman_compress(data)
