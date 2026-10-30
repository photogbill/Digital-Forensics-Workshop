# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Windows Prefetch (`*.pf`): the SCCA format, versions 17 to 31, and the
MAM-compressed form Windows 10 and 11 write.

Windows keeps one prefetch file per executable (per path and, for a few
hosts, per command line) in `C:\\Windows\\Prefetch`. Each records the
executable's name, a hash of its path, how many times the prefetcher saw it
start, the last start time (eight of them from Windows 8 on), the volumes it
touched and the files it loaded in its first seconds.

**How it is read.** From the bytes, following libyal's "Windows Prefetch File
(PF) format" (libscca documentation): the 84-byte header, the version's file
information block, the file-metrics array (one entry per referenced file,
with an NTFS file reference from version 23 on), the filename strings, and
each volume's device path, serial number, creation time and directory
strings. Version 30 has two layouts (220- and 212-byte file information);
they are told apart by the metrics-array offset they declare (0x130 / 0x128),
and the one used is recorded. Version 31 (Windows 11) is read with the
version 30 variant 2 layout, which libyal documents it resembles.

**MAM files.** Windows 10 and 11 store prefetch compressed: `MAM\\x04`, the
uncompressed size, then LZXPRESS Huffman data. The decompressor here is
written from Microsoft's [MS-XCA] description (Huffman-coded LZ77: each block
of up to 65 536 output bytes starts with a 256-byte table of 512 four-bit
code lengths; canonical codes of at most 15 bits; symbols 0–255 are literals,
256–511 a match whose low nibble is the length and high nibble the number of
offset bits; extended lengths follow as bytes in the stream). It is pure
Python, so the engine reads Windows 10/11 prefetch on any operating system.
On Windows only, `decompress_mam(..., native=True)` can use ntdll's
`RtlDecompressBufferEx` (COMPRESSION_FORMAT_XPRESS_HUFF); the pure decoder
stays the default, and `native_cross_check` compares the two where both
exist. The decompressed length is checked against the size the MAM header
declares and against the SCCA header's own file-size field.

**What a value means is not decided here.** A run count is what the
prefetcher stored; it is not a count of launches by a person ("Prefetch
records 7 runs of X.EXE"). The run times are FILETIMEs (UTC) and are kept
raw beside their decoded values. The stored path hash is REPORTED and
compared with the hash in the file name when one is given; it is not
recomputed (that needs the volume's device path at the time, which the file
does not reliably keep).

**Not read.** The trace-chain array (block-level load records) is counted,
not decoded; the per-volume NTFS file-reference array is counted and its
non-zero references listed, without interpretation; the version 30+ "hash
string" block is not decoded; remnant bytes after the executable name are not
reported. The MAM checksum variant (flag 0x80) is decompressed but its
checksum is not verified, and the result says so.
"""

from __future__ import annotations

import re
import struct
import sys

from . import timeutil
from .errors import FileSystemError

MAX_INPUT = 64 << 20            # a prefetch file is kilobytes; refuse silliness
SCCA = b"SCCA"
MAM = b"MAM"
VERSIONS = {17: "Windows XP / 2003", 23: "Windows Vista / 7",
            26: "Windows 8 / 8.1", 30: "Windows 10", 31: "Windows 11"}
FILE_INFO = {17: 68, 23: 156, 26: 220}
METRIC_SIZE = {17: 20}          # 32 bytes for every later version
VOLUME_SIZE = {17: 40, 23: 104, 26: 104, 30: 96, 31: 96}
COMPRESSION_FORMAT_XPRESS_HUFF = 4
BLOCK = 0x10000
_HASH_IN_NAME = re.compile(r"-([0-9A-Fa-f]{8})(?:\.pf)?$")


def _as_bytes(source, limit: int, what: str) -> bytes:
    if isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    elif hasattr(source, "read_at") and hasattr(source, "size"):
        if source.size > limit:
            raise FileSystemError(
                f"This {what} is {source.size:,} bytes, larger than the "
                f"{limit:,} bytes this parser accepts; it is not a {what} "
                "Windows would write. Check that the right file was chosen.")
        data = bytes(source.read_at(0, source.size))
    else:
        raise TypeError("expected bytes or a reader with .size and .read_at")
    if len(data) > limit:
        raise FileSystemError(
            f"This {what} is {len(data):,} bytes, larger than the {limit:,} "
            f"bytes this parser accepts; it is not a {what} Windows would "
            "write. Check that the right file was chosen.")
    return data


def _utf16(raw: bytes) -> str:
    """UTF-16LE that may hold unpaired surrogates: kept as escapes, never
    replaced, so a name is not silently altered on its way to a report."""
    raw = bytes(raw)
    if len(raw) % 2:                    # a damaged length: drop the odd byte
        raw = raw[:-1]
    text = raw.decode("utf-16-le", "surrogatepass")
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in text):
        return text.encode("utf-8", "backslashreplace").decode("utf-8")
    return text


def _utf16z(buf: bytes, offset: int, limit: int | None = None) -> str:
    """A NUL-terminated UTF-16LE string starting at `offset`."""
    end = len(buf) if limit is None else min(limit, len(buf))
    pos = offset
    while pos + 1 < end and buf[pos:pos + 2] != b"\x00\x00":
        pos += 2
    return _utf16(buf[offset:pos])


def _filetime(raw: int) -> dict:
    return {"raw": raw, "epoch": "filetime",
            "utc": timeutil.decode(raw, "filetime")}


# ---------------------------------------------------------------------------
# LZXPRESS Huffman ([MS-XCA] 2.1 / 2.2)
# ---------------------------------------------------------------------------

def _decoding_table(table: bytes) -> list:
    """The 32 768-entry lookup for one block's canonical Huffman code.

    Each of the 512 symbols has a 4-bit code length (low nibble first).
    Codes are assigned in order of (length, symbol); an entry holds
    `symbol << 4 | length`, or -1 where no code reaches (an incomplete code).
    """
    lengths = []
    for b in table:
        lengths.append(b & 0x0F)
        lengths.append(b >> 4)
    by_length = [[] for _ in range(16)]
    for symbol, length in enumerate(lengths):
        if length:
            by_length[length].append(symbol)
    if not any(by_length):
        raise FileSystemError(
            "The compressed prefetch data holds a Huffman table with no codes "
            "at all; the file is damaged or is not LZXPRESS Huffman data.")
    decode = [-1] * 32768
    code = 0
    for length in range(1, 16):
        span = 1 << (15 - length)
        for symbol in by_length[length]:
            start = code * span
            if start + span > 32768:
                raise FileSystemError(
                    "The compressed prefetch data holds a Huffman table whose "
                    "code lengths over-fill the code space; the file is "
                    "damaged.")
            decode[start:start + span] = [(symbol << 4) | length] * span
            code += 1
        code <<= 1
    return decode


def lzxpress_huffman_decompress(src: bytes, out_size: int) -> tuple[bytes, dict]:
    """Decompress LZXPRESS Huffman data to exactly `out_size` bytes.

    Returns (data, stats). Raises FileSystemError when the stream cannot be
    decoded to the size asked for. The decoder reads one 16-bit word ahead;
    a single look-ahead word past the end of the input is padded with zero
    bits and counted in `stats["read_past_end"]` (the caller reports it),
    a second one means the data is truncated and is refused.
    """
    src = bytes(src)
    n = len(src)
    out = bytearray()
    pos = 0
    stats = {"blocks": 0, "input_consumed": 0, "read_past_end": 0}

    def word(p: int) -> int:
        if p + 2 <= n:
            return src[p] | (src[p + 1] << 8)
        stats["read_past_end"] += 1
        if stats["read_past_end"] > 1:
            # One word of look-ahead past the end can be harmless; a second
            # means bits that are not there were decoded.
            raise FileSystemError(
                f"The compressed prefetch data ends after {len(out):,} of the "
                f"{out_size:,} bytes it declares; the file is truncated.")
        return 0

    while len(out) < out_size:
        if pos + 256 > n:
            raise FileSystemError(
                f"The compressed prefetch data ends after {len(out):,} of the "
                f"{out_size:,} bytes it declares, where block "
                f"{stats['blocks'] + 1} should begin; the file is truncated.")
        decode = _decoding_table(src[pos:pos + 256])
        pos += 256
        stats["blocks"] += 1
        bits = (word(pos) << 16) | word(pos + 2)
        pos += 4
        extra = 16
        block_end = min(len(out) + BLOCK, out_size)
        while len(out) < block_end:
            entry = decode[bits >> 17]
            if entry < 0:
                raise FileSystemError(
                    f"The compressed prefetch data has an undecodable bit "
                    f"pattern at output byte {len(out):,}; the file is damaged.")
            length = entry & 0x0F
            symbol = entry >> 4
            bits = (bits << length) & 0xFFFFFFFF
            extra -= length
            if extra < 0:
                bits |= word(pos) << (-extra)
                extra += 16
                pos += 2
            if symbol < 256:
                out.append(symbol)
                continue
            symbol -= 256
            match_len = symbol & 0x0F
            offset_bits = symbol >> 4
            if match_len == 15:
                if pos >= n:
                    raise FileSystemError(
                        "The compressed prefetch data ends inside a match "
                        "length; the file is truncated.")
                match_len = src[pos]
                pos += 1
                if match_len == 255:
                    if pos + 2 > n:
                        raise FileSystemError(
                            "The compressed prefetch data ends inside a match "
                            "length; the file is truncated.")
                    match_len = src[pos] | (src[pos + 1] << 8)
                    pos += 2
                    if match_len < 15:
                        raise FileSystemError(
                            "The compressed prefetch data holds an impossible "
                            "match length; the file is damaged.")
                    match_len -= 15
                match_len += 15
            match_len += 3
            offset = (bits >> (32 - offset_bits)) if offset_bits else 0
            offset += 1 << offset_bits
            bits = (bits << offset_bits) & 0xFFFFFFFF
            extra -= offset_bits
            if extra < 0:
                bits |= word(pos) << (-extra)
                extra += 16
                pos += 2
            if offset > len(out):
                raise FileSystemError(
                    f"The compressed prefetch data refers {offset:,} bytes back "
                    f"from output byte {len(out):,}, before the start of the "
                    "data; the file is damaged.")
            start = len(out) - offset
            if offset >= match_len:
                out += out[start:start + match_len]
            else:
                pattern = bytes(out[start:])
                reps = match_len // offset + 1
                out += (pattern * reps)[:match_len]
    stats["input_consumed"] = min(pos, n)
    return bytes(out[:out_size]), stats


def _native_decompress(src: bytes, out_size: int) -> bytes | None:
    """ntdll's own XPRESS Huffman decoder — Windows only; None elsewhere or
    when the call fails (the caller then uses the pure decoder)."""
    if sys.platform != "win32":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        ntdll = ctypes.WinDLL("ntdll")
        ws_size = wintypes.ULONG()
        frag_size = wintypes.ULONG()
        status = ntdll.RtlGetCompressionWorkSpaceSize(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF),
            ctypes.byref(ws_size), ctypes.byref(frag_size))
        if status != 0:
            return None
        workspace = ctypes.create_string_buffer(max(ws_size.value, 1))
        out = ctypes.create_string_buffer(out_size)
        inp = ctypes.create_string_buffer(bytes(src), len(src))
        final = wintypes.ULONG()
        status = ntdll.RtlDecompressBufferEx(
            ctypes.c_ushort(COMPRESSION_FORMAT_XPRESS_HUFF), out,
            wintypes.ULONG(out_size), inp, wintypes.ULONG(len(src)),
            ctypes.byref(final), workspace)
        if status != 0 or final.value != out_size:
            return None
        return out.raw[:out_size]
    except (OSError, AttributeError, ValueError):
        return None


def _mam_header(data: bytes) -> dict:
    if len(data) < 8 or data[:3] != MAM:
        raise FileSystemError("This is not a MAM-compressed prefetch file "
                              "(no 'MAM' signature at offset 0).")
    flag_byte = data[3]
    fmt = flag_byte & 0x0F
    has_checksum = bool(flag_byte & 0x80)
    out_size = struct.unpack_from("<I", data, 4)[0]
    start = 12 if has_checksum else 8
    if len(data) < start:
        raise FileSystemError("The MAM header is truncated.")
    return {"signature": data[:4].hex(), "format": fmt,
            "has_checksum": has_checksum,
            "checksum": (struct.unpack_from("<I", data, 8)[0]
                         if has_checksum else None),
            "uncompressed_size": out_size, "data_offset": start}


def decompress_mam(data: bytes, *, native: bool = False) -> tuple[bytes, dict]:
    """A Windows 10/11 MAM prefetch file → (the SCCA bytes, how it was done).

    The pure-Python decoder is the default. `native=True` uses ntdll on
    Windows when it is available and falls back to the pure decoder
    otherwise; the returned info names the decoder that produced the bytes.
    """
    head = _mam_header(data)
    if head["format"] != COMPRESSION_FORMAT_XPRESS_HUFF:
        raise FileSystemError(
            f"This MAM file is compressed with method {head['format']}, not "
            "XPRESS Huffman (4); this version does not decompress it.")
    if head["uncompressed_size"] > MAX_INPUT:
        raise FileSystemError(
            f"The MAM header declares {head['uncompressed_size']:,} "
            "uncompressed bytes, far more than any prefetch file; the header "
            "is damaged or this is not a prefetch file.")
    body = data[head["data_offset"]:]
    info = dict(head, decoder="pure-python")
    if native:
        got = _native_decompress(body, head["uncompressed_size"])
        if got is not None:
            info["decoder"] = "ntdll.RtlDecompressBufferEx"
            return got, info
        info["native_unavailable"] = True
    out, stats = lzxpress_huffman_decompress(body, head["uncompressed_size"])
    info.update(stats)
    return out, info


def native_cross_check(data: bytes) -> dict:
    """Decompress with both decoders and say whether they agree. Off
    Windows the native one does not exist and `available` is False."""
    head = _mam_header(data)
    body = data[head["data_offset"]:]
    pure, _stats = lzxpress_huffman_decompress(body, head["uncompressed_size"])
    native = _native_decompress(body, head["uncompressed_size"])
    if native is None:
        return {"available": False, "agree": None,
                "reason": ("ntdll is only present on Windows"
                           if sys.platform != "win32" else
                           "RtlDecompressBufferEx failed or is missing")}
    return {"available": True, "agree": native == pure}


# ---------------------------------------------------------------------------
# SCCA
# ---------------------------------------------------------------------------

def _u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def parse_prefetch(source, *, file_name: str | None = None,
                   native: bool = False) -> dict:
    """Parse one prefetch file (raw SCCA or MAM-compressed).

    `file_name` (the `.pf` file's own name) lets the stored path hash be
    compared with the one in the name. Raises FileSystemError when the file
    is not prefetch at all; damage that can be read around is listed in
    `problems`.
    """
    data = _as_bytes(source, MAX_INPUT, "prefetch file")
    problems: list[str] = []
    compression = None
    if data[:3] == MAM:
        scca, compression = decompress_mam(data, native=native)
        if compression.get("read_past_end"):
            problems.append(
                "The compressed data ended one 16-bit word before the decoder's "
                "look-ahead; the last decoded bytes may be affected.")
        if compression.get("has_checksum"):
            problems.append(
                "The MAM header carries a checksum (flag 0x80); it was not "
                "verified.")
    else:
        scca = data
    if len(scca) < 84 or scca[4:8] != SCCA:
        raise FileSystemError(
            "This is not a Windows prefetch file: there is no 'SCCA' "
            "signature at offset 4" + (" after decompression" if compression
                                       else "") + ".")
    version, _sig, unknown8, declared_size = struct.unpack_from("<I4sII", scca, 0)
    if version not in VERSIONS:
        raise FileSystemError(
            f"Prefetch format version {version} is not one this parser knows "
            f"({', '.join(str(v) for v in sorted(VERSIONS))}); it is not read "
            "rather than read wrongly.")
    if declared_size != len(scca):
        problems.append(
            f"The header declares {declared_size:,} bytes but "
            f"{len(scca):,} are present" + (" after decompression"
                                            if compression else "") + ".")
    executable = _utf16z(scca, 16, 76)
    stored_hash = _u32(scca, 76)
    flags80 = _u32(scca, 80)

    if version in FILE_INFO:
        info_size = FILE_INFO[version]
    else:
        info_size = 220 if _u32(scca, 84) == 0x130 else 212
    if len(scca) < 84 + info_size:
        raise FileSystemError(
            "The prefetch file ends inside its file-information block; it is "
            "truncated and cannot be read.")
    (metrics_off, metrics_n, trace_off, trace_n, names_off, names_size,
     vols_off, vols_n, vols_size) = struct.unpack_from("<9I", scca, 84)

    layout = None
    if version == 17:
        run_times = [struct.unpack_from("<Q", scca, 84 + 36)[0]]
        run_count = _u32(scca, 84 + 60)
    elif version == 23:
        run_times = [struct.unpack_from("<Q", scca, 84 + 44)[0]]
        run_count = _u32(scca, 84 + 68)
    else:
        run_times = list(struct.unpack_from("<8Q", scca, 84 + 44))
        if version == 26:
            run_count = _u32(scca, 84 + 124)
        else:
            label = ("version 30" if version == 30 else
                     f"version {version}, read with the version 30")
            if metrics_off == 0x130:
                layout = f"{label} variant 1 (220-byte file information)"
                run_count = _u32(scca, 84 + 124)
            else:
                layout = f"{label} variant 2 (212-byte file information)"
                if metrics_off != 0x128:
                    problems.append(
                        f"The metrics array is at 0x{metrics_off:X}, neither "
                        "0x128 nor 0x130; the 212-byte layout was assumed.")
                run_count = _u32(scca, 84 + 116)

    # file metrics -> referenced file names
    msize = METRIC_SIZE.get(version, 32)
    files = []
    if metrics_off + metrics_n * msize > len(scca):
        problems.append(
            f"The file-metrics array ({metrics_n} entries at 0x{metrics_off:X}) "
            "runs past the end of the file; only the entries present were read.")
        metrics_n = max(0, (len(scca) - metrics_off) // msize)
    names_end = min(len(scca), names_off + names_size)
    if names_off + names_size > len(scca):
        problems.append("The filename-strings block runs past the end of the "
                        "file; names beyond the end are not read.")
    for i in range(metrics_n):
        base = metrics_off + i * msize
        if version == 17:
            _ti, _tn, name_off, name_chars, mflags = struct.unpack_from(
                "<5I", scca, base)
            ref = None
        else:
            (_ti, _tn, _blocks, name_off, name_chars, mflags, ref
             ) = struct.unpack_from("<6IQ", scca, base)
        start = names_off + name_off
        end = start + 2 * name_chars
        if end > names_end:
            problems.append(f"Metrics entry {i} names a string outside the "
                            "filename-strings block; its name is not read.")
            name = None
        else:
            name = _utf16(scca[start:end])
        entry = {"index": i, "name": name, "flags": mflags}
        if ref is not None:
            entry["file_reference"] = (
                None if ref == 0 else
                {"entry": ref & 0xFFFFFFFFFFFF, "sequence": ref >> 48})
        files.append(entry)

    # volumes
    vsize = VOLUME_SIZE[version]
    volumes = []
    if vols_off + vols_n * vsize > len(scca):
        problems.append(f"The volume-information array ({vols_n} entries) runs "
                        "past the end of the file; only the entries present "
                        "were read.")
        vols_n = max(0, (len(scca) - vols_off) // vsize)
    for i in range(vols_n):
        base = vols_off + i * vsize
        (dev_off, dev_chars, created, serial, fref_off, fref_size, dir_off,
         dir_n) = struct.unpack_from("<IIQIIIII", scca, base)
        dev_start = vols_off + dev_off
        device = (_utf16(scca[dev_start:dev_start + 2 * dev_chars])
                  if dev_start + 2 * dev_chars <= len(scca) else None)
        if device is None:
            problems.append(f"Volume {i}'s device path lies outside the file.")
        directories = []
        pos = vols_off + dir_off
        for _ in range(dir_n):
            if pos + 2 > len(scca):
                problems.append(f"Volume {i}'s directory strings run past the "
                                "end of the file; the rest are not read.")
                break
            chars = struct.unpack_from("<H", scca, pos)[0]
            if pos + 2 + 2 * chars > len(scca):
                problems.append(f"Volume {i}'s directory strings run past the "
                                "end of the file; the rest are not read.")
                break
            directories.append(_utf16(scca[pos + 2:pos + 2 + 2 * chars]))
            pos += 2 + 2 * chars + 2
        refs = _file_references(scca, vols_off + fref_off, fref_size, version)
        volumes.append({
            "index": i, "device_path": device,
            "serial": f"{serial:08X}",
            "serial_short": f"{serial >> 16:04X}-{serial & 0xFFFF:04X}",
            "created": _filetime(created),
            "directories": directories,
            "directory_count_declared": dir_n,
            "file_references": refs,
        })

    stored_runs = [{"index": i, **_filetime(raw)}
                   for i, raw in enumerate(run_times) if raw]
    name_hash = None
    if file_name:
        m = _HASH_IN_NAME.search(file_name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1])
        if m:
            name_hash = m.group(1).upper()
    stored_hex = f"{stored_hash:08X}"
    return {
        "format": "prefetch",
        "version": version,
        "windows": VERSIONS[version],
        "layout": layout,
        "compressed": compression is not None,
        "compression": compression,
        "size": len(data),
        "uncompressed_size": len(scca),
        "executable": executable,
        "prefetch_hash": stored_hex,
        "hash_in_file_name": name_hash,
        "hash_matches_file_name": (None if name_hash is None
                                   else name_hash == stored_hex),
        "header_unknown_8": unknown8,
        "header_flags_80": flags80,
        "run_count": run_count,
        "last_run_times": stored_runs,
        "last_run_slots": len(run_times),
        "files": files,
        "file_count": len(files),
        "trace_chain_count": trace_n,
        "volumes": volumes,
        "problems": problems,
    }


def _file_references(buf: bytes, off: int, size: int, version: int) -> dict:
    """The per-volume NTFS reference array: counted, non-zero ones listed."""
    if size < 8 or off + size > len(buf):
        return {"count": 0, "references": [], "read": size < 8}
    _ver, count = struct.unpack_from("<II", buf, off)
    first = off + (8 if version == 17 else 16)
    end = off + size
    refs = []
    pos = first
    while pos + 8 <= end and len(refs) < count:
        ref = struct.unpack_from("<Q", buf, pos)[0]
        refs.append(ref)
        pos += 8
    nonzero = [{"entry": r & 0xFFFFFFFFFFFF, "sequence": r >> 48}
               for r in refs if r]
    return {"count": count, "references": nonzero, "read": True}


def to_rows(parsed: dict, *, source_path: str) -> list[dict]:
    """Artefact rows: one `prefetch-run` per stored run time and one
    `prefetch` summary row. Wording is measurement, not conclusion."""
    exe = parsed.get("executable") or "(unnamed)"
    count = parsed.get("run_count")
    runs = parsed.get("last_run_times") or []
    rows = []
    for run in runs:
        rank = run["index"] + 1
        rows.append({
            "artefact": "prefetch-run",
            "at_utc": run["utc"], "at_raw": run["raw"], "at_epoch": "filetime",
            "title": f"{exe} — stored run time {rank} of {len(runs)}",
            "value": (f"Prefetch records {count} runs of {exe}; stored run "
                      f"time {rank} (slot 1 is the most recent) is "
                      f"{run['utc'] or 'undecodable'}"),
            "detail": {"executable": exe, "run_count": count, "slot": rank,
                       "prefetch_hash": parsed.get("prefetch_hash"),
                       "version": parsed.get("version"),
                       "source": source_path},
            "row_ref_suffix": f"prefetch-run:{run['index']}",
        })
    volumes = parsed.get("volumes") or []
    rows.append({
        "artefact": "prefetch",
        "at_utc": None, "at_raw": None, "at_epoch": None,
        "title": f"Prefetch for {exe}",
        "value": (f"Prefetch records {count} runs of {exe}, "
                  f"{parsed.get('file_count', 0)} referenced files on "
                  f"{len(volumes)} volume(s); hash {parsed.get('prefetch_hash')}"),
        "detail": {
            "executable": exe, "run_count": count,
            "version": parsed.get("version"), "windows": parsed.get("windows"),
            "compressed": parsed.get("compressed"),
            "prefetch_hash": parsed.get("prefetch_hash"),
            "hash_matches_file_name": parsed.get("hash_matches_file_name"),
            "last_run_times": [{"raw": r["raw"], "utc": r["utc"]} for r in runs],
            "referenced_files": [f["name"] for f in parsed.get("files", [])],
            "volumes": [{"device_path": v["device_path"], "serial": v["serial"],
                         "created_utc": v["created"]["utc"],
                         "created_raw": v["created"]["raw"],
                         "directories": len(v["directories"])} for v in volumes],
            "problems": list(parsed.get("problems", [])),
        },
        "row_ref_suffix": "prefetch",
    })
    return rows
