# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""A small RIFF/WAVE reader — because the standard library's cannot read floats.

`wave` reads integer PCM only. audio.cpp writes IEEE float32 when asked, and
SAM runs ask (`--out-format float32`, see `sam_audio.py`): its float writer is
the one that does not clip what the model produced at full scale. So the
engine needs its own reader to measure that output.

What audio.cpp v0.9.0 actually writes, read from its
`src/framework/audio/wav_writer.cpp`: PCM is format tag 1 with a 16-byte
`fmt `; float32 is tag 3 with an 18-byte `fmt ` (cbSize 0) and a `fact`
chunk before `data`. FFmpeg writes WAVE_FORMAT_EXTENSIBLE (0xFFFE) for some
layouts, so that is read too, by the tag inside its sub-format GUID. 8/16/24/
32-bit integer PCM and 32/64-bit float are read; anything else is refused by
name rather than decoded as noise.

**Read, never written**: every file is opened through `blocker.open_evidence`,
the engine's one read-only door — evidence and the case's own derived audio
alike. Samples come out as floats (integer PCM scaled to [-1, 1); float files
as stored, which may exceed full scale — that is the point of float), mixed
down to mono by averaging the channels, a block at a time, so an hour-long
recording is never held in memory just to be measured.
"""

from __future__ import annotations

import array
import math
import operator
import os
import struct
import sys
from dataclasses import asdict, dataclass
from typing import Iterator

from .. import blocker
from ..errors import MediaError

TAG_PCM = 1
TAG_FLOAT = 3
TAG_EXTENSIBLE = 0xFFFE

#: (format tag, bits) -> (kind, array typecode or "" when converted by hand,
#: scale that maps the integer range onto [-1, 1))
_LAYOUTS = {
    (TAG_PCM, 8): ("pcm", "B", 128.0),
    (TAG_PCM, 16): ("pcm", "h", 32768.0),
    (TAG_PCM, 24): ("pcm", "", 2147483648.0),       # widened to 32-bit first
    (TAG_PCM, 32): ("pcm", "i", 2147483648.0),
    (TAG_FLOAT, 32): ("float", "f", 1.0),
    (TAG_FLOAT, 64): ("float", "d", 1.0),
}

#: The quietest level reported, in dBFS. Digital silence has no logarithm;
#: a floor keeps it a number a table can show and a spread can subtract.
FLOOR_DB = -120.0


@dataclass(frozen=True)
class WavInfo:
    path: str
    kind: str              # "pcm" | "float"
    bits: int
    channels: int
    rate: int
    frames: int
    data_offset: int
    data_bytes: int
    notes: tuple

    @property
    def duration_s(self) -> float:
        return self.frames / self.rate if self.rate else 0.0

    @property
    def block_align(self) -> int:
        return self.channels * (self.bits // 8)

    def as_dict(self) -> dict:
        out = asdict(self)
        out["notes"] = list(self.notes)
        out["duration_s"] = round(self.duration_s, 6)
        return out


def _size(fh) -> int:
    return os.fstat(fh.fileno()).st_size


def _parse(fh, path: str) -> WavInfo:
    total = _size(fh)
    head = fh.read(12)
    if len(head) < 12 or head[8:12] != b"WAVE":
        raise MediaError(f"{path} is not a WAV file (it does not start with "
                         "a RIFF/WAVE header).")
    if head[:4] == b"RF64":
        raise MediaError(f"{path} is an RF64 WAV (over 4 GiB); this reader "
                         "does not read RF64 yet. Cut the recording shorter.")
    if head[:4] != b"RIFF":
        raise MediaError(f"{path} is a {head[:4]!r} WAV; only little-endian "
                         "RIFF is read.")
    notes: list[str] = []
    fmt = None
    pos = 12
    while pos + 8 <= total:
        fh.seek(pos)
        chunk_id, size = struct.unpack("<4sI", fh.read(8))
        body = pos + 8
        if chunk_id == b"fmt ":
            fmt = _parse_fmt(fh.read(min(size, 64)), path)
        elif chunk_id == b"data":
            if fmt is None:
                raise MediaError(f"{path} has its audio before its format "
                                 "chunk, so its samples cannot be read.")
            tag, channels, rate, bits = fmt
            available = total - body
            if size in (0, 0xFFFFFFFF) and available > 0:
                # A streaming writer's placeholder: the length was never
                # filled in. The samples are there; their count is not.
                notes.append(f"the data chunk declares {size:#x} bytes (a "
                             "length never filled in) — read to the end of "
                             "the file")
                size = available
            elif size > available:
                notes.append(f"the data chunk claims {size:,} bytes but the "
                             f"file holds {available:,} after it — read what "
                             "is there (a recording cut off mid-write)")
                size = available
            kind, _code, _scale = _LAYOUTS[(tag, bits)]
            align = channels * (bits // 8)
            frames = size // align
            if size % align:
                notes.append(f"{size % align} trailing byte(s) do not make a "
                             "whole frame and are not read")
            return WavInfo(path, kind, bits, channels, rate, frames, body,
                           frames * align, tuple(notes))
        pos = body + size + (size & 1)          # chunks are word-aligned
    raise MediaError(f"{path} has no audio data chunk.")


def _parse_fmt(raw: bytes, path: str) -> tuple:
    if len(raw) < 16:
        raise MediaError(f"{path} has a format chunk too short to read.")
    tag, channels, rate, _byte_rate, _align, bits = struct.unpack("<HHIIHH",
                                                                 raw[:16])
    if tag == TAG_EXTENSIBLE:
        if len(raw) < 40:
            raise MediaError(f"{path} says WAVE_FORMAT_EXTENSIBLE but its "
                             "format chunk stops before the sub-format.")
        tag = struct.unpack("<H", raw[24:26])[0]
    if channels < 1 or rate < 1:
        raise MediaError(f"{path} declares {channels} channel(s) at {rate} Hz, "
                         "which is not audio that can be measured.")
    if (tag, bits) not in _LAYOUTS:
        raise MediaError(f"{path} is format tag {tag} at {bits} bits; this "
                         "reader handles integer PCM (8/16/24/32-bit) and IEEE "
                         "float (32/64-bit). Convert it with FFmpeg first.")
    return tag, channels, rate, bits


def read_info(path) -> WavInfo:
    """The header facts of a WAV file, read through the read-only door."""
    target = os.fspath(path)
    with blocker.open_evidence(target) as fh:
        return _parse(fh, target)


def _decode(raw: bytes, info: WavInfo) -> array.array:
    """Bytes of whole frames -> interleaved samples as floats."""
    tag = TAG_FLOAT if info.kind == "float" else TAG_PCM
    _kind, code, scale = _LAYOUTS[(tag, info.bits)]
    if info.bits == 24:
        # Widen each 3-byte sample to 4 bytes (low byte zero) so the array
        # module can read it as a 32-bit integer: value << 8, scaled by 2^31.
        wide = bytearray(len(raw) // 3 * 4)
        wide[1::4] = raw[0::3]
        wide[2::4] = raw[1::3]
        wide[3::4] = raw[2::3]
        raw, code = bytes(wide), "i"
    values = array.array(code)
    values.frombytes(raw)
    if sys.byteorder == "big" and values.itemsize > 1:   # pragma: no cover
        values.byteswap()
    if code == "B":
        return array.array("d", ((v - 128) / scale for v in values))
    if scale == 1.0:
        return array.array("d", values)
    inv = 1.0 / scale
    return array.array("d", (v * inv for v in values))


def _mono(samples: array.array, channels: int) -> array.array:
    if channels == 1:
        return samples
    mixed = list(samples[0::channels])
    for c in range(1, channels):
        mixed = list(map(operator.add, mixed, samples[c::channels]))
    inv = 1.0 / channels
    return array.array("d", (v * inv for v in mixed))


def iter_mono(path, block_frames: int = 48000) -> Iterator[array.array]:
    """Mono float samples, a block at a time, in file order."""
    info = read_info(path)
    align = info.block_align
    step = max(1, int(block_frames)) * align
    with blocker.open_evidence(os.fspath(path)) as fh:
        fh.seek(info.data_offset)
        left = info.data_bytes
        while left > 0:
            raw = fh.read(min(step, left))
            if not raw:
                break
            whole = len(raw) - len(raw) % align
            left -= len(raw)
            if whole:
                yield _mono(_decode(raw[:whole], info), info.channels)


def check_stem(path) -> WavInfo:
    """A stem a separator wrote, held to being AUDIO: at least one frame, and
    every sample finite. An empty or NaN-filled target is a broken run — and
    measured as levels it would read as silence, which a negative control
    would call "quiet" and a seed comparison "agreement"."""
    info = read_info(path)
    if info.frames == 0:
        raise MediaError(f"{path} holds no audio (0 frames) — a broken output, "
                         "not silence.")
    if info.notes:
        raise MediaError(f"{path} does not match its own header "
                         f"({'; '.join(info.notes)}) — a broken output.")
    for block in iter_mono(path):
        if not math.isfinite(sum(map(operator.mul, block, block))):
            raise MediaError(f"{path} contains non-finite samples (NaN or "
                             "infinity) — a broken output, not sound.")
    return info


def to_db(mean_square: float) -> float:
    """Mean square -> dBFS (a full-scale sine reads about -3 dB), floored."""
    if mean_square <= 0.0:
        return FLOOR_DB
    return max(FLOOR_DB, 10.0 * math.log10(mean_square))


def window_levels(path, window_s: float = 0.25) -> tuple[WavInfo, list[float]]:
    """RMS level in dBFS of each `window_s` window, the last one partial.

    The envelope the stdlib disagreement measure and the negative control
    both read. One pass, a block at a time.
    """
    info = read_info(path)
    per = max(1, int(round(info.rate * window_s)))
    levels: list[float] = []
    acc, count = 0.0, 0
    for block in iter_mono(path, block_frames=per * 8):
        if not math.isfinite(sum(map(operator.mul, block, block))):
            raise MediaError(f"{path} contains non-finite samples (NaN or "
                             "infinity); its levels cannot be measured.")
        i = 0
        n = len(block)
        while i < n:
            take = min(per - count, n - i)
            part = block[i:i + take]
            acc += sum(map(operator.mul, part, part))
            count += take
            i += take
            if count == per:
                levels.append(to_db(acc / per))
                acc, count = 0.0, 0
    if count:
        levels.append(to_db(acc / count))
    return info, levels


def read_array(path, np, start: int = 0, frames: int | None = None,
               info: WavInfo | None = None):
    """The file — or `frames` of it from frame `start` — as a mono float32
    numpy array, for the numpy measure. A stretch at a time keeps a long
    recording (a windowed SAM run of an hour and more) out of memory.

    `np` is passed in by the caller that already holds numpy, so this module
    never imports it and a bare interpreter can still import this file.
    """
    info = info or read_info(path)
    align = info.block_align
    first = max(0, min(int(start), info.frames))
    count = info.frames - first if frames is None else \
        max(0, min(int(frames), info.frames - first))
    with blocker.open_evidence(os.fspath(path)) as fh:
        fh.seek(info.data_offset + first * align)
        raw = fh.read(count * align)
    raw = raw[:len(raw) - len(raw) % info.block_align]
    tag = TAG_FLOAT if info.kind == "float" else TAG_PCM
    if info.bits == 24:
        u = np.frombuffer(raw, dtype=np.uint8).reshape(-1, 3).astype(np.int32)
        data = ((u[:, 0] | (u[:, 1] << 8) | (u[:, 2] << 16)) << 8).astype(
            np.float64) / 2147483648.0
    else:
        dtype = {8: "u1", 16: "<i2", 32: "<i4" if tag == TAG_PCM else "<f4",
                 64: "<f8"}[info.bits]
        data = np.frombuffer(raw, dtype=dtype).astype(np.float64)
        if info.bits == 8:
            data = (data - 128.0) / 128.0
        elif tag == TAG_PCM:
            data = data / _LAYOUTS[(TAG_PCM, info.bits)][2]
    if info.channels > 1:
        data = data.reshape(-1, info.channels).mean(axis=1)
    if not bool(np.all(np.isfinite(data))):
        raise MediaError(f"{path} contains non-finite samples (NaN or "
                         "infinity); it cannot be measured.")
    return info, data.astype(np.float32)
