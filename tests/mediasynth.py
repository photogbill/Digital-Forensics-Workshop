"""Synthetic audio and two stand-in programs for the media suite.

No network, no GPU: the suite never runs the real audio.cpp or FFmpeg. It
writes a FAKE `audiocpp_cli` — a small Python script — and runs it through
the very same subprocess path the adapter uses for the real one (an argv
prefix `[python, fake_audiocpp_cli.py]`). The fake writes `target.wav` and
`residual.wav` deterministically from the seed and the text, in the format
`--out-format` asks for, laid out the way audio.cpp v0.9.0's
`wav_writer.cpp` lays them out (float32: format tag 3, an 18-byte `fmt `,
then a `fact` chunk). The text steers it:

    "steady ..."   every seed writes the same target      (no disagreement)
    anything else  even seeds add a second tone at 1.5-2.0 s (disagreement)
    "quiet ..."    a silent target                         (negative control)
    "FAIL"         exits 3 after a CUDA-like error on stderr
    "NAN ..."      a target full of NaN                    (a broken output)
    "EMPTY ..."    a target with no frames                 (a broken output)
    "NOTHING"      exits 0 and writes nothing
    "SLEEP"        sleeps 30 s (cancel and timeout)

It prints its argv as one `FAKE-ARGV <json>` line, which lands in the log,
and the TEMP it was given as one `FAKE-TEMP <path>` line.
"""

from __future__ import annotations

import math
import struct
import sys
from pathlib import Path

RATE = 48000


def tone(seconds: float, freq: float = 440.0, amp: float = 0.5,
         rate: int = RATE, start: float = 0.0, total: float | None = None):
    n_total = int(round((total if total is not None else seconds + start)
                        * rate))
    out = [0.0] * n_total
    a, b = int(start * rate), int((start + seconds) * rate)
    for i in range(a, min(b, n_total)):
        out[i] = amp * math.sin(2 * math.pi * freq * i / rate)
    return out


def wav_bytes(samples, *, rate: int = RATE, channels: int = 1,
              fmt: str = "pcm16") -> bytes:
    """Interleaved float samples -> WAV bytes. `fmt`: pcm16, pcm24, pcm32,
    float32 (audio.cpp's layout, with `fact`), float32x (EXTENSIBLE), u8."""
    if fmt == "pcm16":
        data = b"".join(struct.pack("<h", max(-32768, min(32767,
                        int(round(s * 32767))))) for s in samples)
        tag, bits = 1, 16
    elif fmt == "pcm24":
        data = b"".join(int(round(max(-1, min(0.9999999, s)) * 8388607)
                            ).to_bytes(3, "little", signed=True)
                        for s in samples)
        tag, bits = 1, 24
    elif fmt == "pcm32":
        data = b"".join(struct.pack("<i", int(round(max(-1, min(0.9999999, s))
                                                    * 2147483647)))
                        for s in samples)
        tag, bits = 1, 32
    elif fmt == "u8":
        data = bytes(max(0, min(255, int(round(s * 128 + 128))))
                     for s in samples)
        tag, bits = 1, 8
    elif fmt in ("float32", "float32x"):
        data = struct.pack(f"<{len(samples)}f", *samples)
        tag, bits = 3, 32
    else:
        raise ValueError(fmt)
    align = channels * bits // 8
    if fmt == "float32x":
        sub = struct.pack("<H", 3) + bytes.fromhex("000000001000800000aa00389b71")
        fmt_body = struct.pack("<HHIIHHHHI", 0xFFFE, channels, rate,
                               rate * align, align, bits, 22, bits, 0) + sub
        chunks = b"fmt " + struct.pack("<I", len(fmt_body)) + fmt_body
    elif tag == 3:
        fmt_body = struct.pack("<HHIIHHH", 3, channels, rate, rate * align,
                               align, bits, 0)
        chunks = (b"fmt " + struct.pack("<I", 18) + fmt_body + b"fact"
                  + struct.pack("<II", 4, len(samples) // channels))
    else:
        fmt_body = struct.pack("<HHIIHH", tag, channels, rate, rate * align,
                               align, bits)
        chunks = b"fmt " + struct.pack("<I", 16) + fmt_body
    body = b"WAVE" + chunks + b"data" + struct.pack("<I", len(data)) + data
    return b"RIFF" + struct.pack("<I", len(body)) + body


def write_wav(path, samples, **kw) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(wav_bytes(samples, **kw))
    return p


FAKE_CLI = r'''
import json, math, os, struct, sys, time
args = sys.argv[1:]
if "--version" in args:
    print("audio.cpp fake-0.0.0 (test double) commit 0000000 backends: cpu")
    sys.exit(0)
print("FAKE-ARGV " + json.dumps(args), flush=True)
print("FAKE-TEMP " + os.environ.get("TEMP", ""), flush=True)
def opt(name, default=None):
    return args[args.index(name) + 1] if name in args else default
text = opt("--text", "")
if text == "FAIL":
    print("ggml_cuda_compute_forward: out of memory (simulated)", file=sys.stderr)
    sys.exit(3)
if text == "NOTHING":
    sys.exit(0)
if text == "SLEEP":
    time.sleep(30)
    sys.exit(0)
seed = int(opt("--seed", "42"))
out = opt("--out-dir")
fmt = opt("--out-format", "pcm16")
with open(opt("--audio"), "rb") as fh:
    raw = fh.read()
pos, rate, align, nbytes = 12, 48000, 2, 0
while pos + 8 <= len(raw):
    cid, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
    if cid == b"fmt ":
        ch, rate = struct.unpack("<HI", raw[pos + 10:pos + 16])
        bits = struct.unpack("<H", raw[pos + 22:pos + 24])[0]
        align = ch * bits // 8
    if cid == b"data":
        nbytes = min(size, len(raw) - pos - 8)
        break
    pos += 8 + size + (size & 1)
dur = (nbytes // align) / rate
R = 48000
n = int(round(dur * R))
target = [0.0] * n
if not text.startswith("quiet"):
    for i in range(min(n, R)):
        target[i] = 0.5 * math.sin(2 * math.pi * 440 * i / R)
    if not text.startswith("steady") and seed % 2 == 0:
        for i in range(int(1.5 * R), min(n, int(2.0 * R))):
            target[i] = 0.5 * math.sin(2 * math.pi * 880 * i / R)
residual = [0.01 * math.sin(2 * math.pi * 97 * i / R) for i in range(n)]
if text.startswith("NAN"):
    target = [float("nan")] * n
if text.startswith("EMPTY"):
    target = []
def write(path, samples):
    if fmt == "float32":
        data = struct.pack("<%df" % len(samples), *samples)
        fmtb = struct.pack("<HHIIHHH", 3, 1, R, R * 4, 4, 32, 0)
        chunks = b"fmt " + struct.pack("<I", 18) + fmtb + b"fact" + struct.pack("<II", 4, len(samples))
    else:
        data = b"".join(struct.pack("<h", int(round(max(-1, min(1, s)) * 32767))) for s in samples)
        fmtb = struct.pack("<HHIIHH", 1, 1, R, R * 2, 2, 16)
        chunks = b"fmt " + struct.pack("<I", 16) + fmtb
    body = b"WAVE" + chunks + b"data" + struct.pack("<I", len(data)) + data
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(b"RIFF" + struct.pack("<I", len(body)) + body)
    os.replace(tmp, path)
os.makedirs(out, exist_ok=True)
write(os.path.join(out, "target.wav"), target)
write(os.path.join(out, "residual.wav"), residual)
print("separated %.2f s, seed %d" % (dur, seed))
'''

FAKE_FFMPEG = r'''
import math, struct, sys
args = sys.argv[1:]
if "-version" in args:
    print("ffmpeg version fake-0 Copyright (c) test double")
    sys.exit(0)
src = args[args.index("-i") + 1]
dst = args[-1]
if src.endswith(".noaudio"):
    print("Stream map '0:a:0' matches no streams.", file=sys.stderr)
    sys.exit(1)
R, n = 44100, 44100 * 3
frames = []
for i in range(n):
    s = 0.25 * math.sin(2 * math.pi * 330 * i / R)
    frames += [s, s]
data = struct.pack("<%df" % len(frames), *frames)
fmtb = struct.pack("<HHIIHHH", 3, 2, R, R * 8, 8, 32, 0)
body = b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmtb + b"fact" + struct.pack("<II", 4, n) + b"data" + struct.pack("<I", len(data)) + data
with open(dst, "xb") as fh:
    fh.write(b"RIFF" + struct.pack("<I", len(body)) + body)
'''


def install_fakes(folder) -> tuple[list, list]:
    """Write both stand-ins into `folder`; return their argv prefixes."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    cli = root / "fake_audiocpp_cli.py"
    cli.write_text(FAKE_CLI, encoding="utf-8")
    ff = root / "fake_ffmpeg.py"
    ff.write_text(FAKE_FFMPEG, encoding="utf-8")
    return [sys.executable, str(cli)], [sys.executable, str(ff)]


def install_spec(folder) -> Path:
    """The model_specs/sam_audio.json get_sam.bat copies beside the exe."""
    spec = Path(folder) / "model_specs" / "sam_audio.json"
    spec.parent.mkdir(parents=True, exist_ok=True)
    spec.write_text('{"family": "sam_audio"}', encoding="utf-8")
    return spec


def fake_model(folder, name: str = "sam-audio-large-q8_0.gguf",
               payload: bytes = b"GGUF" + b"\x00" * 60) -> Path:
    p = Path(folder) / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(payload)
    return p
