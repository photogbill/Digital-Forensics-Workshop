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
def _read_channels(path):
    with open(path, "rb") as fh:
        raw = fh.read()
    pos, tag, ch, rate, bits, data = 12, 1, 1, 48000, 16, b""
    while pos + 8 <= len(raw):
        cid, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            tag, ch, rate = struct.unpack("<HHI", body[:8])
            bits = struct.unpack("<H", body[14:16])[0]
            if tag == 0xFFFE:
                tag = struct.unpack("<H", body[24:26])[0]
        elif cid == b"data":
            data = body
            break
        pos += 8 + size + (size & 1)
    width = bits // 8
    n = len(data) // (width * ch)
    def sample(i):
        off = i * width
        if tag == 3:
            return struct.unpack("<f", data[off:off + 4])[0]
        if bits == 16:
            return struct.unpack("<h", data[off:off + 2])[0] / 32768.0
        if bits == 8:
            return (data[off] - 128) / 128.0
        if bits == 24:
            return int.from_bytes(data[off:off + 3], "little", signed=True) / 8388608.0
        return struct.unpack("<i", data[off:off + 4])[0] / 2147483648.0
    return [[sample(f * ch + c) for f in range(n)] for c in range(ch)], rate
def _read(path):
    chans, rate = _read_channels(path)
    n = len(chans[0]) if chans else 0
    return [sum(c[i] for c in chans) / len(chans) for i in range(n)], rate
if any(a in args for a in ("-ar", "-ac", "-af", "-filter_complex", "-t")):
    # The voice-print and restoration paths: a real conversion of WAVs —
    # mono (or -ac N channels, or every channel with no -ac), an optional
    # rate and duration, filters stood in for by a 0.9 gain, and the
    # residual (input minus the outputs) for the amerge/pan graph.
    inputs = [args[i + 1] for i, a in enumerate(args) if a == "-i"]
    want = int(args[args.index("-ac") + 1]) if "-ac" in args else 0
    if want != 1 and "-filter_complex" not in args:
        chans, rate = _read_channels(inputs[0])
        k = want or len(chans)
        chans = [chans[c % len(chans)] for c in range(k)]
        if "-t" in args:
            chans = [c[:int(float(args[args.index("-t") + 1]) * rate)] for c in chans]
        n = len(chans[0])
        inter = [chans[c][i] for i in range(n) for c in range(k)]
        pcm = struct.pack("<%df" % len(inter), *inter)
        fmtb = struct.pack("<HHIIHHH", 3, k, rate, rate * 4 * k, 4 * k, 32, 0)
        body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmtb + b"fact"
                + struct.pack("<II", 4, n) + b"data" + struct.pack("<I", len(pcm)) + pcm)
        with open(dst, "xb") as fh:
            fh.write(b"RIFF" + struct.pack("<I", len(body)) + body)
        print("fake ffmpeg: %d channel(s) " % k + " ".join(args[-4:]))
        sys.exit(0)
    decoded = [_read(p) for p in inputs]
    mono, rate = decoded[0]
    if "-filter_complex" in args:
        n = min(len(d[0]) for d in decoded)
        mono = [mono[i] - sum(d[0][i] for d in decoded[1:]) for i in range(n)]
    elif "-af" in args:
        chain = args[args.index("-af") + 1]
        if chain != "anull":
            mono = [v * 0.9 for v in mono]
    if "-ar" in args:
        out_rate = int(args[args.index("-ar") + 1])
        n, m = len(mono), int(len(mono) * out_rate / rate)
        res = []
        for j in range(m):
            x = j * rate / out_rate
            i = int(x)
            frac = x - i
            a = mono[i] if i < n else 0.0
            b = mono[i + 1] if i + 1 < n else a
            res.append(a + (b - a) * frac)
        mono, rate = res, out_rate
    codec = args[args.index("-c:a") + 1] if "-c:a" in args else "pcm_s16le"
    if codec == "pcm_f32le":
        pcm = struct.pack("<%df" % len(mono), *mono)
        fmtb = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
        chunks = b"fmt " + struct.pack("<I", 18) + fmtb + b"fact" + struct.pack("<II", 4, len(mono))
    else:
        pcm = b"".join(struct.pack("<h", max(-32768, min(32767, int(round(v * 32767))))) for v in mono)
        fmtb = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
        chunks = b"fmt " + struct.pack("<I", 16) + fmtb
    body = b"WAVE" + chunks + b"data" + struct.pack("<I", len(pcm)) + pcm
    with open(dst, "xb") as fh:
        fh.write(b"RIFF" + struct.pack("<I", len(body)) + body)
    print("fake ffmpeg: " + " ".join(args[-4:]))
    sys.exit(0)
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


FAKE_VP_WORKER = r'''
import json, math, os, sys, wave
# A stand-in for vp_worker.py: no torch, no SpeechBrain. A segment's "voice"
# is its pitch (zero crossings) spread over Gaussian bumps every 100 Hz, so a
# tone at one pitch is one speaker and a tone far from it another.
CENTRES = [100.0 * k for k in range(1, 25)]
def embedding(samples, rate, salt):
    crossings = sum(1 for a, b in zip(samples, samples[1:]) if (a < 0) != (b < 0))
    f = crossings / (2.0 * len(samples) / rate) if samples else 0.0
    vec = [math.exp(-((f - c) / 150.0) ** 2) for c in CENTRES]
    h = abs(hash(salt)) % 997
    return [v + 0.01 * (((h * (i + 3)) % 17) / 17.0) for i, v in enumerate(vec)]
if len(sys.argv) >= 3 and sys.argv[1] == "--selftest":
    print(json.dumps({"ok": True, "device": "cpu", "dim": len(CENTRES)}))
    sys.exit(0)
req = json.load(open(sys.argv[1], encoding="utf-8"))
print("fake vp worker: loading " + req["model_dir"], flush=True)
items = []
if "CRASH" in req["model_dir"]:
    print("RuntimeError: CUDA error: out of memory (simulated)", flush=True)
    sys.exit(3)
for item in req["items"]:
    with wave.open(item["wav"], "rb") as w:
        assert w.getframerate() == 16000 and w.getnchannels() == 1 and w.getsampwidth() == 2
        raw = w.readframes(w.getnframes())
    pcm = [int.from_bytes(raw[i:i + 2], "little", signed=True) / 32768.0
           for i in range(0, len(raw), 2)]
    vecs = []
    for start, end in item["segments"]:
        part = pcm[int(start * 16000):int(end * 16000)]
        vecs.append(embedding(part, 16000, (item["id"], start)))
    items.append({"id": item["id"], "embeddings": vecs})
    print("embedded %s: %d segment(s)" % (item["id"], len(vecs)), flush=True)
env = {k: os.environ.get(k, "") for k in ("TEMP", "TMP", "HF_HOME", "HF_HUB_OFFLINE", "TORCH_HOME", "CUDA_CACHE_PATH")}
out = {"device": "cpu", "gpu": "", "torch": "fake", "speechbrain": "fake",
       "items": items, "env": env}
tmp = sys.argv[2] + ".part"
with open(tmp, "w", encoding="utf-8") as fh:
    json.dump(out, fh)
os.replace(tmp, sys.argv[2])
print("done", flush=True)
'''


FAKE_RESTORE_WORKER = r'''
import json, math, os, struct, sys
# A stand-in for restore_worker.py: no torch. "analyse" answers with the
# measurements in fake_restore_measurements.json beside this script when it
# is there (each test plants its scenario), else a noisy recording. "model"
# writes float WAVs at 0.8x the input (half each for two voices). "finish"
# aligns with lag 0, writes the residual and reports removal from its energy.
HERE = os.path.dirname(os.path.abspath(__file__))
def read(path):
    raw = open(path, "rb").read()
    pos, rate, tag, bits, data = 12, 16000, 3, 32, b""
    while pos + 8 <= len(raw):
        cid, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            tag, ch, rate = struct.unpack("<HHI", body[:8])
            bits = struct.unpack("<H", body[14:16])[0]
        elif cid == b"data":
            data = body
            break
        pos += 8 + size + (size & 1)
    if tag == 3:
        return list(struct.unpack("<%df" % (len(data) // 4), data[:len(data) // 4 * 4])), rate
    return [v / 32768.0 for v in struct.unpack("<%dh" % (len(data) // 2), data[:len(data) // 2 * 2])], rate
def write(path, x, rate):
    pcm = struct.pack("<%df" % len(x), *x)
    fmtb = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmtb + b"fact" + struct.pack("<II", 4, len(x)) + b"data" + struct.pack("<I", len(pcm)) + pcm
    open(path + ".part", "wb").write(b"RIFF" + struct.pack("<I", len(body)) + body)
    os.replace(path + ".part", path)
def energy_db(x):
    return 10 * math.log10(max(1e-12, sum(v * v for v in x) / max(1, len(x))))
NOISY = {"duration_s": 3.0, "rate": 44100, "peak_dbfs": -6.0, "rms_dbfs": -24.0,
         "dc_offset": 0.0, "clipped_fraction": 0.0, "clipped_runs": 0,
         "clicks_per_s": 0.0, "floor_db": -32.0, "speech_peak_db": -12.0,
         "gate_db": -25.0, "speech_fraction": 0.5, "speech_db": -18.0,
         "noise_db": -31.0, "snr_db": 13.0, "noise_steadiness_db": 1.0,
         "hum": {"hz": 0, "prominence_db": 0.0, "harmonics": 0, "per_harmonic": []},
         "rumble_db": -20.0, "bandwidth_hz": 22050.0}
req = json.load(open(sys.argv[1], encoding="utf-8"))
print("fake restore worker: " + req["op"], flush=True)
op = req["op"]
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
       b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01"
       b"\x01\x00\xc9\xfe\x92\xef\x00\x00\x00\x00IEND\xaeB`\x82")
if op == "analyse":
    # The planted measurements answer; the faint-sound files they promise
    # are written where the request says: the combination (a copy of the
    # mono working file), the map (a 1x1 PNG), one clip per planted clip.
    planted = os.path.join(HERE, "fake_restore_measurements.json")
    m = json.load(open(planted)) if os.path.exists(planted) else NOISY
    items = []
    for it in req["items"]:
        a = json.loads(json.dumps(m))
        ch = a.get("channels") if it.get("channels") else None
        ch = ch or {"count": 1, "kind": "mono"}
        a["channels"] = ch
        a["basis"] = os.path.basename(it["wav"])
        x, rate = read(it["wav"])
        if ch.get("used") and it.get("combined"):
            write(it["combined"], x, rate)
            write(it["best_channel"], [v * 1.1 for v in x], rate)
            a["basis"] = os.path.basename(it["combined"])
        if it.get("faint") is not None:
            fa = a.get("faint") or {"events": [], "lines": [], "clips": []}
            spec = it["faint"]
            if spec.get("png"):
                tmp = spec["png"] + ".part"
                open(tmp, "wb").write(PNG)
                os.replace(tmp, spec["png"])
                fa.setdefault("map", {"width": 1, "height": 1})
            for path, clip in zip(spec.get("clips") or [], fa.get("clips") or []):
                write(path, x[:len(x) // 4], rate)
                clip["file"] = os.path.basename(path)
            fa["clips"] = (fa.get("clips") or [])[:len(spec.get("clips") or [])]
            a["faint"] = fa
        else:
            a.pop("faint", None)
        if it.get("repeats"):
            a.setdefault("repeats", {"found": False})
        else:
            a.pop("repeats", None)
        items.append({"id": it["id"], "analysis": a})
    out = {"items": items}
elif op == "dsp":
    if "CRASH" in req["input"] and req["dsp"] == "average":
        sys.exit(3)
    x, rate = read(req["input"])
    write(req["output"], [v * 0.7 for v in x], rate)
    out = {"dsp": req["dsp"], "info": {"fake": True}, "rate": rate}
elif op == "model":
    if "CRASH" in req["model_dir"]:
        print("RuntimeError: CUDA error: out of memory (simulated)", flush=True)
        sys.exit(3)
    x, rate = read(req["input"])
    k = len(req["outputs"])
    for path in req["outputs"]:
        write(path, [v * (0.8 if k == 1 else 0.5) for v in x], rate)
    out = {"device": "cpu", "gpu": "", "torch": "fake", "speechbrain": "fake"}
elif op == "finish":
    ref, rate = read(req["reference"])
    outs = [read(p)[0] for p in req["outputs"]]
    for path, y in zip(req["aligned"], outs):
        y = (y + [0.0] * len(ref))[:len(ref)]
        write(path, y, rate)
    total = [sum(o[i] if i < len(o) else 0.0 for o in outs) for i in range(len(ref))]
    write(req["residual"], [a - b for a, b in zip(ref, total)], rate)
    rel = round(energy_db([a - b for a, b in zip(ref, total)]) - energy_db(ref), 2)
    out = {"lags": [0] * len(outs), "rate": rate,
           "change": {"during_speech_db": rel - 6.0, "during_pauses_db": rel,
                      "added_speech_db": -40.0, "added_pauses_db": -40.0},
           "outputs": [NOISY for _ in outs]}
else:
    sys.exit(2)
out["op"] = op
json.dump(out, open(sys.argv[2] + ".part", "w"))
os.replace(sys.argv[2] + ".part", sys.argv[2])
print("done", flush=True)
'''


def install_restore_worker(folder, measurements: dict | None = None) -> list:
    """The fake restoration worker (and, optionally, the measurements its
    analyse answers with); returns its argv prefix."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    worker = root / "fake_restore_worker.py"
    worker.write_text(FAKE_RESTORE_WORKER, encoding="utf-8")
    planted = root / "fake_restore_measurements.json"
    if measurements is not None:
        import json as _json
        planted.write_text(_json.dumps(measurements), encoding="utf-8")
    elif planted.exists():
        planted.unlink()
    return [sys.executable, str(worker)]


def fake_restore_models(root) -> Path:
    """Every restoration model folder with placeholder files."""
    from forensics_workshop.media import restore
    base = Path(root)
    for spec in restore.MODELS.values():
        folder = base / spec["folder"]
        folder.mkdir(parents=True, exist_ok=True)
        for name in spec["files"]:
            (folder / name).write_bytes(b"placeholder")
    return base


def install_vp_worker(folder) -> list:
    """The fake voice worker; returns its argv prefix."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    worker = root / "fake_vp_worker.py"
    worker.write_text(FAKE_VP_WORKER, encoding="utf-8")
    return [sys.executable, str(worker)]


def fake_voice_model(folder) -> Path:
    """A model folder with every file get_speechbrain.bat fetches (contents
    are placeholders — the fake worker never reads them)."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    for name in ("hyperparams.yaml", "embedding_model.ckpt",
                 "mean_var_norm_emb.ckpt", "classifier.ckpt",
                 "label_encoder.txt", "label_encoder.ckpt"):
        (root / name).write_bytes(b"placeholder " + name.encode())
    return root


def voice_clip(path, freq: float, *, seconds: float = 4.0, lead: float = 0.5,
               tail: float = 0.5, rate: int = 44100, fmt: str = "pcm16",
               amp: float = 0.4):
    """Silence, a tone at `freq` (one "speaker"), silence — the energy gate
    has a floor to measure."""
    total = lead + seconds + tail
    return write_wav(path, tone(seconds, freq, amp, rate=rate, start=lead,
                                total=total), rate=rate, fmt=fmt)


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
