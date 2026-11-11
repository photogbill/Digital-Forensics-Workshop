"""Synthetic audio and stand-in programs for the media suite.

No network, no GPU: the suite never runs the real FFmpeg or the real
workers. It writes small Python stand-ins and runs them through the very
same subprocess path the engine uses for the real ones (an argv prefix
`[python, fake_ffmpeg.py]`). (The SAM Audio stand-in went with SAM,
2026-10-29.)
"""

from __future__ import annotations

import json
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


FAKE_FFMPEG = r'''
import math, os, struct, sys
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
        if "arnndn=" in chain:
            # FFmpeg's two levels: the graph strips the single quotes, the
            # option parser turns "\\:" back into ":"
            value = chain.split("arnndn=m='", 1)[1].split("'", 1)[0]
            model = value.replace("\\:", ":")
            print("fake ffmpeg: arnndn model " + model)
            if not os.path.isfile(model):
                print("[Parsed_arnndn_0] Error opening model file " + model,
                      file=sys.stderr)
                sys.exit(1)
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
            for key, mkey in (("png", "map"), ("png_high", "map_high")):
                if spec.get(key):
                    tmp = spec[key] + ".part"
                    open(tmp, "wb").write(PNG)
                    os.replace(tmp, spec[key])
                    fa.setdefault(mkey, {"width": 1, "height": 1})
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
    info = {"fake": True}
    copy = req.get("copy") or {}
    if req["dsp"] == "shift" and copy.get("output"):
        k = int(copy.get("factor") or 10)
        if copy["kind"] == "expand":
            write(copy["output"], x[:rate], rate // k)
            info["copy"] = {"kind": "expand", "factor": k, "rate": rate // k,
                            "heard_hz": [1800.0, 2000.0],
                            "start_s": copy.get("start_s") or 0.0,
                            "end_s": copy.get("end_s") or 1.0}
        else:
            write(copy["output"], x[::k], rate)
            info["copy"] = {"kind": "speed", "factor": k, "rate": rate,
                            "heard_hz": [32.0, 320.0]}
    out = {"dsp": req["dsp"], "info": info, "rate": rate}
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
    change = None
    if req.get("residual"):
        write(req["residual"], [a - b for a, b in zip(ref, total)], rate)
        rel = round(energy_db([a - b for a, b in zip(ref, total)]) - energy_db(ref), 2)
        change = {"during_speech_db": rel - 6.0, "during_pauses_db": rel,
                  "added_speech_db": -40.0, "added_pauses_db": -40.0}
    out = {"lags": [0] * len(outs), "rate": rate, "change": change,
           "aligned": req.get("align", True),
           "outputs": [NOISY for _ in outs]}
else:
    sys.exit(2)
out["op"] = op
json.dump(out, open(sys.argv[2] + ".part", "w"))
os.replace(sys.argv[2] + ".part", sys.argv[2])
print("done", flush=True)
'''


FAKE_DEEPFILTER = r'''
import os, struct, sys
# A stand-in for DeepFilterNet's deep-filter: -a N -D -o DIR INPUT. Writes
# DIR/<input's name> as 16-bit PCM at the input's rate, 0.8x the input, as
# the real one writes 16-bit at the input's rate. An input whose name holds
# DFNFAIL exits 3 the way a missing DLL would leave it.
args = sys.argv[1:]
print("FAKE-DEEPFILTER " + " ".join(args), flush=True)
out_dir = args[args.index("-o") + 1]
src = args[-1]
if "DFNFAIL" in src:
    print("error: could not load the model (simulated)", flush=True)
    sys.exit(3)
raw = open(src, "rb").read()
pos, rate, tag, data = 12, 48000, 3, b""
while pos + 8 <= len(raw):
    cid, size = raw[pos:pos + 4], struct.unpack("<I", raw[pos + 4:pos + 8])[0]
    body = raw[pos + 8:pos + 8 + size]
    if cid == b"fmt ":
        tag, ch, rate = struct.unpack("<HHI", body[:8])
    elif cid == b"data":
        data = body
        break
    pos += 8 + size + (size & 1)
x = struct.unpack("<%df" % (len(data) // 4), data[:len(data) // 4 * 4]) if tag == 3 \
    else [v / 32768.0 for v in struct.unpack("<%dh" % (len(data) // 2), data)]
pcm = b"".join(struct.pack("<h", max(-32768, min(32767, int(round(v * 0.8 * 32767))))) for v in x)
fmtb = struct.pack("<HHIIHH", 1, 1, rate, rate * 2, 2, 16)
body = b"WAVE" + b"fmt " + struct.pack("<I", 16) + fmtb + b"data" + struct.pack("<I", len(pcm)) + pcm
os.makedirs(out_dir, exist_ok=True)
with open(os.path.join(out_dir, os.path.basename(src)), "wb") as fh:
    fh.write(b"RIFF" + struct.pack("<I", len(body)) + body)
print("Enhanced audio file " + src, flush=True)
'''


def install_deepfilter(folder) -> list:
    """The fake deep-filter; returns its argv prefix."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    exe = root / "fake_deep_filter.py"
    exe.write_text(FAKE_DEEPFILTER, encoding="utf-8")
    return [sys.executable, str(exe)]


def fake_rnnoise_model(folder, name: str = "sh.rnnn") -> Path:
    """A stand-in RNNoise model file (the fake FFmpeg only checks it is
    there, at the path the filter graph's escaping leads to)."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    path = root / name
    path.write_bytes(b"rnnoise-nu model file (test stand-in)\n")
    return path


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


def install_ffmpeg(folder) -> list:
    """Write the FFmpeg stand-in into `folder`; return its argv prefix."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    ff = root / "fake_ffmpeg.py"
    ff.write_text(FAKE_FFMPEG, encoding="utf-8")
    return [sys.executable, str(ff)]


# ---------------------------------------------------------------------------
# HARK (FORENSICS_PLAN §15): a fake worker for the engine's and ATK's tests
# ---------------------------------------------------------------------------

# A stand-in for hark_worker.py: no torch. It answers each op from what the
# test planted beside it (fake_hark_plan.json), writes the map it was asked
# for, counts its runs, and fails an op named in "fail".
FAKE_HARK_WORKER = r'''
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
plan = json.load(open(os.path.join(HERE, "fake_hark_plan.json"), encoding="utf-8"))
req = json.load(open(sys.argv[1], encoding="utf-8"))
op = req["op"]
print("fake hark worker: " + op, flush=True)
log = os.path.join(HERE, "fake_hark_calls.txt")
open(log, "a", encoding="utf-8").write(op + "\n")
if op in plan.get("fail", []):
    print("planted failure in " + op, flush=True)
    sys.exit(3)
PNG = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
       b"\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\xcf\xc0\x00\x00\x03\x01"
       b"\x01\x00\xc9\xfe\x92\xef\x00\x00\x00\x00IEND\xaeB`\x82")
out = dict(plan.get(op) or {})
def copy_wav(src, dst):
    data = open(src, "rb").read()
    open(dst + ".part", "wb").write(data)
    os.replace(dst + ".part", dst)
if op == "hunt" and req.get("png"):
    open(req["png"], "wb").write(PNG)
prm = req.get("params") or {}
if op == "hunt" and prm.get("f0_min_hz") is not None:
    # Move 7's narrowed hunt: the planted one, its grid the range asked
    out = dict(plan.get("hunt_narrow") or out)
    out["grid"] = dict(out.get("grid") or {}, f0_min_hz=prm["f0_min_hz"],
                       f0_max_hz=prm["f0_max_hz"])
if op == "calibrate" and prm.get("probe_f0_hz"):
    narrowed = float(((req.get("hunt") or {}).get("grid") or {})
                     .get("f0_min_hz") or 60.0) > 60.0
    out = dict(plan.get("calibrate_narrow" if narrowed else
                        "calibrate_broad") or out)
    out["probe_f0_hz"] = prm["probe_f0_hz"]
    out["free_given"] = req.get("free")
if op == "calibrate":
    out["phrases_seen"] = len(req.get("phrases") or [])
if op == "extract":
    # the voice and the lift: copies of the input (same rate and length)
    for key in ("voice", "lift"):
        if (req.get("outputs") or {}).get(key):
            copy_wav(req["wav"], req["outputs"][key])
    out.setdefault("rehunt", bool(req.get("rehunt")))
if op == "census":
    # the recording without its machines, and the machine: copies of the input
    for key in ("without", "machine"):
        if (req.get("outputs") or {}).get(key):
            copy_wav(req["wav"], req["outputs"][key])
    out["machines"] = [{"track": m.get("track", 1), "start_s": m["start_s"],
                        "end_s": m["end_s"],
                        "f0_median_hz": m.get("f0_median_hz", 0.0),
                        "refined_pct": 0.1}
                       for m in req.get("machines") or []] \
        if req.get("outputs") else []
    out["machines_given"] = len(req.get("machines") or [])
    out.setdefault("versions", {"torch": "fake", "device": "cpu"})
if op == "probe":
    for key in ("probe", "clean"):
        copy_wav(req["wav"], req["outputs"][key])
    out["phrases_given"] = len(req.get("phrases") or [])
if op == "score":
    planted = plan.get("scores") or {}
    default = plan.get("default_score")
    ids = ["unprocessed"] + [o["id"] for o in req.get("outputs") or []]
    for o in req.get("outputs") or []:
        for path in o["paths"]:
            if not os.path.isfile(path):
                print("missing output " + path, flush=True)
                sys.exit(4)
    out = {"scores": {i: planted.get(i, default) for i in ids}, "gaps": 2}
if op == "audit":
    flags = plan.get("audit_flags", {})
    out = {"targets": [dict({"id": t["id"], "removed": [], "removed_possible": [],
                             "made": [], "revealed": [], "supported": 1,
                             "residual_tracks": 0, "output_tracks": 1},
                            **flags.get(t["id"].split(":")[0], {}),
                            had_residual=bool(t.get("residual")))
                       for t in req["targets"]]}
out["op"] = op
out["elapsed_s"] = 0.01
json.dump(out, open(sys.argv[2], "w", encoding="utf-8"))
'''

# A stand-in for selftrain_worker.py: no torch. "selftrain" copies the 16 kHz
# input to the output and writes a small model file; "apply" copies its
# input. It logs its ops beside the HARK fake's (fake_selftrain_calls.txt)
# and fails an op named in fake_selftrain_fail.txt.
FAKE_SELFTRAIN_WORKER = r'''
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
req = json.load(open(sys.argv[1], encoding="utf-8"))
op = req["op"]
print("fake selftrain worker: " + op, flush=True)
open(os.path.join(HERE, "fake_selftrain_calls.txt"), "a",
     encoding="utf-8").write(op + ":" + ("finetune" if req.get("weights") else
                                          "scratch") + "\n")
fail = os.path.join(HERE, "fake_selftrain_fail.txt")
if os.path.exists(fail) and op in open(fail).read().split():
    print("planted failure in " + op, flush=True)
    sys.exit(3)
def copy_wav(src, dst):
    data = open(src, "rb").read()
    open(dst + ".part", "wb").write(data)
    os.replace(dst + ".part", dst)
if op == "selftrain":
    copy_wav(req["wav"], req["outputs"]["output"])
    if req["outputs"].get("base"):
        copy_wav(req["wav"], req["outputs"]["base"])
    open(req["outputs"]["model"] + ".part", "wb").write(b"fake gtcrn weights")
    os.replace(req["outputs"]["model"] + ".part", req["outputs"]["model"])
    out = {"mode": "finetune" if req.get("weights") else "scratch",
           "steps": 120, "best_step": 100, "check_first": 9.5,
           "check_best": 7.25, "improved": True, "curve": [[0, 9.5],
                                                          [100, 7.25]],
           "train_s": 1.0, "noise_s": 2.5, "rate": 16000,
           "free_seen": req.get("free"), "teacher": bool(req.get("teacher")),
           "versions": {"torch": "fake", "device": "cpu"}}
elif op == "apply":
    copy_wav(req["wav"], req["output"])
    out = {"rate": 16000, "versions": {"torch": "fake", "device": "cpu"}}
else:
    sys.exit(2)
out["op"] = op
out["elapsed_s"] = 0.01
json.dump(out, open(sys.argv[2], "w", encoding="utf-8"))
'''


def install_selftrain_worker(folder, fail=()) -> list:
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    (root / "fake_selftrain_worker.py").write_text(FAKE_SELFTRAIN_WORKER,
                                                   encoding="utf-8")
    calls = root / "fake_selftrain_calls.txt"
    if calls.exists():
        calls.unlink()
    flag = root / "fake_selftrain_fail.txt"
    if fail:
        flag.write_text(" ".join(fail), encoding="utf-8")
    elif flag.exists():
        flag.unlink()
    return [sys.executable, str(root / "fake_selftrain_worker.py")]


def selftrain_calls(folder) -> list[str]:
    path = Path(folder) / "fake_selftrain_calls.txt"
    return path.read_text(encoding="utf-8").split() if path.exists() else []


def fake_gtcrn_weights(folder) -> Path:
    """A stand-in for GTCRN's published weights (the fake worker only
    checks a path was given)."""
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    path = root / "model_trained_on_dns3.tar"
    path.write_bytes(b"GTCRN DNS3 weights (test stand-in)\n")
    return path


HARK_SEG = {"track": 1, "start_s": 1.2, "end_s": 2.6, "frames": 140,
            "voiced_frames": 120, "parts": 2, "f0_median_hz": 132.0,
            "f0_min_hz": 118.0, "f0_max_hz": 151.0, "f0_hz": [132.0] * 140,
            "score": 210.0, "fa_per_hour": 0.0, "fa_extrapolated": True,
            "status": "detected", "level_est_db": -7.0}

HARK_PLAN = {
    "hunt": {"rate": 16000, "duration_s": 3.0, "frames": 290,
             "device": "cpu", "grid": {"steps_per_octave": 36, "top_hz": 4000},
             "slopes": [0.0], "log_noise": [0.0] * 8,
             "null": {"mu": [0.0], "sd": [1.0], "sd_slope": [[1.0]],
                      "scores": [10.0, 20.0], "hours": 0.25, "rho": 2.5},
             "thresholds": {"detect_score": 120.0, "possible_score": 60.0,
                            "detect_fa_per_hour": 0.1,
                            "possible_fa_per_hour": 10.0},
             "segments": [HARK_SEG],
             "tracks": [{"track": 1, "detected_s": 1.4, "possible_s": 0.0,
                         "f0_median_hz": 132.0, "f0_p10_hz": 120.0,
                         "f0_p90_hz": 148.0}],
             "free": [[0.0, 1.0]], "surrogates": 4, "excised_s": 1.7,
             "map": {"width": 1, "height": 1, "top_hz": 2000.0,
                     "scale": "linear"}},
    "calibrate": {"levels": [
        {"level_db": 0.0, "n": 4, "detected": 4, "possible": 4, "pd": 1.0,
         "pd_synthetic": 1.0, "pd_phrase": 1.0, "estoi_raw": 0.62},
        {"level_db": -10.0, "n": 4, "detected": 2, "possible": 3, "pd": 0.5,
         "pd_synthetic": 0.5, "pd_phrase": 0.5, "estoi_raw": 0.31}],
        "pd50_db": -10.0, "pd90_db": -2.0, "estoi_half_db": -3.5,
        "level_offset_db": -1.0, "level_pairs": 5, "injections": 8},
    "audit_flags": {},
    "extract": {"rate": 16000, "voiced_s": 1.3, "top_hz": 4000.0,
                "cycles": 6.0, "tracks": [1],
                "runs": [{"track": 1, "start_s": 1.2, "end_s": 2.5,
                          "f0_median_hz": 131.0, "refined_pct": 0.8}],
                "versions": {"torch": "fake", "device": "cpu"}},
    "census": {"modulated": {"items": [
        {"kind": "pulsing", "rate_hz": 7.5, "start_s": 0.0, "end_s": 3.0,
         "windows": 1, "score": 9.0, "fa_per_hour": 0.001,
         "fa_extrapolated": False, "status": "detected",
         "multiples": [1, 2]}],
        "bands_hz": [100.0, 8000.0], "null_hours": 0.01, "windows": 1,
        "rates_tried": 400}, "rate": 16000},
    "probe": {"rate": 16000, "duration_s": 3.0, "levels": [0.0, -10.0],
              "per_level": 1, "noise_from_file_s": 1.0,
              "noise_surrogate_s": 2.0,
              "phrases": [{"n": 1, "level_db": 0.0, "phrase": 0,
                           "start_s": 0.5, "end_s": 1.4},
                          {"n": 2, "level_db": -10.0, "phrase": 1,
                           "start_s": 1.8, "end_s": 2.7}]},
    "scores": {
        "unprocessed": {"noise_left_db": 0.0, "by_level": [
            {"level_db": 0.0, "n": 1, "estoi": 0.40, "si_snr_db": -1.0},
            {"level_db": -10.0, "n": 1, "estoi": 0.15, "si_snr_db": -11.0}]},
        "hark": {"noise_left_db": -10.0, "by_level": [
            {"level_db": 0.0, "n": 1, "estoi": 0.50, "si_snr_db": 6.0},
            {"level_db": -10.0, "n": 1, "estoi": 0.22, "si_snr_db": -2.0}]}},
    "default_score": {"noise_left_db": -6.0, "by_level": [
        {"level_db": 0.0, "n": 1, "estoi": 0.42, "si_snr_db": 2.0},
        {"level_db": -10.0, "n": 1, "estoi": 0.16, "si_snr_db": -8.0}]},
}


def install_hark_worker(folder, plan=None) -> list:
    root = Path(folder)
    root.mkdir(parents=True, exist_ok=True)
    (root / "fake_hark_worker.py").write_text(FAKE_HARK_WORKER,
                                              encoding="utf-8")
    (root / "fake_hark_plan.json").write_text(json.dumps(plan or HARK_PLAN),
                                              encoding="utf-8")
    calls = root / "fake_hark_calls.txt"
    if calls.exists():
        calls.unlink()
    return [sys.executable, str(root / "fake_hark_worker.py")]


def hark_calls(folder) -> list[str]:
    path = Path(folder) / "fake_hark_calls.txt"
    return path.read_text(encoding="utf-8").split() if path.exists() else []
