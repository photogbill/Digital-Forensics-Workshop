# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The restoration worker — run as its own process, never imported.

    python -I restore_worker.py REQUEST.json RESPONSE.json

Started by `restore.py` under the host's torch interpreter (ATK:
`envs\\atk_audio\\Scripts\\python.exe`). SELF-CONTAINED: it imports nothing
from the engine, only torch (and SpeechBrain for a model step), and writes
only the paths it is told to — each output WAV and the one response, every
one of them checked by the parent (`assert_child_writes`) before it started.

Four operations, one per request (`"op"`):

* **analyse** — what is wrong with a recording, MEASURED: level, peak, DC
  offset, clipping, clicks, the noise floor and speech level of 25 ms
  frames and the SNR between them, steadiness of the noise, mains hum
  (prominence of 50 or 60 Hz and its harmonics over their neighbours),
  low-frequency rumble, and the bandwidth the speech actually occupies. No
  model; numbers only. The engine turns them into recommendations.
* **model** — one SpeechBrain model over a 16 kHz mono file:
  MetricGAN+ (`SpectralMaskEnhancement`), SepFormer DNS4 enhancement or
  SepFormer WHAMR! two-voice separation (`SepformerSeparation`), loaded
  from its local folder exactly as `vp_worker.py` loads the voice model (no
  network, no symlinks). Long recordings go in overlapping chunks joined by a
  cross-fade; each chunk's output is rescaled to the input by least squares
  (a measured gain — SepFormer's output level is otherwise arbitrary), and for
  two voices each chunk's pair is matched to the previous chunk's so a voice
  does not swap sides at a chunk edge.
* **analyse**, extended for faint sounds (§13.8): given every channel, it
  measures how they relate and, when they carry one sound, combines them
  (maximal-ratio, distortionless toward the best channel — Recovered) and measures
  everything on the combination; it draws the SALIENCE MAP (where something
  stands out of the recording's own noise, long-integrated), cuts a clip of
  each faint event, lists TONAL LINES, and looks for REPEATS.
* **analyse** also says WHAT THE FILE REALLY HOLDS (§13.9): the highest
  frequency with real content against the top the sample rate allows — a
  codec's or a telephone's brick wall, a recording made at a lower rate and
  stored at a higher one, the recorder's own anti-alias filter, or content
  running right up to the top with no roll-off (sound above the top may
  have folded down into the band) — and at the bottom, energy below 20 Hz
  or the recorder's high-pass. And above 12 kHz a second map, LINEAR in
  frequency, where the mel map squeezes the top together.
* **dsp** — a faint-sound step: "mask" keeps what stands out of the noise
  (Cleaned), "average" averages waveform repeats (Recovered), "repet" lifts
  a repeating background off what does not repeat (Cleaned), "shift" moves
  a band out of hearing into it (single-sideband: every frequency moved by
  the same amount, the timing untouched) and writes the same band played
  slower (above hearing) or faster (below it) — Measured.
* **finish** — after a restoration chain: each output is ALIGNED to the
  input (a cross-correlation finds the lag — FFmpeg's afftdn delays its
  output by about 25 ms, measured 2026-10-09 — and the output is shifted
  back, so a restored file lines up with the original sample for sample);
  the RESIDUAL (input minus the aligned outputs) is written to listen to;
  and what changed is measured from MAGNITUDE spectra, so the phase shift an
  IIR notch puts on a voice harmonic near it is not miscounted as removal:
  the energy taken away and the energy ADDED, relative to the input, while
  speech was present and in the pauses. Lots taken from the pauses, little
  more from the speech than its noise, and nothing added, is what a good
  clean-up looks like; energy added is a model making sound.
"""

from __future__ import annotations

import json
import math
import os
import struct
import sys
import time

CHUNK_S = {"metricgan": 30.0, "sepformer-dns4": 8.0, "sepformer-whamr": 8.0}
OVERLAP_S = 1.0
FRAME_S = 0.025
HOP_S = 0.010


def _say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# WAV in and out (float32 out, so nothing is clipped on the way)
# ---------------------------------------------------------------------------

def read_wav(path):
    """(mono float tensor, rate) from PCM 8/16/24/32-bit or float 32/64 —
    the channels averaged."""
    x, rate = read_wav_channels(path)
    return (x.mean(dim=0) if x.shape[0] > 1 else x[0]), rate


def read_wav_channels(path):
    """([channels, samples] float tensor, rate)."""
    import torch
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
        raise ValueError(f"{path} is not a RIFF/WAVE file")
    pos, fmt, data = 12, None, None
    while pos + 8 <= len(raw):
        cid = raw[pos:pos + 4]
        size = struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            tag, ch, rate = struct.unpack("<HHI", body[:8])
            bits = struct.unpack("<H", body[14:16])[0]
            if tag == 0xFFFE and len(body) >= 26:
                tag = struct.unpack("<H", body[24:26])[0]
            fmt = (tag, ch, rate, bits)
        elif cid == b"data":
            data = body
            break
        pos += 8 + size + (size & 1)
    if fmt is None or data is None:
        raise ValueError(f"{path} has no fmt or data chunk")
    tag, ch, rate, bits = fmt
    width = bits // 8
    usable = len(data) - len(data) % (width * ch)
    data = bytearray(data[:usable])
    if tag == 3 and bits == 32:
        x = torch.frombuffer(data, dtype=torch.float32).clone()
    elif tag == 3 and bits == 64:
        x = torch.frombuffer(data, dtype=torch.float64).float()
    elif tag == 1 and bits == 16:
        x = torch.frombuffer(data, dtype=torch.int16).float() / 32768.0
    elif tag == 1 and bits == 32:
        x = torch.frombuffer(data, dtype=torch.int32).float() / 2147483648.0
    elif tag == 1 and bits == 8:
        x = (torch.frombuffer(data, dtype=torch.uint8).float() - 128.0) / 128.0
    elif tag == 1 and bits == 24:
        b = torch.frombuffer(data, dtype=torch.uint8).reshape(-1, 3).int()
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        v = torch.where(v >= 1 << 23, v - (1 << 24), v)
        x = v.float() / 8388608.0
    else:
        raise ValueError(f"{path}: format tag {tag}, {bits}-bit is not read")
    return x.reshape(-1, max(1, ch)).T.contiguous(), rate


def write_wav(path, x, rate: int) -> None:
    """Mono IEEE float32 WAV (format 3, with the fact chunk), written beside
    and renamed into place. The one kind of file this worker writes."""
    import torch
    x = torch.as_tensor(x).detach().float().cpu().contiguous()
    pcm = x.numpy().tobytes() if hasattr(x, "numpy") else bytes()
    fmt = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
            + struct.pack("<II", 4, x.numel()) + b"data"
            + struct.pack("<I", len(pcm)) + pcm)
    _write_bytes(path, b"RIFF" + struct.pack("<I", len(body)) + body)


def _write_bytes(path: str, payload: bytes) -> None:
    tmp = f"{path}.{os.getpid()}.part"
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_json(path: str, data: dict) -> None:
    _write_bytes(path, json.dumps(data).encode("utf-8"))


# ---------------------------------------------------------------------------
# analyse
# ---------------------------------------------------------------------------

def _db(power):
    import torch
    return 10.0 * torch.log10(torch.clamp(power, min=1e-12))


#: Long recordings are measured a block of frames at a time, so an hour at
#: 48 kHz never needs the whole recording's frames in memory at once.
BLOCK_FRAMES = 60000


def frames_db(x, rate):
    """dB of each 25 ms frame, 10 ms apart."""
    import torch
    win = max(1, int(rate * FRAME_S))
    hop = max(1, int(rate * HOP_S))
    if x.numel() < win:
        return _db((x * x).mean().reshape(1))
    n = (x.numel() - win) // hop + 1
    parts = []
    for k0 in range(0, n, BLOCK_FRAMES):
        k1 = min(n, k0 + BLOCK_FRAMES)
        f = x[k0 * hop:(k1 - 1) * hop + win].unfold(0, win, hop)
        parts.append((f * f).mean(dim=1))
    return _db(torch.cat(parts))


def speech_split(db):
    """(speech mask, floor dB, speech dB, gate dB) from frame levels. A
    recording with nothing above the gate — steady noise, or a faint sound
    in it — has no speech: the mask is empty and every frame is a pause."""
    floor = torch_quantile(db, 0.10)
    loud = torch_quantile(db, 0.95)
    gate = max(-60.0, floor + max(6.0, 0.35 * (loud - floor)))
    return db >= gate, floor, loud, gate


def torch_quantile(db, q: float) -> float:
    import torch
    return torch.quantile(db, q).item()


def _mean_db(db, mask) -> float:
    import torch
    if not bool(mask.any()):
        return -120.0
    return 10.0 * math.log10(max(1e-12, torch.pow(10.0, db[mask] / 10.0)
                                 .mean().item()))


def _clipping(x):
    """(fraction of samples in flat-topped runs at the peak, number of runs).
    Only a recording that reaches full scale can be clipped; a run is two or
    more consecutive samples at the peak."""
    import torch
    peak = float(x.abs().max()) if x.numel() else 0.0
    if peak < 0.98 or x.numel() < 2:
        return 0.0, 0
    hot = x.abs() >= 0.999 * peak
    neighbour = torch.zeros_like(hot)
    neighbour[1:] |= hot[:-1]
    neighbour[:-1] |= hot[1:]
    in_run = hot & neighbour
    previous = torch.cat([torch.zeros(1, dtype=torch.bool), in_run[:-1]])
    runs = int((in_run & ~previous).sum())
    return int(in_run.sum()) / x.numel(), runs


def _clicks(x, rate) -> float:
    """Impulsive jumps per second: a sample-to-sample step far above the
    typical step of its neighbourhood, clustered within 2 ms."""
    import torch
    if x.numel() < rate // 10:
        return 0.0
    block = max(64, int(rate * 0.02))
    span = block * max(1, int(10 * rate) // block)        # ten seconds
    gap = int(rate * 0.002)
    clusters, last = 0, None
    for a in range(0, x.numel() - 1, span):
        seg = x[a:a + span + 1]
        d = (seg[1:] - seg[:-1]).abs()
        n = d.numel() // block * block
        if n == 0:
            continue
        local = d[:n].reshape(-1, block).median(dim=1).values
        local = torch.repeat_interleave(local, block)
        hits = torch.nonzero((d[:n] > 8.0 * local + 1e-4) &
                             (d[:n] > 0.1)).flatten() + a
        if hits.numel() == 0:
            continue
        starts = 1 + int(((hits[1:] - hits[:-1]) > gap).sum())
        if last is not None and int(hits[0]) - last <= gap:
            starts -= 1
        clusters += starts
        last = int(hits[-1])
    return clusters / (x.numel() / rate)


def _spectra(x, rate, mask_frames_db):
    """(freqs, all, quiet, loud) mean power spectra, ~4 Hz resolution."""
    import torch
    n_fft = 1 << max(8, int(math.ceil(math.log2(max(256, rate // 4)))))
    if x.numel() < n_fft:
        x = torch.nn.functional.pad(x, (0, n_fft - x.numel()))
    hop = n_fft // 4
    win = torch.hann_window(n_fft)
    n = (x.numel() - n_fft) // hop + 1
    step = max(1, BLOCK_FRAMES // 64)

    def block(k0, k1):
        return torch.stft(x[k0 * hop:(k1 - 1) * hop + n_fft], n_fft=n_fft,
                          hop_length=hop, window=win, return_complex=True,
                          center=False).abs().pow(2)

    # two passes, a block at a time: every frame's energy, then the mean
    # spectra of all frames, the quietest 30% and the loudest 30%
    energy = torch.cat([block(k0, min(n, k0 + step)).sum(dim=0)
                        for k0 in range(0, n, step)])
    order = torch.argsort(energy)
    k = max(1, int(0.3 * order.numel()))
    is_quiet = torch.zeros(n, dtype=torch.bool)
    is_loud = torch.zeros(n, dtype=torch.bool)
    is_quiet[order[:k]] = True
    is_loud[order[-k:]] = True
    F = n_fft // 2 + 1
    total, quiet, loud = torch.zeros(F), torch.zeros(F), torch.zeros(F)
    for k0 in range(0, n, step):
        k1 = min(n, k0 + step)
        spec = block(k0, k1)
        total += spec.sum(dim=1)
        quiet += spec[:, is_quiet[k0:k1]].sum(dim=1)
        loud += spec[:, is_loud[k0:k1]].sum(dim=1)
    freqs = torch.arange(F) * rate / n_fft
    return freqs, total / n, quiet / k, loud / k


def _hum(freqs, power, rate) -> dict:
    """The strongest mains family: prominence of each harmonic's peak (±2 Hz)
    over the median of its neighbours (6-25 Hz either side), dB. Measured on
    the QUIET frames' spectrum: hum stays when the talker pauses and a voice
    does not, and a voice at 120 or 180 Hz puts its own harmonics on mains
    multiples (the first test caught exactly that)."""
    import torch
    best = {"hz": 0, "prominence_db": 0.0, "harmonics": 0, "per_harmonic": []}
    for f0 in (50, 60):
        proms = []
        for k in range(1, 9):
            f = k * f0
            if f > 0.45 * rate or f > 1000:
                break
            peak_band = (freqs >= f - 2) & (freqs <= f + 2)
            side = ((freqs >= f - 25) & (freqs <= f - 6)) | \
                   ((freqs >= f + 6) & (freqs <= f + 25))
            if not bool(peak_band.any()) or not bool(side.any()):
                continue
            p = power[peak_band].max().item()
            s = power[side].median().item()
            proms.append(round(10.0 * math.log10(max(p, 1e-20) /
                                                 max(s, 1e-20)), 2))
        strong = [p for p in proms if p >= 8.0]
        top = sorted(proms, reverse=True)[:3]
        score = sum(top) / len(top) if top else 0.0
        if len(strong) >= 2 and score > best["prominence_db"]:
            best = {"hz": f0, "prominence_db": round(score, 2),
                    "harmonics": len(strong), "per_harmonic": proms}
    return best


def _bandwidth(freqs, loud, rate) -> float:
    """Top of the band the speech occupies: the highest 250 Hz band within
    35 dB of the median level of the 300-3000 Hz bands."""
    edges = list(range(0, int(rate / 2), 250))
    levels = []
    for lo in edges:
        sel = (freqs >= lo) & (freqs < lo + 250)
        levels.append(10.0 * math.log10(max(1e-20, loud[sel].mean().item()))
                      if bool(sel.any()) else -200.0)
    core = sorted(l for lo, l in zip(edges, levels) if 300 <= lo < 3000)
    if not core:
        return rate / 2
    ref = core[len(core) // 2]
    top = 0
    for lo, lvl in zip(edges, levels):
        if lvl >= ref - 35.0:
            top = lo + 250
    return float(min(top, rate / 2))


#: Standard sample rates: a file whose content stops near half of one of
#: these, stored at a higher rate, was made at that rate.
STD_RATES = (8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000,
             88200, 96000, 176400, 192000)
CONTENT_RES_HZ = 1.0
CONTENT_BAND_HZ = 50.0
#: A brick wall: the level 100-600 Hz above an edge at least this far under
#: the level 100-500 Hz below it, and nothing above it climbing back within
#: CUT_STAYS_DB; searched from CUT_MIN_HZ up (speech itself falls away
#: below that, smoothly).
CUT_DROP_DB = 25.0
CUT_STAYS_DB = 18.0
CUT_MIN_HZ = 3000.0
#: An edge above this share of the top is the recorder's own anti-alias
#: filter, which every proper recording has.
ANTI_ALIAS_SHARE = 0.88
#: Content within this many dB of 60-80% of the top, right at the top:
#: no anti-alias roll-off.
OPEN_TOP_DB = 6.0
#: Below 20 Hz within this many dB of 50-200 Hz (per hertz): infrasound
#: worth listening to. The recorder's high-pass: the bottom this far under.
INFRA_PRESENT_DB = -10.0
LOW_CUT_DB = 25.0


def _welch(x, rate, res_hz: float):
    """(freqs, mean power per bin) of the signal with its mean taken off,
    bins about `res_hz` apart (wider for a short file), in blocks."""
    import torch
    n = _pow2(rate / res_hz)
    while n > 256 and n > x.numel() // 4:
        n //= 2
    x = x - x.mean()
    if x.numel() < n:
        x = torch.nn.functional.pad(x, (0, n - x.numel()))
    hop = n // 2
    win = torch.hann_window(n)
    K = (x.numel() - n) // hop + 1
    S = torch.zeros(n // 2 + 1)
    for a in range(0, K, 64):
        b = min(K, a + 64)
        S += torch.stft(x[a * hop:(b - 1) * hop + n], n, hop, window=win,
                        center=False, return_complex=True).abs().pow(2) \
            .sum(dim=1)
    return torch.arange(n // 2 + 1) * rate / n, S / K


def _cut_label(cut: float, rate: int) -> tuple[str, str, int | None]:
    """(kind, label, rate it was made at) for a brick wall at `cut` Hz."""
    nyq = rate / 2
    made = None
    best = None
    for r in STD_RATES:
        if r < rate and 0.80 * r / 2 <= cut <= 1.0 * r / 2:
            score = abs(cut / (r / 2) - 0.92)
            if best is None or score < best:
                best, made = score, r
    if cut >= ANTI_ALIAS_SHARE * nyq:
        return ("anti-alias", f"Cut at {cut / 1000:.1f} kHz, near the top — "
                "the recorder's anti-alias filter (or a codec's low-pass at "
                "a high bit rate): normal", None)
    if 3000 <= cut <= 4200:
        return ("telephone", "Telephone call (narrowband — AMR, GSM, G.711) "
                "or an 8 kHz recording: nothing above about "
                f"{cut / 1000:.1f} kHz", made)
    if 6500 <= cut <= 8100:
        return ("telephone", "Wideband call (AMR-WB, HD Voice) or a 16 kHz "
                f"recording: nothing above about {cut / 1000:.1f} kHz", made)
    if 9500 <= cut <= 20500:
        return ("codec", f"Cut at {cut / 1000:.1f} kHz — a lossy codec's "
                "low-pass (AAC, MP3, Opus" + (" at a low bit rate" if cut <
                                              13000 else "") + ")" + (
                    f" or a {made / 1000:g} kHz recording" if made else ""),
                made)
    if made:
        return ("upsampled", f"Made at {made / 1000:g} kHz, stored at "
                f"{rate / 1000:g} kHz: nothing above {cut / 1000:.1f} kHz",
                made)
    return ("cut", f"Cut at {cut / 1000:.1f} kHz — a filter or codec in the "
            "chain", None)


def content_extent(x, rate) -> dict:
    """What the file really holds, from its long-term spectrum (50 Hz
    bands): the highest frequency with real content against the top the
    rate allows, and why it stops there; and at the bottom, how much lies
    below 20 Hz and whether the recorder cut it."""
    import torch
    nyq = rate / 2
    out = {"nyquist_hz": nyq, "cutoff_hz": None, "drop_db": None,
           "kind": "", "label": "", "made_at": None, "top_hz": nyq,
           "folded_risk": False, "infrasound_db": None, "infrasound": False,
           "low_cut_hz": None}
    if x.numel() < 1024:
        return out
    freqs, S = _welch(x, rate, CONTENT_RES_HZ)
    df = float(freqs[1])
    bw = CONTENT_BAND_HZ
    nb = max(1, int(nyq // bw))
    idx = (freqs / bw).long().clamp(max=nb - 1)
    sums = torch.zeros(nb).index_add_(0, idx, S)
    cnt = torch.zeros(nb).index_add_(0, idx, torch.ones_like(S))
    L = 10.0 * torch.log10((sums / cnt.clamp(min=1)).clamp(min=1e-20))

    def med(a, b):
        a, b = max(0, int(a)), min(nb, int(b))
        return float(L[a:b].median()) if b > a else None

    ref = med(300 / bw, 3000 / bw)
    best = None
    top_i = int(0.995 * nyq / bw)
    for i in range(int(CUT_MIN_HZ / bw), nb - 3):
        below = med(i - 10, i - 2)
        near = med(i + 2, i + 12)
        if below is None or near is None:
            continue
        rest = L[i + 5:top_i]
        stays = float(torch.quantile(rest, 0.95)) if rest.numel() >= 2 \
            else near
        drop = below - near
        if drop >= CUT_DROP_DB and below - stays >= CUT_STAYS_DB and (
                best is None or drop > best[0]):
            best = (drop, i, below)
    if best is not None:
        drop, i, below = best
        # the edge itself: the first band 6 dB under the highest level in
        # the kilohertz below it that keeps falling (6 dB more within
        # 300 Hz) — a resampler's gentle transition starts where the
        # content ends, not where the level has finally gone
        cut_j = i
        for j in range(max(int(CUT_MIN_HZ / bw), i - 30), min(nb - 6, i + 12)):
            peak = float(L[max(0, j - 20):j].max())
            if float(L[j]) < peak - 6.0 and \
                    float(L[j + 6]) < float(L[j]) - 6.0:
                cut_j = j
                break
        cut = round(cut_j * bw, 1)
        kind, label, made = _cut_label(cut, rate)
        out.update(cutoff_hz=cut, drop_db=round(drop, 1), kind=kind,
                   label=label, made_at=made, top_hz=cut)
    else:
        top = med(0.95 * nyq / bw, 0.99 * nyq / bw)
        mid = med(0.60 * nyq / bw, 0.80 * nyq / bw)
        if rate <= 16000:
            out.update(kind="telephone", label=(
                f"A {rate / 1000:g} kHz file — a telephone or voice-recorder "
                f"rate: nothing above {nyq / 1000:g} kHz can be in it"))
        elif top is not None and mid is not None and ref is not None and \
                top >= mid - OPEN_TOP_DB and top > ref - 60.0:
            out.update(kind="open", folded_risk=True, label=(
                f"Content right up to the top ({nyq / 1000:.1f} kHz) with no "
                "anti-alias roll-off: either the recorder has no anti-alias "
                f"filter — so sound above {nyq / 1000:.1f} kHz may have "
                "folded down into the band (aliasing) — or the noise was "
                "made digitally"))
        else:
            hi = 0
            for i in range(nb):
                if ref is not None and float(L[i]) >= ref - 40.0:
                    hi = i
            out.update(kind="rolloff", top_hz=round((hi + 1) * bw, 1),
                       label=f"No hard cut: content tapers off toward "
                       f"{(hi + 1) * bw / 1000:.1f} kHz (within 40 dB of "
                       "the 0.3-3 kHz level)")
    # the bottom: per-hertz density against 50-200 Hz
    lo_ref = (freqs >= 50) & (freqs <= 200)
    if df <= 2.0 and bool(lo_ref.any()):
        r = float(S[lo_ref].mean())
        infra = (freqs >= max(2.0, 2.5 * df)) & (freqs <= 20.0)
        if bool(infra.any()) and r > 0:
            v = 10.0 * math.log10(max(1e-30, float(S[infra].mean())) / r)
            out["infrasound_db"] = round(v, 1)
            out["infrasound"] = v >= INFRA_PRESENT_DB and \
                float(S[infra].mean()) > 1e-16
        bottom = (freqs >= max(2.0, 2.5 * df)) & (freqs <= 10.0)
        if bool(bottom.any()) and r > 0 and 10.0 * math.log10(
                max(1e-30, float(S[bottom].mean())) / r) <= -LOW_CUT_DB:
            f = 10.0
            while f < 200.0:
                sel = (freqs >= f) & (freqs < f + 5.0)
                if bool(sel.any()) and 10.0 * math.log10(max(1e-30, float(
                        S[sel].mean())) / r) >= -10.0:
                    break
                f += 5.0
            out["low_cut_hz"] = f
    return out


def analyse(path, content: bool = True) -> dict:
    import torch
    x, rate = read_wav(path)
    n = x.numel()
    if n == 0:
        return {"duration_s": 0.0, "rate": rate, "empty": True}
    db = frames_db(x, rate)
    mask, floor, loud, gate = speech_split(db)
    noise_db = db[~mask] if bool((~mask).any()) else db
    peak = float(x.abs().max())
    freqs, allp, quiet, loudp = _spectra(x, rate, db)
    low = freqs < 80
    mid = (freqs >= 80) & (freqs < min(4000, rate / 2))
    rumble = 10.0 * math.log10(max(1e-20, quiet[low].sum().item()) /
                               max(1e-20, quiet[mid].sum().item()))
    clip_frac, clip_runs = _clipping(x)
    extra = {"content": content_extent(x, rate)} if content else {}
    return extra | {
        "duration_s": round(n / rate, 3), "rate": rate,
        "peak_dbfs": round(20.0 * math.log10(max(peak, 1e-9)), 2),
        "rms_dbfs": round(10.0 * math.log10(max(1e-12, float((x * x).mean()))),
                          2),
        "dc_offset": round(float(x.mean()), 6),
        "clipped_fraction": round(clip_frac, 6), "clipped_runs": clip_runs,
        "clicks_per_s": round(_clicks(x, rate), 3),
        "floor_db": round(floor, 2), "speech_peak_db": round(loud, 2),
        "gate_db": round(gate, 2),
        "speech_fraction": round(float(mask.float().mean()), 4),
        "speech_db": round(_mean_db(db, mask), 2) if bool(mask.any())
        else None,
        "noise_db": round(_mean_db(db, ~mask), 2) if bool((~mask).any())
        else round(_mean_db(db, mask), 2),
        "snr_db": round(_mean_db(db, mask) - _mean_db(db, ~mask), 2)
        if bool((~mask).any()) and bool(mask.any()) else None,
        "noise_steadiness_db": round(float(noise_db.std()), 2)
        if noise_db.numel() > 1 else 0.0,
        "hum": _hum(freqs, quiet, rate),
        "rumble_db": round(rumble, 2),
        "bandwidth_hz": round(_bandwidth(freqs, loudp, rate), 1),
    }


# ---------------------------------------------------------------------------
# model
# ---------------------------------------------------------------------------

def _device(wanted: str) -> str:
    import torch
    wanted = (wanted or "auto").lower()
    if wanted == "auto":
        return "cuda:0" if torch.cuda.is_available() else "cpu"
    if wanted.startswith("cuda") and not torch.cuda.is_available():
        raise RuntimeError("CUDA was asked for but torch sees no CUDA device "
                           f"(torch {torch.__version__})")
    return "cuda:0" if wanted == "cuda" else wanted


def _load(kind: str, model_dir: str, device: str):
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from speechbrain.utils.fetching import LocalStrategy
    folder = os.path.abspath(model_dir).replace("\\", "/")
    if kind == "metricgan":
        from speechbrain.inference.enhancement import SpectralMaskEnhancement
        cls = SpectralMaskEnhancement
    elif kind in ("sepformer-dns4", "sepformer-whamr"):
        from speechbrain.inference.separation import SepformerSeparation
        cls = SepformerSeparation
    else:
        raise ValueError(f"unknown model {kind!r}")
    model = cls.from_hparams(
        source=folder, savedir=folder, local_strategy=LocalStrategy.NO_LINK,
        overrides={"pretrained_path": folder}, overrides_must_match=False,
        run_opts={"device": device})
    model.eval()
    return model


def _run_chunk(kind, model, seg, device):
    """[T] -> [S, T] on the CPU."""
    import torch
    with torch.no_grad():
        batch = seg.unsqueeze(0).to(device)
        if kind == "metricgan":
            out = model.enhance_batch(batch, lengths=torch.tensor([1.0]))
            out = out.reshape(1, -1)
        else:
            out = model.separate_batch(batch)[0].transpose(0, 1)
    out = out.float().cpu()
    t = seg.numel()
    if out.shape[1] < t:
        out = torch.nn.functional.pad(out, (0, t - out.shape[1]))
    return out[:, :t]


def _fit_gain(src, target):
    """Least-squares gain putting `src` at `target`'s level."""
    den = float((src * src).sum())
    return float((src * target).sum()) / den if den > 0 else 0.0


def run_model(kind, model, x, rate, device):
    """Chunks with a cross-fade; per-chunk LS gain; two-voice pairs matched."""
    import torch
    chunk = int(CHUNK_S[kind] * rate)
    overlap = int(OVERLAP_S * rate)
    step = max(1, chunk - overlap)
    starts = list(range(0, max(1, x.numel() - overlap), step)) or [0]
    out = None
    prev = None
    for i, a in enumerate(starts):
        b = min(x.numel(), a + chunk)
        seg = x[a:b]
        est = _run_chunk(kind, model, seg, device)
        if est.shape[0] == 1:
            est = est * _fit_gain(est[0], seg)
        else:
            if prev is not None and overlap > 0:
                o = min(overlap, est.shape[1], prev.shape[1])
                tail = prev[:, -o:]
                head = est[:, :o]
                keep = (abs(_corr(tail[0], head[0])) + abs(_corr(tail[1], head[1])))
                swap = (abs(_corr(tail[0], head[1])) + abs(_corr(tail[1], head[0])))
                if swap > keep:
                    est = est.flip(0)
            g = torch.linalg.lstsq(est.T, seg.unsqueeze(1)).solution.flatten()
            est = est * g.unsqueeze(1)
        if out is None:
            out = torch.zeros(est.shape[0], x.numel())
            out[:, a:b] = est
        else:
            o = min(overlap, (starts[i - 1] + chunk) - a, b - a)
            if o > 0:
                fade = torch.linspace(0.0, 1.0, o)
                out[:, a:a + o] = out[:, a:a + o] * (1 - fade) + est[:, :o] * fade
            out[:, a + max(o, 0):b] = est[:, max(o, 0):]
        prev = est
        _say(f"chunk {i + 1} of {len(starts)}")
    return out


def _corr(a, b) -> float:
    a = a - a.mean()
    b = b - b.mean()
    den = math.sqrt(float((a * a).sum()) * float((b * b).sum()))
    return float((a * b).sum()) / den if den > 0 else 0.0


def model_op(req) -> dict:
    kind = req["model"]
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["input"])
    if rate != 16000:
        raise ValueError(f"{req['input']} is {rate} Hz; the models take 16 kHz")
    _say(f"loading {kind} from {req['model_dir']} on {device}")
    model = _load(kind, req["model_dir"], device)
    out = run_model(kind, model, x, rate, device)
    paths = req["outputs"]
    if len(paths) != out.shape[0]:
        raise ValueError(f"{kind} made {out.shape[0]} output(s); "
                         f"{len(paths)} path(s) were given")
    for path, row in zip(paths, out):
        write_wav(path, row, rate)
    return _versions(device)


def _versions(device: str) -> dict:
    import torch
    gpu = ""
    if device.startswith("cuda"):
        gpu = torch.cuda.get_device_name(torch.device(device))
    out = {"device": device, "gpu": gpu, "torch": torch.__version__}
    try:
        import speechbrain
        out["speechbrain"] = getattr(speechbrain, "__version__", "")
    except ImportError:
        out["speechbrain"] = ""
    return out


# ---------------------------------------------------------------------------
# finish: align, residual, what changed
# ---------------------------------------------------------------------------

MAX_LAG_S = 0.25
LAG_WINDOW_S = 30.0


def estimate_lag(ref, out, rate, max_lag_s: float = MAX_LAG_S,
                 absolute: bool = False) -> int:
    """Samples by which `out` trails `ref` (negative: leads), from the
    cross-correlation over the loudest LAG_WINDOW_S of the input, searched
    within ±max_lag_s. `absolute` takes the largest peak of either sign, so
    a channel wired in reverse polarity is still found."""
    import torch
    n = min(ref.numel(), out.numel())
    if n < 64:
        return 0
    win = min(n, int(LAG_WINDOW_S * rate))
    start = 0
    if n > win:
        step = max(1, rate)
        best = -1.0
        for s0 in range(0, n - win + 1, step):
            e = float((ref[s0:s0 + win] ** 2).sum())
            if e > best:
                best, start = e, s0
    a = ref[start:start + win]
    b = out[start:start + win]
    size = 1 << int(math.ceil(math.log2(2 * win)))
    cc = torch.fft.irfft(torch.fft.rfft(b, size) *
                         torch.fft.rfft(a, size).conj(), size)
    m = min(int(max_lag_s * rate), win - 1)
    cand = torch.cat([cc[:m + 1], cc[size - m:]]) if m > 0 else cc[:1]
    idx = int(torch.argmax(cand.abs() if absolute else cand))
    return idx if idx <= m else idx - (2 * m + 1)


def shift(out, lag: int, length: int):
    """`out` moved back by `lag` samples and cut or padded to `length`."""
    import torch
    y = out[lag:] if lag >= 0 else torch.nn.functional.pad(out, (-lag, 0))
    if y.numel() < length:
        y = torch.nn.functional.pad(y, (0, length - y.numel()))
    return y[:length]


def spectral_change(ref, out, rate) -> dict:
    """Energy removed and added, from magnitude spectra, relative to the
    input — while speech was present and in the pauses (the input's mask)."""
    import torch
    n_fft = 1 << max(8, int(round(math.log2(rate * 0.046))))
    n = min(ref.numel(), out.numel())
    if n < n_fft:
        return {"during_speech_db": None, "during_pauses_db": None,
                "added_speech_db": None, "added_pauses_db": None}
    win = torch.hann_window(n_fft)
    X = torch.stft(ref[:n], n_fft, n_fft // 2, window=win,
                   return_complex=True, center=False).abs().pow(2)
    Y = torch.stft(out[:n], n_fft, n_fft // 2, window=win,
                   return_complex=True, center=False).abs().pow(2)
    ref_e = X.sum(dim=0)
    removed = torch.clamp(X - Y, min=0).sum(dim=0)
    added = torch.clamp(Y - X, min=0).sum(dim=0)
    mask, _f, _l, _g = speech_split(_db(ref_e / n_fft))
    out_d = {}
    for tag, sel in (("speech", mask), ("pauses", ~mask)):
        base = float(ref_e[sel].sum()) if bool(sel.any()) else 0.0
        for kind, part in (("during", removed), ("added", added)):
            key = f"{kind}_{tag}_db"
            if base <= 0:
                out_d[key] = None
            else:
                out_d[key] = round(10.0 * math.log10(
                    max(1e-12, float(part[sel].sum())) / base), 2)
    return out_d


def finish_op(req) -> dict:
    """Align each output to the reference and write the residual. With
    `"align": false` the outputs are only cut to the reference's length (a
    band moved in frequency does not correlate with where it came from), and
    with no `"residual"` none is written: input minus a moved band is not
    what anything took away."""
    ref, rate = read_wav(req["reference"])
    aligned, lags = [], []
    for src, dst in zip(req["outputs"], req["aligned"]):
        y, r2 = read_wav(src)
        if r2 != rate:
            raise ValueError(f"{src} is {r2} Hz, the input {rate} Hz")
        lag = estimate_lag(ref, y, rate) if req.get("align", True) else 0
        y = shift(y, lag, ref.numel())
        write_wav(dst, y, rate)
        aligned.append(y)
        lags.append(lag)
        _say(f"aligned {os.path.basename(dst)}: lag {lag} samples "
             f"({1000.0 * lag / rate:.1f} ms)")
    total = aligned[0].clone()
    for y in aligned[1:]:
        total = total + y
    change = None
    if req.get("residual"):
        write_wav(req["residual"], ref - total, rate)
        change = spectral_change(ref, total, rate)
    return {"lags": lags, "rate": rate, "change": change,
            "outputs": [analyse(p, content=False) for p in req["aligned"]]}


# ---------------------------------------------------------------------------
# faint sounds (FORENSICS_PLAN §13.8) — channels, salience, lines, repeats
# ---------------------------------------------------------------------------

#: Channels this alike at no lag are copies; channels whose correlation in
#: the loud frames is at least half what one shared sound would give hold
#: the same sound, under a fifth of it their own; combining that measures
#: less than COMBINE_MIN_DB is not used (a downmix that does no harm is
#: kept as the simpler record).
COPY_R = 0.995
COHERENT_SHARE = 0.5
UNRELATED_SHARE = 0.2
CH_MAX_LAG_S = 0.5
COMBINE_MIN_DB = 1.0

#: Salience: 32 ms frames; the ratio of each cell to its bin's own noise
#: level averaged over windows from a quarter second to sixteen seconds and
#: from one bin to 27 bins wide (a whistle is narrow and brief, a voice
#: wider and longer, an engine both long and wide), each scored against its
#: bin's own spread over the recording (log domain, median and MAD), and the
#: highest score kept.
SAL_WIN_S = 0.032
SAL_SCALES_S = (0.25, 0.5, 1.0, 2.0, 4.0, 8.0, 16.0)
SAL_FREQ_BINS = (1, 3, 9, 27)
SAL_MIN_WINDOWS = 30
Z_POSSIBLE = 6.0
Z_DETECT = 7.5
#: The thresholds above were set on ten minutes at 16 kHz (about 9.6 million
#: cells, where noise never scored above 5.8). More cells give noise more
#: chances: both thresholds rise by 0.6 per tenfold more cells.
SAL_REF_CELLS = 9.6e6
#: Below this the bins hold DC and infrasound, where a few bins carry the
#: whole spectrum's variance; nothing there is reported.
SAL_MIN_HZ = 60.0
#: Below this the input is taken out before any of it (twice a moving mean
#: subtracted): sub-bass leaks through every window's sidelobes into the
#: bins above it and makes them restless.
SAL_HIGHPASS_HZ = 30.0
SAL_GROUPS = 200
#: The linear high map: from 12 kHz to the top, when the top is above 14.
SAL_HIGH_FROM_HZ = 12000.0
SAL_HIGH_MIN_NYQ = 14000.0
SAL_HIGH_GROUPS = 160
SAL_MAX_COLS = 1600
SAL_STORE_FRAMES = 100000
SAL_BLOCK_S = 120.0
MAX_EVENTS = 12
MAX_CLIPS = 8
CLIP_PAD_S = 0.5
MASK_FLOOR_DB = -30.0
FAINT_BROADBAND_DB = -3.0

#: Repeats: a pattern at least 0.1 s long seen at least three times.
REP_MIN_S = 0.1
REP_MIN_COUNT = 3
REP_MAX_SCAN_S = 900.0
REP_STRENGTH = 0.05
REP_PROMINENCE = 8.0
REP_CLEAR = 0.5
REP_WAVEFORM_R = 0.02
REP_WAVEFORM_Z = 6.0


def _pow2(n: float) -> int:
    return 1 << max(4, int(round(math.log2(max(16.0, float(n))))))


def _snr_of(x, rate):
    db = frames_db(x, rate)
    mask, _f, _l, _g = speech_split(db)
    if not bool(mask.any()) or not bool((~mask).any()):
        return None
    return _mean_db(db, mask) - _mean_db(db, ~mask)


def _box(x, width: int, dim: int):
    """Moving mean of `width` along `dim`, same size, edges averaged over
    what exists."""
    import torch
    if width <= 1:
        return x
    x = x.transpose(dim, -1)
    c = torch.nn.functional.pad(torch.cumsum(x, dim=-1), (1, 0))
    n = x.shape[-1]
    half = width // 2
    hi = torch.clamp(torch.arange(n) + (width - half), max=n)
    lo = torch.clamp(torch.arange(n) - half, min=0)
    out = (c[..., hi] - c[..., lo]) / (hi - lo).to(x.dtype)
    return out.transpose(dim, -1)


# -- channels ----------------------------------------------------------------

def _quiet_loud(x, rate):
    """(quiet, loud) boolean masks over 25 ms frames: the lowest and the
    highest 30% by energy — usable at any SNR, unlike a speech gate."""
    import torch
    db = frames_db(x, rate)
    order = torch.argsort(db)
    k = max(1, int(0.3 * db.numel()))
    quiet = torch.zeros(db.numel(), dtype=torch.bool)
    loud = torch.zeros_like(quiet)
    quiet[order[:k]] = True
    loud[order[-k:]] = True
    return quiet, loud


def _frame_samples(x, rate, mask):
    """The samples of the frames in `mask`, end to end (frames 25 ms long
    every 10 ms, so a loud stretch is taken whole, once)."""
    import torch
    hop = max(1, int(rate * HOP_S))
    keep = torch.zeros(x.numel(), dtype=torch.bool)
    idx = torch.nonzero(mask).flatten()
    for i in idx.tolist():
        keep[i * hop:i * hop + max(hop, int(rate * FRAME_S))] = True
    return keep


def channel_report(X, rate) -> dict:
    """How the channels relate. Each channel's share of sound above its own
    noise (rho, from its loudest and quietest frames), the best channel,
    every other channel's lag and correlation to it at that lag over the
    loud frames, and what kind of set they are. If two channels carry ONE
    sound with independent noise, their correlation in the loud frames is
    about sqrt(rho_1 * rho_2); far below that, each carries its own sound
    (the two sides of a call) — however faint the sound is, the test holds.
    Kinds: mono, copies, coherent (combinable), unrelated, mixed."""
    import torch
    C = int(X.shape[0])
    if C < 2:
        return {"count": C, "kind": "mono"}
    n = min(X.shape[1], int(600 * rate))
    rho, snrs = [], []
    for c in range(C):
        quiet, loud = _quiet_loud(X[c][:n], rate)
        db = frames_db(X[c][:n], rate)
        p_loud = 10.0 ** (_mean_db(db, loud) / 10.0)
        p_quiet = 10.0 ** (_mean_db(db, quiet) / 10.0)
        rho.append(max(0.0, 1.0 - p_quiet / max(p_loud, 1e-20)))
        snrs.append(_snr_of(X[c], rate))
    rms = [round(10.0 * math.log10(max(1e-12, float((X[c] * X[c]).mean()))),
                 2) for c in range(C)]
    ref = max(range(C), key=lambda c: rho[c])
    _quiet, ref_loud = _quiet_loud(X[ref][:n], rate)
    keep = _frame_samples(X[ref][:n], rate, ref_loud)
    pairs = []
    for c in range(C):
        if c == ref:
            continue
        lag = estimate_lag(X[ref], X[c], rate, CH_MAX_LAG_S, absolute=True)
        y = shift(X[c], lag, X.shape[1])[:n]
        r = _corr(X[ref][:n][keep], y[keep])
        r_all = _corr(X[ref][:n], y)
        expected = math.sqrt(rho[ref] * rho[c])
        z = abs(r) * math.sqrt(max(1.0, float(keep.sum()) / 4.0))
        pairs.append({"channel": c, "lag_samples": int(lag),
                      "lag_ms": round(1000.0 * lag / rate, 2),
                      "r": round(r, 4), "r_all": round(r_all, 4),
                      "expected_r": round(expected, 4),
                      "significance": round(z, 1)})
    if all(abs(p["r_all"]) >= COPY_R and abs(p["lag_samples"]) <= 1
           for p in pairs):
        kind = "copies"
    else:
        same = [p["significance"] >= 8.0 and abs(p["r"]) >=
                COHERENT_SHARE * p["expected_r"] for p in pairs]
        # "different sound" needs evidence: each channel clearly holding
        # sound of its own, and little of it shared. Channels that are
        # mostly noise prove nothing either way — the combination is tried
        # and kept only if it measures better.
        apart = [rho[ref] >= 0.5 and rho[p["channel"]] >= 0.5 and
                 (p["significance"] < 8.0 or abs(p["r"]) <
                  UNRELATED_SHARE * p["expected_r"]) for p in pairs]
        kind = "coherent" if all(same) else "unrelated" if all(apart) \
            else "faint" if max(rho) < 0.5 else "mixed"
    lin = [r / max(1e-6, 1.0 - r) for r in rho]
    expected_gain = round(10.0 * math.log10(sum(lin) / max(max(lin), 1e-9)),
                          2) if kind in ("coherent", "mixed", "faint") else 0.0
    return {"count": C, "kind": kind, "reference": ref,
            "rho": [round(r, 3) for r in rho],
            "snr_db": [None if v is None else round(v, 2) for v in snrs],
            "rms_dbfs": rms, "pairs": pairs,
            "expected_gain_db": expected_gain,
            # only a lag or a polarity that was MEASURED counts: a
            # correlation lost in the noise has neither
            "inverted": any(p["r"] < 0 and p["significance"] >= 8.0
                            for p in pairs),
            "delayed": any(abs(p["lag_samples"]) > 1 and
                           p["significance"] >= 8.0 for p in pairs)}


def _bands(rate, F, df):
    """Band edges in bins: 100 Hz wide to 400 Hz, a third of an octave
    above."""
    edges = [0.0, 100.0, 200.0, 300.0, 400.0]
    while edges[-1] * 2 ** (1 / 3) < rate / 2:
        edges.append(edges[-1] * 2 ** (1 / 3))
    edges.append(rate / 2 + df)
    bins = sorted({min(F, int(round(e / df))) for e in edges})
    return [(a, b) for a, b in zip(bins, bins[1:]) if b > a]


COMBINE_BLOCK_S = 60.0


def combine_channels(X, rate, report: dict):
    """Combining that never reshapes the shared sound (maximal-ratio,
    distortionless toward the best channel, per frequency): every channel
    shifted by its measured lag; per bin, each channel's noise power from
    the quietest 30% of frames and the transfer of the shared sound from the
    covariance of all frames less that noise; the weights pass the shared
    sound at exactly its level and phase in the best channel and weigh each
    channel by how clean it is there, so noise the channels do not share
    averages down. Where a band of the best channel holds under a tenth signal its transfer
    cannot be measured, and each channel's broadband gain stands in for it.
    Linear and distortionless: what it takes away is noise. Worked a minute
    at a time (statistics in two passes, then the weights applied), so an
    hour of several channels fits in memory. Returns (combined, best
    channel, measured) — the measurement is the noise in the quietest frames
    of the output against the best channel's."""
    import torch
    C, T = X.shape
    ref = report["reference"]
    lags = {p["channel"]: p["lag_samples"] for p in report["pairs"]}
    n_fft = _pow2(rate * 0.064)
    hop = n_fft // 4
    win = torch.hann_window(n_fft, dtype=torch.float64)
    F = n_fft // 2 + 1
    df = rate / n_fft
    margin = n_fft
    span = max(4 * n_fft, int(COMBINE_BLOCK_S * rate) // hop * hop)

    def aligned(a, b):
        rows = []
        for c in range(C):
            lag = 0 if c == ref else lags[c]
            lo, hi = a + lag, b + lag
            seg = X[c, max(0, lo):max(0, min(T, hi))].double()
            left = max(0, -lo)
            right = max(0, (b - a) - left - seg.numel())
            rows.append(torch.nn.functional.pad(seg, (left, right)))
        return torch.stack(rows)

    def blocks():
        for a in range(0, T, span):
            b = min(T, a + span)
            m_l = min(margin, a)
            seg = aligned(a - m_l, min(T, b + margin))
            S = torch.stft(seg, n_fft, hop, window=win, return_complex=True,
                           center=True)                       # [C, F, N]
            centres = (a - m_l) + torch.arange(S.shape[2]) * hop
            core = (centres >= a) & (centres < b)
            yield a, b, m_l, seg.shape[1], S, core

    # pass 1: each frame's energy in the best channel, for the quiet frames
    energy = torch.cat([(S[ref].abs() ** 2).sum(dim=0)[core]
                        for _a, _b, _m, _n, S, core in blocks()])
    k = max(C + 1, int(0.3 * energy.numel()))
    threshold = float(torch.sort(energy).values[min(k, energy.numel()) - 1])
    # pass 2: the covariances, all frames and the quiet ones
    phi_x = torch.zeros(F, C, C, dtype=torch.complex128)
    phi_n = torch.zeros_like(phi_x)
    n_all = n_quiet = 0
    for _a, _b, _m, _n, S, core in blocks():
        Z = S[:, :, core].permute(1, 2, 0)                     # [F, N, C]
        e = (S[ref][:, core].abs() ** 2).sum(dim=0)
        Zq = Z[:, e <= threshold, :]
        phi_x += Z.transpose(1, 2) @ Z.conj()
        phi_n += Zq.transpose(1, 2) @ Zq.conj()
        n_all += Z.shape[1]
        n_quiet += Zq.shape[1]
    phi_x /= max(1, n_all)
    phi_n /= max(1, n_quiet)
    phi_s = phi_x - phi_n
    p_ref = phi_x[:, ref, ref].real
    s_ref = phi_s[:, ref, ref].real
    band_ok = torch.zeros(F, dtype=torch.bool)
    for a, b in _bands(rate, F, df):
        share = float(s_ref[a:b].clamp(min=0).sum()) / max(
            1e-30, float(p_ref[a:b].sum()))
        band_ok[a:b] = share >= 0.1
    # a narrow line (a whine, a carrier) holds its band's signal in a few
    # bins: those bins are trusted on their own
    bin_share = _box(s_ref.clamp(min=0), 5, 0) / _box(p_ref, 5, 0).clamp(
        min=1e-30)
    trusted = band_ok | (bin_share >= 0.25)
    h = phi_s[:, :, ref] / s_ref.clamp(min=1e-30)[:, None]     # [F, C]
    h = torch.complex(_box(h.real, 5, 0), _box(h.imag, 5, 0))
    if bool(band_ok.any()):
        broad = torch.stack([
            torch.median(h[band_ok, c].real) for c in range(C)]).to(h.dtype)
    else:
        broad = torch.zeros(C, dtype=h.dtype)
    broad[ref] = 1.0
    h = torch.where(trusted[:, None], h, broad[None, :])
    h[:, ref] = 1.0
    # Maximal-ratio weights: each channel by its transfer over ITS OWN noise
    # power. (The full noise covariance — MVDR — would also cancel noise the
    # channels share, but a steady sound in the quiet frames, an engine or a
    # tone, then counts as noise and the weights cancel the very sound they
    # should keep: measured 2026-10-09, a tone lost 15 dB. Kept out.)
    noise = phi_n.diagonal(dim1=1, dim2=2).real.clamp(min=1e-30)  # [F, C]
    noise = torch.stack([_box(noise[:, c], 5, 0) for c in range(C)], dim=1)
    sol = h / noise
    w = sol / (h.conj() * sol).sum(dim=1)[:, None]  # distortionless: w^H h = 1
    # pass 3: the weights applied, a block at a time, only the core kept
    y = torch.zeros(T)
    for a, b, m_l, n_seg, S, _core in blocks():
        Y = (w.conj().T[:, :, None] * S).sum(dim=0)
        out = torch.istft(Y, n_fft, hop, window=win, center=True,
                          length=n_seg)
        y[a:b] = out[m_l:m_l + (b - a)].float()
    best = X[ref].clone()
    quiet_t, _loud = _quiet_loud(best, rate)
    keep = _frame_samples(best, rate, quiet_t)

    def power(sig):
        v = sig[keep]
        return float((v * v).mean()) if v.numel() else 0.0

    gain = 10.0 * math.log10(max(1e-20, power(best)) /
                             max(1e-20, power(y)))
    measured = {"gain_db": round(gain, 2), "n_fft": n_fft,
                "trusted_share": round(float(trusted.float().mean()), 3),
                "broadband_gain": [round(float(v.real), 3) for v in broad]}
    return y, best, measured


def use_combined(report: dict, measured: dict) -> tuple[bool, str]:
    """Whether the combination replaces the plain downmix, and why."""
    gain = measured.get("gain_db", 0.0)
    if report["kind"] == "unrelated":
        return False, "the channels carry different sound"
    if report["kind"] in ("coherent", "mixed") and gain >= COMBINE_MIN_DB:
        return True, f"combining measured {gain:+.1f} dB less noise than " \
                     "the best channel"
    if report.get("inverted") and gain >= -0.5:
        return True, ("a plain downmix would cancel the inverted channel; "
                      "the aligned combination does not")
    if report.get("delayed") and gain >= 0.5:
        return True, ("a plain downmix would comb-filter the delayed "
                      f"channel; the aligned combination does not, and "
                      f"measured {gain:+.1f} dB")
    return False, f"combining measured only {gain:+.1f} dB"


# -- salience -------------------------------------------------------------------

def _running_median(v, width: int):
    import torch
    h = width // 2
    if v.numel() <= width:
        return v
    p = torch.nn.functional.pad(v[None, None], (h, h), mode="replicate")[0, 0]
    return p.unfold(0, width, 1).median(dim=1).values


def _mel(f):
    return 2595.0 * math.log10(1.0 + f / 700.0)


def _imel(m):
    return 700.0 * (10.0 ** (m / 2595.0) - 1.0)


class Salience:
    """Where in time and frequency something stands out of a recording's own
    noise. Each frequency bin's noise level is its median power over the
    recording; each cell's ratio to it is averaged over a short and a long
    window (that is the long integration: N noise-only frames averaged vary
    by about 1/sqrt(N), so a component that persists is seen far below the
    level where any single frame shows it) and scored, in the log domain,
    against that bin's own median and spread. Measured: nothing is changed."""

    def __init__(self, x, rate, top_hz: float | None = None):
        import torch
        self.hp_width = max(3, int(rate / SAL_HIGHPASS_HZ))
        self.x, self.rate = x, rate
        self.n_fft = _pow2(rate * SAL_WIN_S)
        self.hop = self.n_fft // 2
        self.win = torch.hann_window(self.n_fft)
        self.F = self.n_fft // 2 + 1
        self.N = max(0, (x.numel() - self.n_fft) // self.hop + 1)
        self.df = rate / self.n_fft
        # nothing is scored above the file's own content (a codec's brick
        # wall): up there the 'noise' is digital silence, and the faintest
        # leak of a sound below would stand out of it
        self.top_bin = self.F if not top_hz else max(
            1, min(self.F, int(top_hz / self.df)))
        # a window is used only where the recording holds at least
        # SAL_MIN_WINDOWS of it: its spread is measured over the recording
        # itself, and two or three samples of a 16 s average measure nothing
        dur = x.numel() / rate
        self.widths = [max(1, int(round(t * rate / self.hop)))
                       for t in SAL_SCALES_S
                       if t == SAL_SCALES_S[0] or t * SAL_MIN_WINDOWS <= dur]
        self.scales = [(wt, wf) for wf in SAL_FREQ_BINS for wt in self.widths]
        self.margin = max(self.widths) // 2 + 2
        self.offset = round(max(0.0, 0.6 * math.log10(
            max(1.0, self.N * self.F) / SAL_REF_CELLS)), 2)
        self.possible = Z_POSSIBLE + self.offset
        self.detect = Z_DETECT + self.offset
        self.tp = max(1, math.ceil(self.N / SAL_STORE_FRAMES))
        block = max(4 * self.margin, int(SAL_BLOCK_S * rate / self.hop))
        self.block = self.tp * math.ceil(block / self.tp)
        edges = [_imel(m) for m in
                 [i * _mel(rate / 2) / SAL_GROUPS for i in range(SAL_GROUPS + 1)]]
        self.groups = []
        for g in range(SAL_GROUPS):
            lo = min(self.F - 1, int(edges[g] / self.df))
            hi = min(self.F, max(lo + 1, int(math.ceil(edges[g + 1] / self.df))))
            self.groups.append((lo, hi))
        self.group_hz = [(round(lo * self.df, 1), round(hi * self.df, 1))
                         for lo, hi in self.groups]
        # above SAL_HIGH_FROM_HZ, a second set of groups LINEAR in frequency:
        # the mel scale gives 12 kHz to the top a sliver of the map, and that
        # is where a beacon, a whine or near-ultrasound sits
        self.high_groups, self.high_hz = [], []
        if rate / 2 > SAL_HIGH_MIN_NYQ:
            b0 = int(SAL_HIGH_FROM_HZ / self.df)
            count = max(1, min(SAL_HIGH_GROUPS, self.F - b0))
            for g in range(count):
                lo = b0 + (self.F - b0) * g // count
                hi = max(lo + 1, b0 + (self.F - b0) * (g + 1) // count)
                self.high_groups.append((lo, min(self.F, hi)))
            self.high_hz = [(round(lo * self.df, 1), round(hi * self.df, 1))
                            for lo, hi in self.high_groups]

    def segment(self, a: int, b: int):
        """Samples [a, b) with the high-pass applied (twice a moving mean
        subtracted), computed over the segment and a margin either side —
        never over the whole recording at once."""
        w = self.hp_width
        a2, b2 = max(0, a - 2 * w), min(self.x.numel(), b + 2 * w)
        seg = self.x[a2:b2]
        for _ in range(2):
            seg = seg - _box(seg[None], w, 1)[0]
        return seg[a - a2:a - a2 + (b - a)]

    def power(self, k0, k1):
        import torch
        a = k0 * self.hop
        b = (k1 - 1) * self.hop + self.n_fft
        seg = self.segment(a, b)
        return torch.stft(seg, self.n_fft, self.hop, window=self.win,
                          center=False, return_complex=True).abs().pow(2)

    def blocks(self):
        for k0 in range(0, self.N, self.block):
            yield k0, min(self.N, k0 + self.block)

    def _smoothed(self, k0, k1):
        """The log of the averaged ratio, one map per scale, in the order
        of `self.scales` — a generator, so only one is held at a time."""
        import torch
        a, b = max(0, k0 - self.margin), min(self.N, k1 + self.margin)
        R = self.power(a, b) / self.mu[:, None]
        for wf in SAL_FREQ_BINS:
            Rf = _box(R, wf, 0)
            for wt in self.widths:
                yield torch.log(_box(Rf, wt, 1)[:, k0 - a:k0 - a + (k1 - k0)]
                                .clamp(min=1e-6))

    def fit(self):
        import torch
        if self.N < 8:
            raise ValueError("too short for a salience map")
        meds = [self.power(k0, k1).median(dim=1).values
                for k0, k1 in self.blocks()]
        self.mu = (torch.stack(meds).median(dim=0).values / math.log(2.0)) \
            .clamp(min=1e-20)
        stats = [[] for _ in self.scales]
        for k0, k1 in self.blocks():
            for i, L in enumerate(self._smoothed(k0, k1)):
                med = L.median(dim=1).values
                mad = (L - med[:, None]).abs().median(dim=1).values
                stats[i].append((med, mad))
        self.null = []
        for rows in stats:
            med = torch.stack([m for m, _ in rows]).median(dim=0).values
            mad = torch.stack([d for _, d in rows]).median(dim=0).values
            # each bin's centre and spread, steadied by its neighbours': a
            # long window gives few independent samples per bin
            self.null.append((_running_median(med, 9),
                              (1.4826 * _running_median(mad, 9))
                              .clamp(min=1e-3)))
        return self

    def _edges(self, z, k0, k1, wt):
        """No score within half a window of either end of the recording,
        where the average holds fewer frames than its window."""
        h = wt // 2
        lo = max(0, h - k0)
        hi = max(0, (k1 - k0) - max(0, (k1 + h) - self.N))
        if lo:
            z[:, :lo] = -10.0
        if hi < z.shape[1]:
            z[:, hi:] = -10.0
        return z

    def z(self, k0, k1):
        import torch
        Z = None
        for (wt, _wf), L, (med, sd) in zip(self.scales, self._smoothed(k0, k1),
                                           self.null):
            z = self._edges((L - med[:, None]) / sd[:, None], k0, k1, wt)
            Z = z if Z is None else torch.maximum(Z, z)
        Z[:int(math.ceil(SAL_MIN_HZ / self.df))] = -10.0
        Z[self.top_bin:] = -10.0
        return Z

    def scan(self):
        """(zq, lq): per mel group, the highest z and the mean log power,
        pooled `tp` frames at a time — the whole recording, small. The
        linear high groups, when there are any, into (hzq, hlq) alongside."""
        import torch
        cols = math.ceil(self.N / self.tp)
        sets = [(self.groups, torch.full((len(self.groups), cols), -10.0),
                 torch.zeros((len(self.groups), cols)))]
        if self.high_groups:
            sets.append((self.high_groups,
                         torch.full((len(self.high_groups), cols), -10.0),
                         torch.zeros((len(self.high_groups), cols))))
        for k0, k1 in self.blocks():
            Z = self.z(k0, k1)
            P = torch.log10(self.power(k0, k1).clamp(min=1e-20)) * 10.0
            n = k1 - k0
            pad = (-n) % self.tp
            if pad:
                Z = torch.nn.functional.pad(Z, (0, pad), value=-10.0)
                P = torch.nn.functional.pad(P, (0, pad), mode="replicate") \
                    if n > 0 else P
            c0 = k0 // self.tp
            c1 = c0 + (n + pad) // self.tp
            for groups, zq, lq in sets:
                for g, (lo, hi) in enumerate(groups):
                    zg = Z[lo:hi].amax(dim=0).reshape(-1, self.tp).amax(dim=1)
                    lg = P[lo:hi].mean(dim=0).reshape(-1, self.tp).mean(dim=1)
                    zq[g, c0:c1] = zg[:c1 - c0]
                    lq[g, c0:c1] = lg[:c1 - c0]
        self.zq, self.lq = sets[0][1], sets[0][2]
        self.hzq, self.hlq = (sets[1][1], sets[1][2]) if self.high_groups \
            else (None, None)
        return self.zq, self.lq

    def events(self, period_s: float = 0.0):
        """Stretches where some band stands out (peak z >= Z_POSSIBLE), each
        with its band, its peak, and how strong it is against the noise in
        its own band and against all the noise in the recording. With a
        repeat period, events that fall at the same point of the period
        three or more times are the repeat itself: they are counted, not
        listed, so they do not crowd out what happens only once."""
        import torch
        zq = self.zq
        colmax = zq.max(dim=0).values
        on = (colmax >= self.possible).tolist()
        sec = self.tp * self.hop / self.rate
        gap = max(1, int(round(0.3 / sec)))
        runs, start, last = [], None, None
        for i, flag in enumerate(on):
            if flag:
                if start is None:
                    start = i
                elif last is not None and i - last > gap:
                    runs.append((start, last + 1))
                    start = i
                last = i
        if start is not None:
            runs.append((start, last + 1))
        found = []
        # a sound above SAL_HIGH_FROM_HZ at the same time as one below it
        # is its own event (a whine or a beacon over a voice) — the split is
        # made only there, where a voice holds little, so one voice's
        # separate harmonic regions are not counted as several sounds
        split = next((g for g in range(SAL_GROUPS)
                      if self.group_hz[g][0] >= SAL_HIGH_FROM_HZ), SAL_GROUPS)
        for a, b in runs:
            sub = zq[:, a:b]
            gmax = sub.max(dim=1).values
            if float(gmax.max()) < self.possible:
                continue
            band = (gmax >= self.possible).tolist()
            taken = []
            for lo_g, hi_g in ((0, SAL_GROUPS), (0, split),
                               (split, SAL_GROUPS)):
                if hi_g <= lo_g or float(gmax[lo_g:hi_g].max()) < \
                        self.possible:
                    continue
                g_peak = lo_g + int(gmax[lo_g:hi_g].argmax())
                if any(lo <= g_peak <= hi for lo, hi in taken):
                    continue
                peak = float(gmax[g_peak])
                t_peak = a + int(sub[g_peak].argmax())
                g_lo = g_hi = g_peak
                while g_lo > lo_g and band[g_lo - 1]:
                    g_lo -= 1
                while g_hi < hi_g - 1 and band[g_hi + 1]:
                    g_hi += 1
                taken.append((g_lo, g_hi))
                found.append({"cols": (a, b), "groups": (g_lo, g_hi),
                              "z": round(peak, 1),
                              "start_s": round(a * sec, 3),
                              "end_s": round(b * sec + self.n_fft / self.rate,
                                             3),
                              "peak_s": round(t_peak * sec, 3),
                              "f_lo": self.group_hz[g_lo][0],
                              "f_hi": self.group_hz[g_hi][1]})
        self.repeat_events = 0
        if period_s > 0 and len(found) >= REP_MIN_COUNT:
            tol = max(0.05, 0.08 * period_s)
            phases = [e["peak_s"] % period_s for e in found]
            many = max(REP_MIN_COUNT, int(0.3 * self.x.numel() / self.rate
                                          / period_s))
            keep = []
            for e, ph in zip(found, phases):
                near = sum(1 for q in phases
                           if min(abs(ph - q), period_s - abs(ph - q)) <= tol)
                # a merely possible event at the repeat's own point in the
                # period, three times over, is what is left of the repeat
                if near >= (REP_MIN_COUNT if e["z"] < self.detect else many):
                    self.repeat_events += 1
                else:
                    keep.append(e)
            found = keep
        found.sort(key=lambda e: -e["z"])
        found = found[:MAX_EVENTS]
        for e in found:
            self._refine(e)
        total_noise = float(self.mu.sum())
        for e in found:
            k0 = int(e["start_s"] * self.rate / self.hop)
            k1 = max(k0 + 1, min(self.N, int(math.ceil(
                (e["end_s"] * self.rate - self.n_fft) / self.hop)) + 1))
            lo = self.groups[e["groups"][0]][0]
            hi = self.groups[e["groups"][1]][1]
            P = self.power(k0, k1)[lo:hi]
            # the mean excess over the noise level, signed until the sum — a
            # clamp per cell would count the noise's own upward swings
            excess = float((P - self.mu[lo:hi, None]).mean(dim=1).sum())
            band_noise = float(self.mu[lo:hi].sum())
            e["band_snr_db"] = round(10.0 * math.log10(
                max(1e-9, excess) / max(1e-20, band_noise)), 1)
            e["broadband_snr_db"] = round(10.0 * math.log10(
                max(1e-9, excess) / max(1e-20, total_noise)), 1)
            e["faint"] = e["broadband_snr_db"] <= FAINT_BROADBAND_DB
            e["confidence"] = "detected" if e["z"] >= self.detect \
                else "possible"
        found.sort(key=lambda e: e["start_s"])
        for n, e in enumerate(found, 1):
            e["n"] = n
        self.found = found
        return found

    def _refine(self, e):
        """Tighter edges for an event: in the scale that scored it highest,
        the cells above half its peak."""
        import torch
        k0 = max(0, int(e["start_s"] * self.rate / self.hop))
        k1 = min(self.N, max(k0 + 2, int(math.ceil(
            e["end_s"] * self.rate / self.hop))))
        cands = []
        for (wt, wf), L, (med, sd) in zip(self.scales, self._smoothed(k0, k1),
                                          self.null):
            z = self._edges((L - med[:, None]) / sd[:, None], k0, k1, wt)
            z[:int(math.ceil(SAL_MIN_HZ / self.df))] = -10.0
            z[self.top_bin:] = -10.0
            peak = float(z.max())
            cands.append((peak, wt, wf, z))
        # the shortest, narrowest window that scores nearly as well: a
        # long window scores a short sound too, but smears its edges
        top = max(c[0] for c in cands)
        peak, wt, wf, z = min((c for c in cands if c[0] >= 0.75 * top),
                              key=lambda c: (c[1], c[2]))
        # half the peak: a sound of length D seen through a window of W is
        # max(D, W) wide there, so the edges need no further correction —
        # within the band the coarse search found (two groups either side),
        # where noise in a narrow window cannot pass for the sound
        lo = self.groups[max(0, e["groups"][0] - 2)][0]
        hi = self.groups[min(SAL_GROUPS - 1, e["groups"][1] + 2)][1]
        z = z.clone()
        z[:lo] = -10.0
        z[hi:] = -10.0
        hot = z >= 0.5 * peak
        if not bool(hot.any()):
            return
        rows = torch.nonzero(hot.any(dim=1)).flatten()
        cols = torch.nonzero(hot.any(dim=0)).flatten()
        b0, b1 = int(rows.min()), int(rows.max())
        t0, t1 = int(cols.min()), int(cols.max())
        e["start_s"] = round((k0 + t0) * self.hop / self.rate, 3)
        e["end_s"] = round(((k0 + t1) * self.hop + self.n_fft) / self.rate, 3)
        # the band stays the coarse search's: the narrowest window that
        # scores a voice is often one harmonic of it, and a clip cut to one
        # harmonic would sound like a hum; the strongest part is kept apart
        e["core_hz"] = [round(b0 * self.df, 1), round((b1 + 1) * self.df, 1)]
        e["scale"] = {"seconds": round(wt * self.hop / self.rate, 2),
                      "hz": round(wf * self.df, 1)}

    def mask(self, k0, k1, band=None, threshold=None, inside_db=None):
        """A soft mask on the centred STFT grid of frames [k0, k1): about 1
        where a cell stands out (z above `threshold`, the "possible" one by
        default), MASK_FLOOR_DB elsewhere — or `inside_db` inside `band` —
        smoothed so it does not warble; outside `band` (lo, hi Hz) the floor."""
        import torch
        Z = self.z(k0, k1)
        floor = 10.0 ** (MASK_FLOOR_DB / 20.0)
        level = self.possible if threshold is None else threshold
        G = torch.sigmoid(1.5 * (Z - level)).clamp(
            min=floor if inside_db is None else 10.0 ** (inside_db / 20.0))
        if band is not None:
            lo = max(0, int(band[0] / self.df) - 2)
            hi = min(self.F, int(math.ceil(band[1] / self.df)) + 3)
            G[:lo] = floor
            G[hi:] = floor
        G = _box(_box(G, 3, 0), 3, 1)
        # a centred frame j sits where uncentred frame j - 1 does
        G = torch.cat([G[:, :1], G, G[:, -1:]], dim=1)
        return G

    def apply(self, k0, k1, band=None, **mask):
        """The samples of frames [k0, k1) with the mask applied."""
        import torch
        a = k0 * self.hop
        b = (k1 - 1) * self.hop + self.n_fft
        seg = self.segment(a, b)
        X = torch.stft(seg, self.n_fft, self.hop, window=self.win,
                       center=True, return_complex=True)
        G = self.mask(k0, k1, band, **mask)
        n = min(G.shape[1], X.shape[1])
        Xm = X[:, :n] * G[:, :n]
        return torch.istft(Xm, self.n_fft, self.hop, window=self.win,
                           center=True, length=seg.numel())

    def whole(self):
        """The whole recording through the mask, block by block (each block
        computed with margins, only its core kept)."""
        import torch
        out = torch.zeros(self.x.numel())
        for k0, k1 in self.blocks():
            a, b = max(0, k0 - self.margin), min(self.N, k1 + self.margin)
            y = self.apply(a, b)
            s0 = (k0 - a) * self.hop
            take = (k1 - k0) * self.hop if k1 < self.N else y.numel() - s0
            start = k0 * self.hop
            out[start:start + take] = y[s0:s0 + take]
        return out

    def listening_band(self, e) -> tuple[float, float]:
        """The band a clip keeps: the event's, opened out to an octave below
        and two above (at least 1 kHz wide) — the detector's band is often
        one harmonic of a sound whose others carry what makes it a voice."""
        lo = max(SAL_HIGHPASS_HZ, 0.5 * e["f_lo"])
        hi = min(0.98 * self.rate / 2, max(4.0 * e["f_hi"], e["f_hi"] + 1000.0))
        return round(lo, 1), round(hi, 1)

    def clip(self, e):
        """One event, CLIP_PAD_S either side, its listening band kept (the
        cells that stand out at full level, the rest of the band 12 dB down,
        everything outside the band 30 dB down), its peak brought to
        -3 dBFS. (samples, gain dB, start s, end s)."""
        pad = int(CLIP_PAD_S * self.rate / self.hop)
        k0 = max(0, int(e["start_s"] * self.rate / self.hop) - pad)
        k1 = min(self.N, int(math.ceil(e["end_s"] * self.rate / self.hop))
                 + pad)
        k1 = max(k1, k0 + 4)
        y = self.apply(k0, k1, self.listening_band(e), threshold=3.0,
                       inside_db=-12.0)
        peak = float(y.abs().max()) if y.numel() else 0.0
        gain = min(60.0, 20.0 * math.log10(10.0 ** (-3.0 / 20.0) /
                                           max(peak, 1e-9)))
        return (y * 10.0 ** (gain / 20.0), round(gain, 1),
                round(k0 * self.hop / self.rate, 3),
                round(((k1 - 1) * self.hop + self.n_fft) / self.rate, 3))

    def group_of(self, hz: float, high: bool = False) -> int:
        hz_of = self.high_hz if high else self.group_hz
        return min(range(len(hz_of)), key=lambda i: abs(
            0.5 * (hz_of[i][0] + hz_of[i][1]) - hz))

    def image(self, lines=(), high: bool = False):
        """The salience map as RGB (height = mel groups, top = high), the
        recording's own spectrogram dim beneath, cells that stand out
        coloured from teal (z 3.5) through amber (6) to white-hot (14), each
        event boxed in white, each tonal line dotted in violet across the
        whole width, guide lines at 1, 2, 4 and 8 kHz. `high`: the linear
        map from SAL_HIGH_FROM_HZ to the top, guide lines every 2 kHz (4 or
        8 on a wide band) and a brighter one at 20 kHz, where hearing ends."""
        import torch
        zq, lq = (self.hzq, self.hlq) if high else (self.zq, self.lq)
        hz_of = self.high_hz if high else self.group_hz
        rows = zq.shape[0]
        cols = zq.shape[1]
        step = max(1, math.ceil(cols / SAL_MAX_COLS))
        pad = (-cols) % step
        if pad:
            zq = torch.nn.functional.pad(zq, (0, pad), value=-10.0)
            lq = torch.nn.functional.pad(lq, (0, pad), mode="replicate")
        zc = zq.reshape(rows, -1, step).amax(dim=2)
        lc = lq.reshape(rows, -1, step).mean(dim=2)
        lo = float(torch.quantile(lc.flatten()[:1000000], 0.05))
        hi = float(torch.quantile(lc.flatten()[:1000000], 0.995))
        v = ((lc - lo) / max(1e-6, hi - lo)).clamp(0, 1)
        base = 10.0 + 70.0 * v
        rgb = torch.stack([base * 0.85, base * 0.95, base * 1.15], dim=-1)
        stops = [3.5, 4.5, 6.0, 9.0, 14.0]
        colours = torch.tensor([[0, 80, 100], [0, 180, 215], [255, 185, 0],
                                [255, 85, 0], [255, 250, 225]],
                               dtype=torch.float32)
        alphas = [0.25, 0.55, 0.85, 0.95, 1.0]
        z = zc.clamp(max=stops[-1])
        col = torch.zeros_like(rgb)
        alpha = torch.zeros_like(z)
        for i in range(len(stops) - 1):
            sel = (z >= stops[i]) & (z < stops[i + 1])
            t = ((z - stops[i]) / (stops[i + 1] - stops[i])).clamp(0, 1)
            c = colours[i][None, None, :] * (1 - t[..., None]) + \
                colours[i + 1][None, None, :] * t[..., None]
            col[sel] = c[sel]
            alpha[sel] = (alphas[i] * (1 - t) + alphas[i + 1] * t)[sel]
        top = z >= stops[-1]
        col[top] = colours[-1]
        alpha[top] = 1.0
        rgb = rgb * (1 - alpha[..., None]) + col * alpha[..., None]
        for hz in self.guides(high):
            g = min(range(rows), key=lambda i: abs(hz_of[i][0] - hz))
            if high and hz == 20000.0:
                rgb[g, ::2] = rgb[g, ::2] * 0.3 + 150.0
            else:
                rgb[g, ::4] = rgb[g, ::4] * 0.5 + 60.0
        for line in lines:
            if high and line["hz"] < SAL_HIGH_FROM_HZ:
                continue
            g = self.group_of(line["hz"], high)
            rgb[g, ::3] = torch.tensor([200.0, 90.0, 255.0])
        for e in getattr(self, "found", []):
            box = self._box(e, step, high)
            if box is None:
                continue
            c0, c1, g0, g1 = box
            white = torch.tensor([235.0, 235.0, 235.0])
            rgb[g0, c0:c1] = white
            rgb[g1, c0:c1] = white
            rgb[g0:g1 + 1, c0] = white
            rgb[g0:g1 + 1, min(c1, rgb.shape[1] - 1)] = white
        rgb = rgb.clamp(0, 255).round().to(torch.uint8).flip(0)
        return rgb, step

    def guides(self, high: bool = False) -> list[float]:
        """The frequencies a map marks with a guide line."""
        top = self.rate / 2
        if not high:
            return [hz for hz in (1000.0, 2000.0, 4000.0, 8000.0, 16000.0)
                    if hz < top]
        span = top - SAL_HIGH_FROM_HZ
        every = 2000.0 if span <= 16000 else 4000.0 if span <= 40000 \
            else 8000.0
        out, hz = [], SAL_HIGH_FROM_HZ + every
        while hz < top:
            out.append(hz)
            hz += every
        if 20000.0 < top and 20000.0 not in out:
            out.append(20000.0)
        return sorted(out)

    def _box(self, e, step, high: bool = False):
        """An event's box on the map, from its (refined) times and band,
        one group and one column of margin — None on the high map for an
        event wholly below it."""
        rows = len(self.high_groups) if high else SAL_GROUPS
        if high and e["f_hi"] < SAL_HIGH_FROM_HZ:
            return None
        per = self.tp * self.hop / self.rate * step
        cols = math.ceil(math.ceil(self.N / self.tp) / step)
        c0 = max(0, int(e["start_s"] / per) - 1)
        c1 = min(cols - 1, max(c0 + 2, int(math.ceil(e["end_s"] / per))))
        g0 = max(0, self.group_of(max(e["f_lo"], SAL_HIGH_FROM_HZ) if high
                                  else e["f_lo"], high) - 1)
        g1 = min(rows - 1, max(g0 + 2, self.group_of(e["f_hi"], high) + 1))
        return c0, c1, g0, g1


def write_png(path, rgb) -> None:
    """An 8-bit RGB PNG — zlib and struct only."""
    import zlib
    h, w, _ = rgb.shape
    flat = rgb.contiguous().flatten().tolist()
    row = w * 3
    raw = b"".join(b"\x00" + bytes(flat[r * row:(r + 1) * row])
                   for r in range(h))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    _write_bytes(path, b"\x89PNG\r\n\x1a\n"
                 + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                 + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


# -- tonal lines --------------------------------------------------------------

def tonal_lines(x, rate, top_hz: float | None = None) -> list[dict]:
    """Narrow lines in the long-term spectrum: a frequency that stays —
    a motor, a whine, a carrier, a mains family — standing above the
    spectrum either side of it. Prominence in dB over the local median, a
    z from the number of averaged segments, and harmonic series grouped."""
    import torch
    dur = x.numel() / rate
    res = 1.0 if dur >= 16.0 else max(1.0, 16.0 / max(dur, 0.5))
    n = _pow2(rate / res)
    while n > x.numel() // 4 and n > 256:
        n //= 2
    if x.numel() < 2 * n:
        return []
    hop = n // 2
    win = torch.hann_window(n)
    K = (x.numel() - n) // hop + 1
    S = torch.zeros(n // 2 + 1)
    for a in range(0, K, 64):
        b = min(K, a + 64)
        seg = x[a * hop:(b - 1) * hop + n]
        S += torch.stft(seg, n, hop, window=win, center=False,
                        return_complex=True).abs().pow(2).sum(dim=1)
    S /= K
    df = rate / n
    L = max(6, int(round(15.0 / df)))
    padded = torch.nn.functional.pad(S[None, None], (L, L), mode="reflect")[0, 0]
    floor = padded.unfold(0, 2 * L + 1, 1).median(dim=1).values.clamp(min=1e-20)
    prom = S / floor
    z = (prom - 1.0) * math.sqrt(K) * 0.7
    lines = []
    for i in range(1, S.numel() - 1):
        f = i * df
        if f < 20.0 or f > 0.98 * rate / 2 or (top_hz and f >= top_hz):
            continue
        if prom[i] < 2.0 or z[i] < 10.0 or S[i] < S[i - 1] or S[i] < S[i + 1]:
            continue
        a, b, c = (10 * math.log10(max(1e-30, float(S[j])))
                   for j in (i - 1, i, i + 1))
        den = a - 2 * b + c
        off = 0.5 * (a - c) / den if den != 0 else 0.0
        lines.append({"hz": round((i + max(-0.5, min(0.5, off))) * df, 2),
                      "prominence_db": round(10 * math.log10(float(prom[i])), 1),
                      "z": round(float(z[i]), 1)})
    lines.sort(key=lambda l: -l["z"])
    lines = sorted(lines[:24], key=lambda l: l["hz"])
    tol = 1.5 * df
    for l in lines:
        l["series"] = ""
        l["mains"] = False
    for m in (50.0, 60.0):
        family = [l for l in lines for k in range(1, 21)
                  if abs(l["hz"] - k * m) <= max(1.0, tol * k)]
        # a mains family: its fundamental or second harmonic, and more
        if len(family) >= 2 and any(abs(l["hz"] - k * m) <= max(1.0, tol * k)
                                    for l in family for k in (1, 2, 3)):
            for l in family:
                l["mains"] = True
    for f0 in [l["hz"] for l in lines]:
        members = [l for l in lines
                   if abs(l["hz"] / f0 - round(l["hz"] / f0)) * f0 <= tol
                   * max(1, round(l["hz"] / f0)) and 1 <= round(l["hz"] / f0) <= 12]
        if len(members) >= 3:
            for l in members:
                if not l["series"]:
                    l["series"] = f"{f0:g} Hz"
    return lines


# -- repeats --------------------------------------------------------------------

def find_repeats(x, rate) -> dict:
    """A pattern that repeats at a steady period: the beat spectrum (the
    autocorrelation of every frequency row of the spectrogram, averaged)
    finds the period; then the waveform itself is cut at that period and
    each repeat aligned to the others. If the repeats match as WAVEFORMS
    (an electronic tone, a played recording, a machine cycle), averaging N
    of them lowers independent noise by 10*log10(N) dB — Recovered. If only
    their spectra repeat, the repeating background can still be lifted off
    what does not repeat — Cleaned."""
    import torch
    out = {"found": False}
    n = min(x.numel(), int(REP_MAX_SCAN_S * rate))
    n_fft = _pow2(rate * 0.04)
    hop = max(1, int(round(rate * 0.01)))
    if n < n_fft + hop * 40:
        return out
    V = torch.stft(x[:n], n_fft, hop, window=torch.hann_window(n_fft),
                   center=False, return_complex=True).abs().pow(2)
    top = min(V.shape[0], int(8000.0 / (rate / n_fft)) + 1)
    # every band one vote: log power, each row standardised, so a loud
    # voice in a few bands does not outvote a machine in all of them
    V = torch.log(V[:top].clamp(min=1e-20))
    N = V.shape[1]
    V = (V - V.mean(dim=1, keepdim=True)) / V.std(dim=1, keepdim=True).clamp(
        min=1e-6)
    size = 1 << int(math.ceil(math.log2(2 * N)))
    F = torch.fft.rfft(V, size)
    A = torch.fft.irfft(F * F.conj(), size)[:, :N]
    A = A / (N - torch.arange(N)).clamp(min=1)
    A = A / A[:, :1].clamp(min=1e-12)
    lmin = max(2, int(REP_MIN_S * rate / hop))
    lmax = N // REP_MIN_COUNT
    if lmax <= lmin + 2:
        return out
    # each band weighted by how strongly it repeats at all: a beacon in a
    # few bands is not averaged away by the bands of plain noise around it
    floor = 4.0 / math.sqrt(N)
    w = (A[:, lmin:lmax].max(dim=1).values - floor).clamp(min=0)
    if float(w.sum()) <= 0:
        return out
    b = (A * w[:, None]).sum(dim=0) / w.sum()
    peaks = []
    for l in range(lmin, lmax):
        if b[l] < b[l - 1] or b[l] < b[l + 1]:
            continue
        mults = [float(b[k * l]) for k in range(1, 4) if k * l < N]
        peaks.append((sum(mults) / len(mults), l))
    if not peaks:
        return out
    best = max(peaks)[0]
    # the shortest period that scores nearly as well: its multiples score
    # as well as it does, and the repeat is the shortest of them
    best, lag = min((p for p in peaks if p[0] >= 0.85 * best),
                    key=lambda p: p[1])
    # how far the peak stands above the beat spectrum around it (its own
    # shoulders, a tenth of the lag either side, left out)
    edge = max(3, lag // 10)
    around = torch.cat([b[max(lmin, lag // 2):max(lmin, lag - edge)],
                        b[lag + edge:min(N, lag + lag // 2)]])
    if around.numel() >= 5:
        med = float(around.median())
        mad = float((around - med).abs().median()) * 1.4826
        prominence = (float(b[lag]) - med) / max(mad, 1e-3)
    else:
        prominence = 0.0
    out.update(strength=round(best, 3), prominence=round(prominence, 1),
               period_s=round(lag * hop / rate, 4))
    if lag == 0 or best < REP_STRENGTH or (
            prominence < REP_PROMINENCE and best < REP_CLEAR):
        return out
    # the waveform test, at sample resolution
    P0 = lag * hop
    lo, hi = max(1, P0 - 2 * hop), P0 + 2 * hop
    seg = x[:n]
    size = 1 << int(math.ceil(math.log2(2 * seg.numel())))
    Xf = torch.fft.rfft(seg, size)
    ac = torch.fft.irfft(Xf * Xf.conj(), size)
    P = lo + int(torch.argmax(ac[lo:hi + 1]))
    count = x.numel() // P
    out.update(found=True, period_s=round(P / rate, 5),
               period_samples=int(P), count=int(count))
    if count < REP_MIN_COUNT:
        out["found"] = False
        return out
    epochs, starts = [], []
    tol = max(2, int(0.002 * rate), int(0.005 * P))
    ref = x[:P]
    pos = 0
    for k in range(count):
        s0 = k * P if k == 0 else starts[-1] + P
        a0, a1 = max(0, s0 - tol), min(x.numel() - P, s0 + tol)
        if a1 < a0:
            break
        best_r, best_s = -2.0, a0
        window = x[a0:a1 + P]
        cc = torch.nn.functional.conv1d(window[None, None], ref[None, None])[0, 0]
        if cc.numel() == 0:
            break
        best_s = a0 + int(torch.argmax(cc))
        starts.append(best_s)
        epochs.append(x[best_s:best_s + P])
        if len(epochs) >= 4:
            ref = torch.stack(epochs).mean(dim=0)
    # a second pass: every repeat aligned again, to the average of all of
    # them (the first few were aligned to a template of only a few)
    template = torch.stack(epochs).mean(dim=0)
    for i, s0 in enumerate(starts):
        a0, a1 = max(0, s0 - tol), min(x.numel() - P, s0 + tol)
        cc = torch.nn.functional.conv1d(x[a0:a1 + P][None, None],
                                        template[None, None])[0, 0]
        if cc.numel():
            starts[i] = a0 + int(torch.argmax(cc))
            epochs[i] = x[starts[i]:starts[i] + P]
    # a steady source (a beacon, a loop, a constant-speed machine) repeats
    # on a straight line: positions fitted to one, so the noise's sample of
    # jitter in each alignment does not leave a residue of every repeat
    k = torch.arange(len(starts), dtype=torch.float64)
    st = torch.tensor(starts, dtype=torch.float64)
    if len(starts) >= 3:
        slope = float(((k - k.mean()) * (st - st.mean())).sum() /
                      ((k - k.mean()) ** 2).sum())
        fit = st.mean() + slope * (k - k.mean())
        if float((st - fit).pow(2).mean().sqrt()) <= 2.0:
            starts = [int(v) for v in fit.round().tolist()]
            starts = [min(max(0, v), x.numel() - P) for v in starts]
            epochs = [x[v:v + P] for v in starts]
            out["steady"] = True
            out["period_exact_samples"] = round(slope, 3)
    E = torch.stack(epochs)
    mean = E.mean(dim=0)
    rs = []
    k = E.shape[0]
    for i in range(k):
        others = (mean * k - E[i]) / max(1, k - 1)
        rs.append(_corr(E[i], others))
    rbar = sorted(rs)[len(rs) // 2]
    keep = [i for i, r in enumerate(rs) if r >= 0.5 * rbar] if rbar > 0 else []
    # chance correlation of two noise waveforms P samples long is about
    # 1/sqrt(P) (a quarter of P taken as independent, to be safe); k repeats
    # each matching the rest add their evidence (half of sqrt(k), again to
    # be safe)
    mean_r = sum(rs) / len(rs)
    significance = mean_r * math.sqrt(max(1.0, P / 4.0)) * \
        math.sqrt(len(rs)) / 2.0
    out.update(waveform_r=round(rbar, 3), used=len(keep),
               waveform_significance=round(significance, 1),
               starts=[int(starts[i]) for i in keep],
               per_repeat_r=[round(r, 3) for r in rs],
               waveform=bool(significance >= REP_WAVEFORM_Z
                             and rbar >= REP_WAVEFORM_R
                             and len(keep) >= REP_MIN_COUNT))
    if out["waveform"]:
        out["expected_gain_db"] = round(10.0 * math.log10(len(keep)), 1)
        snr1 = rbar / max(1e-6, 1.0 - rbar)
        out["per_repeat_snr_db"] = round(10.0 * math.log10(max(1e-6, snr1)), 1)
        out["averaged_snr_db"] = round(out["per_repeat_snr_db"] +
                                       out["expected_gain_db"], 1)
    return out


def average_repeats(x, info: dict):
    """The repeats averaged and laid back where each one was — the
    repeating sound with independent noise averaged down. Everything that
    does not repeat is left out (it is in the residual)."""
    import torch
    P = info["period_samples"]
    starts = info["starts"]
    E = torch.stack([x[s:s + P] for s in starts])
    mean = E.mean(dim=0)
    y = torch.zeros_like(x)
    for s in starts:
        y[s:s + P] = mean
    return y, mean


def repeating_apart(x, rate, period_s: float):
    """REPET (Rafii and Pardo): the median of the spectrogram at the same
    point of every period models the repeating background; a soft mask
    lifts it off. Returns (foreground, background)."""
    import torch
    n_fft = _pow2(rate * 0.064)
    hop = n_fft // 4
    win = torch.hann_window(n_fft)
    X = torch.stft(x, n_fft, hop, window=win, center=True, return_complex=True)
    V = X.abs()
    N = V.shape[1]
    p = max(1, int(round(period_s * rate / hop)))
    reps = math.ceil(N / p)
    pad = reps * p - N
    Vp = torch.nn.functional.pad(V, (0, pad), value=float("nan"))
    U = torch.nanmedian(Vp.reshape(V.shape[0], reps, p), dim=1).values
    U = U.repeat(1, reps)[:, :N]
    W = torch.minimum(U, V)
    M = (W / V.clamp(min=1e-12)).clamp(0, 1)
    bg = torch.istft(X * M, n_fft, hop, window=win, center=True,
                     length=x.numel())
    fg = torch.istft(X * (1 - M), n_fft, hop, window=win, center=True,
                     length=x.numel())
    return fg, bg


# -- shift into hearing (§13.9) -------------------------------------------------

SHIFT_BLOCK_S = 10.0
#: An expanded (slowed) copy covers at most this much of the recording.
EXPAND_MAX_S = 30.0
COPY_PEAK_DBFS = -3.0
COPY_MAX_GAIN_DB = 60.0


def shift_band(x, rate, lo: float, hi: float, shift_hz: float = 0.0,
               keep_band: bool = False):
    """The band [lo, hi] Hz with every frequency in it moved by `shift_hz`
    (single-sideband: a tone at f lands at f + shift_hz; the timing is the
    recording's own, so the result lines up with it). In blocks of
    SHIFT_BLOCK_S, Hann-windowed at 50% overlap (the windows sum to one),
    each set in the middle of a buffer twice its length so the band
    filter's ringing has room and nothing wraps round. The band is taken
    from the positive frequencies only (the analytic signal), its edges
    raised-cosine, multiplied by exp(j 2 pi shift t) on the recording's
    clock (in float64, so the phase runs on unbroken from block to block)
    and its real part added in. (moved, band): `band` is the same band
    unmoved — a band-pass — when asked for, else None."""
    import torch
    nyq = rate / 2
    if not (0 <= lo < hi <= nyq):
        raise ValueError(f"the band {lo:g}-{hi:g} Hz is not inside "
                         f"0-{nyq:g} Hz")
    if lo + shift_hz <= 0 or hi + shift_hz >= nyq:
        raise ValueError(f"moving {lo:g}-{hi:g} Hz by {shift_hz:+g} Hz leaves "
                         f"0-{nyq:g} Hz")
    n = x.numel()
    L = _pow2(rate * SHIFT_BLOCK_S)
    h = L // 2
    N = 2 * L
    win = torch.hann_window(L, periodic=True)
    f = torch.arange(N // 2 + 1, dtype=torch.float64) * rate / N
    tw = max(1.0, 0.05 * (hi - lo))
    m = ((f >= lo) & (f <= hi)).double()
    rise = (f > lo - tw) & (f < lo)
    m[rise] = 0.5 - 0.5 * torch.cos(math.pi * (f[rise] - (lo - tw)) / tw)
    fall = (f > hi) & (f < hi + tw)
    m[fall] = 0.5 + 0.5 * torch.cos(math.pi * (f[fall] - hi) / tw)
    m[0] = 0.0
    m[-1] = 0.0
    # the analytic signal's spectrum: twice the positive frequencies
    gain = torch.zeros(N, dtype=torch.float32)
    gain[:N // 2 + 1] = (2.0 * m).float()
    gain[0] = 0.0
    xp = torch.nn.functional.pad(x.float(), (h, L))
    O = L                      # out[O + g] holds sample g of the recording
    moved = torch.zeros(n + O + N)
    band = torch.zeros(n + O + N) if keep_band else None
    buf = torch.zeros(N)
    s = 0
    while s < n + h:
        seg = xp[s:s + L]
        buf.zero_()
        buf[h:h + seg.numel()] = seg * win[:seg.numel()]
        z = torch.fft.ifft(torch.fft.fft(buf) * gain)
        # buffer position p is recording sample g = s + p - L
        g0 = s - L
        if shift_hz:
            t = torch.arange(g0, g0 + N, dtype=torch.float64)
            cyc = torch.remainder(t * (shift_hz / rate), 1.0)
            rot = torch.polar(torch.ones(N, dtype=torch.float64),
                              2.0 * math.pi * cyc).to(torch.complex64)
            y = (z * rot).real
        else:
            y = z.real
        moved[O + g0:O + g0 + N] += y
        if band is not None:
            band[O + g0:O + g0 + N] += z.real
        s += h
    moved = moved[O:O + n].clone()
    return moved, (band[O:O + n].clone() if band is not None else None)


def _to_peak(y, peak_dbfs: float = COPY_PEAK_DBFS):
    """`y` with its peak brought to `peak_dbfs` (a gain, never more than
    COPY_MAX_GAIN_DB): (samples, gain dB)."""
    peak = float(y.abs().max()) if y.numel() else 0.0
    gain = min(COPY_MAX_GAIN_DB, 20.0 * math.log10(
        10.0 ** (peak_dbfs / 20.0) / max(peak, 1e-12)))
    return y * 10.0 ** (gain / 20.0), round(gain, 1)


def expand_factor(lo: float, hi: float, rate: int) -> int:
    """How many times slower to play a band above hearing so its middle
    lands near 2 kHz — a divisor of the rate when one is near, so the slowed
    file's rate is a whole number with no rounding."""
    want = max(2, int(round(0.5 * (lo + hi) / 2000.0)))
    for d in range(4):
        for k in (want - d, want + d):
            if k >= 2 and rate % k == 0:
                return k
    return want


def _loudest_window(y, rate, seconds: float) -> tuple[float, float]:
    """The `seconds` of `y` holding the most energy (1 s steps)."""
    import torch
    n = y.numel()
    w = int(seconds * rate)
    if n <= w:
        return 0.0, n / rate
    sec = int(rate)
    e = torch.stack([y[a:a + sec].pow(2).sum() for a in range(0, n, sec)])
    k = max(1, int(seconds))
    sums = torch.nn.functional.avg_pool1d(e[None, None], k, 1)[0, 0] \
        if e.numel() >= k else e.sum()[None]
    a = int(torch.argmax(sums))
    return float(a), float(min(n / rate, a + seconds))


def shift_op(x, rate, req) -> tuple:
    """The "shift" dsp step: the band moved (peak to -3 dBFS) and, when
    asked, a copy of the same band played slower ("expand": a band above
    hearing, written at rate/k — the same samples, k times longer, every
    frequency divided by k) or faster ("speed": a band below hearing, every
    k-th sample of it written at the full rate — k times shorter, every
    frequency multiplied by k). (moved samples, info)."""
    lo, hi = (float(v) for v in req["band"])
    dshift = float(req.get("shift_hz") or 0.0)
    copy = req.get("copy") or {}
    moved, band = shift_band(x, rate, lo, hi, dshift, keep_band=bool(copy))
    moved, gain = _to_peak(moved)
    info = {"band_hz": [lo, hi], "shift_hz": dshift,
            "to_hz": [round(lo + dshift, 1), round(hi + dshift, 1)],
            "gain_db": gain}
    _say(f"shift: {lo:.0f}-{hi:.0f} Hz moved by {dshift:+.0f} Hz to "
         f"{lo + dshift:.0f}-{hi + dshift:.0f} Hz, gain {gain:+.1f} dB")
    if copy.get("kind") == "expand":
        k = int(copy.get("factor") or expand_factor(lo, hi, rate))
        t0, t1 = copy.get("start_s"), copy.get("end_s")
        if t0 is None or t1 is None:
            t0, t1 = _loudest_window(band, rate, EXPAND_MAX_S)
        t0 = max(0.0, float(t0))
        t1 = min(x.numel() / rate, float(t1), t0 + EXPAND_MAX_S)
        seg = band[int(t0 * rate):int(t1 * rate)]
        out_rate = max(1, rate // k)
        c, cgain = _to_peak(seg)
        write_wav(copy["output"], c, out_rate)
        factor = rate / out_rate
        info["copy"] = {"kind": "expand", "factor": round(factor, 4),
                        "rate": out_rate, "start_s": round(t0, 3),
                        "end_s": round(t1, 3), "gain_db": cgain,
                        "heard_hz": [round(lo / factor, 1),
                                     round(hi / factor, 1)],
                        "duration_s": round(seg.numel() / out_rate, 3)}
        _say(f"expanded copy: {t0:.1f}-{t1:.1f} s played {factor:g}x slower, "
             f"heard at {lo / factor:.0f}-{hi / factor:.0f} Hz")
    elif copy.get("kind") == "speed":
        k = int(copy.get("factor") or 16)
        if hi >= 0.45 * rate / k:
            raise ValueError(f"{hi:g} Hz is too high to play {k}x faster at "
                             f"{rate} Hz")
        c, cgain = _to_peak(band[::k])
        write_wav(copy["output"], c, rate)
        info["copy"] = {"kind": "speed", "factor": k, "rate": rate,
                        "start_s": 0.0, "end_s": round(x.numel() / rate, 3),
                        "gain_db": cgain,
                        "heard_hz": [round(lo * k, 1), round(hi * k, 1)],
                        "duration_s": round(c.numel() / rate, 3)}
        _say(f"sped-up copy: {k}x faster, heard at {lo * k:.0f}-"
             f"{hi * k:.0f} Hz")
    return moved, info


def _public_event(e: dict) -> dict:
    return {k: v for k, v in e.items() if k not in ("cols", "groups")}


def faint_op(x, rate, spec: dict, repeats: dict | None = None,
             top_hz: float | None = None) -> dict:
    """The salience map (PNG), the faint events, a clip of each faint one
    (masked to its band, its peak at -3 dBFS), and the tonal lines. When
    something repeats, the events are found in what is left with the repeat
    taken out (averaged repeats subtracted, or the repeating background
    lifted off): a beacon every second would otherwise be every event, and
    a voice under it none. The map still shows the whole recording.
    `top_hz`: the file's content ends there (a codec's brick wall) —
    nothing above it is scored."""
    rep = repeats or {}
    period = float(rep.get("period_s") or 0.0) if rep.get("found") else 0.0
    base, basis = x, "the recording"
    if rep.get("found"):
        try:
            if rep.get("waveform"):
                part, _mean = average_repeats(x, rep)
                base, basis = x - part, ("the recording with its averaged "
                                         "repeats subtracted")
            else:
                base, _bg = repeating_apart(x, rate, period)
                basis = "the recording with its repeating background lifted off"
        except Exception as exc:                          # noqa: BLE001
            _say(f"repeats could not be taken out ({exc}); events from the "
                 "whole recording")
            base, basis = x, "the recording"
    sal = Salience(base, rate, top_hz).fit()
    sal.scan()
    events = sal.events(period)
    shown = sal
    if base is not x and (spec.get("png") or spec.get("png_high")):
        shown = Salience(x, rate, top_hz).fit()
        shown.scan()
        shown.found = sal.found
    out = {"events": [], "clips": [], "lines": tonal_lines(x, rate, top_hz),
           "repeat_events": sal.repeat_events, "events_from": basis,
           "thresholds": {"possible": sal.possible, "detected": sal.detect,
                          "for_cells": int(sal.N * sal.F),
                          "faint_broadband_db": FAINT_BROADBAND_DB},
           "frame": {"n_fft": sal.n_fft, "hop": sal.hop, "rate": rate},
           "scales": {"seconds": [round(w * sal.hop / rate, 2)
                                  for w in sal.widths],
                      "bins": list(SAL_FREQ_BINS)}}
    if spec.get("png"):
        rgb, step = shown.image([l for l in out["lines"] if not l["mains"]])
        write_png(spec["png"], rgb)
        ticks = {}
        for hz in (100, 250, 500, 1000, 2000, 4000, 8000, 16000):
            if hz < rate / 2:
                g = min(range(SAL_GROUPS),
                        key=lambda i: abs(shown.group_hz[i][0] - hz))
                ticks[str(hz)] = SAL_GROUPS - 1 - g
        out["map"] = {"width": int(rgb.shape[1]), "height": int(rgb.shape[0]),
                      "seconds_per_px": round(step * shown.tp * shown.hop
                                              / rate, 5),
                      "duration_s": round(x.numel() / rate, 3),
                      "f_max": rate / 2, "frequency_scale": "mel",
                      "rows_at_hz": ticks}
        for e in events:
            c0, c1, g0, g1 = shown._box(e, step)
            e["box"] = {"x0": int(c0), "x1": int(c1),
                        "y0": SAL_GROUPS - 1 - int(g1),
                        "y1": SAL_GROUPS - 1 - int(g0)}
        out["map"]["lines_rows"] = [
            {"hz": l["hz"], "row": SAL_GROUPS - 1 - shown.group_of(l["hz"])}
            for l in out["lines"] if not l["mains"]]
    if spec.get("png_high") and shown.high_groups:
        lines = [l for l in out["lines"] if not l["mains"]]
        rgb, step = shown.image(lines, high=True)
        write_png(spec["png_high"], rgb)
        rows = len(shown.high_groups)
        out["map_high"] = {
            "width": int(rgb.shape[1]), "height": int(rgb.shape[0]),
            "seconds_per_px": round(step * shown.tp * shown.hop / rate, 5),
            "duration_s": round(x.numel() / rate, 3),
            "f_min": SAL_HIGH_FROM_HZ, "f_max": rate / 2,
            "frequency_scale": "linear",
            "rows_at_hz": {str(int(hz)): rows - 1 - shown.group_of(hz, True)
                           for hz in shown.guides(True)},
            "lines_rows": [{"hz": l["hz"],
                            "row": rows - 1 - shown.group_of(l["hz"], True)}
                           for l in lines if l["hz"] >= SAL_HIGH_FROM_HZ]}
        for e in events:
            box = shown._box(e, step, high=True)
            if box is not None:
                c0, c1, g0, g1 = box
                e["box_high"] = {"x0": int(c0), "x1": int(c1),
                                 "y0": rows - 1 - int(g1),
                                 "y1": rows - 1 - int(g0)}
    out["events"] = [_public_event(e) for e in events]
    # the strongest faint events, in time order, one clip each
    slots = spec.get("clips") or []
    lows = [e for e in events if e["f_hi"] < SAL_HIGH_FROM_HZ]

    def echo(e):
        # the top of a sound heard below 12 kHz at the same moment (a
        # click's splatter) comes after every sound that is its own
        return e["f_lo"] >= SAL_HIGH_FROM_HZ and any(
            l["start_s"] <= e["peak_s"] <= l["end_s"] for l in lows)

    faint = sorted(sorted([e for e in events if e["faint"]],
                          key=lambda e: (echo(e), -e["z"]))[:len(slots)],
                   key=lambda e: e["start_s"])
    for path, e in zip(slots, faint):
        y, gain, t0, t1 = sal.clip(e)
        write_wav(path, y, rate)
        band = sal.listening_band(e)
        out["clips"].append({"n": e["n"], "file": os.path.basename(path),
                             "gain_db": gain, "start_s": t0, "end_s": t1,
                             "f_lo": band[0], "f_hi": band[1],
                             "z": e["z"]})
        _say(f"faint event {e['n']}: {t0:.1f}-{t1:.1f} s, "
             f"{e['f_lo']:.0f}-{e['f_hi']:.0f} Hz, z {e['z']}")
    return out


def analyse_item(it: dict) -> dict:
    """One recording: its channels (and their combination, when that
    measures better), the standard measurements on the result, then the
    faint-sound measurements if asked for."""
    basis = it["wav"]
    channels = {"count": 1, "kind": "mono"}
    if it.get("channels"):
        X, rate = read_wav_channels(it["channels"])
        channels = channel_report(X, rate)
        if channels["kind"] != "mono" and it.get("combined"):
            y, best, measured = combine_channels(X, rate, channels)
            use, why = use_combined(channels, measured)
            channels.update(combination=measured, used=use, why=why)
            if use:
                write_wav(it["combined"], y, rate)
                if it.get("best_channel"):
                    write_wav(it["best_channel"], best, rate)
                basis = it["combined"]
            _say(f"channels: {channels['kind']}, combining "
                 f"{measured['gain_db']:+.1f} dB — "
                 + ("used" if use else "not used") + f" ({why})")
    a = analyse(basis)
    a["channels"] = channels
    a["basis"] = os.path.basename(basis)
    if it.get("faint") is not None or it.get("repeats"):
        x, rate = read_wav(basis)
        repeats = None
        if it.get("repeats"):
            _say("repeats: the beat spectrum…")
            repeats = a["repeats"] = find_repeats(x, rate)
        if it.get("faint") is not None:
            _say("faint sounds: the salience map…")
            a["faint"] = faint_op(x, rate, it["faint"] or {}, repeats,
                                  (a.get("content") or {}).get("cutoff_hz"))
    return a


def dsp_op(req) -> dict:
    """A faint-sound step over one mono file: "mask" (keep what stands out
    of the noise), "average" (the repeats averaged), "repet" (what does not
    repeat), "shift" (a band moved into hearing, and a slowed or sped-up
    copy of it)."""
    x, rate = read_wav(req["input"])
    kind = req["dsp"]
    if kind == "mask":
        y = Salience(x, rate).fit().whole()
        info = {}
    elif kind == "average":
        info = find_repeats(x, rate)
        if not info.get("waveform"):
            raise ValueError("the repeats no longer match as waveforms in "
                             f"{os.path.basename(req['input'])} (r "
                             f"{info.get('waveform_r')}); nothing averaged")
        y, _mean = average_repeats(x, info)
        info = {k: info[k] for k in ("period_s", "used", "waveform_r",
                                     "expected_gain_db") if k in info}
    elif kind == "repet":
        period = float(req.get("period_s") or 0) or \
            find_repeats(x, rate).get("period_s") or 0
        if not period:
            raise ValueError("no repeating period to separate on")
        y, _bg = repeating_apart(x, rate, period)
        info = {"period_s": period}
    elif kind == "shift":
        y, info = shift_op(x, rate, req)
    else:
        raise ValueError(f"unknown dsp step {kind!r}")
    write_wav(req["output"], y, rate)
    return {"dsp": kind, "info": info, "rate": rate}


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    op = req.get("op")
    if op == "analyse":
        out = {"items": []}
        for it in req["items"]:
            out["items"].append({"id": it["id"],
                                 "analysis": analyse_item(it)})
            _say(f"analysed {it['id']}")
    elif op == "model":
        out = model_op(req)
    elif op == "dsp":
        out = dsp_op(req)
    elif op == "finish":
        out = finish_op(req)
    else:
        raise ValueError(f"unknown op {op!r}")
    out["op"] = op
    out["elapsed_s"] = round(time.monotonic() - started, 3)
    _write_json(response_path, out)
    _say(f"done in {out['elapsed_s']:.1f} s")
    return 0


def main(argv) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    return run(argv[1], argv[2])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:                              # noqa: BLE001
        print(f"restore_worker failed: {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
