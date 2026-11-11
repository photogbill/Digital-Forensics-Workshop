# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""HARK's worker — run as its own process, never imported.

    python -I hark_worker.py REQUEST.json RESPONSE.json

Started by `hark.py` under the host's torch interpreter (ATK:
`envs\\atk_audio\\Scripts\\python.exe`), exactly like `restore_worker.py`.
SELF-CONTAINED: it imports nothing from the engine, only torch, and writes
only the paths it is told to — the map PNG, the extracted voice and the
probe, and the one response — each checked by the parent
(`assert_child_writes`) before it started.

HARK (FORENSICS_PLAN §15, HARK_PLAN.md) finds voiced sound by its PITCH
TRACK, the way a pulsar search finds a periodic source too faint to see in
one look. Hunt, calibrate, probe, score and audit MEASURE; extract writes
new files beside the recording and never changes it.

Seven operations, one per request (`"op"`):

* **hunt** (Move 1) — the recording's spectrum, whitened against its own
  noise (each frequency bin divided by that bin's median power over the
  file, so a steady hum or fan line is flattened away); for every frame and
  every candidate pitch from 60 to 500 Hz, the evidence at its harmonics
  minus the evidence half-way between them (harmonic summing with a
  sub-harmonic penalty, after Drugman & Alwan's SRH); that evidence
  averaged along short straight pitch slopes (the pulsar "acceleration
  search"); then a Viterbi pass that finds the best continuous pitch path
  before anything is thresholded (track-before-detect). Two or three
  tracks are taken one after another, each removed before the next.
  **The false-alarm rate is measured on THIS file**: surrogate copies of
  the recording, each 8 s block with its spectrum's phases randomised, keep
  its noise's colour and level as they change but destroy any harmonic
  structure; the same hunt over them says how often noise alone makes a
  track this strong — per hour, no Gaussian assumption.
* **calibrate** (Move 5) — the file's own CEP: voice-like probes (and real
  phrases when given) injected into the file's own voice-free stretches at
  stepped levels, hunted exactly as the file was; the share found at each
  level, the level where half and nine-tenths are found, the error of the
  level estimate (so a real track's level can be placed on the curve), and
  for real phrases the intelligibility of the raw mixture (ESTOI). The
  injected copies live only in memory — nothing is written.
* **extract** (Move 2) — the voice pulled out along its pitch track. Each
  DETECTED track's pitch is refined frame by frame (three passes, ±3% down
  to ±0.2%, by the coherent energy at its harmonics), its phase integrated
  sample by sample — warped time, in which the voice is periodic — and its
  harmonics fitted in blocks six pitch cycles long, each harmonic weighted
  by a Wiener gain from the noise measured half-way between harmonics (the
  cyclic Wiener filter in its line-spectrum form). Two tracks that overlap
  are fitted in turn, each on what the other leaves. Writes VOICE (the
  harmonics only) and LIFT (the voice plus everything else through a
  Wiener filter on the file's own noise, so consonants survive). Linear
  given the track: it can remove, it cannot add (Cleaned).
* **census** (Move 8) — what else is in the recording, the way passive
  sonar finds ships: DEMON on ten band envelopes (the rates at which the
  noise's LOUDNESS pulses — a propeller, a rotor, a fan, footsteps, an
  engine's firing), each with its false-alarm rate measured on the file's
  own surrogates; and, for the hunt's steady tracks that the parent names
  machines, the recording with each taken out along its own pitch track
  (Move 2 in reverse) — "without" and the machine alone (Cleaned).
* **probe** (increment 2b) — a test recording made of the file's own noise
  (its voice-free stretches, extended by surrogates when short) with clean
  phrases injected at the calibration's levels; writes the probe and the
  clean phrases alone, for scoring every restoration on it.
* **score** (increment 2b) — each restoration's output of the probe against
  the clean phrases: ESTOI and scale-invariant SNR per phrase and level, and
  the noise left in the pauses.
* **audit** (Move 6) — every restoration output and residual hunted the same
  way: one of the input's voice tracks in what a chain REMOVED means it took
  voice; a confident track in its OUTPUT that the input's hunt did not find
  is checked along its exact pitch path in the INPUT — a linear filter
  cannot create harmonic evidence, so no trace there means the chain MADE
  it; a track the input only suspected (possible) that an output makes
  clear is REVEALED.
"""

from __future__ import annotations

import json
import math
import os
import struct
import sys
import time

# -- the analysis -------------------------------------------------------------
WIN_S = 0.064                 # 64 ms Hann: main lobe ±31 Hz, so harmonics of
HOP_S = 0.010                 # a 60 Hz voice stay apart from the half-way bins
BIN_HZ = 8.0                  # target FFT bin spacing (zero padding)
LOCAL_HZ = 250.0              # per-frame level: median over ±250 Hz
F0_MIN, F0_MAX = 60.0, 500.0
HARM_TOP_HZ = 4000.0          # harmonics summed up to here (or the content top)
K_MAX = 30
RATIO_CAP = 100.0             # above 20 dB over its noise a harmonic counts
                              # only logarithmically
LONE_HARMONIC = 1.0           # and never above the next strongest
FLOOR_BELOW_DB = 100.0        # the noise floor never under loudest - 100 dB
WEIGHT_KNEE_HZ = 1000.0
THIRDS_FROM_HZ = 150.0         # third-way penalty only where 1/3 of the
                              # pitch clears the window's main lobe
SURR_BLOCK_S = 8.0            # surrogate blocks: phases randomised per block
SMOOTH_HALF = 5               # slope templates span ±5 frames (110 ms)
BIAS = 2.5                    # Viterbi: a frame must beat this to pay its way
STEP_COST = 0.15              # per pitch step squared, frame to frame
MAX_STEP = 3                  # steps per frame (at 1/36 octave: 1/12 octave)
ON_COST = 3.0
OFF_COST = 1.0
CHUNK_FRAMES = 3000           # Viterbi chunks: 30 s, with 3 s each side
CHUNK_PAD = 300
VIT_BATCH = 64
MEDIAN_FRAMES = 120000
BLOCK_FRAMES = 4000

#: A track is "detected" when noise alone makes one that strong less than
#: once in ten hours of this file's noise, "possible" under ten an hour.
FA_DETECT_PER_HOUR = 0.1
FA_POSSIBLE_PER_HOUR = 10.0
#: The tail of the surrogate scores is fitted from this share upward when a
#: rate below what the surrogates hold has to be extrapolated.
TAIL_SHARE = 0.2
MIN_SEGMENT_FRAMES = 8
TRACK_MATCH_RATIO = 1.06      # same pitch: within 6 %
GROUP_GAP_S = 0.25            # voiced runs this close, pitch continuing,
GROUP_PITCH_RATIO = 1.2       # are one utterance

#: The audit's path support, in noise standard deviations: under this, the
#: input holds no trace along the exact pitch path of a track an output
#: shows that the input's hunt did not find — that output MADE it.
SUPPORT_NONE = 1.0
#: A voice counts as REMOVED only when the output lost at least this share of
#: its harmonic power along the voice's track (measured on the output before
#: its level gain: the reference less the residual). A filter that only
#: shifts phase — a high-pass near the pitch — puts voice in the residual
#: without taking any away; its output keeps the voice's power.
REMOVED_MIN_SHARE = 0.2

# -- the map ------------------------------------------------------------------
MAP_TOP_HZ = 2000.0
MAP_W, MAP_H = 1600, 360
TRACK_COLOURS = ((80, 230, 255), (255, 190, 60), (190, 120, 255))

# -- calibration --------------------------------------------------------------
INJECT_CONTEXT_S = 2.0
PROBE_S = 2.5
ESTOI_FS = 10000

# -- extraction (Move 2) --------------------------------------------------------
EXTRACT_TOP_HZ = 5000.0       # harmonics fitted up to here (or the content's
EXTRACT_CYCLES = 6.0          # top); blocks this many pitch cycles long, half
GAP_FILL_FRAMES = 6           # overlapping; unvoiced gaps up to 60 ms bridged
REFINE_SPANS = (0.03, 0.008, 0.002)    # ± pitch searched per refining pass
REFINE_STEPS = (25, 13, 13)   # candidates per pass
REFINE_STRIDE = 2             # every 2nd frame refined, the rest between
REFINE_MIN_S = 0.04           # refining window: at least 40 ms and 4 cycles
REFINE_MIN_CYCLES = 4.0
NOISE_BLOCKS = 3              # interharmonic noise over ±3 blocks
BLOCK_BUDGET = 8e6            # numbers per chunk of blocks solved at once
REFINE_BUDGET = 1.6e7         # numbers per chunk of frames refined at once
REFINE_RATE = 16000           # the pitch is refined at this rate at most
BACKFIT_ROUNDS = 2            # overlapping tracks fitted in turn, twice
LIFT_FLOOR_DB = -15.0         # the rest's Wiener filter: gain floor,
LIFT_ALPHA = 0.98             # decision-directed smoothing, and the
LIFT_QUANTILE = 0.3           # quantile its noise spectrum is taken at

# -- the census (Move 8) ---------------------------------------------------------
ENV_WIN_S = 0.008             # band envelopes: 8 ms frames every 2 ms
ENV_HOP_S = 0.002             # (modulation rates to 250 Hz)
ENV_BANDS = 10                # log-spaced from ENV_LO_HZ to the top
ENV_LO_HZ = 100.0
MOD_WIN_S = 8.0               # modulation spectra over 8 s, every 4 s
MOD_HOP_S = 4.0
MOD_MIN_HZ, MOD_MAX_HZ = 1.0, 200.0
MOD_HARMONICS = 4             # a pulse train's rate and three multiples
MOD_SURROGATES = 6            # noise copies the false-alarm rate is read on
MOD_RATE_MATCH = 1.04         # one source across windows: rate within 4%
MOD_LOCAL = 0.25              # a rate's background: its neighbours ±25%
MOD_LOCAL_MIN_HZ = 0.5        # (at least ±0.5 Hz)

# -- probe and score (increment 2b) ------------------------------------------
PROBE_GAP_S = 1.0             # noise before and after each phrase
PROBE_FADE_S = 0.02           # cross-fade joining stretches of noise
SCORE_BAND = (60.0, 5000.0)   # scale-invariant SNR measured in this band


def _say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# WAV in, files out (the same reader as restore_worker.py)
# ---------------------------------------------------------------------------

def read_wav(path):
    """(mono float tensor, rate) from PCM 8/16/24/32-bit or float 32/64 —
    the channels averaged."""
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
    x = x.reshape(-1, max(1, ch)).T.contiguous()
    return (x.mean(dim=0) if x.shape[0] > 1 else x[0]), rate


def _write_bytes(path: str, payload: bytes) -> None:
    tmp = f"{path}.{os.getpid()}.part"
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_json(path: str, data: dict) -> None:
    _write_bytes(path, json.dumps(data).encode("utf-8"))


def write_png(path, rgb) -> None:
    """An 8-bit RGB PNG — zlib and struct only."""
    import zlib
    h, w, _ = rgb.shape
    flat = bytes(rgb.contiguous().flatten().tolist())
    row = w * 3
    raw = b"".join(b"\x00" + flat[r * row:(r + 1) * row] for r in range(h))

    def chunk(tag, data):
        return (struct.pack(">I", len(data)) + tag + data +
                struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF))

    _write_bytes(path, b"\x89PNG\r\n\x1a\n"
                 + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
                 + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def _device(wanted: str) -> str:
    import torch
    if wanted == "cpu":
        return "cpu"
    if wanted in ("auto", "cuda") and torch.cuda.is_available():
        return "cuda"
    return "cpu"


# ---------------------------------------------------------------------------
# the grid: frames, bins, pitch states
# ---------------------------------------------------------------------------

class Grid:
    """Everything that depends only on the rate and the pitch resolution."""

    def __init__(self, rate: int, steps_per_octave: int = 36,
                 top_hz: float | None = None, f0_lo: float | None = None,
                 f0_hi: float | None = None):
        import torch
        # the pitch range searched: the whole voice range, or (Move 7) one
        # speaker's — fewer pitches, so a lower line at the same false-alarm
        # rate (the null is measured over the same range)
        self.lo = max(F0_MIN, float(f0_lo or F0_MIN))
        self.hi = min(F0_MAX, float(f0_hi or F0_MAX))
        if self.hi <= self.lo * 1.05:
            raise ValueError(f"pitch range {self.lo:.0f}-{self.hi:.0f} Hz is "
                             "too narrow to hunt")
        self.rate = int(rate)
        self.win = max(16, int(round(rate * WIN_S)))
        self.hop = max(1, int(round(rate * HOP_S)))
        self.n_fft = 1 << max(8, math.ceil(math.log2(rate / BIN_HZ)))
        self.n_fft = max(self.n_fft, 1 << math.ceil(math.log2(self.win)))
        self.df = rate / self.n_fft
        nyq = rate / 2.0
        top = min(HARM_TOP_HZ, 0.95 * nyq)
        if top_hz:
            top = min(top, float(top_hz))
        self.top_hz = top
        self.nb = int(top / self.df) + 2
        self.spo = int(steps_per_octave)
        n_states = int(math.floor(math.log2(self.hi / self.lo)
                                  * self.spo)) + 1
        self.f0 = torch.tensor([self.lo * 2.0 ** (j / self.spo)
                                for j in range(n_states)])
        self.window = torch.hann_window(self.win, periodic=False)
        self._harmonics()

    def _harmonics(self):
        """Index tables: for state j and harmonic k, the pooled-spectrum
        row (by tolerance) and bin of the harmonic, and the plain bin of the
        half-way point below it (never pooled: at 100 Hz the gap between two
        harmonics' main lobes is under 40 Hz, and a pooled half-way window
        would reach into them), the third-way points (penalised for pitches
        from THIRDS_FROM_HZ, so a track cannot lock on three times the true
        pitch, where every third harmonic would otherwise count with nothing
        against it), and each harmonic's weight: 1 up to
        WEIGHT_KNEE_HZ, falling as f^-1.5 above — a voice's harmonics carry
        most of their energy below 1 kHz (the first formant), and thirty
        equally weighted terms would mostly add noise."""
        import torch
        widths = (1, 3, 5, 9, 17)
        self.widths = widths
        J = self.f0.numel()
        hb = torch.zeros(J, K_MAX, dtype=torch.long)
        ib = torch.zeros(J, K_MAX, dtype=torch.long)
        t1 = torch.zeros(J, K_MAX, dtype=torch.long)
        t2 = torch.zeros(J, K_MAX, dtype=torch.long)
        thirds = torch.zeros(J)
        valid = torch.zeros(J, K_MAX)
        for j in range(J):
            f0 = float(self.f0[j])
            for k in range(1, K_MAX + 1):
                f = k * f0
                if f > self.top_hz - self.df:
                    break
                # tolerance: 1.5 % of the harmonic (drift and jitter inside
                # the frame) or one bin, as a pooled width
                tol = max(1.0, 0.015 * f / self.df)
                w = next((i for i, x in enumerate(widths) if x / 2.0 >= tol),
                         len(widths) - 1)
                hb[j, k - 1] = w * self.nb + int(round(f / self.df))
                ib[j, k - 1] = int(round((k - 0.5) * f0 / self.df))
                t1[j, k - 1] = int(round((k - 1 / 3) * f0 / self.df))
                t2[j, k - 1] = int(round((k - 2 / 3) * f0 / self.df))
                valid[j, k - 1] = WEIGHT_KNEE_HZ ** 1.5 / max(
                    WEIGHT_KNEE_HZ, f) ** 1.5
            thirds[j] = 0.5 if f0 >= THIRDS_FROM_HZ else 0.0
        self.hidx, self.iidx, self.valid = hb, ib, valid
        self.t1idx, self.t2idx, self.thirds = t1, t2, thirds
        self.nk = (valid > 0).sum(dim=1).clamp(min=1)

    def frames(self, n_samples: int) -> int:
        return max(0, (n_samples - self.win) // self.hop + 1)

    def state_of(self, hz: float) -> int:
        j = round(math.log2(max(self.lo, min(self.hi, hz)) / self.lo)
                  * self.spo)
        return int(max(0, min(self.f0.numel() - 1, j)))


# ---------------------------------------------------------------------------
# the spectrum, whitened against the file's own noise
# ---------------------------------------------------------------------------

def log_power(x, grid: Grid, device: str):
    """log power [frames, bins up to the harmonic top], float16 on the CPU,
    worked a block of frames at a time."""
    import torch
    T = grid.frames(x.numel())
    out = torch.empty((T, grid.nb), dtype=torch.float16)
    win = grid.window.to(device)
    for k0 in range(0, T, BLOCK_FRAMES):
        k1 = min(T, k0 + BLOCK_FRAMES)
        seg = x[k0 * grid.hop:(k1 - 1) * grid.hop + grid.win].to(device)
        f = seg.unfold(0, grid.win, grid.hop) * win
        spec = torch.fft.rfft(f, n=grid.n_fft)[:, :grid.nb]
        p = spec.real ** 2 + spec.imag ** 2
        out[k0:k1] = torch.log(p.clamp(min=1e-20)).cpu().half()
    return out


def noise_log_mean(lp):
    """Each bin's noise as a log MEAN power: the median over the file (a
    voice moves through a bin far less than half the time), raised from the
    median of exponentially distributed power to its mean (÷ ln 2)."""
    import torch
    T = lp.shape[0]
    step = max(1, T // MEDIAN_FRAMES)
    sub = lp[::step].float()
    med = sub.median(dim=0).values
    # digital silence (a residual that is nothing but what was taken, a
    # gated recording): no floor below FLOOR_BELOW_DB under the loudest bins
    loud = float(torch.quantile(sub.reshape(-1)[::max(1, sub.numel()
                                                      // 1000000)], 0.995))
    floor = loud - FLOOR_BELOW_DB * math.log(10.0) / 10.0
    return med.clamp(min=floor) - math.log(math.log(2.0))


def whiten(lp, logN, grid: Grid):
    """The whitened log spectrum, twice over: each bin against the FILE's
    noise in that bin (its colour), then each frame against its own local
    level — the median over ±LOCAL_HZ around every bin in that frame. Real
    noise rises and falls (traffic, wind, a crowd, a radio's AGC); a frame
    louder all over must not look more harmonic. A harmonic is narrow and
    stands above its neighbours; a level change lifts them all together.
    float16 [T, B]."""
    import torch
    T, B = lp.shape
    half = max(2, int(round(LOCAL_HZ / grid.df)))
    out = torch.empty((T, B), dtype=torch.float16)
    ln_med = math.log(math.log(2.0))
    dec = 4                       # the level is smooth across frequency:
    for k0 in range(0, T, BLOCK_FRAMES // 2):     # measured every 4th bin
        k1 = min(T, k0 + BLOCK_FRAMES // 2)       # from every 2nd bin of
        g = lp[k0:k1].float() - logN              # its window, interpolated
        pad = torch.nn.functional.pad(g.unsqueeze(1), (half, half + dec),
                                      mode="replicate").squeeze(1)
        win = pad.unfold(1, 2 * half + 1, dec)[:, :, ::2]
        coarse = win.median(dim=2).values                # [t, ~B/dec]
        med = torch.nn.functional.interpolate(
            coarse.unsqueeze(1), size=(coarse.shape[1] - 1) * dec + 1,
            mode="linear", align_corners=True).squeeze(1)[:, :B]
        # the median of a log-exponential is log(ln 2); keep the mean ratio 1
        out[k0:k1] = (g - med + ln_med).half()
    return out


def surrogate_wave(x, rate: int, seed: int, block_s: float = SURR_BLOCK_S):
    """A surrogate recording: overlapping blocks of SURR_BLOCK_S, each with
    its spectrum's phases randomised, cross-faded back together. Each block
    keeps its own power spectrum — the noise's colour and level as they
    change through the file — but nothing inside it stays periodic: a
    voice's harmonics are smeared into noise of the same colour. Built in
    the time domain and analysed by the SAME spectrum as the file, so every
    window and pooling effect is identical (a surrogate built by shifting
    bands of the spectrogram is not: it breaks the correlation between
    neighbouring bins, and noise then looks more harmonic than it is)."""
    import torch
    n = x.numel()
    L = 1 << max(10, int(round(math.log2(max(1024, block_s * rate)))))
    if n <= L:
        L = 1 << max(4, int(math.floor(math.log2(max(16, n)))))
    hop = L // 2
    win = torch.hann_window(L, periodic=True).sqrt()
    # randomised phases spread each block's (windowed) power evenly over the
    # block, so the analysis window's power loss is put back
    comp = 1.0 / math.sqrt(float((win * win).mean()))
    gen = torch.Generator().manual_seed(int(seed))
    pad = (hop - (n % hop)) % hop + L
    xp = torch.nn.functional.pad(x.float(), (hop, pad))
    out = torch.zeros_like(xp)
    for k0 in range(0, xp.numel() - L + 1, hop):
        X = torch.fft.rfft(xp[k0:k0 + L] * win)
        ph = torch.rand(X.numel(), generator=gen) * (2 * math.pi)
        ph[0] = 0.0
        Y = X.abs() * torch.exp(1j * ph)
        out[k0:k0 + L] += torch.fft.irfft(Y, n=L) * win * comp
    return out[hop:hop + n]


# ---------------------------------------------------------------------------
# the evidence: harmonic summing, then slopes
# ---------------------------------------------------------------------------

def harmonic_evidence(g, grid: Grid, device: str):
    """S[t, j] — for each frame and candidate pitch, the sum over harmonics
    up to the top of (power at harmonic k − power half-way below it − half
    the power at the two third-way points, for pitches where those clear the
    main lobe), all
    as ratios to that bin's own noise and capped at RATIO_CAP. Power
    ratios, not their logs: a harmonic ten times its noise adds nine noise
    units here and under three in the log domain — at low SNR that is the
    whole difference. The half-way term cancels anything broadband (a
    click, a door, a level change), and the soft cap (linear to RATIO_CAP,
    logarithmic above) stops one loud line from carrying a pitch on its own;
    and no harmonic counts for more than LONE_HARMONIC times the next
    strongest, so a single drifting whistle cannot pose as a voice.
    g is the whitened log spectrum [T, B]."""
    import torch
    import torch.nn.functional as F
    T, B = g.shape
    J = grid.f0.numel()
    out = torch.empty((T, J), dtype=torch.float32)
    hidx = grid.hidx.to(device).reshape(-1)
    iidx = grid.iidx.to(device).reshape(-1)
    t1 = grid.t1idx.to(device).reshape(-1)
    t2 = grid.t2idx.to(device).reshape(-1)
    thirds = grid.thirds.to(device).reshape(1, J, 1)
    valid = grid.valid.to(device)
    lobe = max(1, int(round((2.0 / WIN_S) / grid.df)))   # main-lobe half
    for k0 in range(0, T, BLOCK_FRAMES):
        k1 = min(T, k0 + BLOCK_FRAMES)
        gb = g[k0:k1].to(device).float()
        # linear up to RATIO_CAP, logarithmic above: a loud line cannot carry
        # a pitch alone, yet a harmonic 60 dB up still out-ranks the window
        # sidelobe 40 dB up beside it (a hard cap would flatten both)
        lc = math.log(RATIO_CAP)
        r = torch.where(gb > lc, RATIO_CAP * (1.0 + gb - lc), torch.exp(gb))
        pooled = [r]
        where = [torch.arange(B, device=r.device).expand_as(r)]
        for w in grid.widths[1:]:
            v, ix = F.max_pool1d(r.unsqueeze(1), w, stride=1, padding=w // 2,
                                 return_indices=True)
            pooled.append(v.squeeze(1))
            where.append(ix.squeeze(1))
        stack = torch.cat(pooled, dim=1)                # [t, W*B]
        h = stack[:, hidx].reshape(-1, J, K_MAX)
        hb = torch.cat(where, dim=1)[:, hidx].reshape(-1, J, K_MAX)
        # a tolerance window counts its maximum only when that is a PEAK of
        # the spectrum — not the slope of a neighbouring line's main lobe
        # caught at the window's edge; otherwise the harmonic's own bin
        peak = torch.ones_like(r, dtype=torch.bool)
        peak[:, 1:] &= r[:, 1:] >= r[:, :-1]
        peak[:, :-1] &= r[:, :-1] >= r[:, 1:]
        own = r[:, hidx % B].reshape(-1, J, K_MAX)
        at_peak = torch.gather(peak, 1, hb.reshape(hb.shape[0], -1)
                               ).reshape(hb.shape)
        h = torch.where(at_peak, h, own)
        hb = torch.where(at_peak, hb, (hidx % B).reshape(1, J, K_MAX)
                         .expand_as(hb))
        i = r[:, iidx].reshape(-1, J, K_MAX)
        th = (r[:, t1] + r[:, t2]).reshape(-1, J, K_MAX)
        c = (h - i - thirds * th) * valid
        # one spectral peak is one harmonic: where two neighbouring
        # harmonics' tolerance windows found their maxima inside one main
        # lobe (a low pitch's wide windows overlap at high harmonics, and a
        # line between two of them is caught by both), only the larger
        # counts — two true harmonics are always further apart than that
        same = (hb[..., 1:] - hb[..., :-1]).abs() <= lobe
        drop_hi = same & (c[..., 1:] <= c[..., :-1])
        drop_lo = same & ~drop_hi
        keep = torch.ones_like(c, dtype=torch.bool)
        keep[..., 1:] &= ~drop_hi
        keep[..., :-1] &= ~drop_lo
        c = c * keep
        # one harmonic may count at most LONE_HARMONIC times the next
        # strongest: a whistle or a drifting heterodyne is ONE line, and as
        # "the third harmonic of a third of its frequency" it would otherwise
        # make a voice on its own; a voice spreads over several harmonics
        top = torch.topk(c, 2, dim=2).values
        excess = (top[..., 0] - LONE_HARMONIC * top[..., 1].clamp(min=0.0)
                  ).clamp(min=0.0)
        out[k0:k1] = (c.sum(dim=2) - excess).cpu()
    return out


def slope_smooth(z, grid: Grid, slopes):
    """For each slope (pitch steps per frame), the mean of z over ±SMOOTH_HALF
    frames along that straight line in (time, pitch): a voice's pitch is
    steady or gliding over 110 ms; noise is not. [n_slopes, T, J]."""
    import torch
    T, J = z.shape
    m = SMOOTH_HALF
    out = torch.zeros((len(slopes), T, J), dtype=torch.float32)
    zp = torch.nn.functional.pad(z.unsqueeze(0), (0, 0, m, m),
                                 mode="replicate")[0]
    for si, s in enumerate(slopes):
        acc = torch.zeros((T, J))
        for i in range(-m, m + 1):
            d = int(round(s * i))
            row = zp[m + i:m + i + T]
            if d > 0:
                shifted = torch.cat([row[:, d:], row[:, -1:].expand(T, d)], 1)
            elif d < 0:
                shifted = torch.cat([row[:, :1].expand(T, -d), row[:, :d]], 1)
            else:
                shifted = row
            acc += shifted
        out[si] = acc / (2 * m + 1)
    return out


class Null:
    """What noise alone looks like in this file, from its surrogates: the
    mean and spread of the harmonic evidence per pitch, the spread of each
    slope's smoothed evidence, and the scores of the tracks noise makes."""

    def __init__(self, mu=None, sd=None, sd_slope=None, scores=None,
                 hours=0.0, rho=1.0):
        self.mu, self.sd, self.sd_slope = mu, sd, sd_slope
        self.scores = sorted(scores or [])
        self.hours = float(hours)
        self.rho = float(rho)
        self._fit_tail()

    def _fit_tail(self):
        """An exponential fitted to the top TAIL_SHARE of the noise scores,
        so a rate below one per (surrogate hours) can be extrapolated."""
        s = self.scores
        self.tail = None
        if len(s) >= 10 and self.hours > 0:
            n_tail = max(5, int(len(s) * TAIL_SHARE))
            top = s[-n_tail:]
            x0 = top[0]
            mean_excess = sum(v - x0 for v in top) / len(top)
            if mean_excess > 1e-6:
                self.tail = (x0, n_tail / self.hours, mean_excess)

    def rate(self, score: float) -> tuple[float, bool]:
        """(false alarms per hour at this score or above, extrapolated?)."""
        s = self.scores
        if self.hours <= 0:
            return float("inf"), True
        if not s:
            # the surrogates made no track at all (digital silence, or a
            # residual that is nothing but what was taken): nothing in this
            # file's noise looks like a track
            return 0.0, True
        import bisect
        n_above = len(s) - bisect.bisect_left(s, score)
        if n_above >= 3 or self.tail is None or score <= s[-1]:
            if n_above > 0 or self.tail is None:
                return n_above / self.hours, False
        x0, r0, beta = self.tail
        return r0 * math.exp(-(score - x0) / beta), True

    def threshold(self, per_hour: float) -> float:
        """The score at which noise reaches `per_hour` false alarms."""
        s = self.scores
        if self.hours <= 0:
            return float("inf")
        if not s:
            return 0.0
        n = per_hour * self.hours
        if n >= 1 and int(n) < len(s):
            return s[len(s) - int(n) - 1] if int(n) < len(s) else s[0]
        if self.tail is None:
            return s[-1] + 1e-6
        x0, r0, beta = self.tail
        return x0 + beta * math.log(r0 / per_hour)

    def as_dict(self) -> dict:
        return {"mu": [round(float(v), 5) for v in self.mu],
                "sd": [round(float(v), 5) for v in self.sd],
                "sd_slope": [[round(float(v), 5) for v in row]
                             for row in self.sd_slope],
                "scores": [round(float(v), 4) for v in self.scores],
                "hours": self.hours, "rho": round(self.rho, 4)}

    @classmethod
    def from_dict(cls, d: dict) -> "Null":
        import torch
        return cls(mu=torch.tensor(d["mu"]), sd=torch.tensor(d["sd"]),
                   sd_slope=torch.tensor(d["sd_slope"]),
                   scores=d.get("scores") or [], hours=d.get("hours", 0.0),
                   rho=d.get("rho", 1.0))


def evidence_z(g, grid: Grid, device: str, null: Null, slopes):
    """(z [T, J] — the per-frame harmonic evidence in noise units, and
    Z [T, J] — the best slope's smoothed evidence in noise units)."""
    S = harmonic_evidence(g, grid, device)
    z = (S - null.mu) / null.sd.clamp(min=1e-6)
    sm = slope_smooth(z, grid, slopes)
    sm = sm / null.sd_slope.unsqueeze(1).clamp(min=1e-6)
    return z, sm.max(dim=0).values


def build_null(x, logN, grid: Grid, device: str, slopes, n_surr: int,
               seed: int, say=_say):
    """The null from `n_surr` surrogate recordings of x (whitened by the
    FILE's noise, as the file is): the evidence's mean and spread per pitch
    (from the first two), then every surrogate hunted exactly as the file
    will be, for the scores noise alone reaches."""
    import torch

    def g_of(i):
        lp = log_power(surrogate_wave(x, grid.rate, seed + i), grid, device)
        return whiten(lp, logN, grid)

    first = [g_of(i) for i in range(min(2, n_surr))]
    S = torch.cat([harmonic_evidence(s, grid, device) for s in first], 0)
    mu, sd = S.mean(dim=0), S.std(dim=0)
    z = (S - mu) / sd.clamp(min=1e-6)
    sm = slope_smooth(z, grid, slopes)
    sd_slope = sm.std(dim=1)
    # the frame-to-frame correlation of z at a fixed pitch (for the audit's
    # path support: the effective number of independent frames)
    rho = 1.0
    if z.shape[0] > 40:
        zz = z - z.mean(dim=0)
        v = (zz * zz).mean()
        acc = 0.0
        for lag in range(1, 12):
            c = float((zz[lag:] * zz[:-lag]).mean() / v)
            if c < 0.02:
                break
            acc += c
        rho = 1.0 + 2.0 * acc
    null = Null(mu=mu, sd=sd, sd_slope=sd_slope, rho=rho)
    scores, frames = [], 0
    for i in range(n_surr):
        s = first[i] if i < len(first) else g_of(i)
        _z, Z = evidence_z(s, grid, device, null, slopes)
        for seg in tracks_from(Z, grid, device):
            scores.append(seg["score"])
        frames += Z.shape[0]
        if (i + 1) % 5 == 0 or i + 1 == n_surr:
            say(f"null: {i + 1} of {n_surr} surrogates")
    null.scores = sorted(scores)
    null.hours = frames * HOP_S / 3600.0
    null._fit_tail()
    return null


# ---------------------------------------------------------------------------
# track-before-detect: Viterbi over pitch, in overlapping chunks
# ---------------------------------------------------------------------------

def _chunks(T: int):
    """(start, end, keep_from, keep_to) chunks of CHUNK_FRAMES with
    CHUNK_PAD context each side."""
    out = []
    k = 0
    while k < T:
        s = max(0, k - CHUNK_PAD)
        e = min(T, k + CHUNK_FRAMES + CHUNK_PAD)
        out.append((s, e, k, min(T, k + CHUNK_FRAMES)))
        k += CHUNK_FRAMES
    return out


def _viterbi_batch(E, device: str):
    """E [B, L, J] voiced emissions (the off state earns 0). Returns the
    path [B, L] (pitch state, or -1 for off)."""
    import torch
    Bn, L, J = E.shape
    E = E.to(device)
    D = MAX_STEP
    cost = torch.tensor([STEP_COST * d * d for d in range(-D, D + 1)],
                        device=device)
    pv = torch.full((Bn, J), -1e9, device=device)
    po = torch.zeros(Bn, device=device)
    ptr_v = torch.empty((L, Bn, J), dtype=torch.int8)
    ptr_o = torch.empty((L, Bn), dtype=torch.int16)
    for t in range(L):
        pad = torch.nn.functional.pad(pv, (D, D), value=-1e9)
        win = pad.unfold(1, 2 * D + 1, 1) - cost          # [B, J, 2D+1]
        best, arg = win.max(dim=2)
        from_off = (po - ON_COST).unsqueeze(1).expand(Bn, J)
        use_off = from_off > best
        nv = torch.where(use_off, from_off, best) + E[:, t]
        av = torch.where(use_off, torch.full_like(arg, 2 * D + 1), arg)
        vmax, varg = pv.max(dim=1)
        to_off = vmax - OFF_COST
        stay = po >= to_off
        no = torch.where(stay, po, to_off)
        ao = torch.where(stay, torch.full_like(varg, -1), varg)
        pv, po = nv, no
        ptr_v[t] = av.to(torch.int8).cpu()
        ptr_o[t] = ao.to(torch.int16).cpu()
    # backtrack
    pv, po = pv.cpu(), po.cpu()
    path = torch.full((Bn, L), -1, dtype=torch.long)
    vmax, varg = pv.max(dim=1)
    state = torch.where(po >= vmax, torch.full_like(varg, -1), varg)
    for t in range(L - 1, -1, -1):
        path[:, t] = state
        on = state >= 0
        prev = torch.full_like(state, -1)
        if on.any():
            a = ptr_v[t][on.nonzero().squeeze(1), state[on]].long()
            from_off = a == 2 * D + 1
            src = state[on] + (a - D)
            src = torch.where(from_off, torch.full_like(src, -1), src)
            prev[on] = src
        off = ~on
        if off.any():
            prev[off] = ptr_o[t][off].long()
        state = prev
    return path


def viterbi(Z, grid: Grid, device: str):
    """The best pitch path through Z [T, J]: a state per frame, -1 = off."""
    import torch
    T, J = Z.shape
    path = torch.full((T,), -1, dtype=torch.long)
    if T == 0:
        return path
    E_all = Z - BIAS
    chunks = _chunks(T)
    for c0 in range(0, len(chunks), VIT_BATCH):
        group = chunks[c0:c0 + VIT_BATCH]
        L = max(e - s for s, e, _a, _b in group)
        E = torch.full((len(group), L, J), -BIAS - 5.0)
        for i, (s, e, _a, _b) in enumerate(group):
            E[i, :e - s] = E_all[s:e]
        p = _viterbi_batch(E, device)
        for i, (s, e, a, b) in enumerate(group):
            path[a:b] = p[i, a - s:b - s]
    return path


def segments_from(path, Z, min_frames: int = MIN_SEGMENT_FRAMES):
    """Voiced runs of a path: start, end (frames), states, score (the sum of
    Z - BIAS along it — what the Viterbi path earned)."""
    import torch
    out = []
    T = path.numel()
    on = (path >= 0).tolist()
    t = 0
    while t < T:
        if not on[t]:
            t += 1
            continue
        s = t
        while t < T and on[t]:
            t += 1
        if t - s >= min_frames:
            st = path[s:t]
            sc = float((Z[torch.arange(s, t), st] - BIAS).sum())
            out.append({"start": s, "end": t, "states": st.tolist(),
                        "score": sc})
    return out


def same_voice(f_a: float, f_b: float) -> bool:
    """Two pitches that could be one voice: equal within TRACK_MATCH_RATIO,
    or a whole multiple (2, 3) or fraction of each other — at low levels a
    track can lock on a multiple of the true pitch."""
    if f_a <= 0 or f_b <= 0:
        return False
    for m in (1.0, 2.0, 3.0, 0.5, 1 / 3):
        r = f_a / (f_b * m)
        if 1 / TRACK_MATCH_RATIO <= r <= TRACK_MATCH_RATIO:
            return True
    return False


def group_segments(segs, grid: Grid):
    """Join a track's voiced runs into UTTERANCES: runs no more than
    GROUP_GAP_S apart whose pitch at the join is within GROUP_PITCH_RATIO.
    Speech breaks its voicing every syllable; the pitch carries on. An
    utterance's score is the sum of its runs' — the same rule is applied to
    the noise, so the false-alarm rate stays honest."""
    out = []
    gap = int(GROUP_GAP_S / HOP_S)
    for sgm in sorted(segs, key=lambda q: q["start"]):
        if out:
            last = out[-1]
            f_end = float(grid.f0[last["states"][-1]])
            f_new = float(grid.f0[sgm["states"][0]])
            r = f_new / f_end
            if (sgm["start"] - last["end"] <= gap and
                    1 / GROUP_PITCH_RATIO <= r <= GROUP_PITCH_RATIO):
                last["states"] = (last["states"] + [-1] * (sgm["start"]
                                                           - last["end"])
                                  + sgm["states"])
                last["end"] = sgm["end"]
                last["score"] += sgm["score"]
                last["parts"] += 1
                continue
        out.append(dict(sgm, parts=1, states=list(sgm["states"])))
    return out


def tracks_from(Z, grid: Grid, device: str):
    """Utterances (grouped voiced runs) of the best path through Z."""
    return group_segments(segments_from(viterbi(Z, grid, device), Z), grid)


# ---------------------------------------------------------------------------
# the hunt
# ---------------------------------------------------------------------------

def _suppress(g, grid: Grid, segs, median_value: float = 0.0):
    """Take a found track out of the whitened spectrum before the next hunt:
    its harmonic bins (±2 bins) set to the noise's typical value."""
    for seg in segs:
        for t, j in zip(range(seg["start"], seg["end"]), seg["states"]):
            if j < 0:
                continue
            f0 = float(grid.f0[j])
            k = 1
            while k * f0 < grid.top_hz:
                b = int(round(k * f0 / grid.df))
                lo, hi = max(0, b - 2), min(g.shape[1], b + 3)
                g[t, lo:hi] = median_value
                k += 1


def hunt_tracks(g, grid: Grid, device: str, null: Null, slopes,
                n_tracks: int, say=_say):
    """Up to n_tracks tracks, strongest first; each found track is taken out
    before the next is hunted. Returns (segments with their track number,
    Z of the first pass)."""
    work = g.clone()
    found, Z0 = [], None
    floor = null.threshold(FA_POSSIBLE_PER_HOUR)
    for n in range(n_tracks):
        _z, Z = evidence_z(work, grid, device, null, slopes)
        if Z0 is None:
            Z0 = Z
        segs = [s for s in tracks_from(Z, grid, device)
                if s["score"] >= floor]
        say(f"track {n + 1}: {len(segs)} stretch(es) above the possible line")
        if not segs:
            break
        for s in segs:
            s["track"] = n + 1
        found.extend(segs)
        _suppress(work, grid, segs, float(work.float().median()))
    return found, Z0


def _describe(seg, grid: Grid, lp, logN, null: Null) -> dict:
    """An utterance as the report shows it: times, pitch (None in its
    unvoiced gaps), score, false-alarm rate, status and an estimated level
    against the noise in 60 Hz – top."""
    f0s = [float(grid.f0[j]) if j >= 0 else None for j in seg["states"]]
    voiced = [f for f in f0s if f is not None]
    fa, extrap = null.rate(seg["score"])
    status = ("detected" if fa <= FA_DETECT_PER_HOUR else
              "possible" if fa <= FA_POSSIBLE_PER_HOUR else "below")
    est = level_estimate(lp, logN, grid, seg["start"], seg["end"], f0s)
    hp = harmonic_power(lp, logN, grid, seg["start"], seg["end"], f0s)
    srt = sorted(voiced) or [0.0]
    return {"track": seg.get("track", 1),
            "start_s": round(seg["start"] * HOP_S + WIN_S / 2, 3),
            "end_s": round(seg["end"] * HOP_S + WIN_S / 2, 3),
            "frames": seg["end"] - seg["start"],
            "voiced_frames": len(voiced), "parts": seg.get("parts", 1),
            "f0_median_hz": round(srt[len(srt) // 2], 1),
            "f0_min_hz": round(srt[0], 1), "f0_max_hz": round(srt[-1], 1),
            "f0_hz": [None if f is None else round(f, 1) for f in f0s],
            "score": round(seg["score"], 3),
            "fa_per_hour": (round(fa, 6) if math.isfinite(fa) else None),
            "fa_extrapolated": bool(extrap), "status": status,
            "level_est_db": (round(est, 2) if est is not None else None),
            "harm_power_db": (round(10 * math.log10(hp), 2) if hp else None)}


def level_estimate(lp, logN, grid: Grid, s: int, e: int, f0s) -> float | None:
    """Harmonic power above the noise along the track's voiced frames,
    against the noise power in the band 60 Hz to the harmonic top, in dB —
    uncorrected (the calibration measures this estimator's error and
    corrects it)."""
    hp = harmonic_power(lp, logN, grid, s, e, f0s)
    import torch
    N = torch.exp(logN.float())
    noise_band = float(N[int(F0_MIN / grid.df):].sum())
    if hp is None or noise_band <= 0:
        return None
    return 10.0 * math.log10(hp / noise_band)


def harmonic_power(lp, logN, grid: Grid, s: int, e: int, f0s) -> float | None:
    """Mean harmonic power above the noise per voiced frame (the spectrum's
    own units) — comparable between two files analysed alike, so the audit
    can say what share of a voice a residual holds."""
    import torch
    N = torch.exp(logN.float())
    total, n = 0.0, 0
    for t, f0 in zip(range(s, e), f0s):
        if f0 is None or t >= lp.shape[0]:
            continue
        P = torch.exp(lp[t].float())
        k = 1
        while k * f0 < grid.top_hz:
            b = int(round(k * f0 / grid.df))
            a0, a1 = max(0, b - 3), min(P.numel(), b + 4)
            total += float((P[a0:a1] - N[a0:a1]).clamp(min=0).sum())
            k += 1
        n += 1
    if n == 0 or total <= 0:
        return None
    return total / n


def free_stretches(path_on, T: int, min_frames: int):
    """Runs of frames with no track at all, at least min_frames long."""
    out, t = [], 0
    while t < T:
        if path_on[t]:
            t += 1
            continue
        s = t
        while t < T and not path_on[t]:
            t += 1
        if t - s >= min_frames:
            out.append((s, t))
    return out


def map_png(path, g, grid: Grid, segs) -> dict:
    """The whitened spectrogram to MAP_TOP_HZ, time across, with each
    track's pitch and next three harmonics drawn in its colour (detected
    bright, possible dim). Returns the axes: linear in frequency, row 0 at
    `top_hz`, the last row at 0 Hz."""
    import torch
    T = g.shape[0]
    top_bin = min(g.shape[1], int(MAP_TOP_HZ / grid.df) + 1)
    W = max(1, min(MAP_W, T))
    H = MAP_H
    cols = torch.linspace(0, max(0, T - 1), W).long()
    rows = torch.linspace(top_bin - 1, 0, H).long()
    if T == 0:
        img = torch.zeros((H, W, 3), dtype=torch.uint8)
    else:
        # max over the frames each column covers, so short events survive
        step = max(1, T // W)
        sel = []
        for c in cols.tolist():
            sel.append(g[c:min(T, c + step), :top_bin].float().max(dim=0)
                       .values)
        m = torch.stack(sel, 1)[rows]                       # [H, W]
        v = ((m - 0.5) / 3.5).clamp(0, 1)
        r = (v * 2.2 - 1.0).clamp(0, 1)
        gch = (v * 1.6 - 0.15).clamp(0, 1)
        b = (0.25 + 0.5 * v - (v - 0.7).clamp(min=0) * 0.6).clamp(0, 1)
        img = (torch.stack([r, gch, b], 2) * 255).to(torch.uint8)
    for seg in segs:
        colour = TRACK_COLOURS[(seg.get("track", 1) - 1) % len(TRACK_COLOURS)]
        dim = seg.get("status") != "detected"
        c = torch.tensor(colour, dtype=torch.float32) * (0.55 if dim else 1.0)
        c = c.to(torch.uint8)
        for t, j in zip(range(seg["start"], seg["end"]), seg["states"]):
            if j < 0:
                continue
            x = int(t * (W - 1) / max(1, T - 1))
            f0 = float(grid.f0[j])
            for k in (1, 2, 3, 4):
                f = k * f0
                if f >= MAP_TOP_HZ:
                    break
                y = int((1.0 - (f / grid.df) / max(1, top_bin - 1)) * (H - 1))
                for dy in ((-1, 0, 1) if k == 1 else (0,)):
                    yy = y + dy
                    if 0 <= yy < H:
                        img[yy, x] = c
    write_png(path, img)
    return {"width": int(W), "height": int(H),
            "top_hz": round(float(max(1, top_bin - 1) * grid.df), 1),
            "scale": "linear"}


def quiet_half(x, rate: int, block_s: float = 4.0):
    """The quietest half of the recording's blocks (by power), joined with
    short cross-fades — where a loud voice is least likely to be."""
    import torch
    L = max(1, int(block_s * rate))
    nblk = x.numel() // L
    if nblk < 4:
        return x
    pw = torch.stack([(x[i * L:(i + 1) * L] ** 2).mean()
                      for i in range(nblk)])
    keep = sorted(pw.argsort()[:max(2, nblk // 2)].tolist())
    fade = max(1, int(0.005 * rate))
    ramp = torch.linspace(0.0, 1.0, fade)
    parts = []
    for i in keep:
        seg = x[i * L:(i + 1) * L].clone()
        seg[:fade] *= ramp
        seg[-fade:] *= ramp.flip(0)
        parts.append(seg)
    return torch.cat(parts)


def excise(x, rate: int, grid: Grid, segs, pad_s: float = 0.3):
    """The recording with every found track's stretch (± pad_s) cut out,
    the pieces joined with 5 ms cross-fades — noise only, for the null."""
    import torch
    n = x.numel()
    drop = torch.zeros(n, dtype=torch.bool)
    for sgm in segs:
        a = max(0, int((sgm["start"] * HOP_S - pad_s) * rate))
        b = min(n, int((sgm["end"] * HOP_S + WIN_S + pad_s) * rate))
        drop[a:b] = True
    keep = (~drop).nonzero().squeeze(1)
    if keep.numel() == n:
        return x
    y = x[keep].clone()
    # cross-fade every join (where kept indices jump)
    jumps = ((keep[1:] - keep[:-1]) > 1).nonzero().squeeze(1).tolist()
    fade = max(1, int(0.005 * rate))
    ramp = torch.linspace(0.0, 1.0, fade)
    for j in jumps:
        a0 = max(0, j + 1 - fade)
        a1 = min(y.numel(), j + 1 + fade)
        if a1 - (j + 1) >= fade and (j + 1) - a0 >= fade:
            y[a0:j + 1] *= ramp.flip(0)
            y[j + 1:a1] *= ramp
    return y


def hunt_op(req) -> dict:
    """Hunt the recording: tracks, their false-alarm rates, the free
    stretches, and everything calibrate and audit need to repeat it."""
    import torch  # noqa: F401 — no torch fails here, before any work
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    p = req.get("params") or {}
    grid = Grid(rate, int(p.get("steps_per_octave", 36)),
                req.get("content_top_hz"), p.get("f0_min_hz"),
                p.get("f0_max_hz"))
    slopes = [float(s) for s in p.get("slopes", [0.0])]
    T = grid.frames(x.numel())
    _say(f"hunt: {x.numel() / rate:.1f} s at {rate} Hz, {T} frames, "
         f"{grid.f0.numel()} pitches, {len(slopes)} slope(s), on {device}")
    if T < 4 * SMOOTH_HALF + MIN_SEGMENT_FRAMES:
        raise ValueError("the recording is too short to hunt "
                         f"({x.numel() / rate:.2f} s)")
    lp = log_power(x, grid, device)
    logN = noise_log_mean(lp)
    g = whiten(lp, logN, grid)
    n_surr = max(2, int(p.get("surrogates", 4)))
    min_null_h = float(p.get("min_null_hours", 0.0))
    seed = int(p.get("seed", 1234))
    n_tracks = int(p.get("tracks", 1))
    # The null must model the NOISE. A loud voice left in the surrogates
    # leaves lines in each block's spectrum and inflates the noise scores,
    # hiding the faint tracks. So: a rough null from the quietest half of
    # the recording, a hunt with it, everything it finds cut out, the null
    # rebuilt from what is left — and once more.
    keep = quiet_half(x, rate)
    null = build_null(keep, logN, grid, device, slopes, min(2, n_surr), seed,
                      say=lambda _l: None)
    keep = x
    excised = 0.0
    for _round in range(2):
        segs, _Z = hunt_tracks(g, grid, device, null, slopes, n_tracks,
                               say=lambda _l: None)
        if not segs:
            break
        cut = excise(x, rate, grid, segs)
        if cut.numel() < max(10 * rate, x.numel() // 4):
            _say("null: too little of the recording is free of tracks to "
                 "cut them out — the null keeps them (conservative)")
            break
        keep = cut
        excised = (x.numel() - cut.numel()) / rate
        null = build_null(keep, logN, grid, device, slopes, min(2, n_surr),
                          seed, say=lambda _l: None)
    keep_h = keep.numel() / rate / 3600.0
    if keep_h > 0 and n_surr * keep_h < min_null_h:
        n_surr = min(int(p.get("max_surrogates", 400)),
                     max(n_surr, math.ceil(min_null_h / keep_h)))
    null = build_null(keep, logN, grid, device, slopes, n_surr, seed)
    _say(f"null: {len(null.scores)} noise tracks in {null.hours * 60:.1f} "
         f"min of surrogate noise ({excised:.1f} s of tracks cut out first);"
         f" detect line {null.threshold(FA_DETECT_PER_HOUR):.1f}, possible "
         f"line {null.threshold(FA_POSSIBLE_PER_HOUR):.1f}")
    segs, Z0 = hunt_tracks(g, grid, device, null, slopes, n_tracks)
    described = []
    for s in sorted(segs, key=lambda s: s["start"]):
        d = _describe(s, grid, lp, logN, null)
        s["status"] = d["status"]
        described.append(d)
    on = [False] * T
    for s in segs:
        for t in range(max(0, s["start"] - 50), min(T, s["end"] + 50)):
            on[t] = True
    free = free_stretches(on, T, int((PROBE_S + 1.0) / HOP_S))
    map_axes = map_png(req["png"], g, grid, segs) if req.get("png") else None
    tracks = {}
    for d in described:
        if d["status"] == "below":
            continue
        tr = tracks.setdefault(d["track"], {"track": d["track"],
                                            "detected_s": 0.0,
                                            "possible_s": 0.0, "f0": []})
        tr[d["status"] + "_s"] += d["end_s"] - d["start_s"]
        tr["f0"].extend(f for f in d["f0_hz"] if f is not None)
    track_rows = []
    for tr in tracks.values():
        f = sorted(tr.pop("f0"))
        tr["f0_median_hz"] = round(f[len(f) // 2], 1) if f else None
        tr["f0_p10_hz"] = round(f[len(f) // 10], 1) if f else None
        tr["f0_p90_hz"] = round(f[(9 * len(f)) // 10], 1) if f else None
        tr["detected_s"] = round(tr["detected_s"], 2)
        tr["possible_s"] = round(tr["possible_s"], 2)
        track_rows.append(tr)
    return {"rate": rate, "duration_s": round(x.numel() / rate, 3),
            "frames": T, "device": device,
            "grid": {"win": grid.win, "hop": grid.hop, "n_fft": grid.n_fft,
                     "bins": grid.nb, "top_hz": round(grid.top_hz, 1),
                     "steps_per_octave": grid.spo,
                     "f0_min_hz": round(grid.lo, 2),
                     "f0_max_hz": round(grid.hi, 2)},
            "map": map_axes,
            "slopes": slopes, "log_noise": [round(float(v), 5)
                                            for v in logN],
            "null": null.as_dict(),
            "thresholds": {"detect_score": round(null.threshold(
                FA_DETECT_PER_HOUR), 4),
                "possible_score": round(null.threshold(FA_POSSIBLE_PER_HOUR),
                                        4),
                "detect_fa_per_hour": FA_DETECT_PER_HOUR,
                "possible_fa_per_hour": FA_POSSIBLE_PER_HOUR},
            "segments": [d for d in described if d["status"] != "below"],
            "tracks": sorted(track_rows, key=lambda t: t["track"]),
            "free": [[round(a * HOP_S, 3), round(b * HOP_S, 3)]
                     for a, b in free],
            "surrogates": n_surr, "excised_s": round(excised, 2),
            "versions": _versions(device)}


def _versions(device: str) -> dict:
    import torch
    out = {"torch": torch.__version__, "python": sys.version.split()[0],
           "device": device}
    if device == "cuda":
        try:
            out["gpu"] = torch.cuda.get_device_name(0)
        except Exception:                                 # noqa: BLE001
            pass
    return out


# ---------------------------------------------------------------------------
# hunting a short excerpt against the file's own noise and null
# ---------------------------------------------------------------------------

class Context:
    """What a hunt over THIS file established, rebuilt from its response, so
    calibrate and audit hunt excerpts exactly as the file was hunted."""

    def __init__(self, hunt: dict, rate: int):
        import torch
        gr = hunt["grid"]
        self.grid = Grid(rate, int(gr["steps_per_octave"]), gr["top_hz"] + 1,
                         gr.get("f0_min_hz"), gr.get("f0_max_hz"))
        self.logN = torch.tensor(hunt["log_noise"])
        self.null = Null.from_dict(hunt["null"])
        self.slopes = [float(s) for s in hunt["slopes"]]
        self.detect = float(hunt["thresholds"]["detect_score"])
        self.possible = float(hunt["thresholds"]["possible_score"])


def hunt_excerpt(x, ctx: Context, device: str):
    """(segments, lp, z, Z) of one excerpt, whitened by the FILE's noise."""
    lp = log_power(x, ctx.grid, device)
    g = whiten(lp, ctx.logN, ctx.grid)
    z, Z = evidence_z(g, ctx.grid, device, ctx.null, ctx.slopes)
    segs = tracks_from(Z, ctx.grid, device)
    return segs, lp, z, Z


# ---------------------------------------------------------------------------
# probes: a voice-like sound with a known pitch
# ---------------------------------------------------------------------------

VOWELS = ((730, 1090, 2440), (270, 2290, 3010), (300, 870, 2240),
          (530, 1840, 2480), (570, 840, 2410), (660, 1720, 2410))


def voiced_probe(rate: int, seconds: float, f0_base: float, seed: int):
    """(signal, f0 per hop, voiced per hop): syllables of a harmonic voice
    with a natural pitch contour, vowels through three formants, short
    unvoiced gaps — a test sound whose pitch is known exactly."""
    import torch
    gen = torch.Generator().manual_seed(int(seed))
    n = int(seconds * rate)
    t = torch.arange(n) / rate
    ph1 = float(torch.rand(1, generator=gen)) * 6.28
    f0 = f0_base * 2.0 ** (0.12 * torch.sin(2 * math.pi * 0.8 * t + ph1)
                           + 0.05 * torch.sin(2 * math.pi * 2.1 * t)
                           - 0.08 * t / seconds)
    phase = 2 * math.pi * torch.cumsum(f0, 0) / rate
    # syllables: voiced 160–320 ms, gaps 50–120 ms
    env = torch.zeros(n)
    vowel_at = torch.zeros(n, dtype=torch.long)
    pos, v = int(0.05 * rate), 0
    while pos < n:
        dur = int((0.16 + 0.16 * float(torch.rand(1, generator=gen))) * rate)
        gap = int((0.05 + 0.07 * float(torch.rand(1, generator=gen))) * rate)
        e = min(n, pos + dur)
        if e - pos > 10:
            w = torch.hann_window(e - pos, periodic=False) ** 0.5
            env[pos:e] = w
            vowel_at[pos:e] = int(torch.randint(0, len(VOWELS), (1,),
                                                generator=gen))
        pos = e + gap
        v += 1
    y = torch.zeros(n)
    kmax = int((rate / 2) / float(f0.min()))
    for k in range(1, min(kmax, 60) + 1):
        fk = k * f0
        amp = torch.zeros(n)
        for vi, (F1, F2, F3) in enumerate(VOWELS):
            mask = vowel_at == vi
            if not mask.any():
                continue
            a = (1.0 / (1 + ((fk - F1) / 90.0) ** 2)
                 + 0.6 / (1 + ((fk - F2) / 120.0) ** 2)
                 + 0.3 / (1 + ((fk - F3) / 160.0) ** 2) + 0.02)
            amp = torch.where(mask, a, amp)
        amp = amp * (k ** -0.7) * (fk < rate / 2 - 100).float()
        y += amp * torch.sin(k * phase)
    y = y * env
    y = y / y.abs().max().clamp(min=1e-9) * 0.5
    hop = int(round(rate * HOP_S))
    win = int(round(rate * WIN_S))
    nf = max(0, (n - win) // hop + 1)
    centres = (torch.arange(nf) * hop + win // 2).clamp(max=n - 1)
    return y, f0[centres], env[centres] > 0.5


def _band_power(x, ctx: Context, device: str, voiced=None) -> float:
    """Mean power in the band F0_MIN – harmonic top over the frames (the
    voiced ones when given), from the same spectrum the hunt uses."""
    import torch
    lp = log_power(x, ctx.grid, device).float()
    lo = int(F0_MIN / ctx.grid.df)
    p = torch.exp(lp[:, lo:]).sum(dim=1)
    if voiced is not None:
        v = voiced[:p.numel()]
        if v.any():
            p = p[:v.numel()][v]
    return float(p.mean()) if p.numel() else 0.0


# ---------------------------------------------------------------------------
# ESTOI (Jensen & Taal 2016), after the reference implementation pystoi (MIT)
# ---------------------------------------------------------------------------

def _resample(x, src: int, dst: int):
    """Band-limited resampling through the FFT (fine for short phrases)."""
    import torch
    if src == dst:
        return x
    n = x.numel()
    m = int(round(n * dst / src))
    X = torch.fft.rfft(x.double())
    keep = min(X.numel(), m // 2 + 1)
    Y = torch.zeros(m // 2 + 1, dtype=X.dtype)
    Y[:keep] = X[:keep]
    return (torch.fft.irfft(Y, n=m) * (m / n)).float()


def _thirdoct(fs: int, nfft: int, num_bands: int = 15,
              min_freq: float = 150.0):
    import torch
    f = torch.linspace(0, fs, nfft + 1)[:nfft // 2 + 1]
    obm = torch.zeros(num_bands, f.numel())
    for i in range(num_bands):
        lo = min_freq * 2.0 ** ((2 * i - 1) / 6)
        hi = min_freq * 2.0 ** ((2 * i + 1) / 6)
        a = int(torch.argmin((f - lo) ** 2))
        b = int(torch.argmin((f - hi) ** 2))
        obm[i, a:b] = 1.0
    return obm


def estoi(clean, degraded, rate: int) -> float | None:
    """Extended STOI of `degraded` against `clean` (same length): 0 = no
    intelligibility predicted, 1 = as clean."""
    import torch
    N_FRAME, NFFT, N_SEG, DYN = 256, 512, 30, 40.0
    x = _resample(clean.float(), rate, ESTOI_FS).double()
    y = _resample(degraded.float(), rate, ESTOI_FS).double()
    n = min(x.numel(), y.numel())
    x, y = x[:n], y[:n]
    hop = N_FRAME // 2
    w = torch.hann_window(N_FRAME + 2, periodic=False, dtype=torch.float64)[1:-1]
    starts = list(range(0, n - N_FRAME, hop))
    if len(starts) < N_SEG:
        return None
    xf = torch.stack([w * x[i:i + N_FRAME] for i in starts])
    yf = torch.stack([w * y[i:i + N_FRAME] for i in starts])
    en = 20 * torch.log10(xf.norm(dim=1) + 2.2e-16)
    keep = (en.max() - DYN - en) < 0
    xf, yf = xf[keep], yf[keep]

    def ola(frames):
        L = (frames.shape[0] - 1) * hop + N_FRAME
        out = torch.zeros(L, dtype=torch.float64)
        for i in range(frames.shape[0]):
            out[i * hop:i * hop + N_FRAME] += frames[i]
        return out

    xs, ys = ola(xf), ola(yf)

    def spec(s):
        st = [torch.fft.rfft(w * s[i:i + N_FRAME], n=NFFT)
              for i in range(0, s.numel() - N_FRAME, hop)]
        return torch.stack(st).T if st else torch.zeros(NFFT // 2 + 1, 0)

    X, Y = spec(xs), spec(ys)
    if X.shape[1] < N_SEG:
        return None
    obm = _thirdoct(ESTOI_FS, NFFT).double()
    xt = torch.sqrt(obm @ (X.abs() ** 2))
    yt = torch.sqrt(obm @ (Y.abs() ** 2))
    segs_x = xt.unfold(1, N_SEG, 1).permute(1, 0, 2)    # [M, J, N]
    segs_y = yt.unfold(1, N_SEG, 1).permute(1, 0, 2)

    def norm(a):
        a = a - a.mean(dim=2, keepdim=True)
        a = a / (a.norm(dim=2, keepdim=True) + 2.2e-16)
        a = a - a.mean(dim=1, keepdim=True)
        a = a / (a.norm(dim=1, keepdim=True) + 2.2e-16)
        return a

    xn, yn = norm(segs_x), norm(segs_y)
    return float((xn * yn).sum() / N_SEG / xn.shape[0])


# ---------------------------------------------------------------------------
# calibrate: the file's own CEP
# ---------------------------------------------------------------------------

def _match(segs, ctx: Context, truth_f0, truth_on, offset: int,
           need: float) -> dict | None:
    """The best segment over the probe (frames offset..): which share of
    the probe's voiced frames it tracks within TRACK_MATCH_RATIO."""
    best = None
    n_on = int(truth_on.sum())
    if n_on == 0:
        return None
    for s in segs:
        if s["score"] < need:
            continue
        hit = 0
        for t, j in zip(range(s["start"], s["end"]), s["states"]):
            k = t - offset
            if j >= 0 and 0 <= k < truth_on.numel() and bool(truth_on[k]):
                if same_voice(float(ctx.grid.f0[j]), float(truth_f0[k])):
                    hit += 1
        share = hit / n_on
        if best is None or share > best["share"]:
            best = {"share": share, "seg": s}
    return best


def calibrate_op(req) -> dict:
    """Inject probes into the file's voice-free stretches at stepped levels
    and hunt each mixture as the file was hunted."""
    import torch
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    ctx = Context(req["hunt"], rate)
    p = req.get("params") or {}
    levels = [float(v) for v in p.get("levels", [0, -5, -10, -15, -20])]
    n_synth = int(p.get("probes_per_level", 2))
    phrases = [read_wav(f)[0] for f in req.get("phrases") or []]
    n_real = int(p.get("phrases_per_level", 1)) if phrases else 0
    seed = int(p.get("seed", 4321))
    gen = torch.Generator().manual_seed(seed)
    # the synthetic probes' pitch: 90-250 Hz, or (Move 7) one speaker's range
    f_lo, f_hi = (float(v) for v in p.get("probe_f0_hz") or (90.0, 250.0))
    free = [(int(a / HOP_S), int(b / HOP_S))
            for a, b in req.get("free") or req["hunt"]["free"]]
    ctx_n = int(INJECT_CONTEXT_S * rate)
    probe_n = int(PROBE_S * rate)
    if not free:
        return {"levels": [], "note": "no stretch of the recording is free "
                "of tracks for long enough to inject into — no calibration"}
    rows = []
    jobs = []
    for li, lvl in enumerate(levels):
        for r in range(n_synth + n_real):
            jobs.append((lvl, "synthetic" if r < n_synth else "phrase", r))
    _say(f"calibrate: {len(jobs)} injections over {len(levels)} levels")
    noise_band = float(torch.exp(ctx.logN.float())[int(F0_MIN /
                                                       ctx.grid.df):].sum())
    det = {lvl: [] for lvl in levels}
    est_pairs = []
    for n, (lvl, kind, r) in enumerate(jobs):
        # where: a random free stretch long enough, a random point in it
        a, b = free[int(torch.randint(0, len(free), (1,), generator=gen))]
        lo = a * ctx.grid.hop
        hi = b * ctx.grid.hop - probe_n
        start = lo if hi <= lo else int(torch.randint(lo, hi, (1,),
                                                      generator=gen))
        if kind == "synthetic":
            f0b = f_lo + (f_hi - f_lo) * float(torch.rand(1, generator=gen))
            probe, f0_true, on = voiced_probe(rate, PROBE_S, f0b,
                                              seed + 7 * n + 1)
            clean_ref = None
        else:
            ph = phrases[int(torch.randint(0, len(phrases), (1,),
                                           generator=gen))]
            probe = ph[:probe_n]
            if probe.numel() < probe_n:
                probe = torch.nn.functional.pad(probe,
                                                (0, probe_n - probe.numel()))
            f0_true, on = None, None
            clean_ref = probe
        # level: probe band power over its voiced frames vs the noise band
        pw = _band_power(probe, ctx, device, on)
        if pw <= 0:
            continue
        gain = math.sqrt(10 ** (lvl / 10.0) * noise_band / pw)
        s0 = max(0, start - ctx_n)
        s1 = min(x.numel(), start + probe_n + ctx_n)
        mix = x[s0:s1].clone()
        k0 = start - s0
        mix[k0:k0 + probe_n] += gain * probe[:min(probe_n, mix.numel() - k0)]
        segs, lp, z, Z = hunt_excerpt(mix, ctx, device)
        offset = k0 // ctx.grid.hop
        row = {"level_db": lvl, "kind": kind}
        if kind == "synthetic":
            m = _match(segs, ctx, f0_true, on, offset, ctx.detect)
            hitd = bool(m and m["share"] >= 0.3)
            mp = _match(segs, ctx, f0_true, on, offset, ctx.possible)
            row.update(detected=hitd, possible=bool(mp and mp["share"] >= 0.3))
            if mp and mp["share"] >= 0.3:
                s = mp["seg"]
                f0s = [float(ctx.grid.f0[j]) if j >= 0 else None
                       for j in s["states"]]
                est = level_estimate(lp, ctx.logN, ctx.grid, s["start"],
                                     s["end"], f0s)
                if est is not None:
                    # the estimate counts the probe's power over its voiced
                    # frames only where tracked; compare like with like
                    est_pairs.append((est, lvl))
        else:
            # real speech: any confident track overlapping the phrase
            span = range(offset, offset + probe_n // ctx.grid.hop)
            hit = [s for s in segs if s["score"] >= ctx.detect and
                   s["end"] > span.start and s["start"] < span.stop]
            hitp = [s for s in segs if s["score"] >= ctx.possible and
                    s["end"] > span.start and s["start"] < span.stop]
            row.update(detected=bool(hit), possible=bool(hitp))
            e = estoi(clean_ref * gain, mix[k0:k0 + probe_n], rate)
            row["estoi_raw"] = None if e is None else round(e, 4)
        det[lvl].append(row)
        if (n + 1) % 10 == 0 or n + 1 == len(jobs):
            _say(f"calibrate: {n + 1} of {len(jobs)}")
    for lvl in levels:
        rs = det[lvl]
        syn = [r for r in rs if r["kind"] == "synthetic"]
        real = [r for r in rs if r["kind"] == "phrase"]
        es = [r["estoi_raw"] for r in real if r.get("estoi_raw") is not None]
        rows.append({"level_db": lvl, "n": len(rs),
                     "detected": sum(r["detected"] for r in rs),
                     "possible": sum(r["possible"] for r in rs),
                     "pd": round(sum(r["detected"] for r in rs)
                                 / max(1, len(rs)), 4),
                     "pd_synthetic": (round(sum(r["detected"] for r in syn)
                                            / len(syn), 4) if syn else None),
                     "pd_phrase": (round(sum(r["detected"] for r in real)
                                         / len(real), 4) if real else None),
                     "estoi_raw": (round(sum(es) / len(es), 4) if es
                                   else None)})
    offset = None
    if est_pairs:
        d = sorted(e - t for e, t in est_pairs)
        offset = d[len(d) // 2]
    return {"levels": rows,
            "pd50_db": _crossing(rows, 0.5), "pd90_db": _crossing(rows, 0.9),
            "estoi_half_db": _estoi_crossing(rows, 0.5),
            "level_offset_db": (round(offset, 2) if offset is not None
                                else None),
            "level_pairs": len(est_pairs), "injections": len(jobs),
            "phrases": len(phrases), "device": device}


def _crossing(rows, target: float):
    """The lowest level (dB) at which the share found is still >= target,
    interpolated between the levels either side; None if never reached."""
    rs = sorted(rows, key=lambda r: -r["level_db"])
    prev = None
    for r in rs:
        if r["n"] == 0:
            continue
        if r["pd"] < target:
            if prev is None:
                return None
            a, b = prev, r
            if a["pd"] == b["pd"]:
                return a["level_db"]
            f = (a["pd"] - target) / (a["pd"] - b["pd"])
            return round(a["level_db"] + f * (b["level_db"] - a["level_db"]),
                         2)
        prev = r
    return prev["level_db"] if prev else None


def _estoi_crossing(rows, target: float):
    rs = sorted([r for r in rows if r.get("estoi_raw") is not None],
                key=lambda r: -r["level_db"])
    prev = None
    for r in rs:
        if r["estoi_raw"] < target:
            if prev is None:
                return None
            f = (prev["estoi_raw"] - target) / max(1e-9, prev["estoi_raw"]
                                                   - r["estoi_raw"])
            return round(prev["level_db"] + f * (r["level_db"]
                                                 - prev["level_db"]), 2)
        prev = r
    return prev["level_db"] if prev else None


# ---------------------------------------------------------------------------
# audit: what each restoration removed, and whether it made anything
# ---------------------------------------------------------------------------

def path_support(z, grid: Grid, rho: float, start_s: float, f0s,
                 multiples=(1.0, 0.5, 2.0, 1 / 3, 3.0)) -> float:
    """The input's per-frame evidence summed along an exact pitch path
    (times from start_s, one pitch per hop), in noise standard deviations
    with frame correlation allowed for: no search, so far more sensitive
    than finding the path. The best of the path at its own pitch and at
    whole multiples and fractions of it (a track can lock on a multiple of
    the true pitch in one file and not in the other)."""
    T = z.shape[0]
    t0 = int(round((start_s - WIN_S / 2) / HOP_S))
    best = None
    for m in multiples:
        tot, n = 0.0, 0
        for i, f in enumerate(f0s):
            t = t0 + i
            if f is None or not 0 <= t < T:
                continue
            fm = f * m
            if not grid.lo <= fm <= grid.hi:
                continue
            tot += float(z[t, grid.state_of(fm)])
            n += 1
        if n >= max(1, len([f for f in f0s if f is not None]) // 2):
            v = tot / math.sqrt(n * max(1.0, rho))
            best = v if best is None else max(best, v)
    return 0.0 if best is None else best


def _own_hunt(x, rate: int, params: dict, device: str, seed: int):
    """Hunt a file (a residual or an output) against ITS OWN noise and null."""
    grid = Grid(rate, int(params.get("steps_per_octave", 36)))
    slopes = [float(s) for s in params.get("slopes", [0.0])]
    lp = log_power(x, grid, device)
    logN = noise_log_mean(lp)
    g = whiten(lp, logN, grid)
    null = build_null(x, logN, grid, device, slopes,
                      max(2, int(params.get("audit_surrogates", 2))), seed,
                      say=lambda _l: None)
    segs, _Z = hunt_tracks(g, grid, device, null, slopes, 1,
                           say=lambda _l: None)
    return [_describe(s, grid, lp, logN, null) for s in segs], grid


def _overlaps(seg, others) -> dict | None:
    for o in others:
        if o["end_s"] <= seg["start_s"] or o["start_s"] >= seg["end_s"]:
            continue
        if same_voice(seg["f0_median_hz"], o["f0_median_hz"]):
            return o
    return None


def _reference_for(x, rate: int, r2: int, tgt: dict):
    """The input at the residual's rate: the input itself, or the
    resampled copy the chain was measured against (input16k.wav)."""
    if r2 == rate:
        return x
    if tgt.get("reference"):
        y, rr = read_wav(tgt["reference"])
        if rr == r2:
            return y
    return None


def _lost_share(kept, seg) -> float | None:
    """The share of an input track's harmonic power its output lost, along
    the track's own path: 1 - P(output) / P(input), each above its own
    noise, measured the same way."""
    grid, lp_ref, ln_ref, lp_out, ln_out = kept
    s0 = int(round((float(seg["start_s"]) - WIN_S / 2) / HOP_S))
    f0s = seg.get("f0_hz") or []
    e0 = s0 + len(f0s)
    p_in = harmonic_power(lp_ref, ln_ref, grid, s0, e0, f0s)
    if not p_in:
        return None
    p_out = harmonic_power(lp_out, ln_out, grid, s0, e0, f0s) or 0.0
    return max(0.0, min(1.0, 1.0 - p_out / p_in))


def audit_op(req) -> dict:
    import torch  # noqa: F401 — no torch fails here, before any work
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    ctx = Context(req["hunt"], rate)
    params = req.get("params") or {}
    lp = log_power(x, ctx.grid, device)
    g = whiten(lp, ctx.logN, ctx.grid)
    z, _Z = evidence_z(g, ctx.grid, device, ctx.null, ctx.slopes)
    input_segs = req["hunt"].get("segments") or []
    out = []
    for n, tgt in enumerate(req.get("targets") or []):
        row = {"id": tgt["id"], "removed": [], "removed_possible": [],
               "made": [], "revealed": [], "kept": 0,
               "supported": 0, "residual_tracks": 0, "output_tracks": 0}
        if tgt.get("residual"):
            y, r2 = read_wav(tgt["residual"])
            ref = _reference_for(x, rate, r2, tgt)
            kept = None
            if ref is not None:
                m = min(ref.numel(), y.numel())
                gr = ctx.grid if r2 == rate else \
                    Grid(r2, ctx.grid.spo, ctx.grid.top_hz + 1, ctx.grid.lo,
                         ctx.grid.hi)
                lp_ref = lp if r2 == rate else log_power(ref[:m], gr, device)
                ln_ref = ctx.logN if r2 == rate else noise_log_mean(lp_ref)
                lp_out = log_power(ref[:m] - y[:m], gr, device)
                kept = (gr, lp_ref, ln_ref, lp_out, noise_log_mean(lp_out))
            segs, _grid = _own_hunt(y, r2, params, device, 777 + n)
            row["residual_tracks"] = len(segs)
            for s in segs:
                if s["status"] == "below":
                    continue
                # the residual's track must BE one of the input's voice
                # tracks: the same pitch over the same time. (Evidence along
                # its path in the input proves nothing here: a denoiser's
                # residual is the input's own noise, so any chance pattern
                # in it is in the input too.)
                match = _overlaps(s, input_segs)
                if match is None:
                    continue
                item = {"start_s": s["start_s"], "end_s": s["end_s"],
                        "f0_median_hz": s["f0_median_hz"],
                        "status": s["status"],
                        "input_track": match["track"],
                        "input_status": match.get("status")}
                if kept is not None:
                    # what the OUTPUT lost along the voice's track — a
                    # residual alone cannot tell removal from a phase shift
                    share = _lost_share(kept, match)
                    if share is None or share < REMOVED_MIN_SHARE:
                        row["kept"] += 1
                        continue
                    item["share_db"] = round(10 * math.log10(share), 1)
                    item["share_basis"] = "output"
                else:
                    # no reference at the residual's rate: the share of the
                    # voice's harmonic power the residual holds
                    a, b = s.get("harm_power_db"), match.get("harm_power_db")
                    if a is not None and b is not None:
                        item["share_db"] = round(a - b, 1)
                    item["share_basis"] = "residual"
                if s["status"] == "detected":
                    row["removed"].append(item)
                else:
                    row["removed_possible"].append(item)
        if tgt.get("output"):
            y, r2 = read_wav(tgt["output"])
            segs, _grid = _own_hunt(y, r2, params, device, 999 + n)
            row["output_tracks"] = len(segs)
            for s in segs:
                if s["status"] != "detected":
                    continue
                match = _overlaps(s, input_segs)
                item = {"start_s": s["start_s"], "end_s": s["end_s"],
                        "f0_median_hz": s["f0_median_hz"]}
                if match is not None:
                    if match.get("status") == "possible":
                        # the input only suspected it; this output makes it
                        # clear
                        item["input_track"] = match["track"]
                        row["revealed"].append(item)
                    else:
                        row["supported"] += 1
                    continue
                # no input track there: is there ANY trace along this exact
                # pitch path in the input? A linear filter cannot create
                # harmonic evidence; none at all means this output made it.
                sup = path_support(z, ctx.grid, ctx.null.rho, s["start_s"],
                                   s["f0_hz"])
                item["input_support"] = round(sup, 2)
                if sup < SUPPORT_NONE:
                    row["made"].append(item)
                else:
                    row["supported"] += 1
        out.append(row)
        _say(f"audit: {tgt['id']} — removed {len(row['removed'])}, made "
             f"{len(row['made'])}, revealed {len(row['revealed'])}")
    return {"targets": out, "device": device}


# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# WAV out — the extracted voice and the probe (the same format as
# restore_worker.py writes)
# ---------------------------------------------------------------------------

def write_wav(path, x, rate: int) -> None:
    """Mono IEEE float32 WAV (format 3, with the fact chunk)."""
    import torch
    x = torch.as_tensor(x).detach().float().cpu().contiguous()
    pcm = x.numpy().tobytes()
    fmt = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
            + struct.pack("<II", 4, x.numel()) + b"data"
            + struct.pack("<I", len(pcm)) + pcm)
    _write_bytes(path, b"RIFF" + struct.pack("<I", len(body)) + body)


# ---------------------------------------------------------------------------
# Move 2: the voice pulled out along its pitch track, in warped time
# ---------------------------------------------------------------------------

def voiced_runs(seg) -> list:
    """[(frame times s, f0 Hz)] of one segment: its voiced frames, unvoiced
    gaps up to GAP_FILL_FRAMES bridged (log-linear), longer ones split it."""
    import torch
    t0 = float(seg["start_s"])
    runs, cur, gap = [], [], []
    for i, f in enumerate(seg.get("f0_hz") or []):
        t = t0 + i * HOP_S
        if f is None:
            if cur:
                gap.append(t)
            continue
        if gap:
            if len(gap) <= GAP_FILL_FRAMES:
                ta, fa = cur[-1]
                for tg in gap:
                    a = (tg - ta) / (t - ta)
                    cur.append((tg, math.exp((1 - a) * math.log(fa)
                                             + a * math.log(f))))
            else:
                runs.append(cur)
                cur = []
            gap = []
        cur.append((t, float(f)))
    if cur:
        runs.append(cur)
    return [(torch.tensor([a for a, _ in r], dtype=torch.float64),
             torch.tensor([b for _, b in r], dtype=torch.float64))
            for r in runs if len(r) >= MIN_SEGMENT_FRAMES]


def sample_f0(times, f0, n0: int, n1: int, rate: int):
    """The pitch at every sample n0..n1-1: linear between frame centres,
    held beyond the ends."""
    import torch
    t = torch.arange(n0, n1, dtype=torch.float64) / rate
    if times.numel() == 1:
        return torch.full_like(t, float(f0[0]))
    idx = torch.searchsorted(times, t).clamp(1, times.numel() - 1)
    ta, tb = times[idx - 1], times[idx]
    a = ((t - ta) / (tb - ta)).clamp(0, 1)
    return f0[idx - 1] + a * (f0[idx] - f0[idx - 1])


def _noise_at(ctx: Context):
    """The file's noise power at any frequency (from the hunt's spectrum)."""
    import torch
    N = torch.exp(ctx.logN.double())

    def at(freqs):
        b = (freqs / ctx.grid.df).round().long().clamp(0, N.numel() - 1)
        return N[b].clamp(min=1e-30)
    return at


def _voice_weights(freqs, noise_at):
    """A harmonic's weight in the pitch refinement: what a voice puts there
    (flat to the knee, falling above, as in the hunt) over the noise."""
    import torch
    v = torch.where(freqs < WEIGHT_KNEE_HZ, torch.ones_like(freqs),
                    (WEIGHT_KNEE_HZ / freqs.clamp(min=1.0)) ** 1.5)
    return v / noise_at(freqs)


def refine_pitch(x, rate: int, times, f0, noise_at, top_hz: float,
                 budget: float = REFINE_BUDGET):
    """The track's pitch refined: the scale of the local contour that
    maximises the coherent, noise-weighted energy at its harmonics over a
    short window, at every REFINE_STRIDE-th frame; three passes from ±3% to
    ±0.2%, the contour smoothed between (median of three refined frames,
    then 1-2-1). The hunt's grid is 1/36 octave (2%) — far too coarse to
    integrate a phase over six cycles of the twentieth harmonic."""
    import torch
    T = times.numel()
    f0 = f0.clone()
    if rate > REFINE_RATE:
        # the pitch needs nothing above 5 kHz: refine on this run's stretch
        # resampled to REFINE_RATE (three times faster at 48 kHz)
        pad = 0.2 + REFINE_MIN_CYCLES / float(f0.min())
        a = max(0, int((float(times[0]) - pad) * rate))
        b = min(x.numel(), int((float(times[-1]) + pad) * rate) + 1)
        piece = _resample(x[a:b].float(), rate, REFINE_RATE)
        return refine_pitch(piece, REFINE_RATE, times - a / rate, f0,
                            noise_at, min(top_hz, 0.45 * REFINE_RATE), budget)
    centres = (times * rate).round().long()
    # refined at every REFINE_STRIDE-th frame (and the last); the frames
    # between follow by interpolation of the log pitch
    pick = list(range(0, T, REFINE_STRIDE))
    if pick[-1] != T - 1:
        pick.append(T - 1)
    pick = torch.tensor(pick)
    for span, steps in zip(REFINE_SPANS, REFINE_STEPS):
        half = int(rate * max(REFINE_MIN_S,
                              REFINE_MIN_CYCLES / float(f0.min())) / 2)
        win = torch.hann_window(2 * half + 1, periodic=False,
                                dtype=torch.float64).float()
        K = max(1, int(top_hz / (float(f0.max()) * (1 + span))))
        cands = 1.0 + torch.linspace(-span, span, steps, dtype=torch.float64)
        ks = torch.arange(1, K + 1, dtype=torch.float64)
        lo_all = int(centres.min()) - half
        hi_all = int(centres.max()) + half + 1
        Phi = 2 * math.pi * torch.cumsum(
            sample_f0(times, f0, lo_all, hi_all, rate), 0) / rate
        xpad = torch.zeros(hi_all - lo_all, dtype=torch.float32)
        a, b = max(0, lo_all), min(x.numel(), hi_all)
        if b > a:
            xpad[a - lo_all:b - lo_all] = x[a:b].float()
        mult = (cands[:, None] * ks[None, :]).reshape(-1).float()
        chunk = max(1, int(budget / (mult.numel() * (2 * half + 1))))
        P_ = pick.numel()
        scale = torch.ones(P_, dtype=torch.float64)
        offs = torch.arange(-half, half + 1)
        cp = centres[pick]
        fp = f0[pick]
        for s in range(0, P_, chunk):
            e = min(P_, s + chunk)
            c = cp[s:e] - lo_all
            idx = c[:, None] + offs[None, :]
            ph = (Phi[idx] - Phi[c][:, None]).float()       # [B, N]
            xw = xpad[idx] * win[None, :]
            arg = mult[None, :, None] * ph[:, None, :]       # [B, SK, N]
            re = (torch.cos(arg) * xw[:, None, :]).sum(-1)
            im = (torch.sin(arg) * xw[:, None, :]).sum(-1)
            P = (re ** 2 + im ** 2).double().reshape(e - s, steps, K)
            wts = _voice_weights(ks[None, :] * fp[s:e, None], noise_at)
            E = (P * wts[:, None, :]).sum(-1)                # [B, S]
            jc = E.argmax(1).clamp(1, steps - 2)
            y0 = E.gather(1, (jc - 1)[:, None])[:, 0]
            y1 = E.gather(1, jc[:, None])[:, 0]
            y2 = E.gather(1, (jc + 1)[:, None])[:, 0]
            den = y0 - 2 * y1 + y2
            d = torch.where(den.abs() > 1e-30, 0.5 * (y0 - y2) / den,
                            torch.zeros_like(den)).clamp(-1, 1)
            scale[s:e] = cands[jc] + d * float(cands[1] - cands[0])
        lf = torch.log(fp * scale)
        n_ = lf.numel()
        # a median over about 40 ms (three refined frames), then 1-2-1
        if n_ >= 3:
            pad = torch.cat([lf[:1], lf, lf[-1:]])
            lf = pad.unfold(0, 3, 1).median(1).values
        if n_ >= 3:
            pad = torch.cat([lf[:1], lf, lf[-1:]])
            lf = 0.25 * pad[:-2] + 0.5 * pad[1:-1] + 0.25 * pad[2:]
        # back to every frame
        tp = times[pick]
        if n_ == 1:
            f0 = torch.full_like(f0, float(torch.exp(lf[0])))
        else:
            j = torch.searchsorted(tp, times).clamp(1, n_ - 1)
            a_ = ((times - tp[j - 1]) / (tp[j] - tp[j - 1])).clamp(0, 1)
            f0 = torch.exp(lf[j - 1] + a_ * (lf[j] - lf[j - 1]))
    return f0


def harmonic_blocks(x, Phi, K: int, cycles: float, ridge: float = 1e-4,
                    budget: float = BLOCK_BUDGET):
    """The harmonics of the phase Phi (one value per sample of x) fitted in
    warped time: blocks `cycles` pitch cycles long, half overlapping, each
    a weighted least-squares fit of K harmonics under a Hann window laid
    out in cycles (so the windows sum to one whatever the pitch does). The
    noise each harmonic's estimate carries is measured by the same fit half
    way between harmonics (two either side, over ±NOISE_BLOCKS blocks,
    median / ln 2 — a chi-square with two degrees of freedom), and each
    harmonic is weighted by its Wiener gain: power over power plus noise,
    the power smoothed over neighbouring blocks and harmonics. Blocks are
    solved a chunk at a time (`budget` numbers per chunk), so a track
    minutes long costs time, not memory."""
    import torch
    cyc = Phi / (2 * math.pi)
    c0, c1 = float(cyc[0]), float(cyc[-1])
    starts = torch.arange(c0 - cycles / 2, c1, cycles / 2,
                          dtype=torch.float64)
    starts = starts[starts + cycles > c0]
    out = torch.zeros_like(x)
    if starts.numel() == 0:
        return out
    lo_all = torch.searchsorted(cyc, starts)
    hi_all = torch.searchsorted(cyc, starts + cycles)
    B = starts.numel()
    Nmax = int((hi_all - lo_all).max())
    if Nmax < 4:
        return out
    chunk = max(1, int(budget / (Nmax * (2 * K + 2) * 3)))
    last = Phi.numel() - 1

    def geometry(s, e):
        lo, hi = lo_all[s:e], hi_all[s:e]
        idx = lo[:, None] + torch.arange(Nmax)[None, :]
        valid = idx < hi[:, None]
        idx = idx.clamp(max=last)
        # phase from each block's own start: small numbers, the same fit
        ph = Phi[idx] - Phi[lo.clamp(max=last)][:, None]
        u = ((cyc[idx] - starts[s:e, None]) / cycles).clamp(0, 1)
        w = torch.sin(math.pi * u) ** 2 * valid
        return idx, valid, ph, w

    def basis_of(ph, mult):
        arg = mult[None, None, :] * ph[:, :, None]
        return torch.cat([torch.cos(arg), torch.sin(arg)], -1)

    def solve(basis, w, xs):
        bw = basis * w[:, :, None]
        A = bw.transpose(1, 2) @ basis
        rhs = (bw * xs[:, :, None]).sum(1)
        M2 = A.shape[-1]
        lam = ridge * A.diagonal(dim1=1, dim2=2).mean(1).clamp(min=1e-12)
        A = A + lam[:, None, None] * torch.eye(M2, dtype=A.dtype)
        return torch.linalg.solve(A, rhs)

    harm = torch.arange(1, K + 1, dtype=torch.float64)
    half = torch.arange(0, K + 1, dtype=torch.float64) + 0.5
    th = torch.zeros(B, 2 * K, dtype=torch.float64)
    tho = torch.zeros(B, 2 * K + 2, dtype=torch.float64)
    for s in range(0, B, chunk):
        e = min(B, s + chunk)
        idx, valid, ph, w = geometry(s, e)
        xs = x[idx] * valid
        th[s:e] = solve(basis_of(ph, harm), w, xs)
        tho[s:e] = solve(basis_of(ph, half), w, xs)
    Po = tho[:, :K + 1] ** 2 + tho[:, K + 1:] ** 2
    Ph = th[:, :K] ** 2 + th[:, K:] ** 2
    nb = torch.stack([Po[:, :K], Po[:, 1:]], -1)            # [B, K, 2]
    R = NOISE_BLOCKS
    pad = torch.cat([nb[:1].expand(R, -1, -1), nb,
                     nb[-1:].expand(R, -1, -1)], 0)
    sig2 = pad.unfold(0, 2 * R + 1, 1).reshape(B, K, -1).median(-1).values \
        / math.log(2)
    S = torch.cat([Ph[:1], Ph, Ph[-1:]], 0)
    S = 0.25 * S[:-2] + 0.5 * S[1:-1] + 0.25 * S[2:]
    S = torch.cat([S[:, :1], S, S[:, -1:]], 1)
    S = 0.25 * S[:, :-2] + 0.5 * S[:, 1:-1] + 0.25 * S[:, 2:]
    P = (S - sig2).clamp(min=0)
    g = P / (P + sig2 + 1e-30)
    thg = th * torch.cat([g, g], 1)
    for s in range(0, B, chunk):
        e = min(B, s + chunk)
        idx, valid, ph, w = geometry(s, e)
        fit = (basis_of(ph, harm) * thg[s:e, None, :]).sum(-1)
        out.index_put_((idx[valid],), (fit * w)[valid], accumulate=True)
    return out


def extract_voice(x, rate: int, runs, noise_at, top_hz: float,
                  cycles: float = EXTRACT_CYCLES):
    """The voice along every run [(times, f0, track)]: (voice, the refined
    runs as [(track, start s, end s, median f0, median refinement %)])."""
    import torch
    x = x.double()
    n = x.numel()
    prepared, info = [], []
    for times, f0, track in runs:
        f1 = refine_pitch(x, rate, times, f0, noise_at, top_hz)
        change = float((f1 / f0 - 1).abs().median()) * 100.0
        ext = int(rate * (cycles / 2 + 1) / float(f1.min()))
        half = int(rate * HOP_S / 2)
        a = int(float(times[0]) * rate) - half
        b = int(float(times[-1]) * rate) + half
        n0, n1 = max(0, a - ext), min(n, b + ext)
        if n1 - n0 < 16:
            continue
        Phi = 2 * math.pi * torch.cumsum(sample_f0(times, f1, n0, n1, rate),
                                         0) / rate
        K = max(1, int(top_hz / float(f1.max())))
        fade = torch.ones(n1 - n0, dtype=torch.float64)
        r0, r1 = max(0, a - n0), max(0, min(n1 - n0, b - n0))
        if r0 > 0:
            fade[:r0] = torch.sin(0.5 * math.pi * torch.arange(
                r0, dtype=torch.float64) / r0) ** 2
        tail = (n1 - n0) - r1
        if tail > 0:
            fade[r1:] = torch.cos(0.5 * math.pi * torch.arange(
                tail, dtype=torch.float64) / tail) ** 2
        prepared.append((n0, n1, Phi, K, fade))
        info.append({"track": int(track), "start_s": round(a / rate, 3),
                     "end_s": round(b / rate, 3),
                     "f0_median_hz": round(float(f1.median()), 1),
                     "refined_pct": round(change, 3)})
    voice = torch.zeros(n, dtype=torch.float64)
    parts = [None] * len(prepared)
    overlaps = [any(j != i and p[0] < q[1] and q[0] < p[1]
                    for j, q in enumerate(prepared))
                for i, p in enumerate(prepared)]
    for rnd in range(BACKFIT_ROUNDS):
        for i, (n0, n1, Phi, K, fade) in enumerate(prepared):
            if rnd > 0 and not overlaps[i]:
                continue
            if parts[i] is not None:
                voice[n0:n1] -= parts[i]
            v = harmonic_blocks(x[n0:n1] - voice[n0:n1], Phi, K, cycles) \
                * fade
            parts[i] = v
            voice[n0:n1] += v
        if not any(overlaps):
            break
    return voice.float(), info


def rest_wiener(r, rate: int):
    """A classic decision-directed Wiener filter (Ephraim-Malah's a-priori
    SNR, floor LIFT_FLOOR_DB) on what the harmonic fit left — the noise and
    every unvoiced sound — with the noise spectrum taken as each bin's
    LIFT_QUANTILE quantile over time (an exponential's q-quantile is
    -ln(1-q) times its mean)."""
    import torch
    r = r.double()
    nfft = 1 << int(round(math.log2(0.032 * rate)))
    hop = nfft // 4
    if r.numel() < nfft:
        return r.float()
    win = torch.hann_window(nfft, periodic=True, dtype=torch.float64)
    Rs = torch.stft(r, nfft, hop, window=win, return_complex=True,
                    center=True)
    P = Rs.abs() ** 2
    q = LIFT_QUANTILE
    noise = (P.quantile(q, dim=1, keepdim=True) / (-math.log(1 - q))) \
        .clamp(min=1e-20)
    gmin = 10 ** (LIFT_FLOOR_DB / 20)
    post = P / noise
    G = torch.empty_like(P)
    prev = torch.zeros(P.shape[0], dtype=torch.float64)
    for t in range(P.shape[1]):
        gam = post[:, t]
        xi = LIFT_ALPHA * prev + (1 - LIFT_ALPHA) * (gam - 1).clamp(min=0)
        g = (xi / (1 + xi)).clamp(min=gmin)
        G[:, t] = g
        prev = g ** 2 * gam
    return torch.istft(Rs * G, nfft, hop, window=win, length=r.numel(),
                       center=True).float()


#: The parent's rule (hark.machine_flags, held equal by a test): on one
#: track, segments less than MACHINE_GAP_S apart make a run; a run at least
#: MACHINE_MIN_S long, voiced for MACHINE_COVER of it, whose pitch hardly
#: moves (90th percentile within MACHINE_SPREAD of the 10th) is a machine —
#: an engine, a fan — not a voice. Move 2 leaves it to the census, which
#: takes it out instead.
MACHINE_MIN_S = 5.0
MACHINE_SPREAD = 1.15
MACHINE_GAP_S = 2.0
MACHINE_COVER = 0.5
#: A machine holds its harmonics' levels far longer than a voice holds a
#: syllable: its fit integrates 24 cycles, not 6. Measured 2026-11-11 on an
#: engine (110 Hz +/-4%, 11 harmonics, -4 dB under pink noise): 6 cycles
#: left it 8 dB down, 12 cycles 11 dB, 24 cycles 11 dB (noise untouched),
#: 48 and 96 cycles worse again (the pitch drifts within the window).
MACHINE_CYCLES = 24.0


def _steady(group) -> bool:
    a = min(float(g["start_s"]) for g in group)
    b = max(float(g["end_s"]) for g in group)
    voiced = sum(float(g["end_s"]) - float(g["start_s"]) for g in group)
    if b - a < MACHINE_MIN_S or voiced < MACHINE_COVER * (b - a):
        return False
    f = sorted(v for g in group for v in g.get("f0_hz") or [] if v)
    if len(f) < 10:
        return False
    return f[(9 * len(f)) // 10] / max(1e-9, f[len(f) // 10]) < MACHINE_SPREAD


def machine_flags(segs) -> list:
    segs = list(segs or [])
    tracks = {}
    for i, g in enumerate(segs):
        if g.get("status") in ("detected", "possible"):
            tracks.setdefault(g.get("track", 1), []).append(i)
    flags = [False] * len(segs)
    for idx in tracks.values():
        idx.sort(key=lambda i: float(segs[i]["start_s"]))
        runs, cur, end = [], [], 0.0
        for i in idx:
            a, b = float(segs[i]["start_s"]), float(segs[i]["end_s"])
            if cur and a - end > MACHINE_GAP_S:
                runs.append(cur)
                cur = []
            end = max(end, b) if cur else b
            cur.append(i)
        runs.append(cur)
        for run in runs:
            if _steady([segs[i] for i in run]):
                for i in run:
                    flags[i] = True
    return flags


def machine_runs(segs) -> list:
    """[(frame times s, f0 Hz, track)] for each machine: its run of segments
    joined into ONE track, every gap between them bridged (log-linear) —
    a machine keeps running through the moments the hunt lost it, so its
    cancellation must too."""
    import torch
    segs = list(segs or [])
    flags = machine_flags(segs)
    tracks = {}
    for i, (g, m) in enumerate(zip(segs, flags)):
        if m:
            tracks.setdefault(g.get("track", 1), []).append(g)
    out = []
    for track, group in tracks.items():
        group.sort(key=lambda g: float(g["start_s"]))
        runs, cur, end = [], [], 0.0
        for g in group:
            if cur and float(g["start_s"]) - end > MACHINE_GAP_S:
                runs.append(cur)
                cur = []
            end = max(end, float(g["end_s"])) if cur else float(g["end_s"])
            cur.append(g)
        runs.append(cur)
        for run in runs:
            pts = {}
            for g in run:
                t0 = float(g["start_s"])
                for i, f in enumerate(g.get("f0_hz") or []):
                    if f:
                        pts[round(t0 + i * HOP_S, 6)] = float(f)
            if len(pts) < MIN_SEGMENT_FRAMES:
                continue
            kt = torch.tensor(sorted(pts), dtype=torch.float64)
            kf = torch.log(torch.tensor([pts[k] for k in sorted(pts)],
                                        dtype=torch.float64))
            n = int(round(float(kt[-1] - kt[0]) / HOP_S)) + 1
            times = kt[0] + HOP_S * torch.arange(n, dtype=torch.float64)
            j = torch.searchsorted(kt, times).clamp(1, kt.numel() - 1)
            ta, tb = kt[j - 1], kt[j]
            w = ((times - ta) / (tb - ta).clamp(min=1e-9)).clamp(0, 1)
            f0 = torch.exp((1 - w) * kf[j - 1] + w * kf[j])
            out.append((times, f0, track))
    return out


def _detected_runs(segs) -> list:
    out = []
    for s, machine in zip(segs, machine_flags(segs)):
        if s.get("status") == "detected" and not machine:
            for times, f0 in voiced_runs(s):
                out.append((times, f0, s.get("track", 1)))
    return out


def _rehunt(x, ctx: Context, device: str) -> list:
    """The detected segments of a recording hunted with the FILE's context
    (the probe: its noise is the file's), as the hunt's segments look."""
    segs, _lp, _z, _Z = hunt_excerpt(x, ctx, device)
    out = []
    for s in segs:
        if s["score"] < ctx.detect:
            continue
        out.append({"track": 1,
                    "start_s": s["start"] * HOP_S + WIN_S / 2,
                    "f0_hz": [float(ctx.grid.f0[j]) if j >= 0 else None
                              for j in s["states"]],
                    "status": "detected"})
    return out


def extract_op(req) -> dict:
    """VOICE and LIFT from the recording's DETECTED tracks — or, with
    "rehunt", from the tracks a hunt of THIS recording finds with the
    file's context (the probe)."""
    import torch  # noqa: F401 — no torch fails here, before any work
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    ctx = Context(req["hunt"], rate)
    segs = _rehunt(x, ctx, device) if req.get("rehunt") else \
        (req["hunt"].get("segments") or [])
    top = min(EXTRACT_TOP_HZ, 0.45 * rate,
              float(req.get("content_top_hz") or EXTRACT_TOP_HZ))
    runs = _detected_runs(segs)
    _say(f"extract: {len(runs)} voiced run(s) on "
         f"{len({r[2] for r in runs})} track(s), harmonics to {top:.0f} Hz")
    voice, info = extract_voice(x, rate, runs, _noise_at(ctx), top)
    lift = voice + rest_wiener(x - voice, rate)
    outs = req.get("outputs") or {}
    if outs.get("voice"):
        write_wav(outs["voice"], voice, rate)
    if outs.get("lift"):
        write_wav(outs["lift"], lift, rate)
    seconds = sum(r["end_s"] - r["start_s"] for r in info)
    _say(f"extract: {seconds:.1f} s of voice pulled out along its track")
    return {"rate": rate, "runs": info, "voiced_s": round(seconds, 2),
            "top_hz": round(top, 1), "cycles": EXTRACT_CYCLES,
            "tracks": sorted({r["track"] for r in info}),
            "versions": _versions(device)}


# ---------------------------------------------------------------------------
# Move 8: a sonar-style census — what pulses (DEMON), what hums (machines)
# ---------------------------------------------------------------------------

def band_envelopes(x, rate: int):
    """(envelopes [bands, frames] — each band's amplitude every ENV_HOP_S,
    band edges in Hz). Passive sonar's DEMON starts here: a propeller, a
    rotor, a fan or footsteps make the LOUDNESS of broadband noise pulse at
    a rate, whatever its spectrum."""
    import torch
    win = max(16, int(round(ENV_WIN_S * rate)))
    n_fft = 1 << math.ceil(math.log2(win))
    hop = max(1, int(round(ENV_HOP_S * rate)))
    top = min(8000.0, 0.45 * rate)
    edges = [ENV_LO_HZ * (top / ENV_LO_HZ) ** (i / ENV_BANDS)
             for i in range(ENV_BANDS + 1)]
    X = torch.stft(x.float(), n_fft, hop, win,
                   torch.hann_window(win), return_complex=True, center=True)
    P = X.abs() ** 2                                     # [F, T]
    f = torch.fft.rfftfreq(n_fft, 1.0 / rate)
    env = []
    for a, b in zip(edges[:-1], edges[1:]):
        m = (f >= a) & (f < b)
        if not bool(m.any()):
            m = (f - 0.5 * (a + b)).abs() == (f - 0.5 * (a + b)).abs().min()
        env.append(P[m].sum(0).sqrt())
    return torch.stack(env), [round(e, 1) for e in edges]


def modulation_evidence(env, env_rate: float):
    """(E [windows, rates] — the evidence that the noise's loudness pulses
    at each rate, window starts in s, the rates in Hz). Per band and window:
    the envelope's spectrum over MOD_WIN_S (zero-padded fourfold), each value
    as a ratio to the median of its neighbours within ±MOD_LOCAL of its rate
    — a random swing in loudness has a smooth, sloping spectrum and a pulse
    train a narrow peak, and only the peak stands out of its neighbours —
    averaged over the bands and summed over the rate and MOD_HARMONICS - 1
    of its multiples (each the best within a bin of where it should be,
    weighted 1/k): the harmonic summing of Move 1, on the envelope."""
    import torch
    import torch.nn.functional as F
    B, T = env.shape
    L = max(64, int(round(MOD_WIN_S * env_rate)))
    hop = max(1, int(round(MOD_HOP_S * env_rate)))
    if T < L:
        env = F.pad(env, (0, L - T))
        T = L
    starts = list(range(0, T - L + 1, hop))
    w = torch.hann_window(L)
    seg = torch.stack([env[:, s:s + L] for s in starts], 1)   # [B, W, L]
    seg = seg - seg.mean(-1, keepdim=True)
    nfft = 4 * L
    S = torch.fft.rfft(seg * w, n=nfft, dim=-1).abs() ** 2    # [B, W, M]
    freqs = torch.fft.rfftfreq(nfft, 1.0 / env_rate)
    M = freqs.numel()
    df = float(freqs[1])
    keep = (freqs >= MOD_MIN_HZ) & (freqs <= MOD_MAX_HZ)
    idx = torch.nonzero(keep).flatten()
    # the local background: a median over ±MOD_LOCAL of each rate (at least
    # MOD_LOCAL_MIN_HZ), from a log-spaced set of reference rates
    lS = torch.log(S.clamp(min=1e-30))
    bg = torch.empty_like(S)
    lo_b = 1
    refs = []
    f = MOD_MIN_HZ / 2
    while f < min(env_rate / 2, MOD_MAX_HZ * (MOD_HARMONICS + 1)):
        refs.append(f)
        f *= 1.0 + MOD_LOCAL / 2
    ref_vals = []
    for fr in refs:
        half = max(MOD_LOCAL_MIN_HZ, MOD_LOCAL * fr)
        a = max(lo_b, int((fr - half) / df))
        b = min(M, int((fr + half) / df) + 1)
        ref_vals.append(lS[..., a:b].median(-1).values)
    ref_vals = torch.stack(ref_vals, -1)                      # [B, W, R]
    ref_f = torch.tensor(refs)
    pos = torch.searchsorted(ref_f, freqs).clamp(1, len(refs) - 1)
    f0, f1 = ref_f[pos - 1], ref_f[pos]
    a_ = ((freqs - f0) / (f1 - f0)).clamp(0, 1)
    bg = ref_vals[..., pos - 1] * (1 - a_) + ref_vals[..., pos] * a_
    # the median of a chi-square(2) is ln 2 of its mean; the bands are
    # AVERAGED, not summed: a broadband swing in loudness moves every band
    # together, and the null below assumes they always do
    r = (torch.exp(lS - bg) * math.log(2) - 1.0).clamp(min=-1.0, max=50.0)
    r = r.mean(0)                                             # [W, M]
    rp = F.max_pool1d(r.unsqueeze(1), 3, stride=1, padding=1).squeeze(1)
    E = torch.zeros(len(starts), idx.numel())
    for k in range(1, MOD_HARMONICS + 1):
        j = (idx * k).clamp(max=M - 1)
        valid = (idx * k < M).float()
        E += (r if k == 1 else rp)[:, j] * valid / k
    return E, [s / env_rate for s in starts], freqs[idx]


def _mod_null(x, rate: int, n_surr: int, seed: int):
    """Every (window, rate) evidence value of surrogate copies of the
    recording (each 8 s block's phases randomised: the spectrum kept, any
    pulsing of the loudness destroyed), sorted, and their hours."""
    import torch
    vals, hours = [], 0.0
    for k in range(n_surr):
        sx = surrogate_wave(x, rate, seed + 7919 * (k + 1))
        env, _e = band_envelopes(sx, rate)
        E, _st, _f = modulation_evidence(env, 1.0 / ENV_HOP_S)
        vals.append(E.flatten())
        hours += sx.numel() / rate / 3600.0
    return torch.sort(torch.cat(vals)).values, hours


def _model_null(n: int = 400000, seed: int = 11):
    """The evidence noise makes at one rate in one window if every band
    moved together (the worst case — a random broadband swing in loudness):
    each harmonic's ratio is an exponential of mean one (a chi-square with
    two degrees of freedom, normalised by its local median), the multiples
    the best of three neighbouring bins; returned sorted."""
    import torch
    g = torch.Generator().manual_seed(seed)
    E = torch.zeros(n)
    for k in range(1, MOD_HARMONICS + 1):
        if k == 1:
            v = -torch.log(torch.rand(n, generator=g).clamp(min=1e-12))
        else:
            v = (-torch.log(torch.rand(n, 3, generator=g).clamp(min=1e-12))
                 ).max(1).values
        E += (v - 1.0).clamp(max=50.0) / k
    return torch.sort(E).values


def _model_fa(null_sorted, score: float) -> tuple[float, bool]:
    """False alarms per hour under the worst-case model: every window (one
    each MOD_HOP_S) times every independent rate (one each 1/MOD_WIN_S Hz)
    is a trial."""
    trials = (3600.0 / MOD_HOP_S) * (MOD_MAX_HZ - MOD_MIN_HZ) * MOD_WIN_S
    n = null_sorted.numel()
    # "hours" of the model: n draws are n / trials hours of trials
    return _rate_fa(null_sorted, n / trials, score)


def _rate_fa(null_sorted, hours: float, score: float) -> tuple[float, bool]:
    """(false alarms per hour of audio at this score or above — every rate
    of every window counted as a trial — and whether it was extrapolated):
    counted while at least three noise values reach it, past that an
    exponential fitted to the noise's top values (the top 0.2%, at least
    fifty: the far tail, not the bulk)."""
    import torch
    if hours <= 0:
        return float("inf"), True
    n = null_sorted.numel()
    above = n - int(torch.searchsorted(null_sorted, torch.tensor(score)))
    if above >= 3:
        return above / hours, False
    k = min(n, max(50, n // 500))
    top = null_sorted[-k:]
    x0 = float(top[0])
    beta = float((top - x0).mean())
    if beta <= 1e-9:
        return max(above, 0.5) / hours, False
    return (k / hours) * math.exp(-(score - x0) / beta), True


def _harmonic_of(a: float, b: float) -> bool:
    """a is a whole multiple or fraction of b (within MOD_RATE_MATCH)."""
    hi, lo = max(a, b), min(a, b)
    k = round(hi / lo)
    return k >= 2 and abs(hi / (k * lo) - 1.0) < MOD_RATE_MATCH - 1.0


def census_modulated(x, rate: int, n_surr: int, seed: int) -> dict:
    """The DEMON census: rates the recording's noise pulses at, with their
    false-alarm rates measured on its own surrogates, grouped over windows."""
    import torch
    env, edges = band_envelopes(x, rate)
    env_rate = 1.0 / ENV_HOP_S
    E, starts, freqs = modulation_evidence(env, env_rate)
    null, hours = _mod_null(x, rate, n_surr, seed)
    model = _model_null()
    hits = []
    for w in range(E.shape[0]):
        row = E[w]
        # local peaks, strongest first; a rate whose multiple or fraction is
        # already taken in this window is the same source
        pk = [(float(row[i]), i) for i in range(1, row.numel() - 1)
              if row[i] >= row[i - 1] and row[i] >= row[i + 1]]
        pk.sort(reverse=True)
        taken = []
        for score, i in pk[:12]:
            # the larger of the two: this file's own surrogates, and the
            # worst case of every band swinging together
            fa, extrap = max(_rate_fa(null, hours, score),
                             _model_fa(model, score))
            if fa > FA_POSSIBLE_PER_HOUR:
                break
            f = float(freqs[i])
            if any(abs(f / t - 1) < MOD_RATE_MATCH - 1 or _harmonic_of(f, t)
                   for t in taken):
                continue
            taken.append(f)
            hits.append({"window": w, "rate_hz": f, "score": score,
                         "fa_per_hour": fa, "extrapolated": extrap})
    # group: the same rate (within MOD_RATE_MATCH) in consecutive windows
    hits.sort(key=lambda h: (h["window"], -h["score"]))
    groups = []
    for h in hits:
        g = next((g for g in groups if g["last"] in (h["window"] - 1,
                                                     h["window"])
                  and abs(h["rate_hz"] / g["rate_hz"] - 1)
                  < MOD_RATE_MATCH - 1), None)
        if g is None:
            groups.append({"first": h["window"], "last": h["window"],
                           "rate_hz": h["rate_hz"], "rates": [h["rate_hz"]],
                           "score": h["score"], "fa": h["fa_per_hour"],
                           "extrap": h["extrapolated"]})
        else:
            g["last"] = h["window"]
            g["rates"].append(h["rate_hz"])
            if h["score"] > g["score"]:
                g["score"], g["extrap"] = h["score"], h["extrapolated"]
            g["fa"] = min(g["fa"], h["fa_per_hour"])
    dur = x.numel() / rate
    out = []
    for g in groups:
        rs = sorted(g["rates"])
        status = ("detected" if g["fa"] <= FA_DETECT_PER_HOUR else
                  "possible")
        out.append({"kind": "pulsing", "rate_hz": round(rs[len(rs) // 2], 2),
                    "start_s": round(starts[g["first"]], 2),
                    "end_s": round(min(dur, starts[g["last"]] + MOD_WIN_S),
                                   2),
                    "windows": g["last"] - g["first"] + 1,
                    "score": round(g["score"], 2),
                    "fa_per_hour": round(g["fa"], 6),
                    "fa_extrapolated": bool(g["extrap"]), "status": status})
    # twice: a source merged over a longer span may now cover more of its
    # own multiples
    out = _merge_harmonics(_merge_harmonics(out))
    out.sort(key=lambda o: (o["status"] != "detected", o["start_s"]))
    return {"items": out, "bands_hz": edges,
            "null_hours": round(hours, 3), "windows": E.shape[0],
            "rates_tried": int(freqs.numel())}


def _merge_harmonics(items: list) -> list:
    """A pulse train is found at its rate and at multiples of it (footsteps
    every 0.55 s show at 1.8, 3.6, 5.5 ... Hz): items that overlap in time
    and are whole multiples of one base rate — the base being one of them or
    a whole fraction of one — become one source, at that base, with the
    multiples it was seen at."""
    left = sorted(items, key=lambda o: -o["score"])
    out = []
    while left:
        best = None
        for it in left:
            for k in range(1, 7):
                base = it["rate_hz"] / k
                if base < MOD_MIN_HZ:
                    break
                group = [o for o in left
                         if o["start_s"] < it["end_s"]
                         and it["start_s"] < o["end_s"]
                         and round(o["rate_hz"] / base) >= 1
                         and abs(o["rate_hz"] / (round(o["rate_hz"] / base)
                                                 * base) - 1)
                         < MOD_RATE_MATCH - 1]
                key = (len(group), -k)
                if best is None or key > best[0]:
                    best = (key, base, group)
        _key, base, group = best
        lead = max(group, key=lambda o: o["score"])
        seen = set()
        for o in group:
            m = int(round(o["rate_hz"] / base))
            seen |= {m * k for k in (o.get("multiples") or [1])}
        merged = dict(lead, rate_hz=round(base, 2),
                      start_s=min(o["start_s"] for o in group),
                      end_s=max(o["end_s"] for o in group),
                      multiples=sorted(seen),
                      fa_per_hour=min(o["fa_per_hour"] for o in group))
        merged["status"] = ("detected" if merged["fa_per_hour"]
                            <= FA_DETECT_PER_HOUR else "possible")
        out.append(merged)
        left = [o for o in left if o not in group]
    return out


def census_op(req) -> dict:
    """Move 8: what pulses (DEMON on the band envelopes) and what hums (the
    hunt's steady tracks, which the parent names machines) — and, for the
    machines, the recording with each one taken out along its own pitch
    track (Move 2 in reverse): "without" and the machine alone."""
    import torch  # noqa: F401 — no torch fails here, before any work
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    p = req.get("params") or {}
    mod = census_modulated(x, rate, int(p.get("census_surrogates",
                                              MOD_SURROGATES)),
                           int(p.get("seed", 4321)))
    _say(f"census: {len(mod['items'])} pulsing source(s) over "
         f"{mod['null_hours'] * 60:.0f} min of surrogate noise")
    machines = req.get("machines") or []
    out = {"modulated": mod, "machines": [], "rate": rate,
           "versions": _versions(device)}
    if machines and req.get("outputs"):
        ctx = Context(req["hunt"], rate)
        # the parent sends a machine's whole run of segments; joined, gaps
        # bridged (a single segment the parent judged alone still counts)
        runs = machine_runs([dict(m, status="detected") for m in machines])
        top = min(EXTRACT_TOP_HZ, 0.45 * rate)
        machine, info = extract_voice(x, rate, runs, _noise_at(ctx), top,
                                      cycles=MACHINE_CYCLES)
        outs = req["outputs"]
        write_wav(outs["without"], x - machine, rate)
        write_wav(outs["machine"], machine, rate)
        out["machines"] = info
        out["cycles"] = MACHINE_CYCLES
        out["top_hz"] = round(top, 1)
        _say(f"census: {len(info)} machine(s) taken out along their pitch")
    return out


# ---------------------------------------------------------------------------
# increment 2b: a probe made of the file's own noise, and every restoration
# scored on it
# ---------------------------------------------------------------------------

def _join(pieces, rate: int):
    """Pieces of noise end to end, each join cross-faded over PROBE_FADE_S
    (power-complementary, so the level holds through the join)."""
    import torch
    f = max(1, int(PROBE_FADE_S * rate))
    out = None
    for p in pieces:
        if p.numel() <= 2 * f:
            continue
        if out is None:
            out = p.clone()
            continue
        ramp = torch.linspace(0, 0.5 * math.pi, f)
        a, b = torch.cos(ramp), torch.sin(ramp)
        out = torch.cat([out[:-f], out[-f:] * a + p[:f] * b, p[f:]])
    return out


def noise_bed(x, rate: int, free, need: int, seed: int):
    """(noise, seconds from free stretches, seconds of surrogate): the
    file's voice-free stretches joined; when they are shorter than `need`,
    surrogate copies of them (each 8 s block's phases randomised — the same
    colour and level, nothing periodic) follow until it is long enough."""
    trim = int(0.1 * rate)
    pieces = []
    for a, b in free:
        lo, hi = int(a * rate) + trim, int(b * rate) - trim
        if hi - lo > int(0.5 * rate):
            pieces.append(x[lo:hi])
    src = _join(pieces, rate) if pieces else None
    from_file = 0.0 if src is None else src.numel() / rate
    if src is None:
        # nothing free: the whole recording through surrogates (its voices
        # become noise of their colour — the bed is then a little loud)
        src = surrogate_wave(x, rate, seed)
    bed, k = [src], 0
    total = src.numel()
    while total < need:
        k += 1
        s = surrogate_wave(src, rate, seed + 101 * k)
        bed.append(s)
        total += s.numel()
    out = _join(bed, rate)[:need]
    return out, round(from_file, 2), round(max(0, need - min(
        need, int(from_file * rate))) / rate, 2)


def probe_op(req) -> dict:
    """The probe: the file's own noise with clean phrases at the
    calibration's levels (levels in random order, so a chain that adapts as
    it goes meets them mixed), PROBE_GAP_S of noise around each."""
    import torch
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    ctx = Context(req["hunt"], rate)
    p = req.get("params") or {}
    levels = [float(v) for v in p.get("levels") or [0.0, -5.0, -10.0]]
    per = max(1, int(p.get("probe_per_level", 1)))
    seed = int(p.get("seed", 4321))
    phrases = []
    for f in req.get("phrases") or []:
        y, r = read_wav(f)
        phrases.append(_resample(y, r, rate) if r != rate else y)
    if not phrases:
        raise ValueError("the probe needs clean phrases")
    gen = torch.Generator().manual_seed(seed)
    jobs = [lvl for lvl in levels for _ in range(per)]
    order = torch.randperm(len(jobs), generator=gen).tolist()
    gap = int(PROBE_GAP_S * rate)
    noise_band = float(torch.exp(ctx.logN.float())[int(F0_MIN /
                                                       ctx.grid.df):].sum())
    layout, pos = [], gap
    for n, j in enumerate(order):
        ph = phrases[n % len(phrases)]
        layout.append((jobs[j], ph, pos, n % len(phrases)))
        pos += ph.numel() + gap
    total = pos
    free = req.get("free")
    if free is None:
        free = req["hunt"].get("free") or []
    bed, from_file, surr = noise_bed(x, rate, free, total, seed)
    clean = torch.zeros(total)
    rows = []
    for n, (lvl, ph, at, which) in enumerate(layout):
        pw = _band_power(ph, ctx, device)
        if pw <= 0:
            continue
        g = math.sqrt(10 ** (lvl / 10.0) * noise_band / pw)
        clean[at:at + ph.numel()] += g * ph
        rows.append({"n": n + 1, "level_db": lvl, "phrase": which,
                     "start_s": round(at / rate, 4),
                     "end_s": round((at + ph.numel()) / rate, 4)})
    outs = req["outputs"]
    write_wav(outs["probe"], bed + clean, rate)
    write_wav(outs["clean"], clean, rate)
    _say(f"probe: {len(rows)} phrases over {total / rate:.1f} s "
         f"({from_file:.1f} s of the file's own noise, {surr:.1f} s of "
         "surrogate)")
    return {"rate": rate, "duration_s": round(total / rate, 3),
            "phrases": rows, "levels": levels, "per_level": per,
            "noise_from_file_s": from_file, "noise_surrogate_s": surr}


def _si_snr(ref, est, rate: int) -> float | None:
    """Scale-invariant SNR (dB) of est against ref in SCORE_BAND."""
    import torch
    lo, hi = SCORE_BAND

    def band(z):
        Z = torch.fft.rfft(z.double())
        f = torch.fft.rfftfreq(z.numel(), 1.0 / rate)
        Z[(f < lo) | (f > hi)] = 0
        return torch.fft.irfft(Z, z.numel())
    r, e = band(ref), band(est)
    den = float((r ** 2).sum())
    if den <= 0:
        return None
    a = float((r * e).sum()) / den
    num = float(((a * r) ** 2).sum())
    err = float(((e - a * r) ** 2).sum())
    if num <= 0 or a <= 0:
        return -60.0
    return round(max(-60.0, 10 * math.log10(num / max(err, 1e-30))), 2)


def score_op(req) -> dict:
    """Every output of the probe scored against the clean phrases: ESTOI
    and scale-invariant SNR per phrase (the best of an output's stems),
    their means per level, and the noise each leaves in the pauses."""
    import torch
    clean, rate = read_wav(req["clean"])
    probe, r2 = read_wav(req["probe"])
    rows = req["phrases"]
    gaps = []
    edge = int(0.2 * rate)
    prev = 0
    for r in rows:
        a = int(r["start_s"] * rate)
        if a - prev > 2 * edge + int(0.3 * rate):
            gaps.append((prev + edge, a - edge))
        prev = int(r["end_s"] * rate)
    candidates = [{"id": "unprocessed", "paths": [req["probe"]]}] + \
        list(req.get("outputs") or [])
    probe_gap = sum(float((probe[a:b].double() ** 2).sum()) for a, b in gaps)
    out = {}
    for c in candidates:
        stems = []
        for path in c["paths"]:
            y, ry = read_wav(path)
            if ry != rate:
                y = _resample(y, ry, rate)
            if y.numel() < clean.numel():
                y = torch.nn.functional.pad(y, (0, clean.numel() - y.numel()))
            stems.append(y[:clean.numel()])
        per = []
        for r in rows:
            a, b = int(r["start_s"] * rate), int(r["end_s"] * rate)
            ref = clean[a:b]
            best_e, best_s = None, None
            for y in stems:
                e = estoi(ref, y[a:b], rate)
                s = _si_snr(ref, y[a:b], rate)
                if e is not None and (best_e is None or e > best_e):
                    best_e = e
                if s is not None and (best_s is None or s > best_s):
                    best_s = s
            per.append({"n": r["n"], "level_db": r["level_db"],
                        "estoi": None if best_e is None else round(best_e, 4),
                        "si_snr_db": best_s})
        left = None
        if probe_gap > 0:
            left = min(10 * math.log10(max(1e-12, sum(
                float((y[a:b].double() ** 2).sum()) for a, b in gaps)
                / probe_gap)) for y in stems)
        levels = {}
        for p in per:
            levels.setdefault(p["level_db"], []).append(p)
        by_level = []
        for lvl in sorted(levels, reverse=True):
            es = [p["estoi"] for p in levels[lvl] if p["estoi"] is not None]
            ss = [p["si_snr_db"] for p in levels[lvl]
                  if p["si_snr_db"] is not None]
            by_level.append({"level_db": lvl, "n": len(levels[lvl]),
                             "estoi": round(sum(es) / len(es), 4) if es
                             else None,
                             "si_snr_db": round(sum(ss) / len(ss), 2) if ss
                             else None})
        out[c["id"]] = {"by_level": by_level, "phrases": per,
                        "noise_left_db": None if left is None
                        else round(left, 2)}
        _say(f"score: {c['id']} — " + ", ".join(
            f"{b['level_db']:+g} dB {b['estoi']}" for b in by_level))
    return {"scores": out, "gaps": len(gaps)}


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    op = req.get("op")
    if op == "hunt":
        out = hunt_op(req)
    elif op == "calibrate":
        out = calibrate_op(req)
    elif op == "audit":
        out = audit_op(req)
    elif op == "extract":
        out = extract_op(req)
    elif op == "probe":
        out = probe_op(req)
    elif op == "score":
        out = score_op(req)
    elif op == "census":
        out = census_op(req)
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
        print(f"hark_worker failed: {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
