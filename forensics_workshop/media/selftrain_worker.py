# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
#
# The GTCRN network below (the section marked "GTCRN") is a port to plain
# torch of Rong Xiaobin's GTCRN, https://github.com/Xiaobin-Rong/gtcrn
# (commit 502ebfab64da7c4a9af78dcb9c6ceef1ebb01c73), used under its licence:
#
#   MIT License
#
#   Copyright (c) 2024 Rong Xiaobin
#
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files (the
#   "Software"), to deal in the Software without restriction, including
#   without limitation the rights to use, copy, modify, merge, publish,
#   distribute, sublicense, and/or sell copies of the Software, and to
#   permit persons to whom the Software is furnished to do so, subject to
#   the following conditions:
#
#   The above copyright notice and this permission notice shall be included
#   in all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
#   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
#   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
#   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
#   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
#   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
#   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""HARK's self-training worker (Move 3) — run as its own process, never
imported.

    python -I selftrain_worker.py REQUEST.json RESPONSE.json

Started by `hark.py` under the host's torch interpreter (ATK:
`envs\\atk_audio\\Scripts\\python.exe`), like `hark_worker.py`.
SELF-CONTAINED: it imports nothing from the engine, only torch, and writes
only the paths it is told to — the trained weights, the denoised audio and
the one response — each checked by the parent before it started.

**The file trains its own denoiser.** Every denoiser Restore Audio offers
was trained on someone else's microphone noise. This one is GTCRN (48 000
parameters, 16 kHz) retrained on the noise in THIS recording, with no clean
speech and no dataset, by remixing (RemixIT, Tzinis et al. 2022): the
starting model cleans the recording; that cleaned speech plus more of the
recording's own noise — taken from the stretches HARK's hunt found free of
any voice — goes in, and the cleaned speech is the target. The network
learns to take away noise exactly like this recording's, keeping what it
already knew about speech. (Training on the noisy recording itself as the
target — noisy-target training — was tried first and taught a model that
already denoises to keep the noise: measured 2026-11-10, not used.)

It starts from GTCRN's published DNS3 weights (`"weights"`), whose own
output is written too (`"base"`), so Move 3 is always measured against
where it started. With no weights it starts from random ones (HARK's mad
move M4) and its teacher is Move 2's LIFT (`"teacher"`) — HARK's own signal
processing on this file — so everything it learns about speech came from
this one recording and it cannot import anyone else's words. The weights it
ends with are the ones that did best on a fixed check set of the same kind
of pairs, checked every CHECK_EVERY steps.

Two operations (`"op"`):

* **selftrain** — train on the recording, write the weights, and run them on
  the recording (and on any further inputs, the probe among them).
* **apply** — run saved weights on a recording.

Tier: **Inferred** — a trained network decides what is speech.
"""

from __future__ import annotations

import io
import json
import math
import os
import struct
import sys
import time

RATE = 16000                  # GTCRN's rate; the parent gives 16 kHz copies
NFFT, HOP = 512, 256          # its STFT
CROP_S = 2.0                  # training crops
BATCH = 8
VOICED_SHARE = 0.6            # crops centred on the hunt's voiced stretches
GAIN = (0.6, 1.4)             # the added noise's amplitude, against its own
LR = {"finetune": 1e-4, "scratch": 1e-3}
LR_FLOOR = 0.1                # cosine to a tenth of the rate
CLIP = 5.0
CHECK_EVERY = 25
CHECK_CROPS = 16
TRIM_S = 0.1                  # off each end of a voice-free stretch
MIN_NOISE_S = 4.0             # less voice-free noise than this: no training
CHUNK_S = 60.0                # applied a minute at a time, joined over
OVERLAP_S = 1.0               # a second


def _say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# files (the same reader and writer as hark_worker.py)
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
        x = (torch.frombuffer(data, dtype=torch.uint8).float() - 128) / 128.0
    elif tag == 1 and bits == 24:
        b = torch.frombuffer(data, dtype=torch.uint8).reshape(-1, 3).int()
        v = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        v = torch.where(v >= 1 << 23, v - (1 << 24), v)
        x = v.float() / float(1 << 23)
    else:
        raise ValueError(f"{path}: unsupported WAV format {tag}/{bits}-bit")
    if ch > 1:
        x = x.reshape(-1, ch).mean(dim=1)
    return x, rate


def _write_bytes(path: str, payload: bytes) -> None:
    tmp = f"{path}.{os.getpid()}.part"
    with open(tmp, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _write_json(path: str, data: dict) -> None:
    _write_bytes(path, json.dumps(data).encode("utf-8"))


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


def _device(wanted: str) -> str:
    import torch
    if wanted == "cpu":
        return "cpu"
    if wanted in ("auto", "cuda") and torch.cuda.is_available():
        return "cuda"
    return "cpu"


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
# GTCRN — ported from Rong Xiaobin's gtcrn.py (MIT, notice at the top of this
# file): the same layers and parameter names, so the published weights load
# unchanged; numpy and einops replaced by torch.
# ---------------------------------------------------------------------------

def _build_gtcrn():
    import torch
    import torch.nn as nn

    def hz2erb(f):
        return 21.4 * math.log10(0.00437 * f + 1)

    def erb2hz(e):
        return (10 ** (e / 21.4) - 1) / 0.00437

    def erb_filters(sub1=65, sub2=64, nfft=512, high=8000.0, fs=16000):
        pts = torch.linspace(hz2erb(sub1 / nfft * fs), hz2erb(high), sub2,
                             dtype=torch.float64)
        b = [int(round(erb2hz(float(e)) / fs * nfft)) for e in pts]
        F = torch.zeros(sub2, nfft // 2 + 1, dtype=torch.float32)
        for k in range(b[0], b[1]):
            F[0, k] = (b[1] - k + 1e-12) / (b[1] - b[0] + 1e-12)
        for i in range(sub2 - 2):
            for k in range(b[i], b[i + 1]):
                F[i + 1, k] = (k - b[i] + 1e-12) / (b[i + 1] - b[i] + 1e-12)
            for k in range(b[i + 1], b[i + 2]):
                F[i + 1, k] = (b[i + 2] - k + 1e-12) / (b[i + 2] - b[i + 1]
                                                        + 1e-12)
        for k in range(b[-2], b[-1] + 1):
            F[-1, k] = 1 - F[-2, k]
        return F[:, sub1:].abs()

    class ERB(nn.Module):
        def __init__(self, sub1=65, sub2=64, nfft=512):
            super().__init__()
            filt = erb_filters(sub1, sub2, nfft)
            self.sub1 = sub1
            self.erb_fc = nn.Linear(nfft // 2 + 1 - sub1, sub2, bias=False)
            self.ierb_fc = nn.Linear(sub2, nfft // 2 + 1 - sub1, bias=False)
            self.erb_fc.weight = nn.Parameter(filt, requires_grad=False)
            self.ierb_fc.weight = nn.Parameter(filt.T.contiguous(),
                                               requires_grad=False)

        def bm(self, x):
            return torch.cat([x[..., :self.sub1],
                              self.erb_fc(x[..., self.sub1:])], -1)

        def bs(self, x):
            return torch.cat([x[..., :self.sub1],
                              self.ierb_fc(x[..., self.sub1:])], -1)

    class SFE(nn.Module):
        def __init__(self, k=3):
            super().__init__()
            self.k = k
            self.unfold = nn.Unfold(kernel_size=(1, k), stride=(1, 1),
                                    padding=(0, (k - 1) // 2))

        def forward(self, x):
            return self.unfold(x).reshape(x.shape[0], x.shape[1] * self.k,
                                          x.shape[2], x.shape[3])

    class TRA(nn.Module):
        def __init__(self, ch):
            super().__init__()
            self.att_gru = nn.GRU(ch, ch * 2, 1, batch_first=True)
            self.att_fc = nn.Linear(ch * 2, ch)
            self.att_act = nn.Sigmoid()

        def forward(self, x):
            at = self.att_gru(x.pow(2).mean(-1).transpose(1, 2))[0]
            at = self.att_act(self.att_fc(at).transpose(1, 2))
            return x * at[..., None]

    class ConvBlock(nn.Module):
        def __init__(self, cin, cout, k, stride, padding, groups=1,
                     deconv=False, last=False):
            super().__init__()
            mod = nn.ConvTranspose2d if deconv else nn.Conv2d
            self.conv = mod(cin, cout, k, stride, padding, groups=groups)
            self.bn = nn.BatchNorm2d(cout)
            self.act = nn.Tanh() if last else nn.PReLU()

        def forward(self, x):
            return self.act(self.bn(self.conv(x)))

    class GTConvBlock(nn.Module):
        def __init__(self, cin, hid, k, stride, padding, dilation,
                     deconv=False):
            super().__init__()
            self.pad_size = (k[0] - 1) * dilation[0]
            mod = nn.ConvTranspose2d if deconv else nn.Conv2d
            self.sfe = SFE(3)
            self.point_conv1 = mod(cin // 2 * 3, hid, 1)
            self.point_bn1 = nn.BatchNorm2d(hid)
            self.point_act = nn.PReLU()
            self.depth_conv = mod(hid, hid, k, stride=stride,
                                  padding=padding, dilation=dilation,
                                  groups=hid)
            self.depth_bn = nn.BatchNorm2d(hid)
            self.depth_act = nn.PReLU()
            self.point_conv2 = mod(hid, cin // 2, 1)
            self.point_bn2 = nn.BatchNorm2d(cin // 2)
            self.tra = TRA(cin // 2)

        def forward(self, x):
            x1, x2 = torch.chunk(x, 2, dim=1)
            h = self.point_act(self.point_bn1(self.point_conv1(
                self.sfe(x1))))
            h = nn.functional.pad(h, [0, 0, self.pad_size, 0])
            h = self.depth_act(self.depth_bn(self.depth_conv(h)))
            h = self.tra(self.point_bn2(self.point_conv2(h)))
            # the two halves' channels interleaved (the original's shuffle)
            y = torch.stack([h, x2], dim=2)
            return y.reshape(y.shape[0], -1, y.shape[3], y.shape[4])

    class GRNN(nn.Module):
        def __init__(self, inp, hid, bidirectional=False):
            super().__init__()
            self.hid, self.bi = hid, bidirectional
            self.rnn1 = nn.GRU(inp // 2, hid // 2, 1, batch_first=True,
                               bidirectional=bidirectional)
            self.rnn2 = nn.GRU(inp // 2, hid // 2, 1, batch_first=True,
                               bidirectional=bidirectional)

        def forward(self, x):
            h = torch.zeros(2 if self.bi else 1, x.shape[0], self.hid,
                            device=x.device, dtype=x.dtype)
            x1, x2 = torch.chunk(x, 2, dim=-1)
            h1, h2 = torch.chunk(h, 2, dim=-1)
            y1, _ = self.rnn1(x1, h1.contiguous())
            y2, _ = self.rnn2(x2, h2.contiguous())
            return torch.cat([y1, y2], dim=-1)

    class DPGRNN(nn.Module):
        def __init__(self, inp, width, hid):
            super().__init__()
            self.width, self.hid = width, hid
            self.intra_rnn = GRNN(inp, hid // 2, bidirectional=True)
            self.intra_fc = nn.Linear(hid, hid)
            self.intra_ln = nn.LayerNorm((width, hid), eps=1e-8)
            self.inter_rnn = GRNN(inp, hid)
            self.inter_fc = nn.Linear(hid, hid)
            self.inter_ln = nn.LayerNorm((width, hid), eps=1e-8)

        def forward(self, x):
            x = x.permute(0, 2, 3, 1)
            B, T, F, C = x.shape
            a = self.intra_fc(self.intra_rnn(x.reshape(B * T, F, C)))
            intra = x + self.intra_ln(a.reshape(B, T, self.width, self.hid))
            y = intra.permute(0, 2, 1, 3)
            b = self.inter_fc(self.inter_rnn(y.reshape(B * F, T, C)))
            b = b.reshape(B, self.width, T, self.hid).permute(0, 2, 1, 3)
            return (intra + self.inter_ln(b)).permute(0, 3, 1, 2)

    class Encoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.en_convs = nn.ModuleList([
                ConvBlock(9, 16, (1, 5), (1, 2), (0, 2)),
                ConvBlock(16, 16, (1, 5), (1, 2), (0, 2), groups=2),
                GTConvBlock(16, 16, (3, 3), (1, 1), (0, 1), (1, 1)),
                GTConvBlock(16, 16, (3, 3), (1, 1), (0, 1), (2, 1)),
                GTConvBlock(16, 16, (3, 3), (1, 1), (0, 1), (5, 1))])

        def forward(self, x):
            outs = []
            for m in self.en_convs:
                x = m(x)
                outs.append(x)
            return x, outs

    class Decoder(nn.Module):
        def __init__(self):
            super().__init__()
            self.de_convs = nn.ModuleList([
                GTConvBlock(16, 16, (3, 3), (1, 1), (10, 1), (5, 1),
                            deconv=True),
                GTConvBlock(16, 16, (3, 3), (1, 1), (4, 1), (2, 1),
                            deconv=True),
                GTConvBlock(16, 16, (3, 3), (1, 1), (2, 1), (1, 1),
                            deconv=True),
                ConvBlock(16, 16, (1, 5), (1, 2), (0, 2), groups=2,
                          deconv=True),
                ConvBlock(16, 2, (1, 5), (1, 2), (0, 2), deconv=True,
                          last=True)])

        def forward(self, x, outs):
            n = len(self.de_convs)
            for i, m in enumerate(self.de_convs):
                x = m(x + outs[n - 1 - i])
            return x

    class GTCRN(nn.Module):
        def __init__(self):
            super().__init__()
            self.erb = ERB(65, 64)
            self.sfe = SFE(3)
            self.encoder = Encoder()
            self.dpgrnn1 = DPGRNN(16, 33, 16)
            self.dpgrnn2 = DPGRNN(16, 33, 16)
            self.decoder = Decoder()

        def forward(self, spec):
            """(B, F, T, 2) -> (B, F, T, 2): a complex ratio mask applied."""
            re = spec[..., 0].permute(0, 2, 1)
            im = spec[..., 1].permute(0, 2, 1)
            mag = torch.sqrt(re ** 2 + im ** 2 + 1e-12)
            feat = self.sfe(self.erb.bm(torch.stack([mag, re, im], dim=1)))
            feat, outs = self.encoder(feat)
            feat = self.dpgrnn2(self.dpgrnn1(feat))
            m = self.erb.bs(self.decoder(feat, outs))
            sr = spec.permute(0, 3, 2, 1)
            s_re = sr[:, 0] * m[:, 0] - sr[:, 1] * m[:, 1]
            s_im = sr[:, 1] * m[:, 0] + sr[:, 0] * m[:, 1]
            return torch.stack([s_re, s_im], dim=1).permute(0, 3, 2, 1)

    return GTCRN()


# ---------------------------------------------------------------------------
# training on one file
# ---------------------------------------------------------------------------

def _window(device):
    import torch
    return torch.hann_window(NFFT, device=device).pow(0.5)


def stft(x, win):
    import torch
    return torch.view_as_real(torch.stft(x, NFFT, HOP, NFFT, win,
                                         return_complex=True))


def istft(s, n, win):
    import torch
    return torch.istft(torch.view_as_complex(s.contiguous()), NFFT, HOP,
                       NFFT, win, length=n)


def hybrid_loss(pred, true, n, win):
    """GTCRN's training loss: compressed complex and magnitude spectra plus
    scale-invariant SNR — here against a NOISY target (the file itself)."""
    import torch
    pr, pi = pred[..., 0], pred[..., 1]
    tr, ti = true[..., 0], true[..., 1]
    pm = torch.sqrt(pr ** 2 + pi ** 2 + 1e-12)
    tm = torch.sqrt(tr ** 2 + ti ** 2 + 1e-12)
    real = ((pr / pm ** 0.7 - tr / tm ** 0.7) ** 2).mean()
    imag = ((pi / pm ** 0.7 - ti / tm ** 0.7) ** 2).mean()
    mag = ((pm ** 0.3 - tm ** 0.3) ** 2).mean()
    yp, yt = istft(pred, n, win), istft(true, n, win)
    yt = (yt * yp).sum(-1, keepdim=True) * yt / \
        ((yt ** 2).sum(-1, keepdim=True) + 1e-8)
    sisnr = -torch.log10(yt.norm(dim=-1) ** 2
                         / ((yp - yt).norm(dim=-1) ** 2 + 1e-8) + 1e-8).mean()
    return 30 * (real + imag) + 70 * mag + sisnr


def noise_pool(x, rate: int, free):
    """The voice-free stretches joined (each trimmed TRIM_S at both ends)."""
    import torch
    parts = []
    for a, b in free:
        lo, hi = int((a + TRIM_S) * rate), int((b - TRIM_S) * rate)
        if hi - lo > int(0.5 * rate):
            parts.append(x[lo:hi])
    return torch.cat(parts) if parts else torch.zeros(0)


def _load_weights(model, path: str) -> None:
    import torch
    ck = torch.load(path, map_location="cpu", weights_only=True)
    model.load_state_dict(ck["model"] if isinstance(ck, dict) and "model" in
                          ck else ck)


def train(x, free, voiced, *, weights, minutes: float, max_steps: int,
          seed: int, device: str, teacher=None):
    """(model, report): GTCRN trained on x (16 kHz) with noise from `free`
    added; the weights that did best on the check set kept.

    The target is `teacher` (x cleaned by the starting model, or by Move 2
    for the network trained from nothing) — remixing after RemixIT
    (Tzinis et al. 2022): teacher's speech plus the file's own noise in,
    teacher's speech out. With no teacher the target is x itself
    (noisy-target training, which on a model that already denoises teaches
    it to keep noise — measured 2026-11-10, so not used by HARK)."""
    import torch
    torch.manual_seed(seed)
    mode = "finetune" if weights else "scratch"
    model = _build_gtcrn()
    if weights:
        _load_weights(model, weights)
    model = model.to(device)
    win = _window(device)
    target = x if teacher is None else teacher[:x.numel()]
    pool = noise_pool(x, RATE, free)
    L = int(CROP_S * RATE)
    n = x.numel()
    if n < L + 1:
        raise ValueError("the recording is shorter than one training crop")
    noise_s = pool.numel() / RATE
    if pool.numel() < L:
        pool = pool.repeat(math.ceil(L / max(1, pool.numel())) + 1)
    gen = torch.Generator().manual_seed(seed)
    centres = [max(0, min(n - L, int(0.5 * (a + b) * RATE) - L // 2))
               for a, b in voiced]

    def crops(count, g):
        xs, ns = [], []
        for _ in range(count):
            if centres and float(torch.rand(1, generator=g)) < VOICED_SHARE:
                s = centres[int(torch.randint(len(centres), (1,),
                                              generator=g))]
                s += int(torch.randint(-L // 4, L // 4 + 1, (1,),
                                       generator=g))
                s = max(0, min(n - L, s))
            else:
                s = int(torch.randint(0, n - L, (1,), generator=g))
            p = int(torch.randint(0, max(1, pool.numel() - L), (1,),
                                  generator=g))
            k = GAIN[0] + (GAIN[1] - GAIN[0]) * float(torch.rand(
                1, generator=g))
            xs.append(target[s:s + L])
            ns.append(pool[p:p + L] * k)
        return torch.stack(xs).to(device), torch.stack(ns).to(device)

    cx, cn = crops(CHECK_CROPS, torch.Generator().manual_seed(seed + 999))
    cX = stft(cx, win)
    cY = stft(cx + cn, win)

    def check() -> float:
        model.eval()
        with torch.no_grad():
            return float(hybrid_loss(model(cY), cX, L, win))

    params = [p for p in model.parameters() if p.requires_grad]
    lr = LR[mode]
    opt = torch.optim.Adam(params, lr)
    first = best = check()
    best_state = {k: v.detach().clone() for k, v in
                  model.state_dict().items()}
    best_step, step = 0, 0
    curve = [[0, round(first, 5)]]
    t0 = time.monotonic()
    last_say = t0
    while step < max_steps and time.monotonic() - t0 < minutes * 60.0:
        model.train()
        if mode == "finetune":
            # the published weights' normalisation statistics are kept
            for mod in model.modules():
                if isinstance(mod, torch.nn.BatchNorm2d):
                    mod.eval()
        frac = step / max(1, max_steps)
        for pg in opt.param_groups:
            pg["lr"] = lr * (LR_FLOOR + (1 - LR_FLOOR) * 0.5
                             * (1 + math.cos(math.pi * frac)))
        xs, ns = crops(BATCH, gen)
        loss = hybrid_loss(model(stft(xs + ns, win)), stft(xs, win), L, win)
        opt.zero_grad()
        loss.backward()
        torch.nn.utils.clip_grad_norm_(params, CLIP)
        opt.step()
        step += 1
        if step % CHECK_EVERY == 0:
            v = check()
            curve.append([step, round(v, 5)])
            if v < best:
                best, best_step = v, step
                best_state = {k: t.detach().clone() for k, t in
                              model.state_dict().items()}
        if time.monotonic() - last_say > 30:
            last_say = time.monotonic()
            _say(f"selftrain {mode}: step {step}, check loss {first:.4f} -> "
                 f"best {best:.4f} (step {best_step})")
    model.load_state_dict(best_state)
    model.eval()
    elapsed = time.monotonic() - t0
    _say(f"selftrain {mode}: {step} steps in {elapsed:.0f} s; check loss "
         f"{first:.4f} -> {best:.4f} at step {best_step}")
    return model, {"mode": mode, "teacher": teacher is not None,
                   "steps": step, "best_step": best_step,
                   "check_first": round(first, 5),
                   "check_best": round(best, 5),
                   "improved": best < first, "curve": curve,
                   "train_s": round(elapsed, 1),
                   "noise_s": round(noise_s, 2)}


def apply(model, x, device: str):
    """The model over a whole recording, a minute at a time, the pieces
    joined by cross-fades over OVERLAP_S."""
    import torch
    win = _window(device)
    n = x.numel()
    chunk, ov = int(CHUNK_S * RATE), int(OVERLAP_S * RATE)
    out = torch.zeros(n)
    weight = torch.zeros(n)
    s = 0
    with torch.no_grad():
        while s < n:
            a = max(0, s - ov)
            b = min(n, s + chunk + ov)
            seg = x[a:b].to(device)
            y = istft(model(stft(seg, win)[None])[0], seg.numel(), win).cpu()
            w = torch.ones(b - a)
            if a > 0:
                r = min(ov, b - a)
                w[:r] = torch.linspace(0, 1, r)
            if b < n:
                r = min(ov, b - a)
                w[-r:] = torch.minimum(w[-r:], torch.linspace(1, 0, r))
            out[a:b] += y * w
            weight[a:b] += w
            s += chunk
    return out / weight.clamp(min=1e-6)


def _state_bytes(model) -> bytes:
    import torch
    buf = io.BytesIO()
    torch.save({"model": {k: v.cpu() for k, v in model.state_dict().items()},
                "arch": "GTCRN", "rate": RATE}, buf)
    return buf.getvalue()


def selftrain_op(req) -> dict:
    import torch
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    if rate != RATE:
        raise ValueError(f"{req['wav']} is {rate} Hz; GTCRN trains at "
                         f"{RATE} Hz (the parent passes a 16 kHz copy)")
    p = req.get("params") or {}
    free = req.get("free") or []
    pool_s = sum(max(0.0, b - a - 2 * TRIM_S) for a, b in free
                 if b - a - 2 * TRIM_S > 0.5)
    if pool_s < MIN_NOISE_S:
        raise ValueError(f"only {pool_s:.1f} s of the recording is free of "
                         f"voice — at least {MIN_NOISE_S:.0f} s is needed to "
                         "learn its noise")
    weights = req.get("weights") or None
    outs = req["outputs"]
    teacher = None
    if weights:
        # the starting model's own cleaning of the file is the target (and,
        # written as "base", the reference Move 3 is measured against)
        base = _build_gtcrn()
        _load_weights(base, weights)
        teacher = apply(base.to(device).eval(), x, device)
        if outs.get("base"):
            write_wav(outs["base"], teacher, RATE)
    elif req.get("teacher"):
        teacher, r2 = read_wav(req["teacher"])
        if r2 != RATE:
            raise ValueError(f"{req['teacher']} is {r2} Hz, not {RATE}")
        if teacher.numel() < x.numel():
            teacher = torch.nn.functional.pad(
                teacher, (0, x.numel() - teacher.numel()))
    model, rep = train(x, free, req.get("voiced") or [], weights=weights,
                       minutes=float(p.get("minutes", 5.0)),
                       max_steps=int(p.get("max_steps", 400)),
                       seed=int(p.get("seed", 4321)), device=device,
                       teacher=teacher)
    _write_bytes(outs["model"], _state_bytes(model))
    write_wav(outs["output"], apply(model, x, device), RATE)
    applied = []
    for item in req.get("also") or []:
        y, r2 = read_wav(item["wav"])
        if r2 != RATE:
            raise ValueError(f"{item['wav']} is {r2} Hz, not {RATE}")
        write_wav(item["output"], apply(model, y, device), RATE)
        applied.append(item["output"])
    rep.update(rate=RATE, applied=applied, versions=_versions(device),
               duration_s=round(x.numel() / RATE, 3))
    return rep


def apply_op(req) -> dict:
    import torch  # noqa: F401 — no torch fails here, before any work
    device = _device(req.get("device", "auto"))
    model = _build_gtcrn()
    _load_weights(model, req["model"])
    model = model.to(device).eval()
    x, rate = read_wav(req["wav"])
    if rate != RATE:
        raise ValueError(f"{req['wav']} is {rate} Hz, not {RATE}")
    write_wav(req["output"], apply(model, x, device), RATE)
    return {"rate": RATE, "versions": _versions(device)}


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    op = req.get("op")
    if op == "selftrain":
        out = selftrain_op(req)
    elif op == "apply":
        out = apply_op(req)
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
        print(f"selftrain_worker failed: {type(exc).__name__}: {exc}",
              flush=True)
        sys.exit(1)
