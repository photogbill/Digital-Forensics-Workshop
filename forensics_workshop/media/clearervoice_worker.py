# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
#
# The section marked "the network" below is a port to plain torch:
# ClearerVoice-Studio's MossFormer2_SS_16K network (the same layers and
# parameter names; einops and rotary_embedding_torch replaced by plain
# torch), used under its licence:
#
#   Copyright 2024 Alibaba Inc. (ClearerVoice-Studio, Shengkui Zhao et al.)
#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain a
#   copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.
#
#   Its MaskNet/Encoder/Decoder are modified from SpeechBrain's dual_path.py
#   (Apache-2.0). Its rotary position embedding follows Phil Wang's
#   rotary-embedding-torch 0.8.3 (MIT, Copyright (c) 2021 Phil Wang).
#   Changes here: re-implemented in plain torch, inference only; the
#   segmented decoding and the speaker selection below are ours.
"""ClearerVoice's two-speaker separator, steered to ONE speaker — HARK's
Move 7, second half (FORENSICS_PLAN §15, HARK_PLAN.md).

Run as its own process in ``envs\\atk_audio`` (torch only). Ops:

* ``selfcheck`` — load the weights strictly into the port and separate a
  mixture of two clean phrases (given), reporting how far each separated
  stream beats the mixture (SI-SNR improvement). If the port and the
  published weights disagree in any parameter name or shape, it refuses and
  names them.
* ``tse`` — target-speaker extraction: MossFormer2_SS_16K separates each 2 s
  window into two streams; consecutive windows are put in the same order by
  their 0.5 s overlap; and in every window where HARK's Move 2 pulled the
  target voice, the stream whose spectrum follows that voice is the target —
  the speaker's own voice, made by HARK from this file, is the profile that
  steers the choice. Windows with no evidence keep the choice of the nearest
  window that had some. Writes the target and the other stream.

Request/response are JSON files, as for every HARK worker.
"""

from __future__ import annotations

import json
import math
import os
import struct
import sys
import time

RATE = 16000
WINDOW_S, STRIDE_S = 2.0, 1.5          # ClearerVoice's own decode window
EMBED = 512
SEQ_DIM = 512
LAYERS = 24
KERNEL = 16
SPEAKERS = 2
GROUP = 256
QK_DIM = 128
EXPANSION = 4.0
ROT_DIM = 32
TARGET_RMS = 10 ** (-25 / 20)         # ClearerVoice's input level
MIN_EVIDENCE = 0.05                    # share of a window the voice must fill


def _say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# WAV in and out (float32 or 16-bit PCM mono)
# ---------------------------------------------------------------------------

def read_wav(path):
    import torch
    raw = open(path, "rb").read()
    pos, fmt, ch, rate, bits, data = 12, 1, 1, RATE, 16, b""
    while pos + 8 <= len(raw):
        cid = raw[pos:pos + 4]
        size = struct.unpack("<I", raw[pos + 4:pos + 8])[0]
        body = raw[pos + 8:pos + 8 + size]
        if cid == b"fmt ":
            fmt, ch, rate = struct.unpack("<HHI", body[:8])
            bits = struct.unpack("<H", body[14:16])[0]
            if fmt == 0xFFFE:
                fmt = struct.unpack("<H", body[24:26])[0]
        elif cid == b"data":
            data = body
            break
        pos += 8 + size + (size & 1)
    if fmt == 3:
        x = torch.frombuffer(bytearray(data), dtype=torch.float32)
    elif bits == 16:
        x = torch.frombuffer(bytearray(data), dtype=torch.int16).float() / 32768
    else:
        raise ValueError(f"{path}: {bits}-bit format {fmt} is not read here")
    if ch > 1:
        x = x[: x.numel() // ch * ch].view(-1, ch).mean(1)
    return x.clone(), rate


def _write_bytes(path, data: bytes) -> None:
    tmp = path + ".part"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def write_wav(path, x, rate: int) -> None:
    pcm = x.float().cpu().numpy().tobytes()
    fmt = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
            + struct.pack("<II", 4, x.numel()) + b"data"
            + struct.pack("<I", len(pcm)) + pcm)
    _write_bytes(os.fspath(path), b"RIFF" + struct.pack("<I", len(body))
                 + body)


def _write_json(path, data) -> None:
    _write_bytes(os.fspath(path), json.dumps(data, indent=1).encode("utf-8"))


def _device(name: str) -> str:
    import torch
    if name in ("", "auto"):
        return "cuda" if torch.cuda.is_available() else "cpu"
    return name


def _versions(device: str) -> dict:
    import torch
    return {"torch": torch.__version__, "device": device,
            "gpu": torch.cuda.get_device_name(0)
            if device == "cuda" else ""}


# ---------------------------------------------------------------------------
# the network (MossFormer2_SS_16K)
# ---------------------------------------------------------------------------

def _build():
    import torch
    import torch.nn as nn
    import torch.nn.functional as F

    class ScaleNorm(nn.Module):
        def __init__(self, dim, eps=1e-5):
            super().__init__()
            self.scale = dim ** -0.5
            self.eps = eps
            self.g = nn.Parameter(torch.ones(1))

        def forward(self, x):
            n = torch.norm(x, dim=-1, keepdim=True) * self.scale
            return x / n.clamp(min=self.eps) * self.g

    class ScaledSinuEmbedding(nn.Module):
        def __init__(self, dim):
            super().__init__()
            self.scale = nn.Parameter(torch.ones(1))
            inv = 1.0 / (10000 ** (torch.arange(0, dim, 2).float() / dim))
            self.register_buffer("inv_freq", inv)

        def forward(self, x):
            t = torch.arange(x.shape[1], device=x.device).type_as(
                self.inv_freq)
            s = t[:, None] * self.inv_freq[None, :]
            return torch.cat((s.sin(), s.cos()), dim=-1) * self.scale

    class OffsetScale(nn.Module):
        def __init__(self, dim, heads=1):
            super().__init__()
            self.gamma = nn.Parameter(torch.ones(heads, dim))
            self.beta = nn.Parameter(torch.zeros(heads, dim))

        def forward(self, x):
            out = x[..., None, :] * self.gamma + self.beta
            return out.unbind(dim=-2)

    class Rotary(nn.Module):
        """rotary-embedding-torch 0.8.3 'lang' frequencies, interleaved
        pairs, applied to the first `dim` features; `freqs` is a frozen
        parameter there, so it is one here (and in the state dict)."""

        def __init__(self, dim, theta=10000.0):
            super().__init__()
            freqs = 1.0 / (theta ** (torch.arange(0, dim, 2)[:dim // 2]
                                     .float() / dim))
            self.freqs = nn.Parameter(freqs, requires_grad=False)

        def rotate(self, t):
            n = t.shape[-2]
            pos = torch.arange(n, device=t.device, dtype=self.freqs.dtype)
            f = pos[:, None] * self.freqs[None, :]
            f = f.repeat_interleave(2, dim=-1)              # (n r) r = 2
            rd = f.shape[-1]
            mid = t[..., :rd].float()
            x = mid.view(*mid.shape[:-1], rd // 2, 2)
            x1, x2 = x.unbind(-1)
            half = torch.stack((-x2, x1), dim=-1).view_as(mid)
            mid = mid * f.cos() + half * f.sin()
            return torch.cat((mid.to(t.dtype), t[..., rd:]), dim=-1)

    class Transpose(nn.Module):
        def __init__(self, shape):
            super().__init__()
            self.shape = shape

        def forward(self, x):
            return x.transpose(*self.shape)

    class DepthwiseConv1d(nn.Module):
        def __init__(self, cin, cout, k, stride=1, padding=0, bias=False):
            super().__init__()
            self.conv = nn.Conv1d(cin, cout, k, groups=cin, stride=stride,
                                  padding=padding, bias=bias)

        def forward(self, x):
            return self.conv(x)

    class ConvModule(nn.Module):
        def __init__(self, cin, k=17):
            super().__init__()
            self.sequential = nn.Sequential(
                Transpose((1, 2)),
                DepthwiseConv1d(cin, cin, k, 1, (k - 1) // 2))

        def forward(self, x):
            return x + self.sequential(x).transpose(1, 2)

    class FFConvM(nn.Module):
        def __init__(self, din, dout, norm_klass=nn.LayerNorm):
            super().__init__()
            self.mdl = nn.Sequential(norm_klass(din), nn.Linear(din, dout),
                                     nn.SiLU(), ConvModule(dout),
                                     nn.Dropout(0.1))

        def forward(self, x):
            return self.mdl(x)

    class Flash(nn.Module):           # FLASH_ShareA_FFConvM
        def __init__(self, dim, rotary):
            super().__init__()
            hidden = int(dim * EXPANSION)
            self.group_size = GROUP
            self.rotary_pos_emb = rotary
            self.to_hidden = FFConvM(dim, hidden, ScaleNorm)
            self.to_qk = FFConvM(dim, QK_DIM, ScaleNorm)
            self.qk_offset_scale = OffsetScale(QK_DIM, heads=4)
            self.to_out = FFConvM(dim * 2, dim, ScaleNorm)

        def forward(self, x):
            residual = x
            xs, xp = x.chunk(2, dim=-1)
            xs = F.pad(xs, (0, 0, 1, -1), value=0.0)
            x = torch.cat((xs, xp), dim=-1)
            v, u = self.to_hidden(x).chunk(2, dim=-1)
            qk = self.to_qk(x)
            qq, lq, qk_, lk = self.qk_offset_scale(qk)
            av, au = self.attention(x, qq, lq, qk_, lk, v, u)
            out = (au * v) * torch.sigmoid(av * u)
            return residual + self.to_out(out)

        def attention(self, x, qq, lq, kk, lk, v, u):
            b, n, g = x.shape[0], x.shape[-2], self.group_size
            r = self.rotary_pos_emb.rotate
            qq, lq, kk, lk = r(qq), r(lq), r(kk), r(lk)
            pad = (g - n % g) % g
            mask = None
            if pad:
                qq, kk, lq, lk, v, u = (F.pad(t, (0, 0, 0, pad), value=0.0)
                                        for t in (qq, kk, lq, lk, v, u))
                mask = F.pad(torch.ones((b, n), device=x.device,
                                        dtype=torch.bool), (0, pad),
                             value=False)
            G = (n + pad) // g

            def grp(t):
                return t.reshape(b, G, g, t.shape[-1])
            qq, kk, lq, lk, v, u = map(grp, (qq, kk, lq, lk, v, u))
            sim = torch.einsum("bgid,bgjd->bgij", qq, kk) / g
            attn = F.relu(sim) ** 2
            if mask is not None:
                attn = attn.masked_fill(~mask.reshape(b, G, 1, g), 0.0)
            qv = torch.einsum("bgij,bgjd->bgid", attn, v)
            qu = torch.einsum("bgij,bgjd->bgid", attn, u)
            kv = torch.einsum("bgnd,bgne->bde", lk, v) / n
            lv = torch.einsum("bgnd,bde->bgne", lq, kv)
            ku = torch.einsum("bgnd,bgne->bde", lk, u) / n
            lu = torch.einsum("bgnd,bde->bgne", lq, ku)
            return ((qv + lv).reshape(b, G * g, -1)[:, :n],
                    (qu + lu).reshape(b, G * g, -1)[:, :n])

    class CLayerNorm(nn.LayerNorm):
        def forward(self, x):
            return super().forward(x.transpose(1, 2)).transpose(1, 2)

    class DilatedDenseNet(nn.Module):
        def __init__(self, depth=2, lorder=20, cin=64):
            super().__init__()
            self.depth = depth
            k = (lorder * 2 - 1, 1)
            for i in range(depth):
                dil = 2 ** i
                p = lorder + (dil - 1) * (lorder - 1) - 1
                setattr(self, f"pad{i + 1}",
                        nn.ConstantPad2d((0, 0, p, p), value=0.0))
                setattr(self, f"conv{i + 1}",
                        nn.Conv2d(cin * (i + 1), cin, kernel_size=k,
                                  dilation=(dil, 1), groups=cin, bias=False))
                setattr(self, f"norm{i + 1}",
                        nn.InstanceNorm2d(cin, affine=True))
                setattr(self, f"prelu{i + 1}", nn.PReLU(cin))

        def forward(self, x):
            skip = x
            for i in range(self.depth):
                out = getattr(self, f"pad{i + 1}")(skip)
                out = getattr(self, f"conv{i + 1}")(out)
                out = getattr(self, f"norm{i + 1}")(out)
                out = getattr(self, f"prelu{i + 1}")(out)
                skip = torch.cat([out, skip], dim=1)
            return out

    class UniDeepFsmnDilated(nn.Module):
        def __init__(self, din, dout, lorder, hidden):
            super().__init__()
            self.linear = nn.Linear(din, hidden)
            self.project = nn.Linear(hidden, dout, bias=False)
            self.conv = DilatedDenseNet(2, lorder, dout)

        def forward(self, x):
            p = self.project(F.relu(self.linear(x)))
            out = self.conv(p.unsqueeze(1).permute(0, 3, 2, 1))
            return x + out.permute(0, 3, 2, 1)[:, 0]

    class GatedFsmnDilated(nn.Module):
        def __init__(self, cin, cout, lorder, hidden):
            super().__init__()
            self.to_u = FFConvM(cin, hidden)
            self.to_v = FFConvM(cin, hidden)
            self.fsmn = UniDeepFsmnDilated(cin, cout, lorder, hidden)

        def forward(self, x):
            return self.to_v(x) * self.fsmn(self.to_u(x)) + x

    class GatedFsmnBlockDilated(nn.Module):
        def __init__(self, dim, inner=256):
            super().__init__()
            self.conv1 = nn.Sequential(nn.Conv1d(dim, inner, 1), nn.PReLU())
            self.norm1 = CLayerNorm(inner)
            self.gated_fsmn = GatedFsmnDilated(inner, inner, 20, inner)
            self.norm2 = CLayerNorm(inner)
            self.conv2 = nn.Conv1d(inner, dim, 1)

        def forward(self, x):
            c1 = self.norm1(self.conv1(x.transpose(2, 1)))
            s = self.gated_fsmn(c1.transpose(2, 1))
            return self.conv2(self.norm2(s.transpose(2, 1))).transpose(2, 1) \
                + x

    class MossformerBlockGFSMN(nn.Module):
        def __init__(self, dim, depth):
            super().__init__()
            rotary = Rotary(min(ROT_DIM, QK_DIM))
            self.fsmn = nn.ModuleList([GatedFsmnBlockDilated(dim)
                                       for _ in range(depth)])
            self.layers = nn.ModuleList([Flash(dim, rotary)
                                         for _ in range(depth)])

        def forward(self, x):
            for flash, fsmn in zip(self.layers, self.fsmn):
                x = fsmn(flash(x))
            return x

    class MossFormerM(nn.Module):
        def __init__(self, num_blocks, d_model):
            super().__init__()
            self.mossformerM = MossformerBlockGFSMN(d_model, num_blocks)
            self.norm = nn.LayerNorm(d_model, eps=1e-6)

        def forward(self, x):
            return self.norm(self.mossformerM(x))

    class ComputationBlock(nn.Module):
        def __init__(self, num_blocks, ch):
            super().__init__()
            self.intra_mdl = MossFormerM(num_blocks, ch)
            self.intra_norm = nn.GroupNorm(1, ch, eps=1e-8)

        def forward(self, x):
            intra = self.intra_mdl(x.permute(0, 2, 1).contiguous())
            intra = self.intra_norm(intra.permute(0, 2, 1).contiguous())
            return intra + x

    class MaskNet(nn.Module):
        def __init__(self, cin, cout, num_blocks, spks):
            super().__init__()
            self.num_spks = spks
            self.norm = nn.GroupNorm(1, cin, eps=1e-8)
            self.conv1d_encoder = nn.Conv1d(cin, cout, 1, bias=False)
            self.pos_enc = ScaledSinuEmbedding(cout)
            self.mdl = ComputationBlock(num_blocks, cout)
            self.conv1d_out = nn.Conv1d(cout, cout * spks, kernel_size=1)
            self.conv1_decoder = nn.Conv1d(cout, cin, 1, bias=False)
            self.prelu = nn.PReLU()
            self.output = nn.Sequential(nn.Conv1d(cout, cout, 1), nn.Tanh())
            self.output_gate = nn.Sequential(nn.Conv1d(cout, cout, 1),
                                             nn.Sigmoid())

        def forward(self, x):
            x = self.conv1d_encoder(self.norm(x))
            emb = self.pos_enc(x.transpose(1, -1)).transpose(0, -1)
            x = self.mdl(x + emb)
            x = self.conv1d_out(self.prelu(x))
            B, _, S = x.shape
            x = x.view(B * self.num_spks, -1, S)
            x = self.conv1_decoder(self.output(x) * self.output_gate(x))
            _, N, L = x.shape
            return F.relu(x.view(B, self.num_spks, N, L)).transpose(0, 1)

    class Encoder(nn.Module):
        def __init__(self, k, cout):
            super().__init__()
            self.conv1d = nn.Conv1d(1, cout, k, stride=k // 2, bias=False)

        def forward(self, x):
            return F.relu(self.conv1d(x.unsqueeze(1)))

    class MossFormer(nn.Module):
        def __init__(self):
            super().__init__()
            self.num_spks = SPEAKERS
            self.enc = Encoder(KERNEL, EMBED)
            self.mask_net = MaskNet(EMBED, SEQ_DIM, LAYERS, SPEAKERS)
            self.dec = nn.ConvTranspose1d(SEQ_DIM, 1, KERNEL,
                                          stride=KERNEL // 2, bias=False)

        def forward(self, wav):
            x = self.enc(wav)
            mask = self.mask_net(x)
            sep = torch.stack([x] * self.num_spks) * mask
            outs = [self.dec(sep[i]).squeeze(1) for i in range(self.num_spks)]
            T = wav.shape[1]
            return [F.pad(o, (0, max(0, T - o.shape[1])))[:, :T]
                    for o in outs]

    return MossFormer()


def load_model(weights: str, device: str):
    """The port with the published weights, loaded strictly: every
    parameter's name and shape must match, or this refuses and names them."""
    import torch
    net = _build()
    ck = torch.load(weights, map_location="cpu", weights_only=True)
    sd = ck.get("model", ck) if isinstance(ck, dict) else ck
    sd = {k[7:] if k.startswith("module.") else k: v for k, v in sd.items()}
    own = net.state_dict()
    if sd and all(k.startswith("model.") for k in sd):
        sd = {k[6:]: v for k, v in sd.items()}
    missing = [k for k in own if k not in sd and "rotary_pos_emb" not in k]
    extra = [k for k in sd if k not in own]
    shape = [k for k in own if k in sd and tuple(sd[k].shape)
             != tuple(own[k].shape)]
    if missing or extra or shape:
        raise ValueError(
            "the published MossFormer2_SS_16K weights do not fit this port: "
            f"{len(missing)} missing (e.g. {missing[:4]}), {len(extra)} "
            f"unexpected (e.g. {extra[:4]}), {len(shape)} of another shape "
            f"(e.g. {shape[:4]})")
    for k in own:
        if k not in sd:       # the rotary frequencies: fixed, made above
            sd[k] = own[k]
    net.load_state_dict({k: sd[k] for k in own}, strict=True)
    return net.to(device).eval(), sum(p.numel() for p in net.parameters())


def separate(net, x, device: str):
    """Both streams for every 2 s window, put in one order across the file
    by the windows' 0.5 s overlaps; the edges of each window (where the
    model sees least) given up, as ClearerVoice's own decoder does.
    Returns (streams [2, n], window starts, the order flips made)."""
    import torch
    w, st = int(WINDOW_S * RATE), int(STRIDE_S * RATE)
    give = (w - st) // 2
    n = x.numel()
    total = max(w, n if (n - w) % st == 0 else n + st - (n - w) % st)
    xp = torch.zeros(total)
    xp[:n] = x
    out = torch.zeros(SPEAKERS, total)
    starts, prev, flips = [], None, 0
    with torch.no_grad():
        for a in range(0, total - w + 1, st):
            seg = xp[a:a + w]
            rms = float(seg.pow(2).mean().sqrt())
            scale = TARGET_RMS / max(rms, 1e-8)
            ys = net((seg * scale)[None].to(device))
            ys = torch.stack([y[0].cpu() for y in ys]) / scale
            if prev is not None:
                ov_a, ov_b = prev[:, st:], ys[:, :w - st]

                def score(p):
                    return sum(float(torch.nn.functional.cosine_similarity(
                        ov_a[i], ov_b[p[i]], dim=0)) for i in range(2))
                if score((1, 0)) > score((0, 1)):
                    ys = ys.flip(0)
                    flips += 1
            lo = 0 if a == 0 else give
            hi = w if a + w >= total else w - give
            out[:, a + lo:a + hi] = ys[:, lo:hi]
            starts.append(a)
            prev = ys
    return out[:, :n], starts, flips


def _spec(x, n_fft=512, hop=160):
    import torch
    X = torch.stft(x, n_fft, hop, n_fft, torch.hann_window(n_fft),
                   return_complex=True).abs()
    return torch.log1p(X * 100.0)


def choose(streams, voice, starts):
    """Per window, the stream whose spectrum follows HARK's Move 2 voice
    (where that voice fills at least MIN_EVIDENCE of the window); windows
    without evidence keep the nearest choice. Returns (target, other,
    choices)."""
    import torch
    w, st = int(WINDOW_S * RATE), int(STRIDE_S * RATE)
    give = (w - st) // 2
    n = streams.shape[1]
    S = [_spec(s) for s in streams]
    V = _spec(voice[:n]) if voice is not None else None
    hop = 160
    picks = []
    for a in starts:
        f0, f1 = a // hop, min(S[0].shape[1], (a + w) // hop)
        if V is None or f1 <= f0:
            picks.append(None)
            continue
        vseg = V[:, f0:f1]
        active = (voice[a:a + w].abs() > 1e-4).float().mean() \
            if voice is not None else 0.0
        if float(active) < MIN_EVIDENCE:
            picks.append(None)
            continue
        sc = [float(torch.nn.functional.cosine_similarity(
            s[:, f0:f1].flatten(), vseg.flatten(), dim=0)) for s in S]
        picks.append((int(sc[1] > sc[0]), sc))
    known = [i for i, p in enumerate(picks) if p is not None]
    choice = []
    for i, p in enumerate(picks):
        if p is not None:
            choice.append(p[0])
        elif known:
            j = min(known, key=lambda k: abs(k - i))
            choice.append(picks[j][0])
        else:
            choice.append(0)
    target, other = torch.zeros(n), torch.zeros(n)
    for i, a in enumerate(starts):
        lo = 0 if i == 0 else give
        hi = w if i == len(starts) - 1 else w - give
        c = choice[i]
        target[a + lo:min(n, a + hi)] = streams[c, a + lo:min(n, a + hi)]
        other[a + lo:min(n, a + hi)] = streams[1 - c, a + lo:min(n, a + hi)]
    rows = [{"start_s": round(a / RATE, 2), "stream": choice[i],
             "evidence": None if picks[i] is None else
             [round(v, 3) for v in picks[i][1]]}
            for i, a in enumerate(starts)]
    return target, other, rows


def si_snr(est, ref) -> float:
    est, ref = est - est.mean(), ref - ref.mean()
    proj = (est @ ref) / max(1e-12, float(ref @ ref)) * ref
    noise = est - proj
    return 10 * math.log10(max(1e-12, float(proj @ proj))
                           / max(1e-12, float(noise @ noise)))


def _resample(x, r_in: int, r_out: int):
    """Band-limited resampling by FFT — enough for a self-check."""
    import torch
    if r_in == r_out:
        return x
    n_out = int(round(x.numel() * r_out / r_in))
    X = torch.fft.rfft(x.double())
    Y = torch.zeros(n_out // 2 + 1, dtype=X.dtype)
    m = min(X.numel(), Y.numel())
    Y[:m] = X[:m]
    return (torch.fft.irfft(Y, n_out) * (n_out / x.numel())).float()


def selfcheck_op(req) -> dict:
    device = _device(req.get("device", "auto"))
    net, n_params = load_model(req["weights"], device)
    a, ra = read_wav(req["a"])
    b, rb = read_wav(req["b"])
    a, b = _resample(a, ra, RATE), _resample(b, rb, RATE)
    n = min(a.numel(), b.numel(), int(6 * RATE))
    a, b = a[:n] / a[:n].std(), b[:n] / b[:n].std()
    mix = a + b
    streams, _starts, flips = separate(net, mix, device)
    base = (si_snr(mix, a) + si_snr(mix, b)) / 2
    best = max((si_snr(streams[0], a) + si_snr(streams[1], b)) / 2,
               (si_snr(streams[1], a) + si_snr(streams[0], b)) / 2)
    _say(f"selfcheck: {n_params} parameters; mixture {base:.1f} dB, "
         f"separated {best:.1f} dB (+{best - base:.1f} dB)")
    return {"parameters": n_params, "mixture_si_snr_db": round(base, 2),
            "separated_si_snr_db": round(best, 2),
            "improvement_db": round(best - base, 2), "flips": flips,
            "versions": _versions(device)}


def tse_op(req) -> dict:
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    if rate != RATE:
        raise ValueError(f"MossFormer2_SS_16K needs 16 kHz, not {rate} Hz")
    voice = None
    if req.get("voice"):
        voice, vr = read_wav(req["voice"])
        if vr != RATE:
            raise ValueError("the steering voice must be 16 kHz too")
    net, n_params = load_model(req["weights"], device)
    _say(f"tse: {x.numel() / RATE:.1f} s, {n_params} parameters, on "
         f"{device}")
    streams, starts, flips = separate(net, x, device)
    target, other, rows = choose(streams, voice, starts)
    out = req["outputs"]
    write_wav(out["target"], target, RATE)
    write_wav(out["other"], other, RATE)
    steered = sum(1 for r in rows if r["evidence"] is not None)
    _say(f"tse: {len(rows)} windows, {steered} steered by the voice, "
         f"{flips} order flips")
    return {"windows": rows, "steered": steered, "flips": flips,
            "parameters": n_params, "versions": _versions(device)}


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    op = req.get("op")
    if op == "selfcheck":
        out = selfcheck_op(req)
    elif op == "tse":
        out = tse_op(req)
    else:
        raise ValueError(f"unknown op {op!r}")
    out["op"] = op
    out["elapsed_s"] = round(time.monotonic() - started, 3)
    _write_json(response_path, out)
    _say(f"done in {out['elapsed_s']:.1f} s")
    return 0


def main(argv) -> int:
    if len(argv) != 3:
        print("usage: clearervoice_worker.py REQUEST.json RESPONSE.json",
              file=sys.stderr)
        return 2
    try:
        return run(argv[1], argv[2])
    except Exception as exc:                              # noqa: BLE001
        print(f"{type(exc).__name__}: {exc}", flush=True)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
