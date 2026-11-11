# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""HARK's generative lane — Move 4, with M2 and M6 (FORENSICS_PLAN §15,
HARK_PLAN.md). Our own code throughout; torch only. Run as its own process
in ``envs\\atk_audio``.

A **speech prior** is a score model (a small 2-D U-Net in the EDM
formulation — Karras et al. 2022) that has learnt what clean speech looks
like in a compressed complex spectrogram. It is trained on CC BY 4.0 speech
(LibriSpeech's training sets) on the operator's GPU — that takes days, and
is what ``train_prior.bat`` runs; nothing here ships trained weights.

Posterior sampling then GUESSES the speech under the noise, honestly:

* the file's own noise is modelled per frequency and time by NMF (low rank,
  Itakura-Saito), first fitted on HARK's voice-free stretches and refitted
  by EM on what each guess leaves (after Nortier et al.'s UDiffSE and Ayilo
  et al.'s NMF noise model);
* each reverse step denoises with the prior, then pulls the guess back to
  what the recording allows — a closed-form data step per bin under that
  noise model (DiffPIR-style, Zhu et al. 2023), in the LINEAR spectrum where
  the noise adds;
* many samples, each with its own seed: their mean is the guess, their
  spread per time-frequency cell is the **uncertainty map** — where the
  samples disagree, the prior is talking, not the recording;
* a consistency check: what each guess leaves should look like the noise
  model (|residual|^2 / noise variance about 1); cells far above it are
  flagged.

**M2** runs it with two priors trained on different speech: content that
survives the swap came from the recording; the per-cell difference is a
"prior dependence" map. **M6** fine-tunes a prior a little on the confident
speech HARK found of this speaker (and only with Move 5 measuring before and
after, in the engine).

Everything it makes is **Invented** — a measured guess, never evidence.

Ops (request/response JSON, like every HARK worker):
``prepare`` (speech files to training shards, via FFmpeg), ``train``
(resumable, checkpoints), ``sample`` (Move 4 / M2), ``finetune`` (M6),
``info`` (what a prior file holds).
"""

from __future__ import annotations

import json
import math
import os
import struct
import subprocess
import sys
import time

RATE = 16000
N_FFT, HOP = 510, 128                 # 256 frequency bins
COMPRESS, SCALE = 0.5, 0.15           # |X|^0.5 * 0.15 (SGMSE's compression)
SIGMA_DATA = 0.5
SIGMA_MIN, SIGMA_MAX, RHO = 0.002, 10.0, 7.0
P_MEAN, P_STD = -1.2, 1.2
CROP_FRAMES = 256                     # about 2 s per training example
NMF_RANK = 8
SHARD_S = 3600                        # one hour of speech per shard
CONFIGS = {
    # channels per level, residual blocks per level
    "tiny": {"ch": (16, 32, 64), "blocks": 1},
    "small": {"ch": (32, 64, 128), "blocks": 2},
    "base": {"ch": (64, 128, 256), "blocks": 2},
}


def _say(text: str) -> None:
    print(text, flush=True)


# ---------------------------------------------------------------------------
# files
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
    tmp = os.fspath(path) + ".part"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, os.fspath(path))


def write_wav(path, x, rate: int) -> None:
    pcm = x.float().cpu().numpy().tobytes()
    fmt = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
            + struct.pack("<II", 4, x.numel()) + b"data"
            + struct.pack("<I", len(pcm)) + pcm)
    _write_bytes(path, b"RIFF" + struct.pack("<I", len(body)) + body)


def _append_text(path, text: str) -> None:
    """A line added to a log or a list beside the worker's own output."""
    with open(os.fspath(path), "a", encoding="utf-8") as fh:
        fh.write(text)


def _ensure_dir(path) -> None:
    os.makedirs(os.fspath(path), exist_ok=True)


def _write_json(path, data) -> None:
    _write_bytes(path, json.dumps(data, indent=1).encode("utf-8"))


def _save_torch(obj, path) -> None:
    import io
    import torch
    buf = io.BytesIO()
    torch.save(obj, buf)
    _write_bytes(path, buf.getvalue())


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
# the spectrum: linear complex, and the prior's compressed form
# ---------------------------------------------------------------------------

def _window(device="cpu"):
    import torch
    return torch.hann_window(N_FFT, periodic=True, device=device).sqrt()


def stft(x):
    import torch
    return torch.stft(x, N_FFT, HOP, N_FFT, _window(x.device), center=True,
                      return_complex=True)


def istft(X, length: int):
    import torch
    return torch.istft(X, N_FFT, HOP, N_FFT, _window(X.device), center=True,
                       length=length)


def compress(X):
    """Linear complex spectrum -> the prior's [.., 2, F, T] real tensor."""
    import torch
    mag = X.abs().clamp(min=1e-12)
    C = mag ** COMPRESS * SCALE * (X / mag)
    return torch.stack([C.real, C.imag], dim=-3)


def decompress(C):
    """The prior's [.., 2, F, T] -> linear complex spectrum."""
    import torch
    Z = torch.complex(C[..., 0, :, :], C[..., 1, :, :])
    mag = Z.abs().clamp(min=1e-12)
    return (mag / SCALE) ** (1.0 / COMPRESS) * (Z / mag)


# ---------------------------------------------------------------------------
# the score network (EDM preconditioning around a small U-Net)
# ---------------------------------------------------------------------------

def build_net(config: str = "small"):
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    cfg = CONFIGS[config]
    chans, nblocks = cfg["ch"], cfg["blocks"]
    emb_dim = chans[0] * 4

    class Fourier(nn.Module):
        def __init__(self, dim):
            super().__init__()
            self.register_buffer("freqs", torch.randn(dim // 2) * 16.0)

        def forward(self, c):
            a = c[:, None] * self.freqs[None, :] * 2 * math.pi
            return torch.cat([a.cos(), a.sin()], dim=1)

    class Res(nn.Module):
        def __init__(self, cin, cout):
            super().__init__()
            self.n1 = nn.GroupNorm(min(8, cin), cin)
            self.c1 = nn.Conv2d(cin, cout, 3, padding=1)
            self.e = nn.Linear(emb_dim, cout * 2)
            self.n2 = nn.GroupNorm(min(8, cout), cout)
            self.c2 = nn.Conv2d(cout, cout, 3, padding=1)
            self.skip = nn.Conv2d(cin, cout, 1) if cin != cout else \
                nn.Identity()

        def forward(self, x, emb):
            h = self.c1(F.silu(self.n1(x)))
            s, b = self.e(emb)[:, :, None, None].chunk(2, dim=1)
            h = self.n2(h) * (1 + s) + b
            h = self.c2(F.silu(h))
            return h + self.skip(x)

    class UNet(nn.Module):
        def __init__(self):
            super().__init__()
            self.fourier = Fourier(chans[0])
            self.emb = nn.Sequential(nn.Linear(chans[0], emb_dim), nn.SiLU(),
                                     nn.Linear(emb_dim, emb_dim))
            self.inp = nn.Conv2d(2, chans[0], 3, padding=1)
            self.down = nn.ModuleList()
            self.pools = nn.ModuleList()
            c = chans[0]
            skips = []
            for i, ch in enumerate(chans):
                blocks = nn.ModuleList()
                for _ in range(nblocks):
                    blocks.append(Res(c, ch))
                    c = ch
                self.down.append(blocks)
                skips.append(c)
                self.pools.append(nn.Conv2d(c, c, 3, stride=2, padding=1)
                                  if i < len(chans) - 1 else nn.Identity())
            self.mid = Res(c, c)
            self.up = nn.ModuleList()
            self.ups = nn.ModuleList()
            for i, ch in reversed(list(enumerate(chans))):
                blocks = nn.ModuleList()
                for j in range(nblocks):
                    blocks.append(Res(c + (skips[i] if j == 0 else 0), ch))
                    c = ch
                self.up.append(blocks)
                self.ups.append(nn.ConvTranspose2d(c, c, 4, stride=2,
                                                   padding=1)
                                if i > 0 else nn.Identity())
            self.out = nn.Sequential(nn.GroupNorm(min(8, c), c), nn.SiLU(),
                                     nn.Conv2d(c, 2, 3, padding=1))

        def forward(self, x, c_noise):
            emb = self.emb(self.fourier(c_noise))
            h = self.inp(x)
            hs = []
            for blocks, pool in zip(self.down, self.pools):
                for b in blocks:
                    h = b(h, emb)
                hs.append(h)
                h = pool(h)
            h = self.mid(h, emb)
            for blocks, up in zip(self.up, self.ups):
                skip = hs.pop()
                if h.shape[-2:] != skip.shape[-2:]:
                    h = F.interpolate(h, size=skip.shape[-2:])
                h = torch.cat([h, skip], dim=1)
                for b in blocks:
                    h = b(h, emb)
                h = up(h)
            return self.out(h)

    class Denoiser(nn.Module):
        """D(x; sigma): EDM's preconditioned denoiser — its best guess of
        the clean compressed spectrum from one at noise level sigma."""

        def __init__(self):
            super().__init__()
            self.net = UNet()

        def forward(self, x, sigma):
            sigma = sigma.reshape(-1, 1, 1, 1).to(x.dtype)
            c_skip = SIGMA_DATA ** 2 / (sigma ** 2 + SIGMA_DATA ** 2)
            c_out = sigma * SIGMA_DATA / (sigma ** 2 + SIGMA_DATA ** 2).sqrt()
            c_in = 1 / (SIGMA_DATA ** 2 + sigma ** 2).sqrt()
            F_x = self.net(c_in * x, sigma.log().flatten() / 4)
            return c_skip * x + c_out * F_x

    return Denoiser()


def load_prior(path, device: str):
    import torch
    ck = torch.load(path, map_location="cpu", weights_only=True)
    net = build_net(ck.get("config", "small"))
    net.load_state_dict(ck["ema"] if "ema" in ck else ck["model"])
    return net.to(device).eval(), ck


# ---------------------------------------------------------------------------
# prepare: speech files to one-hour shards of 16 kHz float16
# ---------------------------------------------------------------------------

SPEECH_EXT = (".flac", ".wav", ".ogg", ".mp3")


def _decode(ffmpeg, path):
    import torch
    out = subprocess.run([ffmpeg, "-hide_banner", "-loglevel", "error",
                          "-nostdin", "-i", path, "-ac", "1", "-ar",
                          str(RATE), "-f", "f32le", "-"],
                         capture_output=True, check=True)
    return torch.frombuffer(bytearray(out.stdout), dtype=torch.float32)


def prepare_op(req) -> dict:
    """Every speech file under `source` (LibriSpeech's training folders)
    decoded by FFmpeg to 16 kHz mono and packed into one-hour float16
    shards in `shards`. Resumable: a list of what was packed is kept."""
    import torch
    src, dst, ffmpeg = req["source"], req["shards"], req["ffmpeg"]
    _ensure_dir(dst)
    done_path = os.path.join(dst, "packed.txt")
    done = set(open(done_path, encoding="utf-8").read().split("\n")) \
        if os.path.exists(done_path) else set()
    files = sorted(os.path.join(r, f) for r, _d, fs in os.walk(src)
                   for f in fs if f.lower().endswith(SPEECH_EXT))
    todo = [f for f in files if os.path.relpath(f, src) not in done]
    limit = int(req.get("max_files") or 0)
    if limit:
        todo = todo[:limit]
    _say(f"prepare: {len(files)} speech file(s), {len(todo)} to pack")
    buf, buf_n, packed, tried = [], 0, [], 0
    n_shard = len([f for f in os.listdir(dst) if f.startswith("shard")])

    def flush():
        nonlocal buf, buf_n, n_shard, packed
        if not buf:
            return
        x = torch.cat(buf).to(torch.float16)
        _save_torch({"rate": RATE, "audio": x},
                    os.path.join(dst, f"shard{n_shard:04d}.pt"))
        n_shard += 1
        _append_text(done_path, "\n".join(packed) + "\n")
        _say(f"prepare: shard {n_shard} ({x.numel() / RATE / 60:.0f} min)")
        buf, buf_n, packed = [], 0, []

    for i, f in enumerate(todo):
        try:
            x = _decode(ffmpeg, f)
        except (subprocess.CalledProcessError, OSError) as exc:
            _say(f"prepare: skipped {f}: {exc}")
            continue
        tried += 1
        peak = float(x.abs().max()) if x.numel() else 0.0
        if peak > 0:
            buf.append(x / max(peak, 1e-6) * 0.5)
            buf_n += x.numel()
        packed.append(os.path.relpath(f, src))
        if buf_n >= SHARD_S * RATE:
            flush()
    flush()
    shards = sorted(f for f in os.listdir(dst) if f.startswith("shard"))
    return {"files": len(files), "packed_now": tried,
            "skipped": len(todo) - tried, "shards": len(shards)}


# ---------------------------------------------------------------------------
# train: EDM denoising score matching on random 2 s crops, resumable
# ---------------------------------------------------------------------------

def _crops(shards, gen, batch: int, device: str, gain_db=(-10.0, 6.0)):
    import torch
    n = (CROP_FRAMES - 1) * HOP
    out = []
    for _ in range(batch):
        sh = shards[int(torch.randint(0, len(shards), (1,), generator=gen))]
        a = int(torch.randint(0, max(1, sh.numel() - n), (1,), generator=gen))
        x = sh[a:a + n].float()
        if x.numel() < n:
            x = torch.nn.functional.pad(x, (0, n - x.numel()))
        g = gain_db[0] + (gain_db[1] - gain_db[0]) * float(
            torch.rand(1, generator=gen))
        out.append(x * 10 ** (g / 20))
    X = stft(torch.stack(out).to(device))[..., :CROP_FRAMES]
    return compress(X)


def edm_loss(net, x0, gen):
    import torch
    b = x0.shape[0]
    sigma = (torch.randn(b, generator=gen) * P_STD + P_MEAN).exp().to(
        x0.device)
    noise = torch.randn(x0.shape, generator=gen).to(x0.device)
    w = (sigma ** 2 + SIGMA_DATA ** 2) / (sigma * SIGMA_DATA) ** 2
    d = net(x0 + sigma.reshape(-1, 1, 1, 1) * noise, sigma)
    return (w.reshape(-1, 1, 1, 1) * (d - x0) ** 2).mean()


def train_op(req) -> dict:
    """Train (or resume) a prior: `shards` folder, `out` checkpoint file,
    `config`, `steps`, `minutes`, `batch`, `lr`. An EMA of the weights is
    what sampling uses. Checkpoints every `save_every` steps, atomically."""
    import copy
    import torch
    device = _device(req.get("device", "auto"))
    shard_dir = req["shards"]
    files = sorted(os.path.join(shard_dir, f) for f in os.listdir(shard_dir)
                   if f.startswith("shard") and f.endswith(".pt"))
    if not files:
        raise ValueError(f"no training shards in {shard_dir} — run prepare")
    shards = [torch.load(f, map_location="cpu", weights_only=True)["audio"]
              for f in files[:int(req.get("max_shards") or len(files))]]
    hours = sum(s.numel() for s in shards) / RATE / 3600
    out = req["out"]
    config = req.get("config", "small")
    net = build_net(config).to(device)
    ema = copy.deepcopy(net).eval()
    opt = torch.optim.Adam(net.parameters(), lr=float(req.get("lr", 2e-4)))
    step, seen = 0, 0.0
    if os.path.exists(out):
        ck = torch.load(out, map_location="cpu", weights_only=True)
        if ck.get("config") != config:
            raise ValueError(f"{out} holds a {ck.get('config')} prior, not "
                             f"{config}")
        net.load_state_dict(ck["model"])
        ema.load_state_dict(ck["ema"])
        opt.load_state_dict(ck["opt"])
        step, seen = int(ck["step"]), float(ck.get("seen_hours", 0.0))
        _say(f"train: resumed at step {step}")
    gen = torch.Generator().manual_seed(int(req.get("seed", 1)) + step)
    batch = int(req.get("batch", 16))
    steps = int(req.get("steps", 1000))
    minutes = float(req.get("minutes", 0) or 0)
    save_every = int(req.get("save_every", 500))
    decay = float(req.get("ema", 0.999))
    t0 = time.monotonic()
    losses = []
    n_params = sum(p.numel() for p in net.parameters())
    _say(f"train: {config} prior, {n_params} parameters, {len(shards)} "
         f"shard(s) = {hours:.1f} h of speech, on {device}")

    def save():
        _save_torch({"config": config, "step": step, "model": net.state_dict(),
                     "ema": ema.state_dict(), "opt": opt.state_dict(),
                     "seen_hours": seen, "hours": hours,
                     "loss": sum(losses[-100:]) / max(1, len(losses[-100:])),
                     "rate": RATE, "n_fft": N_FFT, "hop": HOP,
                     "trained_on": req.get("trained_on", "")}, out)

    target = step + steps
    while step < target:
        if minutes and time.monotonic() - t0 > minutes * 60:
            break
        x0 = _crops(shards, gen, batch, device)
        loss = edm_loss(net, x0, gen)
        opt.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(net.parameters(), 1.0)
        opt.step()
        with torch.no_grad():
            for pe, pn in zip(ema.parameters(), net.parameters()):
                pe.mul_(decay).add_(pn.detach(), alpha=1 - decay)
        step += 1
        seen += batch * CROP_FRAMES * HOP / RATE / 3600
        losses.append(loss.item())
        if step % 50 == 0:
            line = (f"{time.strftime('%Y-%m-%d %H:%M:%S')} step {step} loss "
                    f"{sum(losses[-50:]) / 50:.4f} seen {seen:.2f} h")
            _say("train: " + line)
            _append_text(out + ".log.txt", line + "\n")
        if step % save_every == 0:
            save()
    save()
    return {"steps": step, "config": config, "parameters": n_params,
            "hours_of_speech": round(hours, 3),
            "seen_hours": round(seen, 3),
            "loss": round(sum(losses[-100:]) / max(1, len(losses[-100:])), 5)
            if losses else None,
            "elapsed_s": round(time.monotonic() - t0, 1),
            "versions": _versions(device)}


# ---------------------------------------------------------------------------
# the noise model: NMF (Itakura-Saito) on the noise's power spectrum
# ---------------------------------------------------------------------------

def nmf_is(P, rank: int, iters: int, W=None, H=None, gen=None,
           fix_w: bool = False):
    """P ~ W H, Itakura-Saito multiplicative updates. P [F, T] > 0."""
    import torch
    Fq, T = P.shape
    if W is None:
        W = torch.rand(Fq, rank, generator=gen).to(P) * P.mean() + 1e-6
    if H is None:
        H = torch.rand(rank, T, generator=gen).to(P) + 1e-3
    for _ in range(iters):
        V = W @ H + 1e-12
        H = H * (W.t() @ (P * V ** -2)) / (W.t() @ V ** -1 + 1e-20)
        if not fix_w:
            V = W @ H + 1e-12
            W = W * ((P * V ** -2) @ H.t()) / (V ** -1 @ H.t() + 1e-20)
    return W, H


def noise_model(Y, free_frames, rank: int, gen):
    """The noise variance per bin and frame: NMF basis learnt on the
    voice-free frames, activations fitted on every frame (they hold speech
    too, so the activations are fitted to the frame's floor: the lower
    envelope of its power)."""
    import torch
    P = Y.abs() ** 2 + 1e-12
    if free_frames is not None and int(free_frames.sum()) >= 8:
        W, _H = nmf_is(P[:, free_frames], rank, 60, gen=gen)
    else:
        q = P.quantile(0.2, dim=1, keepdim=True)
        W, _H = nmf_is(q.expand(-1, 16).contiguous(), rank, 60, gen=gen)
    floor = torch.minimum(P, P.median(dim=0, keepdim=True).values * 4)
    _W, H = nmf_is(floor, rank, 40, W=W, gen=gen, fix_w=True)
    return W, H


# ---------------------------------------------------------------------------
# posterior sampling (Move 4)
# ---------------------------------------------------------------------------

def _sigmas(steps: int, device):
    import torch
    i = torch.arange(steps, dtype=torch.float64)
    s = (SIGMA_MAX ** (1 / RHO) + i / max(1, steps - 1)
         * (SIGMA_MIN ** (1 / RHO) - SIGMA_MAX ** (1 / RHO))) ** RHO
    return torch.cat([s, torch.zeros(1, dtype=torch.float64)]).float().to(
        device)


def posterior_sample(net, Y, V, steps: int, gen, lam: float = 1.0,
                     zeta: float = 0.3, chunk: int = 512):
    """One guess of the clean linear spectrum under Y (linear complex
    [F, T]) with noise variance V [F, T]: the prior denoises in its
    compressed domain; the data step pulls the guess to what the recording
    allows, per bin, in the linear domain. Long files go in chunks of
    `chunk` frames (overlapping by an eighth, crossfaded)."""
    import torch
    Fq, T = Y.shape
    out = torch.zeros_like(Y)
    weight = torch.zeros(T, device=Y.device)
    ov = chunk // 8
    starts = list(range(0, max(1, T - ov), chunk - ov)) if T > chunk else [0]
    for a in starts:
        b = min(T, a + chunk)
        Yc, Vc = Y[:, a:b], V[:, a:b]
        S = _sample_chunk(net, Yc, Vc, steps, gen, lam, zeta)
        w = torch.ones(b - a, device=Y.device)
        if a > 0:
            w[:ov] = torch.linspace(0, 1, ov, device=Y.device)
        if b < T:
            w[-ov:] = torch.minimum(w[-ov:], torch.linspace(
                1, 0, ov, device=Y.device))
        out[:, a:b] += S * w
        weight[a:b] += w
    return out / weight.clamp(min=1e-6)


def _sample_chunk(net, Y, V, steps, gen, lam, zeta):
    import torch
    sig = _sigmas(steps, Y.device)
    Yc = compress(Y)[None]
    x = Yc + sig[0] * torch.randn(Yc.shape, generator=gen).to(Y.device)
    T = Y.shape[1]
    pad = (-T) % 4
    with torch.no_grad():
        for i in range(steps):
            s, s_next = sig[i], sig[i + 1]
            xin = torch.nn.functional.pad(x, (0, pad)) if pad else x
            d = net(xin, s.reshape(1))[..., :T]
            # the data step, in the linear spectrum where the noise adds:
            # the prior's guess has its own uncertainty, rho^2, which grows
            # with the noise level; the recording's is the noise model's V
            S0 = decompress(d[0])
            # sigma in the compressed domain, carried to the linear one:
            # |X| = (|C| / SCALE)^(1/COMPRESS), so dX = k |C|^(1/c - 1) dC,
            # plus the floor where |C| is itself about sigma
            c0 = torch.complex(d[0, 0], d[0, 1]).abs()
            k = (1 / COMPRESS) / SCALE ** (1 / COMPRESS)
            rho2 = lam ** 2 * ((k * c0 ** (1 / COMPRESS - 1) * float(s)) ** 2
                               + (float(s) / SCALE) ** (2 / COMPRESS)) + 1e-12
            Sdc = (S0 * V + Y * rho2) / (V + rho2)
            d_dc = compress(Sdc)[None]
            if float(s_next) <= 0:
                x = d_dc
                break
            eps_hat = (x - d) / s
            eps = torch.randn(x.shape, generator=gen).to(x.device)
            x = d_dc + s_next * (math.sqrt(1 - zeta ** 2) * eps_hat
                                 + zeta * eps)
    return decompress(x[0])


def _spread_png(path, spread, uncert_mask, width=1100, height=256):
    """The uncertainty map: time across, 0-8 kHz up; brighter = the samples
    disagree more (the prior is talking); amber where the consistency check
    flags a cell. A plain PNG writer — no imaging library."""
    import zlib
    import torch
    Fq, T = spread.shape
    cols = torch.linspace(0, max(0, T - 1), min(width, max(1, T))).long()
    rows = torch.linspace(Fq - 1, 0, height).long()
    s = spread[rows][:, cols]
    v = (s / 12.0).clamp(0, 1)                       # 12 dB = full
    m = uncert_mask[rows][:, cols].float()
    r = (v * 255 * (1 - m) + 230 * m).to(torch.uint8)
    g = (v * 200 * (1 - m) + 179 * m).to(torch.uint8)
    b = (40 + v * 120 * (1 - m) + 74 * m).to(torch.uint8)
    img = torch.stack([r, g, b], 2)
    H, W = img.shape[0], img.shape[1]
    rawrows = b"".join(b"\x00" + bytes(img[y].flatten().tolist())
                       for y in range(H))

    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(rawrows, 6)) + chunk(b"IEND", b""))
    _write_bytes(path, png)
    return {"width": W, "height": H, "top_hz": RATE / 2, "full_db": 12.0}


def sample_op(req) -> dict:
    """Move 4 (and M2): `wav` (16 kHz), `priors` [{name, path}], `free`
    [[start s, end s]] voice-free stretches, `samples`, `steps`, `outputs`
    {mean, png} (per prior beyond the first: mean_<name>), `em_rounds`."""
    import torch
    device = _device(req.get("device", "auto"))
    x, rate = read_wav(req["wav"])
    if rate != RATE:
        raise ValueError(f"the speech prior works at 16 kHz, not {rate} Hz")
    gen = torch.Generator().manual_seed(int(req.get("seed", 4321)))
    Y = stft(x.to(device))
    Fq, T = Y.shape
    free = torch.zeros(T, dtype=torch.bool)
    for a, b in req.get("free") or []:
        free[int(a * RATE / HOP):int(b * RATE / HOP)] = True
    W, H = noise_model(Y, free.to(device), NMF_RANK, gen)
    n_samples = max(2, int(req.get("samples", 4)))
    steps = int(req.get("steps", 30))
    em_rounds = max(1, int(req.get("em_rounds", 2)))
    outs = req["outputs"]
    results, means = [], {}
    for k, pr in enumerate(req["priors"]):
        net, ck = load_prior(pr["path"], device)
        Wk, Hk = W.clone(), H.clone()
        for rnd in range(em_rounds):
            V = (Wk @ Hk).clamp(min=1e-12)
            guesses = [posterior_sample(net, Y, V, steps, gen)
                       for _ in range(n_samples if rnd == em_rounds - 1
                                      else 1)]
            mean = torch.stack(guesses).mean(0)
            # EM: the noise model refitted on what the guess leaves
            R = (Y - mean).abs() ** 2 + 1e-12
            Wk, Hk = nmf_is(R, NMF_RANK, 30, W=Wk, H=Hk)
        V = (Wk @ Hk).clamp(min=1e-12)
        mags = torch.stack([g.abs() for g in guesses])
        db = 20 * torch.log10(mags + 1e-8)
        spread = db.std(0)                            # dB, per cell
        speech = mean.abs() ** 2 > V                  # cells the guess fills
        ratio = (Y - mean).abs() ** 2 / V
        flagged = ratio > 9.0                         # 3 sigma, power
        means[pr.get("name", f"p{k}")] = mean
        name = pr.get("name", f"p{k}")
        key = "mean" if k == 0 else f"mean_{name}"
        if outs.get(key):
            write_wav(outs[key], istft(mean, x.numel()).cpu(), RATE)
        png = None
        if k == 0 and outs.get("png"):
            png = _spread_png(outs["png"], spread.cpu(), flagged.cpu())
        per_frame = spread.masked_fill(~speech, 0).sum(0) / \
            speech.sum(0).clamp(min=1)
        results.append({
            "prior": name, "config": ck.get("config"),
            "step": int(ck.get("step", 0)),
            "trained_on": ck.get("trained_on", ""),
            "hours": ck.get("hours"),
            "samples": len(guesses), "steps": steps, "em_rounds": em_rounds,
            "spread_db_speech": round(float(spread[speech].mean()), 2)
            if bool(speech.any()) else None,
            "speech_cells": round(float(speech.float().mean()), 4),
            "flagged_cells": round(float(flagged.float().mean()), 4),
            "uncertain_s": round(float((per_frame > 6.0).float().sum())
                                 * HOP / RATE, 2),
            "png": png})
        _say(f"sample: prior {name}: {len(guesses)} samples, spread "
             f"{results[-1]['spread_db_speech']} dB where it guessed speech")
    out = {"priors": results, "frames": T, "versions": _versions(device)}
    if len(means) >= 2:                               # M2: the prior swap
        a, b = list(means.values())[:2]
        da, dbb = 20 * torch.log10(a.abs() + 1e-8), \
            20 * torch.log10(b.abs() + 1e-8)
        sp = (a.abs() ** 2 > (W @ H)) | (b.abs() ** 2 > (W @ H))
        diff = (da - dbb).abs()
        out["prior_swap"] = {
            "priors": list(means)[:2],
            "differ_db_speech": round(float(diff[sp].mean()), 2)
            if bool(sp.any()) else None,
            "depends_cells": round(float(((diff > 6.0) & sp).float().mean()),
                                   4)}
    return out


def finetune_op(req) -> dict:
    """M6: a prior fine-tuned a little on one speaker's confident speech
    (`wav` + `spans`), written to `out`. Few steps, small learning rate."""
    import copy
    import torch
    device = _device(req.get("device", "auto"))
    net, ck = load_prior(req["prior"], device)
    net.train()
    ema = copy.deepcopy(net).eval()
    x, rate = read_wav(req["wav"])
    if rate != RATE:
        raise ValueError("M6 needs the speaker's speech at 16 kHz")
    parts = [x[int(a * RATE):int(b * RATE)] for a, b in req["spans"]]
    speech = torch.cat([p for p in parts if p.numel() > HOP * 8]) \
        if parts else x[:0]
    need = (CROP_FRAMES - 1) * HOP
    if speech.numel() < need:
        raise ValueError(f"M6 needs at least {need / RATE:.1f} s of the "
                         "speaker's confident speech")
    speech = speech / max(1e-6, float(speech.abs().max())) * 0.5
    gen = torch.Generator().manual_seed(int(req.get("seed", 7)))
    opt = torch.optim.Adam(net.parameters(), lr=float(req.get("lr", 2e-5)))
    steps = int(req.get("steps", 200))
    losses = []
    for _ in range(steps):
        x0 = _crops([speech.half()], gen, int(req.get("batch", 8)), device)
        loss = edm_loss(net, x0, gen)
        opt.zero_grad(set_to_none=True)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(net.parameters(), 1.0)
        opt.step()
        with torch.no_grad():
            for pe, pn in zip(ema.parameters(), net.parameters()):
                pe.mul_(0.99).add_(pn.detach(), alpha=0.01)
        losses.append(loss.item())
    _save_torch(dict(ck, ema=ema.state_dict(), model=net.state_dict(),
                     opt={}, speaker_steps=steps,
                     trained_on=str(ck.get("trained_on", ""))
                     + f" + {speech.numel() / RATE:.0f} s of this speaker"),
                req["out"])
    return {"steps": steps, "speech_s": round(speech.numel() / RATE, 2),
            "loss_first": round(sum(losses[:10]) / 10, 5),
            "loss_last": round(sum(losses[-10:]) / 10, 5),
            "versions": _versions(device)}


def info_op(req) -> dict:
    import torch
    ck = torch.load(req["prior"], map_location="cpu", weights_only=True)
    return {k: ck.get(k) for k in ("config", "step", "hours", "seen_hours",
                                   "loss", "trained_on", "rate")}


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    ops = {"prepare": prepare_op, "train": train_op, "sample": sample_op,
           "finetune": finetune_op, "info": info_op}
    op = req.get("op")
    if op not in ops:
        raise ValueError(f"unknown op {op!r}")
    out = ops[op](req)
    out["op"] = op
    out["elapsed_s"] = round(time.monotonic() - started, 3)
    _write_json(response_path, out)
    _say(f"done in {out['elapsed_s']:.1f} s")
    return 0


USAGE = """usage:
  prior_worker.py REQUEST.json RESPONSE.json
  prior_worker.py --prepare SPEECH_DIR SHARD_DIR FFMPEG
  prior_worker.py --train SHARD_DIR PRIOR.pt CONFIG MINUTES [BATCH]
  prior_worker.py --info PRIOR.pt"""


def _cli(argv) -> int:
    """The forms train_prior.bat uses: each op straight from arguments,
    its answer printed as JSON."""
    flag, args = argv[1], argv[2:]
    if flag == "--prepare" and len(args) == 3:
        out = prepare_op({"source": args[0], "shards": args[1],
                          "ffmpeg": args[2]})
    elif flag == "--train" and len(args) in (4, 5):
        out = train_op({"shards": args[0], "out": args[1],
                        "config": args[2], "minutes": float(args[3]),
                        "steps": 10 ** 9, "batch": int(args[4])
                        if len(args) == 5 else 16, "save_every": 1000,
                        "trained_on": "LibriSpeech training sets (CC BY "
                                      "4.0, openslr.org/12)"})
    elif flag == "--info" and len(args) == 1:
        out = info_op({"prior": args[0]})
    else:
        print(USAGE, file=sys.stderr)
        return 2
    print(json.dumps(out, indent=1), flush=True)
    return 0


def main(argv) -> int:
    if len(argv) >= 2 and argv[1].startswith("--"):
        try:
            return _cli(argv)
        except Exception as exc:                          # noqa: BLE001
            print(f"{type(exc).__name__}: {exc}", flush=True)
            return 3
    if len(argv) != 3:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        return run(argv[1], argv[2])
    except Exception as exc:                              # noqa: BLE001
        print(f"{type(exc).__name__}: {exc}", flush=True)
        return 3


if __name__ == "__main__":
    sys.exit(main(sys.argv))
