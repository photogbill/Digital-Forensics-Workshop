# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The voice-model worker — run as its own process, never imported.

    python -I vp_worker.py REQUEST.json RESPONSE.json
    python -I vp_worker.py --selftest MODEL_DIR [auto|cuda|cpu]

Started by `voiceprint.embed` under the host's torch interpreter (ATK:
`envs\\atk_audio\\Scripts\\python.exe`). SELF-CONTAINED on purpose: it imports
nothing from the engine (that interpreter need not have it), only torch and
SpeechBrain, and touches nothing but the files it is told to read and the one
response it is told to write (written beside it, then renamed into place).

**Loading, with no network and no symlinks.** SpeechBrain 1.x's
`from_hparams` fetches each file into a `savedir`, by default as a SYMLINK —
which Windows refuses without developer mode — and from Hugging Face when the
file is not already there. So: source = savedir = the model folder,
`LocalStrategy.NO_LINK`, the model's `pretrained_path` pointed at that folder,
HF_HUB_OFFLINE=1 in the environment (the engine sets it too), and
get_speechbrain.bat puts `label_encoder.ckpt` beside `label_encoder.txt`,
because SpeechBrain looks for every loadable as `<name>.ckpt` first. Read from
SpeechBrain 1.1.1's own `speechbrain/inference/interfaces.py`,
`utils/fetching.py` and `utils/parameter_transfer.py`, 2026-10-09.

**Embeddings** are `EncoderClassifier.encode_batch(wavs, wav_lens)` — the
same call SpeakerRecognition.verify_batch scores with — over the segments the
engine chose, in padded batches with relative lengths, on the GPU when torch
sees one (else the CPU; the response names which).
"""

from __future__ import annotations

import json
import os
import sys
import time
import wave

BATCH = 16
RATE = 16000


def _say(text: str) -> None:
    print(text, flush=True)


def _read_wav16(path):
    """16 kHz mono 16-bit PCM (what the engine's FFmpeg step writes) -> a
    float tensor in [-1, 1)."""
    import torch
    with wave.open(path, "rb") as w:
        if w.getframerate() != RATE or w.getnchannels() != 1 or \
                w.getsampwidth() != 2:
            raise ValueError(f"{path} is not 16 kHz mono 16-bit PCM "
                             f"({w.getframerate()} Hz, {w.getnchannels()} ch, "
                             f"{8 * w.getsampwidth()}-bit)")
        raw = w.readframes(w.getnframes())
    if not raw:
        return torch.zeros(0)
    return torch.frombuffer(bytearray(raw), dtype=torch.int16).float() / 32768.0


def _device(wanted: str) -> str:
    import torch
    wanted = (wanted or "auto").lower()
    if wanted == "auto":
        return "cuda:0" if torch.cuda.is_available() else "cpu"
    if wanted.startswith("cuda") and not torch.cuda.is_available():
        raise RuntimeError("CUDA was asked for but torch sees no CUDA device "
                           f"(torch {torch.__version__}, built for CUDA "
                           f"{torch.version.cuda})")
    return "cuda:0" if wanted == "cuda" else wanted


def load(model_dir: str, device: str):
    """The ECAPA encoder from its local folder — offline, no symlinks."""
    os.environ.setdefault("HF_HUB_OFFLINE", "1")
    from speechbrain.inference.classifiers import EncoderClassifier
    from speechbrain.utils.fetching import LocalStrategy
    folder = os.path.abspath(model_dir).replace("\\", "/")
    model = EncoderClassifier.from_hparams(
        source=folder, savedir=folder, local_strategy=LocalStrategy.NO_LINK,
        overrides={"pretrained_path": folder}, overrides_must_match=False,
        run_opts={"device": device})
    model.eval()
    return model


def _versions(device: str) -> dict:
    import torch
    import speechbrain
    gpu = ""
    if device.startswith("cuda"):
        gpu = torch.cuda.get_device_name(torch.device(device))
    return {"device": device, "gpu": gpu, "torch": torch.__version__,
            "cuda": torch.version.cuda or "",
            "speechbrain": getattr(speechbrain, "__version__", "")}


def embed_segments(model, signal, spans):
    """One embedding per (start, end) span of `signal`, in padded batches."""
    import torch
    chunks = []
    for start, end in spans:
        a = max(0, int(round(float(start) * RATE)))
        b = min(signal.shape[0], int(round(float(end) * RATE)))
        chunks.append(signal[a:b] if b > a else signal[a:a + 1])
    out = []
    for first in range(0, len(chunks), BATCH):
        batch = chunks[first:first + BATCH]
        longest = max(c.shape[0] for c in batch)
        wavs = torch.zeros(len(batch), longest)
        for i, c in enumerate(batch):
            wavs[i, :c.shape[0]] = c
        lens = torch.tensor([c.shape[0] / longest for c in batch])
        with torch.no_grad():
            emb = model.encode_batch(wavs, lens)
        emb = emb.reshape(len(batch), -1).float().cpu()
        for row in emb:
            out.append([round(float(v), 7) for v in row.tolist()])
    return out


def _write(path: str, data: dict) -> None:
    tmp = f"{path}.{os.getpid()}.part"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def run(request_path: str, response_path: str) -> int:
    started = time.monotonic()
    with open(request_path, "r", encoding="utf-8") as fh:
        req = json.load(fh)
    device = _device(req.get("device", "auto"))
    _say(f"loading {req['model_dir']} on {device}")
    model = load(req["model_dir"], device)
    info = _versions(device)
    _say(f"loaded: torch {info['torch']}, speechbrain {info['speechbrain']}, "
         f"{info['gpu'] or 'cpu'}")
    items = []
    for item in req["items"]:
        signal = _read_wav16(item["wav"])
        vectors = embed_segments(model, signal, item["segments"])
        items.append({"id": item["id"], "embeddings": vectors})
        _say(f"embedded {item['id']}: {len(vectors)} segment(s)")
    _write(response_path, dict(info, items=items,
                               elapsed_s=round(time.monotonic() - started, 3)))
    _say(f"done in {time.monotonic() - started:.1f} s")
    return 0


def selftest(model_dir: str, wanted: str = "auto") -> int:
    """Load the model and embed two seconds of quiet noise; print one JSON
    line. Writes nothing."""
    import torch
    device = _device(wanted)
    model = load(model_dir, device)
    vec = embed_segments(model, torch.randn(2 * RATE) * 0.01, [(0.0, 2.0)])[0]
    print(json.dumps(dict(_versions(device), ok=True, dim=len(vec))),
          flush=True)
    return 0


def main(argv) -> int:
    if len(argv) >= 3 and argv[1] == "--selftest":
        return selftest(argv[2], argv[3] if len(argv) > 3 else "auto")
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    return run(argv[1], argv[2])


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:                              # noqa: BLE001
        print(f"vp_worker failed: {type(exc).__name__}: {exc}", flush=True)
        sys.exit(1)
