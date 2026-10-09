# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Voice comparison — speaker embeddings, case-scoped profiles, and a
probability only when it has been calibrated (FORENSICS_PLAN §13).

Bill, 2026-10-09: *"Voice Print Analysis — Create a voice print for
identifying an individual based off their voice, with a percentage
probability"* — and *"a probability score is fine, it can be used more as a
lead rather than courtroom evidence."* So every comparison is a LEAD filed
into the review queue, never an identification.

**THE MODEL** is SpeechBrain's ECAPA-TDNN, `speechbrain/spkrec-ecapa-voxceleb`
(Apache-2.0, trained on VoxCeleb 1+2): a 192-number embedding of 16 kHz mono
speech. It runs in its OWN short-lived process — `vp_worker.py` under the
host's torch interpreter (ATK: `envs\\atk_audio`) — never in this one and never
inside ATK's audio service, where faster-whisper's cuDNN and torch's collide
(ATK, 2026-08-28). This module is stdlib-only: it segments, scores, calibrates,
records and files; the worker only turns audio into numbers.

**THE NUMBER.** Two embeddings give a cosine similarity — the RAW SCORE. It
is not a probability: the same person rarely scores near 1.0 and where the
same/different boundary falls moves with the channel. A CALIBRATION — a
two-parameter logistic map fitted on same-speaker and different-speaker pairs
from a reference set, the two classes weighted equally — turns it into
P(same speaker | score) at even odds, and the examiner's PRIOR moves it from
there. Uncalibrated, a result carries the raw score, marked UNCALIBRATED, and
no probability at all.

**THE INPUT'S TIER GATES IT** (§12.2): Invented audio is refused — a
generative separator can reshape a voice — and Cleaned or Inferred audio is
compared but flagged. Every input is read once through the read-only door
into the case, then FFmpeg makes the 16 kHz mono PCM the model hears — a
measured step.

**WHERE THINGS LIVE.** Profiles and comparison runs: in the case,
`<case>/voiceprint/profiles/<id>/` and `<case>/voiceprint/runs/<id>/`, with
`voiceprint.enrolled / .compared / .failed` custody. Calibrations: beside the
model, `voiceprint_calibration.json`, a statement about that model's scores —
never in a case; their working files go to a harness folder (§12.12). The
worker's TMP/TEMP and every cache (HF_HOME, TORCH_HOME, CUDA_CACHE_PATH) go
to a scratch folder the host names, so nothing lands in the Windows profile.
"""

from __future__ import annotations

import bisect
import json
import math
import os
from pathlib import Path

from .. import blocker, hashing, review
from .. import case as _case
from ..errors import Cancelled, MediaError
from ..timeutil import utc_now
from . import lab as _lab
from . import sam_audio as _sam
from . import wav as _wav

MODEL_ID = "speechbrain/spkrec-ecapa-voxceleb"
MODEL_LICENCE = "Apache-2.0"
#: What get_speechbrain.bat fetches from the model's Hugging Face repository.
#: `label_encoder.ckpt` is a copy of `label_encoder.txt`: SpeechBrain looks for
#: every loadable as `<name>.ckpt` in the model folder first, and with that
#: copy present it never reaches for the network.
MODEL_FILES = ("hyperparams.yaml", "embedding_model.ckpt",
               "mean_var_norm_emb.ckpt", "classifier.ckpt",
               "label_encoder.txt", "label_encoder.ckpt")
SOURCE = "model:spkrec-ecapa-voxceleb"
FINDING_KIND = "voice-comparison"
RATE = 16000
VP_DIR = "voiceprint"
CALIBRATION_FILE = "voiceprint_calibration.json"
WORKER = Path(__file__).with_name("vp_worker.py")
INSTALL_HINT = "Run get_speechbrain.bat in the ATK folder."

#: The energy gate: 250 ms windows, speech-bearing when at least this far
#: above the recording's own quiet floor (its 10th-percentile window).
WINDOW_S = 0.25
GATE_FRACTION = 0.35
GATE_MIN_DB = 6.0
ABS_FLOOR_DB = -55.0
#: Segments: fixed SEGMENT_S stretches of the timeline, kept when at least
#: SEGMENT_SPEECH of each is speech-bearing; a tail at least MIN_SEGMENT_S.
SEGMENT_S = 3.0
MIN_SEGMENT_S = 1.0
SEGMENT_SPEECH = 0.3

NET_SPEECH_AMBER_S = 10.0
NET_SPEECH_RED_S = 3.0
#: SpeechBrain's own default decision threshold for this model
#: (speechbrain.inference.speaker.SpeakerRecognition.verify_batch) — the only
#: fixed reference an uncalibrated raw score is shown against.
RAW_THRESHOLD = 0.25
DEFAULT_PRIOR = 0.5
SHOWN_MAX = 0.999
#: Calibration: at most this many clips per reference speaker; half enrol a
#: profile, the rest are scored against every profile — the way the page uses
#: the model, so the map is fitted on the scores it will be asked to read.
MAX_CLIPS_PER_SPEAKER = 8
MIN_CALIBRATION_SPEAKERS = 2
L2 = 1e-3

AUDIO_EXT = frozenset({".wav", ".flac", ".mp3", ".m4a", ".aac", ".ogg",
                       ".opus", ".amr", ".wma", ".mp4", ".mov", ".m4v",
                       ".3gp", ".mkv", ".avi", ".webm"})

_FINGERPRINTS: dict = {}


# ---------------------------------------------------------------------------
# the model folder, the interpreter, the scratch folder
# ---------------------------------------------------------------------------

def model_missing(model_dir) -> list[str]:
    """The files get_speechbrain.bat should have put in the model folder that
    are not there — empty when the folder is complete."""
    root = Path(model_dir)
    return [name for name in MODEL_FILES if not (root / name).is_file()]


def check_model(model_dir) -> Path:
    root = Path(model_dir)
    gone = model_missing(root)
    if gone:
        raise MediaError(f"The voice model folder {root} is missing "
                         f"{', '.join(gone)}. {INSTALL_HINT}")
    return root


def model_fingerprint(model_dir) -> str:
    """SHA-256 of `embedding_model.ckpt` — the weights every embedding came
    from. Cached per path, size and modification time."""
    path = Path(model_dir) / "embedding_model.ckpt"
    try:
        st = path.stat()
    except OSError as exc:
        raise MediaError(f"{path} cannot be read: {exc}. {INSTALL_HINT}"
                         ) from exc
    key = (os.path.abspath(path), st.st_size, st.st_mtime_ns)
    if key not in _FINGERPRINTS:
        _FINGERPRINTS[key] = hashing.hash_evidence(path).sha256
    return _FINGERPRINTS[key]


def worker_argv(python=None, worker=None) -> list[str]:
    """The argv prefix that starts the worker: `[python, -I, vp_worker.py]`,
    or `worker` as given (the suite drives a fake the same way)."""
    if worker:
        return [os.fspath(a) for a in worker]
    if not python:
        raise MediaError("No Python with torch and SpeechBrain was given for "
                         "the voice model. " + INSTALL_HINT)
    if not Path(python).is_file():
        raise MediaError(f"The voice model's Python is not at {python}. "
                         + INSTALL_HINT)
    return [os.fspath(python), "-I", os.fspath(WORKER)]


def default_scratch(model_dir) -> Path:
    return Path(os.path.abspath(os.fspath(model_dir))).parent / "tmp"


def assert_runtime_scratch(named, target) -> Path:
    """The run-time guard for `make_scratch`: exactly the folder the host
    named, and not inside a case."""
    expected = Path(os.path.abspath(os.fspath(named)))
    if os.path.normcase(os.path.abspath(os.fspath(target))) != \
            os.path.normcase(os.fspath(expected)):
        raise MediaError(f"Refusing to make {target}: the voice worker's "
                         f"temp folder is only ever {expected}.")
    for parent in [expected, *expected.parents]:
        if (parent / "case.json").is_file():
            raise MediaError(f"Refusing a temp folder inside the case at "
                             f"{parent}.")
    return expected


def make_scratch(scratch) -> Path:
    """Make (once) the worker's TMP/TEMP and cache folder."""
    target = assert_runtime_scratch(scratch, scratch)
    target.mkdir(parents=True, exist_ok=True)
    return target


def worker_env(scratch) -> dict:
    """Temp and every cache torch, CUDA and Hugging Face would otherwise put
    in the Windows profile — all in `scratch`. And offline, always."""
    env = _sam.child_env(scratch)
    root = os.fspath(scratch)
    env.update({"HF_HOME": os.path.join(root, "hf"),
                "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                "TORCH_HOME": os.path.join(root, "torch"),
                "CUDA_CACHE_PATH": os.path.join(root, "cuda"),
                "XDG_CACHE_HOME": os.path.join(root, "cache"),
                "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                "PYTHONDONTWRITEBYTECODE": "1"})
    return env


# ---------------------------------------------------------------------------
# pure: the energy gate, segments, vectors, the calibration
# ---------------------------------------------------------------------------

def _percentile(values, q: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return _wav.FLOOR_DB
    i = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return ordered[i]


def speech_mask(levels) -> tuple[list[bool], dict]:
    """Which 250 ms windows bear speech, by energy — and how that was
    decided. The floor is the recording's own 10th-percentile window; the
    gate sits GATE_FRACTION of the way from it to the 95th percentile (at
    least GATE_MIN_DB above the floor, never below ABS_FLOOR_DB). A flat
    recording — no quiet stretch to measure — counts every window above
    ABS_FLOOR_DB, and says so."""
    levels = list(levels)
    if not levels:
        return [], {"floor_db": _wav.FLOOR_DB, "gate_db": ABS_FLOOR_DB,
                    "note": "no audio"}
    floor = _percentile(levels, 0.10)
    peak = _percentile(levels, 0.95)
    gate = max(ABS_FLOOR_DB, floor + max(GATE_MIN_DB,
                                         GATE_FRACTION * (peak - floor)))
    mask = [lvl >= gate for lvl in levels]
    note = ""
    if not any(mask):
        mask = [lvl >= ABS_FLOOR_DB for lvl in levels]
        gate = ABS_FLOOR_DB
        note = ("flat level - no quiet stretch to measure a floor from; every "
                "window above the absolute floor counted")
    return mask, {"floor_db": round(floor, 2), "peak_db": round(peak, 2),
                  "gate_db": round(gate, 2), "note": note}


def segments(mask, duration_s: float) -> list[dict]:
    """Fixed SEGMENT_S stretches of the timeline that carry enough speech;
    a clip shorter than one segment is one segment if it has any speech."""
    per = max(1, int(round(SEGMENT_S / WINDOW_S)))
    out = []
    for first in range(0, len(mask), per):
        part = mask[first:first + per]
        start = first * WINDOW_S
        end = min(duration_s, (first + len(part)) * WINDOW_S)
        speech = sum(part) * WINDOW_S
        long_enough = end - start >= MIN_SEGMENT_S or len(mask) <= per
        if speech > 0 and long_enough and \
                sum(part) >= SEGMENT_SPEECH * len(part):
            out.append({"start": round(start, 3), "end": round(end, 3),
                        "speech_s": round(speech, 3)})
    return out


def _norm(vec) -> list[float]:
    length = math.sqrt(sum(v * v for v in vec))
    if not length or not math.isfinite(length):
        raise MediaError("An embedding has no length (all zeros or not a "
                         "number) — the worker returned a broken vector.")
    return [v / length for v in vec]


def cosine(a, b) -> float:
    """Cosine similarity of two embeddings."""
    if len(a) != len(b) or not a:
        raise MediaError(f"Embeddings of different sizes ({len(a)} and "
                         f"{len(b)}) cannot be compared — re-enrol with the "
                         "same model.")
    na, nb = _norm(a), _norm(b)
    return max(-1.0, min(1.0, sum(x * y for x, y in zip(na, nb))))


def mean_embedding(vectors, weights=None) -> list[float]:
    """The weighted mean of unit-length embeddings, itself made unit
    length — one recording's or one profile's voice."""
    vectors = [_norm(v) for v in vectors]
    if not vectors:
        raise MediaError("No speech-bearing segment to make a voice print "
                         "from.")
    w = list(weights) if weights is not None else [1.0] * len(vectors)
    total = sum(w) or float(len(vectors))
    dim = len(vectors[0])
    acc = [0.0] * dim
    for vec, wi in zip(vectors, w):
        for i in range(dim):
            acc[i] += vec[i] * wi / total
    return [round(v, 7) for v in _norm(acc)]


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


def equal_error_rate(same, diff) -> tuple[float, float]:
    """(EER, the score threshold where false accepts equal false rejects) —
    one sorted sweep, so thousands of pairs cost milliseconds."""
    if not same or not diff:
        raise MediaError("An equal error rate needs same- and "
                         "different-speaker scores.")
    s_sorted, d_sorted = sorted(same), sorted(diff)
    best = (2.0, 0.0, 1.0)
    for t in sorted(set(same) | set(diff)):
        frr = bisect.bisect_left(s_sorted, t) / len(s_sorted)
        far = (len(d_sorted) - bisect.bisect_left(d_sorted, t)) / len(d_sorted)
        gap = abs(frr - far)
        if gap < best[0]:
            best = (gap, t, (frr + far) / 2)
    return round(best[2], 6), round(best[1], 6)


def fit_calibration(same, diff, *, l2: float = L2,
                    iterations: int = 100) -> dict:
    """Fit P(same | score) = sigmoid(a·score + b) by Newton's method, the two
    classes weighted equally (so the map reads at even prior odds), with a
    small ridge on `a` so a reference set that separates perfectly still
    gives finite numbers. Returns a, b, the EER, and the score at 50%."""
    same = [float(s) for s in same]
    diff = [float(s) for s in diff]
    if len(same) < 2 or len(diff) < 2:
        raise MediaError(f"A calibration needs at least two same-speaker and "
                         f"two different-speaker pairs (got {len(same)} and "
                         f"{len(diff)}).")
    data = [(s, 1.0, 0.5 / len(same)) for s in same] + \
           [(s, 0.0, 0.5 / len(diff)) for s in diff]
    a, b = 1.0, 0.0
    for _ in range(iterations):
        ga, gb = l2 * a, 0.0
        haa, hab, hbb = l2, 0.0, 1e-9
        for s, y, w in data:
            p = _sigmoid(a * s + b)
            r = w * (p - y)
            v = w * p * (1.0 - p)
            ga += r * s
            gb += r
            haa += v * s * s
            hab += v * s
            hbb += v
        det = haa * hbb - hab * hab
        if det <= 0 or not math.isfinite(det):
            break
        da = (hbb * ga - hab * gb) / det
        db = (haa * gb - hab * ga) / det
        a, b = a - da, b - db
        if abs(da) < 1e-10 and abs(db) < 1e-10:
            break
    eer, eer_t = equal_error_rate(same, diff)
    return {"a": round(a, 8), "b": round(b, 8), "eer": eer,
            "eer_threshold": eer_t,
            "score_at_50": round(-b / a, 6) if a else None,
            "same_pairs": len(same), "diff_pairs": len(diff),
            "same_mean": round(sum(same) / len(same), 6),
            "diff_mean": round(sum(diff) / len(diff), 6)}


def check_prior(prior) -> float:
    prior = float(prior)
    if not 0.0 < prior < 1.0:
        raise MediaError(f"The prior is a probability between 0 and 1, not "
                         f"{prior:g}.")
    return prior


def probability(score: float, calibration: dict | None,
                prior: float = DEFAULT_PRIOR) -> float | None:
    """P(same speaker) for a raw score, through a calibration, at `prior` —
    None when there is no calibration: an uncalibrated score has none."""
    if not calibration:
        return None
    prior = check_prior(prior)
    z = float(calibration["a"]) * float(score) + float(calibration["b"]) + \
        math.log(prior / (1.0 - prior))
    return _sigmoid(z)


def band(score: float, prob: float | None) -> str:
    """The colour band a surface draws: strong / likely / inconclusive /
    unlikely when calibrated; above / below SpeechBrain's own threshold when
    not — no invented bands on an uncalibrated number."""
    if prob is None:
        return "above-threshold" if score >= RAW_THRESHOLD else \
            "below-threshold"
    if prob >= 0.90:
        return "strong"
    if prob >= 0.70:
        return "likely"
    if prob >= 0.30:
        return "inconclusive"
    return "unlikely"


def speech_flag(seconds: float, whose: str) -> dict | None:
    if seconds < NET_SPEECH_RED_S:
        return {"level": "red", "text": f"{whose}: only {seconds:.1f} s of "
                "speech - a score on this little is unreliable"}
    if seconds < NET_SPEECH_AMBER_S:
        return {"level": "amber", "text": f"{whose}: {seconds:.1f} s of "
                f"speech - under {NET_SPEECH_AMBER_S:g} s, scores are less "
                "stable"}
    return None


def shown(prob: float | None) -> str:
    """`87%`, `>99.9%`, `<0.1%`, or "" — a probability as a person reads it."""
    if prob is None:
        return ""
    if prob > SHOWN_MAX:
        return ">99.9%"
    if prob < 1.0 - SHOWN_MAX:
        return "<0.1%"
    return f"{prob * 100:.0f}%" if 0.01 <= prob <= 0.99 else \
        f"{prob * 100:.1f}%"


# ---------------------------------------------------------------------------
# where a run writes: the case, or a harness folder
# ---------------------------------------------------------------------------

class _CaseSpot:
    """Writes go into the open case, through the case writers."""

    def __init__(self, case):
        self.case = case
        self.root = Path(case.root)

    def guard(self, path):
        return blocker.assert_case_path(self.case.root, path)

    def dirs(self, *parts) -> Path:
        return _case.make_case_dirs(self.case.root, *parts)

    def log(self, path):
        return _lab._case_log(self.case, path)

    def json(self, path, data: dict) -> str:
        return _case.write_json_atomic(self.case.root, path, data)


class _HarnessSpot:
    """Writes go into a harness folder outside every case (§12.12)."""

    def __init__(self, root):
        self.root = Path(os.path.abspath(os.fspath(root)))

    def guard(self, path):
        return blocker.assert_harness_path(self.root, path)

    def dirs(self, *parts) -> Path:
        return _lab._harness_dirs(self.root, "/".join(parts))

    def log(self, path):
        return _lab._harness_log(self.root, path)

    def json(self, path, data: dict) -> None:
        _lab._harness_json(self.root, path, data)


# ---------------------------------------------------------------------------
# children: FFmpeg to 16 kHz mono, then the worker
# ---------------------------------------------------------------------------

def _cancelled(should_cancel) -> bool:
    return bool(should_cancel is not None and should_cancel())


def require_ffmpeg(ffmpeg) -> list[str]:
    """FFmpeg's argv prefix, or the sentence saying it is missing."""
    if not ffmpeg:
        raise MediaError("Voice comparison needs FFmpeg to make 16 kHz mono "
                         "audio. ATK uses bin\\ffmpeg\\ffmpeg.exe "
                         "(get_tools.bat fetches it).")
    argv0 = _sam.runtime_argv(ffmpeg)
    if not Path(argv0[-1]).is_file():
        raise MediaError(f"FFmpeg is not at {argv0[-1]}. Run get_tools.bat in "
                         "the ATK folder.")
    return argv0


def to_16k(ffmpeg, src, dst, *, log, guard, should_cancel=None) -> None:
    """FFmpeg: the first audio stream, mixed to mono, at 16 kHz, 16-bit PCM
    — what the model hears. A measured step."""
    argv = require_ffmpeg(ffmpeg) + ["-hide_banner", "-nostdin", "-n", "-i", os.fspath(src),
                    "-map", "0:a:0", "-vn", "-sn", "-dn", "-ac", "1",
                    "-ar", str(RATE), "-c:a", "pcm_s16le", os.fspath(dst)]
    outcome = _sam.run_process(argv, log=log, timeout_s=3600.0, writes=[dst],
                               guard=guard, should_cancel=should_cancel)
    if outcome["state"] == "cancelled":
        raise Cancelled("stopped while FFmpeg ran")
    if outcome["state"] != "completed" or not Path(dst).is_file():
        raise MediaError(
            f"FFmpeg could not take 16 kHz mono audio out of "
            f"{Path(src).name} ({outcome['state']}, "
            f"{_sam.exit_sentence(outcome['returncode'])}): "
            f"{_sam.log_tail(getattr(log, 'name', '')) or outcome['error']}"
            f" — log {getattr(log, 'name', '')}.")


def _measure(wav_path) -> dict:
    """Levels, the speech mask and segments of one 16 kHz WAV."""
    info, levels = _wav.window_levels(wav_path, WINDOW_S)
    mask, gate = speech_mask(levels)
    segs = segments(mask, info.duration_s)
    return {"duration_s": round(info.duration_s, 3),
            "net_speech_s": round(sum(mask) * WINDOW_S, 3),
            "gate": gate, "segments": segs, "rate": info.rate,
            "channels": info.channels}


def _worker_timeout(total_audio_s: float) -> float:
    return 900.0 + 5.0 * max(0.0, float(total_audio_s))


def embed(items, *, spot, run_dir: Path, model_dir, python=None, worker=None,
          scratch=None, device: str = "auto", log, should_cancel=None,
          heartbeat=None, say=None) -> dict:
    """Run the worker once over `items` ([{id, wav, segments}]) and return
    its response: device, versions, and per item the segment embeddings."""
    say = say or (lambda _l: None)
    argv = worker_argv(python, worker)
    scratch = make_scratch(scratch or default_scratch(model_dir))
    request = run_dir / "request.json"
    response = run_dir / "response.json"
    spot.json(request, {
        "schema": 1, "model_dir": Path(os.path.abspath(
            os.fspath(model_dir))).as_posix(), "device": device,
        "rate": RATE, "items": [{"id": it["id"], "wav": os.fspath(it["wav"]),
                                 "segments": [[s["start"], s["end"]]
                                              for s in it["segments"]]}
                                for it in items]})
    total = sum(s["end"] - s["start"] for it in items for s in it["segments"])
    if _cancelled(should_cancel):
        raise Cancelled("stopped before the voice model ran")
    say(f"Voice model: {sum(len(it['segments']) for it in items)} segment(s) "
        f"from {len(items)} recording(s), {total:.0f} s of audio…")
    log_path = getattr(log, "name", None)

    def beat(elapsed):
        if heartbeat is not None:
            last = _sam.last_line(log_path) if isinstance(
                log_path, (str, os.PathLike)) else ""
            heartbeat(f"Voice model running {_sam.clock(elapsed)} · worker: "
                      f"{last or 'nothing printed yet'}")

    outcome = _sam.run_process(
        argv + [os.fspath(request), os.fspath(response)], log=log,
        timeout_s=_worker_timeout(total), writes=[response], guard=spot.guard,
        should_cancel=should_cancel, env=worker_env(scratch),
        heartbeat=beat if heartbeat is not None else None)
    if outcome["state"] == "cancelled":
        raise Cancelled("stopped while the voice model ran")
    if outcome["state"] != "completed" or not response.is_file():
        why = {"timeout": f"it ran past {_worker_timeout(total):.0f} s and "
                          "was stopped"}.get(
            outcome["state"],
            "the worker " + _sam.exit_sentence(outcome["returncode"]))
        raise MediaError(
            f"The voice model did not finish: {why}. It said: "
            f"{_sam.log_tail(log_path) or outcome['error'] or '(nothing)'}"
            f" — full log {log_path}.")
    try:
        with open(response, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise MediaError(f"The voice model's answer {response} cannot be "
                         f"read: {exc}") from exc
    got = {it.get("id"): it for it in data.get("items") or []}
    for it in items:
        back = got.get(it["id"])
        if back is None or len(back.get("embeddings") or []) != \
                len(it["segments"]):
            raise MediaError(f"The voice model returned no embedding for "
                             f"every segment of {it['id']} — log "
                             f"{log_path}.")
    return data


def _voice(item: dict, back: dict) -> dict:
    """One recording's segments with their embeddings, and its voice — the
    mean of its segments weighted by speech."""
    segs = []
    for seg, vec in zip(item["segments"], back["embeddings"]):
        segs.append(dict(seg, embedding=[round(float(v), 7) for v in vec]))
    voice = mean_embedding([s["embedding"] for s in segs],
                           [s["speech_s"] for s in segs])
    return {"segments": segs, "embedding": voice}


# ---------------------------------------------------------------------------
# inputs into the case
# ---------------------------------------------------------------------------

def _gate_tier(case, original: dict) -> tuple[str, str, str]:
    """(tier, how it is known, upstream recipe) — Invented refused."""
    rid, tier, basis = _lab.upstream_of_input(case, original["path"])
    if tier == "invented":
        raise MediaError(
            f"{original['name']} is INVENTED audio (a generative model made "
            f"it — recipe {rid or 'unknown'}, known by its {basis}). A "
            "generative separator can reshape a voice, so it is never "
            "voice-compared. Compare the original, or a faithful-lane output.")
    return tier or "measured", basis, rid


def _take_in(case, spot, folder: Path, source, n: int, ffmpeg, log,
             should_cancel, evidence_id: str = "") -> dict:
    """One input: resolved, tier-gated, copied through the read-only door,
    made 16 kHz mono, measured."""
    original = _lab.resolve_input(case, source, evidence_id)
    tier, basis, rid = _gate_tier(case, original)
    stem = f"{n:02d}"
    copy = folder / f"{stem}-{original['name']}"
    hashes = _lab._copy_in(case, original["path"], copy)
    wav16 = folder / f"{stem}.16k.wav"
    to_16k(ffmpeg, copy, wav16, log=log, guard=spot.guard,
           should_cancel=should_cancel)
    measured = _measure(wav16)
    return {"n": n, "original": dict(original, sha256=hashes.sha256,
                                     size=hashes.size),
            "copy": copy.name, "wav": wav16.name,
            "wav_sha256": hashing.hash_case_file(wav16).sha256,
            "tier": tier, "tier_basis": basis, "upstream_recipe": rid,
            **measured}


def _new_id(prefix: str) -> str:
    stamp = utc_now()[:19].replace("-", "").replace(":", "")
    return f"{prefix}-{stamp}Z-{os.urandom(3).hex()}"


def profiles_root(case) -> Path:
    return Path(case.root) / VP_DIR / "profiles"


def runs_root(case) -> Path:
    return Path(case.root) / VP_DIR / "runs"


def _safe_id(value: str) -> str:
    name = str(value or "").strip()
    if not name or any(ch in name for ch in "/\\:") or name in (".", ".."):
        raise MediaError(f"{value!r} is not an id.")
    return name


# ---------------------------------------------------------------------------
# profiles
# ---------------------------------------------------------------------------

def load_profile(case, profile_id: str) -> dict:
    path = profiles_root(case) / _safe_id(profile_id) / "profile.json"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        raise MediaError(f"No voice profile {profile_id} in this case."
                         ) from None
    except (OSError, ValueError) as exc:
        raise MediaError(f"The voice profile {path} cannot be read: {exc}"
                         ) from exc
    if data.get("kind") != "forensics_workshop.voiceprint.profile":
        raise MediaError(f"{path} is not a voice profile.")
    return data


def list_profiles(case) -> list[dict]:
    """Every profile in the case, newest first; an unreadable one is listed
    with its reason, never skipped."""
    rows = []
    try:
        folders = sorted(p for p in profiles_root(case).iterdir()
                         if p.is_dir())
    except OSError:
        return rows
    for folder in folders:
        try:
            p = load_profile(case, folder.name)
            rows.append({"id": p["id"], "name": p.get("name", ""),
                         "samples": len(p.get("samples") or []),
                         "net_speech_s": p.get("net_speech_s", 0.0),
                         "created_at": p.get("created_at", ""),
                         "updated_at": p.get("updated_at", ""),
                         "model": (p.get("model") or {}).get("fingerprint", ""),
                         "tiers": sorted({s.get("tier", "")
                                          for s in p.get("samples") or []}),
                         "error": ""})
        except MediaError as exc:
            rows.append({"id": folder.name, "name": "", "samples": 0,
                         "net_speech_s": 0.0, "created_at": "",
                         "updated_at": "", "model": "", "tiers": [],
                         "error": str(exc)})
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows


def enrol(case, sources, *, name: str = "", profile_id: str = "",
          model_dir, ffmpeg, python=None, worker=None, scratch=None,
          device: str = "auto", evidence_id: str = "", progress=None,
          heartbeat=None, should_cancel=None) -> dict:
    """Make a voice profile from known samples — or add samples to one.

    Refused before anything is written: no samples, no name for a new
    profile, an incomplete model folder, a missing worker or FFmpeg, and an
    Invented sample. A sample with too little speech is kept and flagged."""
    say = progress or (lambda _l: None)
    sources = [s for s in (sources or []) if str(s).strip()]
    if not sources:
        raise MediaError("Choose at least one recording of the known speaker.")
    check_model(model_dir)
    worker_argv(python, worker)
    require_ffmpeg(ffmpeg)
    fingerprint = model_fingerprint(model_dir)
    existing = load_profile(case, profile_id) if profile_id else None
    if existing is None and not str(name).strip():
        raise MediaError("Give the profile a name — who these recordings are "
                         "of (\"Caller A\", \"J. Smith\").")
    if existing is not None and \
            (existing.get("model") or {}).get("fingerprint") != fingerprint:
        raise MediaError(f"Profile {profile_id} was enrolled with a different "
                         "voice model file; make a new profile.")
    for s in sources:
        _gate_tier(case, _lab.resolve_input(case, s, evidence_id))
    pid = existing["id"] if existing else _new_id("vp")
    spot = _CaseSpot(case)
    folder = spot.dirs(VP_DIR, "profiles", pid)
    batch = _new_id("enrol")
    work = spot.dirs(VP_DIR, "profiles", pid, batch)
    samples = list((existing or {}).get("samples") or [])
    try:
        with spot.log(work / "voiceprint.log") as log:
            fresh, items = [], []
            for i, source in enumerate(sources, len(samples) + 1):
                if _cancelled(should_cancel):
                    raise Cancelled("enrolment was stopped")
                say(f"Sample {i}: copying and making 16 kHz mono…")
                taken = _take_in(case, spot, work, source, i, ffmpeg, log,
                                 should_cancel, evidence_id)
                if not taken["segments"]:
                    raise MediaError(
                        f"{taken['original']['name']} has no stretch of "
                        f"speech the energy gate can find "
                        f"({taken['net_speech_s']:.1f} s above the gate). "
                        "Choose a recording where the speaker is audible.")
                fresh.append(taken)
                items.append({"id": f"s{i:02d}", "wav": work / taken["wav"],
                              "segments": taken["segments"]})
            data = embed(items, spot=spot, run_dir=work, model_dir=model_dir,
                         python=python, worker=worker, scratch=scratch,
                         device=device, log=log, should_cancel=should_cancel,
                         heartbeat=heartbeat, say=say)
        back = {it["id"]: it for it in data["items"]}
        for taken, item in zip(fresh, items):
            voice = _voice(item, back[item["id"]])
            taken.update(folder=batch, segments=voice["segments"],
                         embedding=voice["embedding"])
            samples.append(taken)
        profile = {
            "schema": 1, "kind": "forensics_workshop.voiceprint.profile",
            "id": pid, "name": (existing or {}).get("name") or name.strip(),
            "created_at": (existing or {}).get("created_at") or utc_now(),
            "updated_at": utc_now(), "examiner": case.examiner,
            "model": {"id": MODEL_ID, "licence": MODEL_LICENCE,
                      "fingerprint": fingerprint},
            "device": data.get("device", ""), "gpu": data.get("gpu", ""),
            "runtime": {"torch": data.get("torch", ""),
                        "speechbrain": data.get("speechbrain", "")},
            "samples": samples,
            "net_speech_s": round(sum(s["net_speech_s"] for s in samples), 3),
            "embedding": mean_embedding([s["embedding"] for s in samples],
                                        [s["net_speech_s"] for s in samples])}
        spot.json(folder / "profile.json", profile)
    except Exception as exc:
        case.custody.record(
            "voiceprint.failed", actor=case.actor(), target=pid,
            detail={"profile": pid, "stage": "enrol", "error": str(exc),
                    "folder": os.fspath(work)})
        raise
    case.custody.record(
        "voiceprint.enrolled", actor=case.actor(), target=pid,
        hashes={f"sample{s['n']:02d}": s["original"]["sha256"]
                for s in fresh},
        detail={"profile": pid, "name": profile["name"],
                "samples": [{"n": s["n"], "file": s["original"]["name"],
                             "evidence_id": s["original"].get("evidence_id",
                                                              ""),
                             "sha256": s["original"]["sha256"],
                             "net_speech_s": s["net_speech_s"],
                             "tier": s["tier"]} for s in fresh],
                "model": fingerprint, "device": data.get("device", ""),
                "folder": os.fspath(folder)})
    say(f"Profile {profile['name']}: {len(samples)} sample(s), "
        f"{profile['net_speech_s']:.0f} s of speech.")
    return dict(profile, folder=os.fspath(folder))


# ---------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------

def _flags(taken: dict, profile_rows: list, cal: dict | None) -> list[dict]:
    flags = []
    f = speech_flag(taken["net_speech_s"], "Questioned recording")
    if f:
        flags.append(f)
    if taken["tier"] not in ("measured", "recovered"):
        flags.append({"level": "amber", "text": f"The questioned recording is "
                      f"{taken['tier'].upper()} audio (processed) - processing "
                      "can shift a voice"})
    if taken["gate"].get("note"):
        flags.append({"level": "amber", "text": "Speech detection: "
                      + taken["gate"]["note"]})
    for p in profile_rows:
        pf = speech_flag(p["net_speech_s"], f"Profile {p['name']}")
        if pf:
            flags.append(pf)
    if cal is None:
        flags.append({"level": "amber", "text": "UNCALIBRATED - raw scores "
                      "only; no probability until a calibration is chosen"})
    else:
        cond = f", {cal['conditions']}" if cal.get("conditions") else ""
        flags.append({"level": "info", "text": f"Calibrated on "
                      f"\"{cal['name']}\" ({cal.get('speakers', '?')} "
                      f"speakers{cond}) - a probability is only as good as "
                      "the match between those recordings and this one"})
    return flags


def compare(case, source, *, model_dir, ffmpeg, python=None, worker=None,
            scratch=None, profiles=None, calibration: str = "",
            prior: float = DEFAULT_PRIOR, device: str = "auto",
            evidence_id: str = "", propose: bool = True, progress=None,
            heartbeat=None, should_cancel=None) -> dict:
    """Score a questioned recording against the case's voice profiles.

    Every profile (or those named) gets a raw score — and, with a
    calibration, a probability at `prior`. Each segment of the recording
    names its closest profile, so a recording with more than one voice shows
    where each one speaks. One review-queue proposal is filed per run."""
    say = progress or (lambda _l: None)
    check_model(model_dir)
    worker_argv(python, worker)
    fingerprint = model_fingerprint(model_dir)
    cal = calibration_by_name(model_dir, calibration) if calibration else None
    if cal is not None and cal.get("model") not in ("", None, fingerprint):
        raise MediaError(f"The calibration \"{calibration}\" was fitted on a "
                         "different voice model file; calibrate again.")
    check_prior(prior)
    original = _lab.resolve_input(case, source, evidence_id)
    _gate_tier(case, original)        # Invented audio: refused before all else
    wanted = set(profiles or [])
    loaded = []
    for row in list_profiles(case):
        if wanted and row["id"] not in wanted:
            continue
        if row["error"]:
            raise MediaError(row["error"])
        p = load_profile(case, row["id"])
        if (p.get("model") or {}).get("fingerprint") != fingerprint:
            raise MediaError(f"Profile {p.get('name') or p['id']} was "
                             "enrolled with a different voice model file; "
                             "re-enrol it.")
        loaded.append(p)
    if not loaded:
        raise MediaError("There are no voice profiles to compare against. "
                         "Enrol a known speaker first.")
    require_ffmpeg(ffmpeg)
    spot = _CaseSpot(case)
    run_id = _new_id("vc")
    run_dir = spot.dirs(VP_DIR, "runs", run_id)
    result = {"schema": 1, "kind": "forensics_workshop.voiceprint.comparison",
              "run_id": run_id, "created_at": utc_now(),
              "examiner": case.examiner, "state": "running",
              "model": {"id": MODEL_ID, "licence": MODEL_LICENCE,
                        "fingerprint": fingerprint},
              "calibration": cal, "prior": float(prior), "failure": ""}
    stage = "input"
    try:
        with spot.log(run_dir / "voiceprint.log") as log:
            say("Copying the questioned recording and making 16 kHz mono…")
            taken = _take_in(case, spot, run_dir, source, 1, ffmpeg, log,
                             should_cancel, evidence_id)
            result.update(original=taken["original"], tier=taken["tier"],
                          tier_basis=taken["tier_basis"],
                          input_sha256=taken["original"]["sha256"],
                          wav={"file": taken["wav"],
                               "sha256": taken["wav_sha256"],
                               "duration_s": taken["duration_s"]},
                          net_speech_s=taken["net_speech_s"],
                          gate=taken["gate"])
            if not taken["segments"]:
                raise MediaError(
                    f"No stretch of speech was found in "
                    f"{taken['original']['name']} "
                    f"({taken['net_speech_s']:.1f} s above the energy gate).")
            stage = "model"
            item = {"id": "q", "wav": run_dir / taken["wav"],
                    "segments": taken["segments"]}
            data = embed([item], spot=spot, run_dir=run_dir,
                         model_dir=model_dir, python=python, worker=worker,
                         scratch=scratch, device=device, log=log,
                         should_cancel=should_cancel, heartbeat=heartbeat,
                         say=say)
        stage = "scoring"
        voice = _voice(item, data["items"][0])
        rows = []
        for p in loaded:
            score = cosine(voice["embedding"], p["embedding"])
            prob = probability(score, cal, prior)
            rows.append({"profile": p["id"], "name": p.get("name", ""),
                         "score": round(score, 6),
                         "probability": None if prob is None
                         else round(prob, 6),
                         "shown": shown(prob), "band": band(score, prob),
                         "net_speech_s": p.get("net_speech_s", 0.0),
                         "samples": len(p.get("samples") or [])})
        rows.sort(key=lambda r: r["score"], reverse=True)
        segs = []
        for seg in voice["segments"]:
            scores = {p["id"]: round(cosine(seg["embedding"], p["embedding"]),
                                     6) for p in loaded}
            best = max(scores, key=scores.get)
            segs.append({"start": seg["start"], "end": seg["end"],
                         "speech_s": seg["speech_s"], "best": best,
                         "best_score": scores[best], "scores": scores})
        flags = _flags(taken, rows, cal)
        winners = {}
        for s in segs:
            if s["best_score"] >= RAW_THRESHOLD:
                winners[s["best"]] = winners.get(s["best"], 0) + 1
        if len([k for k, v in winners.items() if v >= max(1, 0.2 * len(segs))
                ]) > 1:
            flags.append({"level": "amber", "text": "Segments disagree on the "
                          "closest profile - more than one known voice may "
                          "be in this recording (see the timeline)"})
        result.update(state="completed", matches=rows, segments=segs,
                      flags=flags, device=data.get("device", ""),
                      gpu=data.get("gpu", ""),
                      runtime={"torch": data.get("torch", ""),
                               "speechbrain": data.get("speechbrain", "")},
                      embedding=voice["embedding"])
        top = rows[0]
        if propose:
            what = top["shown"] or f"raw {top['score']:.2f} (uncalibrated)"
            result["finding"] = review.propose(
                case, source=SOURCE, kind=FINDING_KIND,
                evidence_id=taken["original"].get("evidence_id", ""),
                title=f"Voice comparison: {taken['original']['name']} is "
                      f"closest to {top['name']} - {what}",
                detail={"run_id": run_id, "folder": os.fspath(run_dir),
                        "matches": [{k: r[k] for k in ("name", "score",
                                                       "probability", "band")}
                                    for r in rows],
                        "calibration": (cal or {}).get("name", ""),
                        "prior": float(prior),
                        "flags": [f["text"] for f in flags],
                        "key": f"{FINDING_KIND}:{run_id}"},
                refs=[f"voiceprint:{run_id}"])
        result_sha = spot.json(run_dir / "result.json", result)
    except Exception as exc:
        state = "cancelled" if isinstance(exc, Cancelled) else "failed"
        result.update(state=state, failure=f"{state.capitalize()} at {stage}: "
                                           f"{exc}")
        case.custody.record(
            "voiceprint.failed", actor=case.actor(), target=run_id,
            detail={"run_id": run_id, "stage": stage, "state": state,
                    "error": str(exc), "folder": os.fspath(run_dir)})
        try:
            spot.json(run_dir / "result.json", result)
        except Exception:                                 # noqa: BLE001
            pass         # the custody record above already says what failed
        raise
    # What was done, on what, with which model — and the hash of the result
    # that holds the scores. The scores themselves are not custody: custody
    # records what was done and by whom, never what it means.
    case.custody.record(
        "voiceprint.compared", actor=case.actor(), target=run_id,
        hashes={"input": result["input_sha256"],
                "wav16k": result["wav"]["sha256"], "result.json": result_sha},
        detail={"run_id": run_id, "input": taken["original"],
                "tier": taken["tier"],
                "profiles": [r["profile"] for r in rows],
                "calibration": (cal or {}).get("name", ""),
                "prior": float(prior), "model": fingerprint,
                "device": result["device"], "folder": os.fspath(run_dir)})
    say(f"Compared against {len(rows)} profile(s): closest {top['name']} — "
        f"{top['shown'] or 'raw %.2f, uncalibrated' % top['score']}.")
    return dict(result, folder=os.fspath(run_dir))


def list_runs(case) -> list[dict]:
    rows = []
    try:
        folders = sorted(p for p in runs_root(case).iterdir() if p.is_dir())
    except OSError:
        return rows
    for folder in folders:
        try:
            with open(folder / "result.json", "r", encoding="utf-8") as fh:
                r = json.load(fh)
            top = (r.get("matches") or [{}])[0]
            rows.append({"run_id": r.get("run_id", folder.name),
                         "created_at": r.get("created_at", ""),
                         "state": r.get("state", ""),
                         "input": (r.get("original") or {}).get("name", ""),
                         "closest": top.get("name", ""),
                         "shown": top.get("shown", ""),
                         "score": top.get("score"),
                         "calibration": (r.get("calibration") or {}).get(
                             "name", ""), "error": r.get("failure", "")})
        except (OSError, ValueError, AttributeError, IndexError) as exc:
            rows.append({"run_id": folder.name, "created_at": "",
                         "state": "unreadable", "input": "", "closest": "",
                         "shown": "", "score": None, "calibration": "",
                         "error": f"{type(exc).__name__}: {exc}"})
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows


def load_run(case, run_id: str) -> dict:
    folder = runs_root(case) / _safe_id(run_id)
    try:
        with open(folder / "result.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise MediaError(f"The comparison {run_id} cannot be read: {exc}"
                         ) from exc
    return dict(data, folder=os.fspath(folder))


# ---------------------------------------------------------------------------
# calibration — beside the model, never in a case
# ---------------------------------------------------------------------------

def calibration_path(model_dir) -> Path:
    return Path(os.path.abspath(os.fspath(model_dir))) / CALIBRATION_FILE


def assert_calibration_path(model_dir, target) -> Path:
    """The run-time guard for `_write_calibration`: exactly the calibration
    file in this model's folder, and not inside a case."""
    expected = calibration_path(model_dir)
    if os.path.normcase(os.path.abspath(os.fspath(target))) != \
            os.path.normcase(os.fspath(expected)):
        raise MediaError(f"Refusing to write {target}: a voice calibration is "
                         f"only ever {expected}.")
    for parent in expected.parents:
        if (parent / "case.json").is_file():
            raise MediaError(f"Refusing to write a calibration inside the case "
                             f"at {parent}; the voice model does not belong "
                             "in a case.")
    return expected


def _write_calibration(model_dir, data: dict) -> Path:
    target = assert_calibration_path(model_dir, calibration_path(model_dir))
    tmp = target.with_name(f".{target.name}.{os.urandom(4).hex()}.tmp")
    with open(tmp, "x", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, target)
    return target


def load_calibrations(model_dir) -> list[dict]:
    """Every calibration fitted for this model, oldest first."""
    path = calibration_path(model_dir)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        raise MediaError(f"The calibration file {path} cannot be read: {exc}"
                         ) from exc
    return list(data.get("calibrations") or [])


def calibration_by_name(model_dir, name: str) -> dict:
    for cal in load_calibrations(model_dir):
        if cal.get("name") == name:
            return cal
    raise MediaError(f"No calibration named \"{name}\" for the voice model in "
                     f"{model_dir}.")


def reference_set(root, max_clips: int = MAX_CLIPS_PER_SPEAKER) -> dict:
    """{speaker: [recordings]} from a folder with one subfolder per speaker
    (nested folders allowed), at most `max_clips` each, sorted — speakers
    with fewer than two recordings left out."""
    base = Path(root)
    if not base.is_dir():
        raise MediaError(f"{root} is not a folder.")
    out = {}
    for folder in sorted(p for p in base.iterdir() if p.is_dir()):
        clips = sorted(p for p in folder.rglob("*")
                       if p.is_file() and p.suffix.lower() in AUDIO_EXT)
        if len(clips) >= 2:
            out[folder.name] = clips[:max(2, int(max_clips))]
    if len(out) < MIN_CALIBRATION_SPEAKERS:
        raise MediaError(
            f"{root} needs at least {MIN_CALIBRATION_SPEAKERS} speaker "
            "subfolders with two or more recordings each (found "
            f"{len(out)}). One subfolder per speaker; ten or more speakers "
            "make a steadier calibration.")
    return out


def pair_scores(voices: dict) -> tuple[list[float], list[float]]:
    """Same- and different-speaker scores, the way the page uses the model:
    each speaker's first half of clips enrols a profile, every other clip is
    scored against every profile. {speaker: [clip embeddings]}."""
    profiles, tests = {}, {}
    for spk, clips in voices.items():
        k = max(1, len(clips) // 2)
        profiles[spk] = mean_embedding(clips[:k])
        tests[spk] = clips[k:]
    same, diff = [], []
    for spk, prof in profiles.items():
        for other, clips in tests.items():
            for clip in clips:
                (same if other == spk else diff).append(cosine(clip, prof))
    return same, diff


def calibrate(reference_dir, *, name: str, model_dir, ffmpeg, out_dir,
              python=None, worker=None, scratch=None, device: str = "auto",
              conditions: str = "", max_clips: int = MAX_CLIPS_PER_SPEAKER,
              progress=None, heartbeat=None, should_cancel=None) -> dict:
    """Fit a calibration on a reference set and keep it beside the model.

    The reference recordings are not evidence and nothing goes into a case:
    the working files land in a harness folder (`out_dir`, ATK:
    data\\media\\harness), and the fitted map in the model's
    voiceprint_calibration.json under `name` (a same-named one is replaced)."""
    say = progress or (lambda _l: None)
    name = str(name or "").strip()
    if not name:
        raise MediaError("Name the calibration — what its recordings are like "
                         "(\"clean read speech\", \"phone calls\", \"VHF "
                         "radio\").")
    check_model(model_dir)
    worker_argv(python, worker)
    require_ffmpeg(ffmpeg)
    fingerprint = model_fingerprint(model_dir)
    refs = reference_set(reference_dir, max_clips)
    spot = _HarnessSpot(out_dir)
    run_name = f"voiceprint-calibration-{_new_id('cal')[4:]}"
    run_dir = spot.dirs(run_name)
    items, owner = [], {}
    total = sum(len(v) for v in refs.values())
    with spot.log(run_dir / "voiceprint.log") as log:
        n = 0
        for spk, clips in refs.items():
            for clip in clips:
                n += 1
                if _cancelled(should_cancel):
                    raise Cancelled("the calibration was stopped")
                say(f"Reference {n} of {total} ({spk}): 16 kHz mono…")
                wav16 = run_dir / f"{n:04d}.16k.wav"
                to_16k(ffmpeg, clip, wav16, log=log, guard=spot.guard,
                       should_cancel=should_cancel)
                measured = _measure(wav16)
                if not measured["segments"]:
                    continue
                cid = f"c{n:04d}"
                owner[cid] = spk
                items.append({"id": cid, "wav": wav16,
                              "segments": measured["segments"]})
        data = embed(items, spot=spot, run_dir=run_dir, model_dir=model_dir,
                     python=python, worker=worker, scratch=scratch,
                     device=device, log=log, should_cancel=should_cancel,
                     heartbeat=heartbeat, say=say)
    back = {it["id"]: it for it in data["items"]}
    voices: dict = {}
    for item in items:
        voices.setdefault(owner[item["id"]], []).append(
            _voice(item, back[item["id"]])["embedding"])
    voices = {k: v for k, v in voices.items() if len(v) >= 2}
    if len(voices) < MIN_CALIBRATION_SPEAKERS:
        raise MediaError("Too few reference speakers had speech in two or "
                         "more recordings to calibrate.")
    same, diff = pair_scores(voices)
    fit = fit_calibration(same, diff)
    entry = dict(fit, name=name, conditions=str(conditions or "").strip(),
                 created_at=utc_now(), reference_dir=os.fspath(reference_dir),
                 speakers=len(voices),
                 clips=sum(len(v) for v in voices.values()),
                 model=fingerprint, device=data.get("device", ""),
                 method="logistic map on cosine scores, classes weighted "
                        "equally (even prior odds); half of each speaker's "
                        "clips enrol a profile, the rest are scored against "
                        "every profile",
                 folder=os.fspath(run_dir))
    spot.json(run_dir / "calibration.json",
              dict(entry, same_scores=same, diff_scores=diff))
    kept = [c for c in load_calibrations(model_dir) if c.get("name") != name]
    _write_calibration(model_dir, {
        "schema": 1, "kind": "forensics_workshop.voiceprint.calibrations",
        "model": MODEL_ID, "calibrations": kept + [entry]})
    say(f"Calibration \"{name}\": {entry['speakers']} speakers, "
        f"{fit['same_pairs']} same / {fit['diff_pairs']} different pairs, "
        f"EER {fit['eer'] * 100:.1f}%, 50% at a raw score of "
        f"{fit['score_at_50']}.")
    return entry


def capability_note() -> str:
    return ("Voice comparison runs SpeechBrain's ECAPA model in a separate "
            "worker process (the host's torch interpreter); a probability is "
            "shown only through a calibration.")

