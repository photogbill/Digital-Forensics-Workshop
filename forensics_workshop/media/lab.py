# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""A whole SAM run into a case — and replay, and the negative control.

**THE FORENSIC DOOR (FORENSICS_PLAN §12.3).** Everything a run produces lives
in the CASE, never in ATK: `<case>/media/<recipe-id>/`, with custody records
naming the recipe, the tier, the input hash and every output:

    media.started   what is about to run, on what, with which weights
    media.derived   files that landed — the measured input, then each seed's
                    target and residual — with their hashes and tier
    media.failed    the stage that stopped, and the sentence saying why

**THE ORIGINAL IS NEVER TOUCHED.** It is read once, through
`blocker.open_evidence`, into a hashed working copy inside the run folder —
the copy and its hash are one read, so what was hashed is what was copied.
A WAV is that copy (`input.wav`). Anything else — a phone video, an M4A —
is copied to `source/` and FFmpeg (injected: ATK passes `bin\\ffmpeg\\
ffmpeg.exe`) extracts its first audio stream, losslessly as float, into
`input.wav`: a MEASURED step in the recipe. A file inside a disk image is
reached by recovering it into the case first; that recovered file is then
the input.

    <case>/media/sam-20261005T221430Z-3fa9c1/
        recipe.json                         the whole run (lab.load_run)
        input.wav  (+ .recipe.json)          what SAM heard — measured
        source/<name>                        the copy, when FFmpeg was needed
        seed1.target.invented.wav  (+ sidecar)
        seed1.residual.invented.wav (+ sidecar)   ALWAYS kept: what was taken
        seed1.audiocpp.log                  audio.cpp's stdout and stderr
        …

**SEVERAL SEEDS, AND WHERE THEY DISAGREE.** Default three. The port has no
candidate ranker, so the run shows per-window disagreement between the
seeds' targets (`disagreement.py`) and choosing one is the examiner's act.

**LONGER THAN SAM TAKES AT ONCE: WINDOWS.** The model's context is 400 s
(`sam_audio.MAX_AUDIO_S`). A longer recording is cut — sample for sample, a
measured step — into windows of `WINDOW_S` overlapping by `OVERLAP_S`, each
window runs as its own SAM pass (anchors moved into its time), and each
seed's outputs are joined as the windows finish: every window's own stretch
as SAM wrote it, a `CROSSFADE_S` linear crossfade in the middle of each
overlap, where both windows have context. The window files and the
per-window outputs are discarded once joined; their SHA-256s stay in the
recipe. Bill, 2026-10-09: a 99 min 55 s video ran the codec for 3 min 47 s
and then failed on the limit.

**REPLAY** re-runs a recipe from the untouched original — refused if the
original's hash has changed or the weights are not the ones recorded — into
a new run folder, and compares: the measured stage must be bit-exact; a
generative GPU stage is held to `REPLAY_TOLERANCE_DB`, said in the result,
because audio.cpp's own documentation warns that different computation
shapes give small floating-point differences.

**THE NEGATIVE CONTROL (§12.12), first and small.** SAM on speech-absent
noise: does the target carry sound where the input has no speech? An
energy check only — the ASR check comes later — recorded in the model
manifest, so every surface can say "not yet negative-control tested" until
it has been run. Its files go to a harness folder the caller names (ATK:
`data\\media\\harness\\`), never a case: a validation run is not case work.
"""

from __future__ import annotations

import array
import functools
import json
import math
import os
import struct
import time
from pathlib import Path

from .. import blocker, hashing
from .. import case as _case
from .. import extract as _extract
from ..errors import Cancelled, MediaError
from ..timeutil import utc_now
from . import disagreement as _dis
from . import recipe as _recipe
from . import sam_audio as _sam
from . import separator as _sep
from . import wav as _wav
from . import weights as _weights

MEDIA_DIR = "media"
DEFAULT_SEEDS = (1, 2, 3)
MAX_SEEDS = 5
COPY_CHUNK = 1 << 20
INPUT_NAME = "input.wav"
REPLAY_TOLERANCE_DB = 1.0
NEGATIVE_TEXT = "person speaking"
#: Windows for a recording longer than SAM takes at once (module notes).
#: ONCE_LIMIT_S leaves room under the model's 400 s for audio.cpp's padding
#: to the next 40 ms frame.
WINDOW_S = 360.0
OVERLAP_S = 20.0
CROSSFADE_S = 2.0
ONCE_LIMIT_S = 390.0
WINDOW_TOOL = "forensics_workshop media windows"
JOIN_TOOL = "forensics_workshop media join"
WINDOWS_DIR = "windows"
#: The negative control flags a window where the target is itself audible
#: (>= -60 dBFS) AND within 20 dB of the noise it was given: a separator
#: asked for speech that hands back a fifth of the noise's amplitude or more
#: from no speech at all is producing something, and that is the warning.
SPEAKS_FLOOR_DB = -60.0
SPEAKS_WITHIN_DB = 20.0
_FFMPEG_VERSION: dict = {}


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------

def capability_note() -> str:
    """The live half of the capability row: which disagreement measure this
    interpreter can run. Presence only (`find_spec`), never an import — the
    capability table must not load numpy to describe itself."""
    import importlib.util
    try:
        present = importlib.util.find_spec("numpy") is not None
    except (ImportError, ValueError):
        present = False
    if present:
        return ("Seed disagreement here: band-energy spread (numpy is "
                "present).")
    return ("Seed disagreement here: RMS-envelope spread only — numpy is not "
            "installed (the pyproject extra `media` adds it).")


def seed_list(seeds) -> tuple:
    """`3` -> (1, 2, 3); `[7, 42]` -> (7, 42). One to five distinct
    non-negative seeds — never -1, audio.cpp's "random", because a random
    seed cannot be replayed."""
    if isinstance(seeds, int):
        if not 1 <= seeds <= MAX_SEEDS:
            raise MediaError(f"Run 1 to {MAX_SEEDS} seeds, not {seeds}.")
        return tuple(range(1, seeds + 1))
    try:
        out = tuple(int(s) for s in seeds)
    except (TypeError, ValueError):
        raise MediaError(f"Seeds are whole numbers; {seeds!r} is not.") from None
    if not 1 <= len(out) <= MAX_SEEDS:
        raise MediaError(f"Run 1 to {MAX_SEEDS} seeds, not {len(out)}.")
    if len(set(out)) != len(out) or any(s < 0 or s > 4294967295 for s in out):
        raise MediaError("Seeds must be distinct whole numbers from 0 to "
                         "4294967295 (no random seed: it cannot be replayed).")
    return out


def plan_windows(duration_s: float, *, window_s: float = WINDOW_S,
                 overlap_s: float = OVERLAP_S,
                 once_limit_s: float = ONCE_LIMIT_S) -> list:
    """[(start, end)] in seconds: the whole recording when it fits at once,
    else windows of `window_s` every `window_s - overlap_s`, the last one
    ending exactly at the end (a full window, overlapping its neighbour
    more)."""
    d = float(duration_s)
    if d <= once_limit_s:
        return [(0.0, d)]
    if not (0.0 <= overlap_s < window_s <= once_limit_s):
        raise MediaError(f"A window of {window_s:g} s overlapping by "
                         f"{overlap_s:g} s does not fit SAM's "
                         f"{once_limit_s:g} s.")
    hop = window_s - overlap_s
    n = math.ceil((d - window_s) / hop) + 1
    spans = [(i * hop, i * hop + window_s) for i in range(n - 1)]
    spans.append((max(0.0, d - window_s), d))
    return [(round(a, 6), round(b, 6)) for a, b in spans]


def crossfades(spans, crossfade_s: float = CROSSFADE_S) -> list:
    """[(start, end)] seconds of the crossfade at each join: `crossfade_s`
    (never more than the overlap) centred in the overlap of two windows."""
    out = []
    for (_a0, b0), (a1, _b1) in zip(spans, spans[1:]):
        mid = 0.5 * (a1 + b0)
        half = 0.5 * min(crossfade_s, b0 - a1)
        out.append((round(mid - half, 6), round(mid + half, 6)))
    return out


def window_anchors(anchors, start: float, end: float) -> tuple:
    """The anchors that reach into [start, end), moved into its own time."""
    out = []
    for a in anchors:
        s, e = round(max(a.start, start) - start, 3), \
            round(min(a.end, end) - start, 3)
        if s < e:
            out.append(_sep.make_anchor(a.sign, s, e))
    return tuple(out)


def new_recipe_id() -> str:
    stamp = utc_now()[:19].replace("-", "").replace(":", "")
    return f"sam-{stamp}Z-{os.urandom(3).hex()}"


def _tool_version(argv: list[str]) -> str:
    """`ffmpeg -version`'s first line, cached; never raises."""
    key = tuple(argv)
    if key not in _FFMPEG_VERSION:
        _FFMPEG_VERSION[key] = _sam.probe_version(argv, "-version").split(
            " | ")[0]
    return _FFMPEG_VERSION[key]


def _cancelled(should_cancel) -> bool:
    return bool(should_cancel is not None and should_cancel())


def _beat(say, head: str):
    """The separator's heartbeat as one sentence: what is running, for how
    long, and the last thing audio.cpp printed."""
    def beat(elapsed_s: float, last: str) -> None:
        say(f"{head} — running {_sam.clock(elapsed_s)} · audio.cpp: "
            f"{last or 'nothing printed yet'}")
    return beat


def _wav_or_none(path):
    try:
        return _wav.read_info(path)
    except MediaError:
        return None


# ---------------------------------------------------------------------------
# the writers — every file this module itself writes passes through these
# ---------------------------------------------------------------------------

def _case_log(case, path):
    """Open a new log inside the case for a child's stdout and stderr."""
    target = blocker.assert_case_path(case.root, path)
    return open(target, "xb")


def _case_settle(case, moves, work_dir) -> list[str]:
    """Give the runtime's outputs their labelled names, inside the case."""
    notes = []
    for src, dst in moves:
        blocker.assert_case_path(case.root, src)
        os.replace(src, blocker.assert_case_path(case.root, dst))
    work = blocker.assert_case_path(case.root, work_dir)
    try:
        os.rmdir(work)
    except OSError:
        notes.append(f"{Path(work).name} still holds files the runtime wrote "
                     "besides the two stems; they are left as they are")
    return notes


def _case_cut(case, info, src, dst, first_frame: int, frames: int) -> None:
    """A stretch of a WAV copied sample for sample into a new WAV inside the
    case: the same sample format, rate and channels, the bytes of those
    frames and nothing else."""
    target = blocker.assert_case_path(case.root, dst)
    align = info.block_align
    nbytes = frames * align
    if info.kind == "float":
        fmt = struct.pack("<HHIIHHH", 3, info.channels, info.rate,
                          info.rate * align, align, info.bits, 0)
        head = (b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
                + struct.pack("<II", 4, frames))
    else:
        fmt = struct.pack("<HHIIHH", 1, info.channels, info.rate,
                          info.rate * align, align, info.bits)
        head = b"fmt " + struct.pack("<I", 16) + fmt
    pad = nbytes & 1
    with blocker.open_evidence(src) as fin, open(target, "xb") as fout:
        fout.write(b"RIFF" + struct.pack("<I", 4 + len(head) + 8 + nbytes + pad)
                   + b"WAVE" + head + b"data" + struct.pack("<I", nbytes))
        fin.seek(info.data_offset + first_frame * align)
        left = nbytes
        while left > 0:
            chunk = fin.read(min(COPY_CHUNK, left))
            if not chunk:
                break
            fout.write(chunk)
            left -= len(chunk)
        fout.write(b"\0" * (left + pad))


class _Join:
    """One output of a windowed run, written as the windows finish: each
    window's own stretch exactly as SAM wrote it, a linear crossfade where
    two windows meet. Only a crossfade's worth of samples is held in memory;
    the file is mono IEEE float32, as audio.cpp writes its stems."""

    def __init__(self, case, dst, rate: int, total: int) -> None:
        self.case, self.rate, self.total = case, int(rate), int(total)
        self.path = blocker.assert_case_path(case.root, dst)
        self.fh = open(self.path, "xb")
        data = self.total * 4
        fmt = struct.pack("<HHIIHHH", 3, 1, self.rate, self.rate * 4, 4, 32, 0)
        self.fh.write(b"RIFF" + struct.pack("<I", 50 + data) + b"WAVE"
                      + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
                      + struct.pack("<II", 4, self.total) + b"data"
                      + struct.pack("<I", data))
        self.written = 0
        self.fade = None                       # (f0, f1) frames, pending
        self.carry = array.array("d")          # the earlier window's part

    def _put(self, samples) -> None:
        if len(samples):
            self.fh.write(array.array("f", samples).tobytes())
            self.written += len(samples)

    def _mix(self, mine) -> None:
        f0, f1 = self.fade
        n = f1 - f0
        mine = list(mine) + [0.0] * (n - len(mine))
        old = list(self.carry) + [0.0] * (n - len(self.carry))
        self._put([old[i] + (mine[i] - old[i]) * ((i + 0.5) / n)
                   for i in range(n)])
        self.fade, self.carry = None, array.array("d")

    def add(self, src, start: int, fade_out=None) -> None:
        """Window output `src`, its first sample at frame `start`; `fade_out`
        (frames) is where it hands over to the next window."""
        blocker.assert_case_path(self.case.root, self.path)
        own_to = fade_out[0] if fade_out else self.total
        pending = array.array("d")
        nxt = array.array("d")
        t0 = int(start)
        for block in _wav.iter_mono(src, block_frames=self.rate * 10):
            t1 = t0 + len(block)
            if self.fade:
                a, b = max(t0, self.fade[0]), min(t1, self.fade[1])
                if a < b:
                    pending.extend(block[a - t0:b - t0])
                if t1 >= self.fade[1]:
                    self._mix(pending)
            if not self.fade:
                a, b = max(t0, self.written), min(t1, own_to)
                if a < b:
                    self._put(block[a - t0:b - t0])
            if fade_out:
                a, b = max(t0, fade_out[0]), min(t1, fade_out[1])
                if a < b:
                    nxt.extend(block[a - t0:b - t0])
            t0 = t1
        if self.fade:                          # a window shorter than said
            self._mix(pending)
        if self.written < own_to:
            self._put(array.array("d", bytes(8 * (own_to - self.written))))
        self.fade, self.carry = (tuple(fade_out), nxt) if fade_out else \
            (None, array.array("d"))

    def close(self) -> None:
        blocker.assert_case_path(self.case.root, self.path)
        if self.written < self.total:
            self._put(array.array("d", bytes(8 * (self.total - self.written))))
        self.fh.close()


def _case_discard(case, paths, folders=()) -> None:
    """Delete files this run made inside the case (window copies, window
    outputs once joined) and then their folders if empty — their hashes are
    in the recipe."""
    for path in paths:
        target = blocker.assert_case_path(case.root, path)
        try:
            os.remove(target)
        except FileNotFoundError:
            pass
    for folder in folders:
        target = blocker.assert_case_path(case.root, folder)
        try:
            os.rmdir(target)
        except OSError:
            pass


def _harness_dirs(root, name) -> Path:
    target = blocker.assert_harness_path(root, Path(root) / name)
    target.mkdir(parents=True, exist_ok=True)
    return target


def _harness_log(root, path):
    return open(blocker.assert_harness_path(root, path), "xb")


def _harness_settle(root, moves, work_dir) -> list[str]:
    notes = []
    for src, dst in moves:
        blocker.assert_harness_path(root, src)
        os.replace(src, blocker.assert_harness_path(root, dst))
    try:
        os.rmdir(blocker.assert_harness_path(root, work_dir))
    except OSError:
        notes.append(f"{Path(work_dir).name} still holds files the runtime "
                     "wrote besides the two stems; they are left as they are")
    return notes


def _harness_json(root, path, data: dict) -> None:
    target = blocker.assert_harness_path(root, path)
    with open(target, "x", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())


# ---------------------------------------------------------------------------
# the input
# ---------------------------------------------------------------------------

def resolve_input(case, source, evidence_id: str = "") -> dict:
    """Where the input is, said the way custody will say it.

    With `evidence_id`, `source` is a path inside that registered folder.
    Without one, `source` is any file: inside registered evidence it is
    named as such; anywhere else it is the examiner's choice, and its
    outputs still go into THIS case.
    """
    if evidence_id:
        item = case.evidence_item(evidence_id)
        if item.kind != "logical-folder":
            raise MediaError(
                f"{evidence_id} is a disk image. Recover the file into the "
                "case first (Disk Image page, Recover), then choose the "
                "recovered file as the input.")
        rel = _extract.safe_relpath(source)
        path = Path(item.source).joinpath(*rel.parts)
        if not blocker.is_inside(path, item.source):
            raise MediaError(f"{source!r} resolves outside {evidence_id}.")
        kind, relpath = "evidence", rel.as_posix()
    else:
        path = Path(os.path.abspath(os.fspath(source)))
        kind, relpath = "examiner-chosen", ""
        for item in case.evidence():
            if item.kind == "logical-folder" and blocker.is_inside(
                    path, item.source):
                kind, evidence_id = "evidence", item.id
                relpath = Path(os.path.relpath(path, item.source)).as_posix()
                break
        else:
            if blocker.is_inside(path, case.root):
                kind = "case-file"
                relpath = Path(os.path.relpath(path, case.root)).as_posix()
    if not path.is_file():
        raise MediaError(f"{path} is not a file (or is no longer there).")
    return {"kind": kind, "path": os.fspath(path), "name": path.name,
            "evidence_id": evidence_id, "relpath": relpath}


def _copy_in(case, source, dest):
    """One read of the original through the read-only door: the copy and
    its hashes come out of the same bytes."""
    with blocker.open_evidence(source) as fh:
        return _extract.copy_stream_to_case(
            case, iter(lambda: fh.read(COPY_CHUNK), b""), dest)


def _prepare_input(case, run_dir: Path, original: dict, ffmpeg, say,
                   should_cancel, input_name: str = INPUT_NAME) -> tuple:
    """(input path, its WavInfo, steps, the original's Hashes, the input's
    SHA-256). A WAV's input IS the copy; anything else goes through FFmpeg."""
    src = original["path"]
    target = run_dir / input_name
    header = _wav_or_none(src) if Path(src).suffix.lower() == ".wav" else None
    # A WAV goes straight to SAM only when its header and its data agree:
    # audio.cpp's reader throws on a data chunk longer than the file, or a
    # length never filled in — so such a file is rewritten by FFmpeg, as a
    # measured step, like any non-WAV input.
    is_wav = header is not None and not header.notes and header.frames > 0
    odd = "" if header is None or is_wav else (
        "; ".join(header.notes) or "it holds no audio frames")
    steps = []
    if is_wav:
        say("Copying the WAV into the case through the read-only door…")
        hashes = _copy_in(case, src, target)
        steps.append(_recipe.step(
            "forensics_workshop read-only door (hashed copy)", tier="measured",
            params={"from": original["kind"]},
            inputs={"original": hashes.sha256},
            outputs={input_name: hashes.sha256},
            note="the original's bytes, unchanged"))
        return target, _wav.read_info(target), steps, hashes, hashes.sha256
    if not ffmpeg:
        why = (f"is a WAV whose header does not match its data ({odd}), which "
               "audio.cpp's reader refuses" if odd else
               "is not a WAV this engine can read")
        raise MediaError(
            f"{original['name']} {why}, so its audio must be rewritten by "
            "FFmpeg first, and no FFmpeg was given. ATK uses "
            "bin\\ffmpeg\\ffmpeg.exe (get_tools.bat fetches it).")
    argv0 = _sam.runtime_argv(ffmpeg)
    if not Path(argv0[-1]).is_file():
        raise MediaError(f"FFmpeg is not at {argv0[-1]}; it is needed to take "
                         f"the audio out of {original['name']}. Run "
                         "get_tools.bat in the ATK folder.")
    say("Copying the original into the case through the read-only door…")
    copy = run_dir / "source" / original["name"]
    hashes = _copy_in(case, src, copy)
    steps.append(_recipe.step(
        "forensics_workshop read-only door (hashed copy)", tier="measured",
        params={"from": original["kind"]}, inputs={"original": hashes.sha256},
        outputs={f"source/{original['name']}": hashes.sha256},
        note="the original's bytes, unchanged"))
    if _cancelled(should_cancel):
        raise Cancelled("the SAM run was stopped before FFmpeg ran")
    say("Extracting the audio with FFmpeg (lossless, float)…")
    argv = argv0 + ["-hide_banner", "-nostdin", "-n", "-i", os.fspath(copy),
                    "-map", "0:a:0", "-vn", "-sn", "-dn", "-c:a", "pcm_f32le",
                    os.fspath(target)]
    log_path = run_dir / "ffmpeg.log"
    blocker.assert_case_path(case.root, target)
    with _case_log(case, log_path) as log:
        outcome = _sam.run_process(
            argv, log=log, timeout_s=3600.0, writes=[target],
            guard=functools.partial(blocker.assert_case_path, case.root),
            should_cancel=should_cancel)
    if outcome["state"] == "cancelled":
        raise Cancelled("the SAM run was stopped while FFmpeg ran")
    try:
        info = _wav.check_stem(target) if target.is_file() else None
    except MediaError:
        info = None
    if outcome["state"] != "completed" or info is None:
        raise MediaError(
            f"FFmpeg could not take an audio track out of {original['name']} "
            f"({outcome['state']}, {_sam.exit_sentence(outcome['returncode'])})"
            f": {_sam.log_tail(log_path) or outcome['error']}. The log is "
            f"{log_path}.")
    out_sha = hashing.hash_case_file(target).sha256
    steps.append(_recipe.step(
        "ffmpeg", tier="measured", version=_tool_version(argv0),
        params={"args": ["-map", "0:a:0", "-vn", "-sn", "-dn", "-c:a",
                         "pcm_f32le"], "stream": "first audio stream"},
        inputs={f"source/{original['name']}": hashes.sha256},
        outputs={input_name: out_sha},
        note="decoded to 32-bit float at the track's own rate and channels; "
             "nothing resampled or mixed"
             + (f". The WAV's header did not match its data ({odd})"
                if odd else "")))
    return target, info, steps, hashes, out_sha


# ---------------------------------------------------------------------------
# the run
# ---------------------------------------------------------------------------

def _output_entry(name, sha, stem, seed, tier, chain, log="",
                  size=None) -> dict:
    return {"file": name, "sha256": sha, "stem": stem, "seed": seed,
            "tier": tier, "chain": list(chain), "size": size,
            "sidecar": _recipe.sidecar_path(name).name, "log": log}


def upstream_of_input(case, path) -> tuple[str, str, str]:
    """(recipe id, tier, how it is known) for an input that may itself be a
    derived item — so an invented stem fed back in stays Invented.

    Its sidecar first; then its name (`….invented.wav`); then its BYTES: a
    renamed stem with no sidecar is matched by SHA-256 against every output
    above Measured recorded in this case's runs. Only an input whose size
    matches such an output is hashed, so an ordinary input costs a few stats.
    """
    rid, tier = _recipe.upstream_of(path)
    if tier:
        basis = ("sidecar" if _recipe.sidecar_path(path).is_file()
                 else "filename")
        return rid, tier, basis
    try:
        size = os.path.getsize(path)
    except OSError:
        return "", "", ""
    candidates = []
    # SAM runs and restoration runs (restore.py) keep the same recipe format.
    roots = (runs_root(case), Path(case.root) / "restoration")
    for folder in [f for r in roots if r.is_dir() for f in r.iterdir()]:
        try:
            data = _recipe.load_recipe(folder)
        except Exception:                                 # noqa: BLE001
            continue        # an unreadable run cannot vouch for anything
        for out in data.get("outputs", []):
            if out.get("tier", "measured") == "measured":
                continue    # a measured copy carries nothing up; skip its hash
            known = out.get("size")
            if known is None:
                try:
                    known = os.path.getsize(folder / out.get("file", ""))
                except OSError:
                    continue
            if known == size:
                candidates.append((data["recipe_id"], out))
    if not candidates:
        return "", "", ""
    digest = hashing.hash_evidence(path).sha256
    hits = [(rid, out["tier"]) for rid, out in candidates
            if out.get("sha256") == digest]
    if not hits:
        return "", "", ""
    rid, tier = max(hits, key=lambda h: _recipe.tier_rank(h[1]))
    return rid, tier, "hash"


def _write_sidecar(case, run_dir, entry, steps, original, upstream_tier,
                   recipe_id) -> None:
    data = _recipe.sidecar(
        recipe_id=recipe_id, file=entry["file"], sha256=entry["sha256"],
        stem=entry["stem"], seed=entry["seed"],
        chain=[steps[i] for i in entry["chain"]],
        input_sha256=original["sha256"], original=original,
        upstream_tier=upstream_tier, written_at=utc_now())
    _case.write_json_atomic(case.root, _recipe.sidecar_path(
        run_dir / entry["file"]), data)


def _finish(case, run_dir, recipe: dict, targets: dict, method: str,
            say) -> dict:
    if targets:
        say("Measuring where the seeds disagree…")
        try:
            recipe["disagreement"] = _dis.compare(targets, method=method)
        except MediaError as exc:
            recipe["disagreement"] = {"method": "", "spans": [], "series": [],
                                      "summary": f"Not measured: {exc}"}
    tiers = [o["tier"] for o in recipe["outputs"]]
    recipe["tier"] = _recipe.highest_tier(tiers) if tiers else ""
    _case.write_json_atomic(case.root, run_dir / _recipe.RECIPE_FILE, recipe)
    return with_paths(recipe, run_dir)


def with_paths(recipe: dict, run_dir) -> dict:
    """The recipe with absolute paths added for a surface to play and open."""
    out = dict(recipe, folder=os.fspath(run_dir))
    out["outputs"] = [dict(o, path=os.fspath(Path(run_dir) / o["file"]))
                      for o in recipe.get("outputs", [])]
    return out


def run_sam(case, source, *, text: str, model, audiocpp, anchors=(),
            seeds=DEFAULT_SEEDS, ffmpeg=None, evidence_id: str = "",
            backend: str | None = None, memory_bounded: bool | None = None,
            steps: int | None = None, timeout_s: float | None = None,
            method: str = "auto", replay_of: str = "", progress=None,
            should_cancel=None, allow_cpu: bool = False,
            heartbeat=None, window_s: float = WINDOW_S,
            overlap_s: float = OVERLAP_S,
            once_limit_s: float = ONCE_LIMIT_S) -> dict:
    """Separate `source` with SAM Audio, every seed, into the open case.

    Refused before anything is written: no text, a bad anchor or seed, no
    runtime, a CPU-only runtime (unless `allow_cpu`), no model, or weights
    whose hash differs from their pin. Once `media.started` is recorded, any
    stop is `media.failed` with the stage and the reason, and what had
    already landed is kept and listed.

    `progress` gets one line per stage; `heartbeat` (default: `progress`)
    gets the "still running" line every few seconds while audio.cpp runs —
    a host that logs `progress` can keep the heartbeat on screen only.

    A recording longer than SAM takes at once runs as windows (module notes);
    `window_s`, `overlap_s` and `once_limit_s` are recorded with the run so a
    replay cuts the same windows.
    """
    say = progress or (lambda _line: None)
    beat_to = heartbeat or say
    seeds = seed_list(seeds)
    text = _sam.require_text(text)
    anchors = _sep.check_anchors(anchors)
    original = resolve_input(case, source, evidence_id)
    upstream_id, upstream_tier, upstream_basis = upstream_of_input(
        case, original["path"])
    _sam.check_runtime(audiocpp)
    separator = _sam.SamAudioSeparator(audiocpp, model, backend=backend,
                                       steps=steps, allow_cpu=allow_cpu)
    separator.check_backend()        # a CPU build: refused before the hash
    if not Path(model).is_file():
        raise MediaError(f"The model file {model} does not exist. "
                         + _sam.INSTALL_HINT)
    _sam.ansi_path(case.root)        # refused here, before anything is written
    _sam.ansi_path(model)
    say(f"SAM Audio will run on {_sam.backend_label(separator.backend)} "
        f"({_sam.build_sentence(audiocpp)}).")
    say("Checking the model file against its pin (hashed once, then cached)…")
    weights = _weights.check_weights(model, should_cancel=should_cancel)
    negative = _weights.negative_control_status(model, weights["sha256"])
    tool = separator.describe()
    recipe_id = new_recipe_id()
    run_dir = _case.make_case_dirs(case.root, MEDIA_DIR, recipe_id)
    model_entry = {"file": Path(model).name,
                   "path": os.path.abspath(os.fspath(model)),
                   "sha256": weights["sha256"], "weights": weights["state"]}
    recipe = {"schema": _recipe.SCHEMA, "kind": "forensics_workshop.media.recipe",
              "recipe_id": recipe_id, "created_at": utc_now(),
              "examiner": case.examiner, "state": "running",
              "separator": tool, "model": model_entry,
              "prompt": {"text": text.strip(),
                         "anchors": [a.as_list() for a in anchors]},
              "seeds": list(seeds), "original": dict(original),
              "upstream": {"recipe_id": upstream_id, "tier": upstream_tier,
                           "basis": upstream_basis},
              "upstream_tier": upstream_tier, "input_sha256": "",
              "input": {}, "steps": [], "outputs": [], "tier": "",
              "weights": {"state": weights["state"],
                          "sentence": weights["sentence"]},
              "negative_control": {"state": negative["state"],
                                   "sentence": negative["sentence"]},
              "disagreement": {}, "replay_of": replay_of,
              "failure": "", "notes": []}
    case.custody.record(
        "media.started", actor=case.actor(), target=recipe_id,
        detail={"recipe_id": recipe_id, "tool": "sam_audio via audiocpp_cli",
                "tier": "invented", "input": original,
                "text": text.strip(), "anchors": recipe["prompt"]["anchors"],
                "seeds": list(seeds), "model": model_entry,
                "runtime": tool.get("version", ""), "replay_of": replay_of,
                "folder": os.fspath(run_dir)})
    stage = "input"
    targets: dict = {}
    input_name = _recipe.output_name("input", upstream_tier or "measured")
    try:
        input_wav, info, prep, hashes, input_wav_sha = _prepare_input(
            case, run_dir, original, ffmpeg, say, should_cancel, input_name)
        original["sha256"] = hashes.sha256
        original["size"] = hashes.size
        recipe["original"] = dict(original)
        recipe["input_sha256"] = hashes.sha256
        recipe["input"] = {"file": input_name, "sha256": input_wav_sha,
                           "wav": info.as_dict()}
        recipe["steps"].extend(prep)
        prep_chain = list(range(len(prep)))
        entry = _output_entry(input_name, input_wav_sha, "input", None,
                              _recipe.output_tier(prep, upstream_tier),
                              prep_chain, size=os.path.getsize(input_wav))
        recipe["outputs"].append(entry)
        _write_sidecar(case, run_dir, entry, recipe["steps"], original,
                       upstream_tier, recipe_id)
        case.custody.record(
            "media.derived", actor=case.actor(), target=recipe_id,
            hashes={input_name: input_wav_sha},
            detail={"recipe_id": recipe_id, "tier": entry["tier"],
                    "input_sha256": hashes.sha256, "stage": "input",
                    "outputs": [{"file": input_name, "sha256": input_wav_sha}],
                    "duration_s": round(info.duration_s, 3)})
        _sep.check_anchors(anchors, info.duration_s)
        spans = plan_windows(info.duration_s, window_s=window_s,
                             overlap_s=overlap_s, once_limit_s=once_limit_s)
        windows = None
        if len(spans) > 1:
            stage = "windows"
            windows = _cut_windows(case, run_dir, recipe, input_wav, info,
                                   input_name, input_wav_sha, spans, say,
                                   window_s, overlap_s, once_limit_s)
        for n, seed in enumerate(seeds, 1):
            stage = f"seed {seed}"
            if _cancelled(should_cancel):
                raise Cancelled(f"the SAM run was stopped before seed {seed}")
            where = _sam.backend_label(separator.backend)
            if windows is not None:
                _run_windowed_seed(
                    case, run_dir, recipe, separator, windows, seed, n,
                    len(seeds), text=text, anchors=anchors, info=info,
                    prep_chain=prep_chain, model_entry=model_entry,
                    original=original, upstream_tier=upstream_tier,
                    hashes=hashes, weights=weights, targets=targets,
                    memory_bounded=memory_bounded, timeout_s=timeout_s,
                    should_cancel=should_cancel, say=say, beat_to=beat_to,
                    where=where)
                continue
            say(f"SAM Audio, seed {seed} ({n} of {len(seeds)}) — "
                f"{info.duration_s:.1f} s of audio on {where}…")
            work = _case.make_case_dirs(case.root, MEDIA_DIR, recipe_id,
                                        f"work-seed{seed}")
            log_name = f"seed{seed}.audiocpp.log"
            with _case_log(case, run_dir / log_name) as log:
                raw = separator.separate(
                    input_wav, text=text, anchors=anchors, seed=seed,
                    out_dir=work, log=log,
                    guard=functools.partial(blocker.assert_case_path,
                                            case.root),
                    should_cancel=should_cancel,
                    duration_s=info.duration_s, memory_bounded=memory_bounded,
                    timeout_s=timeout_s,
                    heartbeat=_beat(beat_to, f"SAM Audio seed {seed} "
                                    f"({n} of {len(seeds)}) on {where}"))
            if raw["state"] == "cancelled":
                raise Cancelled(f"the SAM run was stopped during seed {seed}")
            got = [Path(raw["target"]).is_file(), Path(raw["residual"]).is_file()]
            if raw["state"] != "completed" or not all(got):
                why = {"timeout": f"it ran past {raw['timeout_s']:.0f} s and "
                                  "was stopped",
                       "failed": "audiocpp_cli " + _sam.exit_sentence(
                           raw["returncode"])}.get(
                    raw["state"], "it reported success")
                missing = "" if all(got) else " and wrote no target.wav/" \
                                              "residual.wav"
                raise MediaError(
                    f"SAM Audio seed {seed} did not finish: {why}{missing}. "
                    f"audio.cpp said: {_sam.log_tail(run_dir / log_name) or raw['error'] or '(nothing)'}"
                    f" — full log {run_dir / log_name}.")
            names = {"target": _recipe.invented_name("target", seed),
                     "residual": _recipe.invented_name("residual", seed)}
            recipe["notes"].extend(_case_settle(
                case, [(raw["target"], run_dir / names["target"]),
                       (raw["residual"], run_dir / names["residual"])], work))
            sizes = {}
            for stem, name in names.items():
                try:            # a stem must be audio: frames, all finite
                    _wav.check_stem(run_dir / name)
                except MediaError as exc:
                    raise MediaError(f"SAM Audio seed {seed} wrote a broken "
                                     f"{stem}: {exc}") from exc
                sizes[stem] = os.path.getsize(run_dir / name)
            shas = {stem: hashing.hash_case_file(run_dir / name).sha256
                    for stem, name in names.items()}
            params = dict(raw["params"], argv=raw["argv"],
                          elapsed_s=raw["elapsed_s"])
            recipe["steps"].append(_recipe.step(
                "audiocpp_cli sam_audio", tier=separator.tier,
                version=raw["tool_version"], params=params, seed=seed,
                model=model_entry, time_range=[0.0, round(info.duration_s, 3)],
                inputs={input_name: input_wav_sha},
                outputs={names[s]: shas[s] for s in names},
                note=raw["params"].get("note", "")))
            chain = prep_chain + [len(recipe["steps"]) - 1]
            landed = []
            for stem in ("target", "residual"):
                entry = _output_entry(names[stem], shas[stem], stem, seed,
                                      _recipe.output_tier(
                                          [recipe["steps"][i] for i in chain],
                                          upstream_tier), chain, log_name,
                                      size=sizes[stem])
                recipe["outputs"].append(entry)
                _write_sidecar(case, run_dir, entry, recipe["steps"], original,
                               upstream_tier, recipe_id)
                landed.append({"file": names[stem], "sha256": shas[stem],
                               "stem": stem, "seed": seed})
            targets[seed] = run_dir / names["target"]
            case.custody.record(
                "media.derived", actor=case.actor(), target=recipe_id,
                hashes={names[s]: shas[s] for s in names},
                detail={"recipe_id": recipe_id, "tier": entry["tier"],
                        "input_sha256": hashes.sha256, "stage": stage,
                        "outputs": landed, "seed": seed,
                        "elapsed_s": raw["elapsed_s"],
                        "memory_bounded": raw["params"]["memory_bounded"],
                        "weights": weights["state"]})
    except Exception as exc:
        # Every stop is recorded — a defect as much as a refusal — and then
        # raised as it was. What had landed stays, listed in the recipe.
        state = "cancelled" if isinstance(exc, Cancelled) else "failed"
        recipe["state"] = state
        recipe["failure"] = (f"Stopped at {stage}: {exc}" if state == "cancelled"
                             else f"Failed at {stage}: {exc}")
        case.custody.record(
            "media.failed", actor=case.actor(), target=recipe_id,
            detail={"recipe_id": recipe_id, "tier": "invented",
                    "input_sha256": recipe["input_sha256"], "stage": stage,
                    "state": state, "error": str(exc),
                    "outputs": [o["file"] for o in recipe["outputs"]]})
        _finish(case, run_dir, recipe, targets, method, say)
        raise
    if windows is not None:
        _case_discard(case, [run_dir / w["file"] for w in windows["files"]],
                      [run_dir / WINDOWS_DIR])
        recipe["notes"].append(
            f"The {len(windows['files'])} window copies were discarded once "
            "every seed had run; their SHA-256s are in the windows step, and "
            "replay cuts them again from the input.")
    recipe["state"] = "completed"
    result = _finish(case, run_dir, recipe, targets, method, say)
    say(f"Done: {len(seeds)} seed(s), INVENTED tier — {result['folder']}")
    return result


def _cut_windows(case, run_dir, recipe, input_wav, info, input_name,
                 input_sha, spans, say, window_s, overlap_s,
                 once_limit_s) -> dict:
    """The input cut into its windows (a measured step); returns the plan:
    spans, frames, the files and the step's index."""
    _case.make_case_dirs(case.root, MEDIA_DIR, run_dir.name, WINDOWS_DIR)
    say(f"{info.duration_s / 60:.1f} min is longer than SAM Audio takes at "
        f"once ({_sam.MAX_AUDIO_S:g} s): {len(spans)} windows of "
        f"{window_s / 60:g} min, each overlapping the next by {overlap_s:g} s, "
        "joined afterwards. Cutting them…")
    files, outs = [], {}
    for k, (a, b) in enumerate(spans, 1):
        f0 = int(round(a * info.rate))
        f1 = min(info.frames, int(round(b * info.rate)))
        rel = f"{WINDOWS_DIR}/w{k:02d}.wav"
        _case_cut(case, info, input_wav, run_dir / rel, f0, f1 - f0)
        sha = hashing.hash_case_file(run_dir / rel).sha256
        files.append({"file": rel, "sha256": sha, "start_s": a, "end_s": b,
                      "frames": [f0, f1]})
        outs[rel] = sha
    fades = crossfades(spans)
    recipe["steps"].append(_recipe.step(
        WINDOW_TOOL, tier="measured",
        params={"windows": [list(s) for s in spans], "window_s": window_s,
                "overlap_s": overlap_s, "crossfade_s": CROSSFADE_S,
                "crossfades": [list(f) for f in fades],
                "once_limit_s": once_limit_s,
                "model_limit_s": _sam.MAX_AUDIO_S},
        inputs={input_name: input_sha}, outputs=outs,
        note=f"the input cut sample for sample into {len(spans)} windows: "
             f"SAM Audio takes at most {_sam.MAX_AUDIO_S:g} s at once (10,000 "
             "frames of 40 ms)"))
    return {"spans": spans, "files": files, "fades": fades,
            "step": len(recipe["steps"]) - 1}


def _run_windowed_seed(case, run_dir, recipe, separator, windows, seed, n,
                       of, *, text, anchors, info, prep_chain, model_entry,
                       original, upstream_tier, hashes, weights, targets,
                       memory_bounded, timeout_s, should_cancel, say, beat_to,
                       where) -> None:
    """One seed over every window, each output joined into the seed's two
    stems as soon as that window finishes, then discarded."""
    recipe_id = run_dir.name
    names = {"target": _recipe.invented_name("target", seed),
             "residual": _recipe.invented_name("residual", seed)}
    log_name = f"seed{seed}.audiocpp.log"
    spans, fades = windows["spans"], windows["fades"]
    joins: dict = {}
    per_window, window_outs, first = [], {}, None
    stage = f"seed {seed}"
    started = None
    try:
        with _case_log(case, run_dir / log_name) as log:
            for k, (span, wfile) in enumerate(zip(spans, windows["files"]), 1):
                if _cancelled(should_cancel):
                    raise Cancelled(f"the SAM run was stopped during seed "
                                    f"{seed}, before window {k}")
                eta = ""
                if started is not None and k > 1:
                    each = (time.monotonic() - started) / (k - 1)
                    eta = (f", about {_sam.clock(each * (len(spans) - k + 1))}"
                           " left for this seed")
                say(f"SAM Audio, seed {seed} ({n} of {of}), window {k} of "
                    f"{len(spans)} ({span[0] / 60:.1f}-{span[1] / 60:.1f} min) "
                    f"on {where}{eta}…")
                if started is None:
                    started = time.monotonic()
                work = _case.make_case_dirs(case.root, MEDIA_DIR, recipe_id,
                                            f"work-seed{seed}", f"w{k:02d}")
                mine = window_anchors(anchors, span[0], span[1])
                raw = separator.separate(
                    run_dir / wfile["file"], text=text, anchors=mine,
                    seed=seed, out_dir=work, log=log,
                    guard=functools.partial(blocker.assert_case_path,
                                            case.root),
                    should_cancel=should_cancel,
                    duration_s=span[1] - span[0],
                    memory_bounded=memory_bounded, timeout_s=timeout_s,
                    heartbeat=_beat(beat_to, f"SAM Audio seed {seed} ({n} of "
                                    f"{of}), window {k} of {len(spans)} on "
                                    f"{where}"))
                if raw["state"] == "cancelled":
                    raise Cancelled(f"the SAM run was stopped during seed "
                                    f"{seed}, window {k}")
                got = [Path(raw["target"]).is_file(),
                       Path(raw["residual"]).is_file()]
                if raw["state"] != "completed" or not all(got):
                    why = {"timeout": f"it ran past {raw['timeout_s']:.0f} s "
                                      "and was stopped",
                           "failed": "audiocpp_cli " + _sam.exit_sentence(
                               raw["returncode"])}.get(
                        raw["state"], "it reported success")
                    raise MediaError(
                        f"SAM Audio seed {seed}, window {k} of {len(spans)} "
                        f"did not finish: {why}"
                        + ("" if all(got) else " and wrote no target.wav/"
                           "residual.wav")
                        + f". audio.cpp said: "
                        f"{_sam.log_tail(run_dir / log_name) or raw['error'] or '(nothing)'}"
                        f" — full log {run_dir / log_name}.")
                record = {"window": k, "span": list(span),
                          "anchors": [a.as_list() for a in mine],
                          "elapsed_s": raw["elapsed_s"], "argv": raw["argv"]}
                for stem in ("target", "residual"):
                    path = Path(raw[stem])
                    try:
                        winfo = _wav.check_stem(path)
                    except MediaError as exc:
                        raise MediaError(f"SAM Audio seed {seed}, window {k} "
                                         f"wrote a broken {stem}: {exc}") \
                            from exc
                    rel = f"work-seed{seed}/w{k:02d}/{stem}.wav"
                    sha = hashing.hash_case_file(path).sha256
                    window_outs[rel] = sha
                    record[f"{stem}_sha256"] = sha
                    if stem not in joins:
                        joins[stem] = _Join(case, run_dir / names[stem],
                                            winfo.rate,
                                            int(round(info.duration_s
                                                      * winfo.rate)))
                    rate = joins[stem].rate
                    fade = fades[k - 1] if k <= len(fades) else None
                    joins[stem].add(
                        path, int(round(span[0] * rate)),
                        (int(round(fade[0] * rate)), int(round(fade[1] * rate)))
                        if fade else None)
                if first is None:
                    first = raw
                per_window.append(record)
                _case_discard(case, [raw["target"], raw["residual"]], [work])
        for j in joins.values():
            j.close()
        joins = {}
        _case_discard(case, [], [run_dir / f"work-seed{seed}"])
    finally:
        for j in joins.values():
            try:
                j.fh.close()
            except OSError:
                pass
    sizes, shas = {}, {}
    for stem, name in names.items():
        _wav.check_stem(run_dir / name)
        sizes[stem] = os.path.getsize(run_dir / name)
        shas[stem] = hashing.hash_case_file(run_dir / name).sha256
    params = dict(first["params"], windows=per_window,
                  elapsed_s=round(sum(w["elapsed_s"] for w in per_window), 3))
    recipe["steps"].append(_recipe.step(
        "audiocpp_cli sam_audio", tier=separator.tier,
        version=first["tool_version"], params=params, seed=seed,
        model=model_entry, time_range=[0.0, round(info.duration_s, 3)],
        inputs={w["file"]: w["sha256"] for w in windows["files"]},
        outputs=window_outs,
        note=(first["params"].get("note", "") + " " if first["params"].get(
            "note") else "") + f"{len(spans)} windows; each window's outputs "
        "were joined and then discarded — their SHA-256s are here"))
    sam_step = len(recipe["steps"]) - 1
    recipe["steps"].append(_recipe.step(
        JOIN_TOOL, tier="measured",
        params={"crossfade_s": CROSSFADE_S,
                "crossfades": [list(f) for f in fades],
                "windows": [list(s) for s in spans]},
        inputs=window_outs, outputs={names[s]: shas[s] for s in names},
        note="each window's own stretch exactly as SAM wrote it, a linear "
             "crossfade in the middle of each overlap"))
    chain = prep_chain + [windows["step"], sam_step, len(recipe["steps"]) - 1]
    landed = []
    for stem in ("target", "residual"):
        entry = _output_entry(names[stem], shas[stem], stem, seed,
                              _recipe.output_tier(
                                  [recipe["steps"][i] for i in chain],
                                  upstream_tier), chain, log_name,
                              size=sizes[stem])
        recipe["outputs"].append(entry)
        _write_sidecar(case, run_dir, entry, recipe["steps"], original,
                       upstream_tier, recipe_id)
        landed.append({"file": names[stem], "sha256": shas[stem],
                       "stem": stem, "seed": seed})
    targets[seed] = run_dir / names["target"]
    case.custody.record(
        "media.derived", actor=case.actor(), target=recipe_id,
        hashes={names[s]: shas[s] for s in names},
        detail={"recipe_id": recipe_id, "tier": entry["tier"],
                "input_sha256": hashes.sha256, "stage": stage,
                "outputs": landed, "seed": seed,
                "elapsed_s": params["elapsed_s"],
                "windows": len(spans),
                "memory_bounded": first["params"]["memory_bounded"],
                "weights": weights["state"]})


# ---------------------------------------------------------------------------
# reading runs back
# ---------------------------------------------------------------------------

def runs_root(case) -> Path:
    return Path(case.root) / MEDIA_DIR


def _run_row(data: dict, orig: dict, folder: Path) -> dict:
    return {"recipe_id": str(data["recipe_id"]),
            "created_at": str(data.get("created_at", "")),
            "state": str(data.get("state", "")),
            "text": str((data.get("prompt") or {}).get("text", "")),
            "anchors": list((data.get("prompt") or {}).get("anchors", [])),
            "seeds": list(data.get("seeds", [])),
            "tier": str(data.get("tier", "")),
            "input": (f"{orig.get('evidence_id')}:{orig.get('relpath')}"
                      if orig.get("evidence_id") else
                      str(orig.get("relpath") or orig.get("path", ""))),
            "weights": str((data.get("weights") or {}).get("state", "")),
            "replay_of": str(data.get("replay_of", "")),
            "spans": len((data.get("disagreement") or {}).get("spans", [])),
            "folder": os.fspath(folder), "error": ""}


def list_runs(case) -> list[dict]:
    """Every run in the case, newest first. A run whose recipe cannot be
    read is listed with the reason — never silently skipped, never raised."""
    rows = []
    root = runs_root(case)
    try:
        folders = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return rows
    for folder in folders:
        try:
            data = _recipe.load_recipe(folder)
            row = _run_row(data, data.get("original") or {}, folder)
        except Exception as exc:                          # noqa: BLE001
            # Any bad recipe — edited, half-written, a wrong type where a
            # dict should be — is listed as unreadable, never raised on the
            # surface that is only trying to show the list.
            row = {"recipe_id": folder.name, "state": "unreadable",
                   "error": f"{type(exc).__name__}: {exc}",
                   "folder": os.fspath(folder), "created_at": "", "text": "",
                   "anchors": [], "seeds": [], "tier": "", "input": "",
                   "weights": "", "replay_of": "", "spans": 0}
        rows.append(row)
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows


def load_run(case, recipe_id: str) -> dict:
    """One run's recipe, with absolute paths for playing and opening."""
    name = str(recipe_id or "").strip()
    if not name or any(ch in name for ch in "/\\:") or name in (".", ".."):
        raise MediaError(f"{recipe_id!r} is not a run id.")
    folder = runs_root(case) / name
    return with_paths(_recipe.load_recipe(folder), folder)


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------

def compare_stems(first, second, *, window_s: float = _dis.WINDOW_S,
                  tolerance_db: float = REPLAY_TOLERANCE_DB) -> dict:
    """Bit-exact, within tolerance, or different — with the number."""
    a, b = hashing.hash_case_file(first), hashing.hash_case_file(second)
    if a.sha256 == b.sha256:
        return {"result": "bit-exact", "max_diff_db": 0.0}
    la = _wav.window_levels(first, window_s)[1]
    lb = _wav.window_levels(second, window_s)[1]
    diffs = [abs(x - y) for x, y in zip(la, lb)
             if max(x, y) >= _dis.SILENT_DB]
    worst = round(max(diffs), 2) if diffs else 0.0
    note = "" if len(la) == len(lb) else "lengths differ"
    return {"result": "within tolerance" if worst <= tolerance_db
            else "differs", "max_diff_db": worst, "note": note}


def replay(case, recipe_id: str, *, audiocpp, ffmpeg=None, model=None,
           method: str = "auto", progress=None, should_cancel=None,
           allow_cpu: bool = False, heartbeat=None) -> dict:
    """Run a recipe again from the untouched original, into a new run, and
    say how close it came. Tolerance: the measured stage must be bit-exact;
    each generative stem within `REPLAY_TOLERANCE_DB` per window wherever
    either is above -60 dBFS (seeded GPU runs are not promised bit-exact)."""
    old = load_run(case, recipe_id)
    orig = old["original"]
    path = orig.get("path", "")
    if not path or not Path(path).is_file():
        raise MediaError(f"The original {path or '(unrecorded)'} is not there "
                         "any more, so this recipe cannot be replayed from it.")
    now = hashing.hash_evidence(path, should_cancel=should_cancel).sha256
    if now != old["input_sha256"]:
        raise MediaError(f"The original {path} has changed since the run "
                         f"(SHA-256 now {now}, then {old['input_sha256']}). "
                         "A replay is only meaningful from the same bytes.")
    use_model = model or old["model"]["path"]
    sha = _weights.model_sha256(use_model)[0]
    if sha != old["model"]["sha256"]:
        raise MediaError(f"{use_model} is not the weights this recipe used "
                         f"(SHA-256 {sha}, recorded {old['model']['sha256']}).")
    sams = [st for st in old["steps"] if st["tool"] == "audiocpp_cli sam_audio"]
    params = sams[-1]["params"] if sams else {}
    # a windowed run is replayed with the same windows
    cut = next((st["params"] for st in old["steps"]
                if st["tool"] == WINDOW_TOOL), {})
    new = run_sam(case, path, text=old["prompt"]["text"], model=use_model,
                  audiocpp=audiocpp, anchors=old["prompt"]["anchors"],
                  seeds=old["seeds"], ffmpeg=ffmpeg,
                  backend=params.get("backend"),
                  memory_bounded=params.get("memory_bounded"),
                  steps=params.get("num_inference_steps"), method=method,
                  replay_of=old["recipe_id"], progress=progress,
                  should_cancel=should_cancel, allow_cpu=allow_cpu,
                  heartbeat=heartbeat,
                  window_s=cut.get("window_s", WINDOW_S),
                  overlap_s=cut.get("overlap_s", OVERLAP_S),
                  once_limit_s=cut.get("once_limit_s", ONCE_LIMIT_S))
    by_name = {o["file"]: o for o in new["outputs"]}
    rows = []
    for out in old["outputs"]:
        twin = by_name.get(out["file"])
        if twin is None:
            rows.append({"file": out["file"], "result": "missing"})
            continue
        cmp = compare_stems(Path(old["folder"]) / out["file"], twin["path"])
        rows.append(dict(cmp, file=out["file"], tier=out["tier"]))
    measured_ok = all(r["result"] == "bit-exact" for r in rows
                      if r.get("tier") == "measured")
    generative_ok = all(r["result"] in ("bit-exact", "within tolerance")
                        for r in rows if r.get("tier") != "measured")
    report = {"replay_of": old["recipe_id"], "replay": new["recipe_id"],
              "at": utc_now(), "tolerance": {
                  "measured": "bit-exact",
                  "generative_db": REPLAY_TOLERANCE_DB,
                  "window_s": _dis.WINDOW_S,
                  "why": "seeded GPU runs are not bit-exact; audio.cpp warns "
                         "that different computation shapes give small "
                         "floating-point differences"},
              "outputs": rows, "reproduced": measured_ok and generative_ok}
    _case.write_json_atomic(case.root, Path(new["folder"]) / "replay.json",
                            report)
    return dict(report, folder=new["folder"])


# ---------------------------------------------------------------------------
# the negative control (§12.12)
# ---------------------------------------------------------------------------

def negative_control(noise_wav, *, out_dir, model, audiocpp,
                     text: str = NEGATIVE_TEXT, seeds=DEFAULT_SEEDS,
                     backend: str | None = None, progress=None,
                     should_cancel=None, allow_cpu: bool = False,
                     heartbeat=None) -> dict:
    """SAM on speech-absent noise. Does it put sound in the target?

    Energy only, per 250 ms window: a window is flagged where the target is
    audible and within `SPEAKS_WITHIN_DB` of the noise. Any flagged window
    in any seed -> "speaks on noise", recorded against the model's hash.
    The ASR check — does it produce WORDS from no speech — is the next step
    of §12.12 and is not done here.
    """
    say = progress or (lambda _line: None)
    beat_to = heartbeat or say
    seeds = seed_list(seeds)
    try:
        noise = _wav.check_stem(noise_wav)
    except MediaError as exc:
        raise MediaError(f"The noise file cannot be the negative control's "
                         f"input: {exc} Rewrite it as a clean WAV with FFmpeg "
                         "first.") from exc
    _sam.check_runtime(audiocpp)
    separator = _sam.SamAudioSeparator(audiocpp, model, backend=backend,
                                       allow_cpu=allow_cpu)
    separator.check_backend()
    noise_sha = hashing.hash_evidence(noise_wav).sha256
    _sam.ansi_path(noise_wav)
    _sam.ansi_path(model)
    where = _sam.backend_label(separator.backend)
    weights = _weights.check_weights(model, should_cancel=should_cancel)
    root = Path(os.path.abspath(os.fspath(out_dir)))
    name = f"negative-control-{new_recipe_id()[4:]}"
    run = _harness_dirs(root, name)
    noise_levels = _wav.window_levels(noise_wav)[1]
    per_seed, flagged_total, windows_total, loudest = [], 0, 0, _wav.FLOOR_DB
    for seed in seeds:
        if _cancelled(should_cancel):
            raise Cancelled("the negative control was stopped")
        say(f"Negative control, seed {seed} on {where}…")
        work = _harness_dirs(root, f"{name}/work-seed{seed}")
        log_path = run / f"seed{seed}.audiocpp.log"
        with _harness_log(root, log_path) as log:
            raw = separator.separate(
                noise_wav, text=text, seed=seed, out_dir=work, log=log,
                guard=functools.partial(blocker.assert_harness_path, root),
                should_cancel=should_cancel, duration_s=noise.duration_s,
                heartbeat=_beat(beat_to, f"Negative control seed {seed} on "
                                f"{where}"))
        if raw["state"] == "cancelled":
            raise Cancelled("the negative control was stopped")
        if raw["state"] != "completed" or not Path(raw["target"]).is_file():
            raise MediaError(f"The negative control's seed {seed} did not "
                             f"finish ({raw['state']}, "
                             f"{_sam.exit_sentence(raw['returncode'])}): "
                             f"{_sam.log_tail(log_path)} — log {log_path}. "
                             "Nothing was recorded.")
        target = run / _recipe.invented_name("target", seed)
        notes = _harness_settle(root, [
            (raw["target"], target),
            (raw["residual"], run / _recipe.invented_name("residual", seed))],
            work)
        try:
            # An empty or NaN target is a BROKEN run: measured as levels it
            # would read as silence, and a pass would be recorded for it.
            _wav.check_stem(target)
        except MediaError as exc:
            raise MediaError(f"The negative control's seed {seed} wrote a "
                             f"broken target ({exc}). No result was recorded "
                             "against the model.") from exc
        levels = _wav.window_levels(target)[1]
        flags = [i for i, (t, n) in enumerate(zip(levels, noise_levels))
                 if t >= SPEAKS_FLOOR_DB and t >= n - SPEAKS_WITHIN_DB]
        loudest = max([loudest] + levels)
        flagged_total += len(flags)
        windows_total += min(len(levels), len(noise_levels))
        per_seed.append({"seed": seed, "flagged_windows": len(flags),
                         "first_flagged_s": (round(flags[0] * _dis.WINDOW_S, 3)
                                             if flags else None),
                         "max_target_db": round(max(levels), 2)
                         if levels else _wav.FLOOR_DB, "notes": notes})
    result = {"at": utc_now(), "noise": os.fspath(noise_wav),
              "noise_sha256": noise_sha, "text": text, "seeds": list(seeds),
              "model": Path(model).name, "weights": weights["state"],
              "method": "energy only: per 250 ms window, target audible "
                        f"(>= {SPEAKS_FLOOR_DB:g} dBFS) and within "
                        f"{SPEAKS_WITHIN_DB:g} dB of the noise; the ASR check "
                        "(FORENSICS_PLAN §12.12) comes later",
              "speaks_on_noise": flagged_total > 0,
              "flagged_windows": flagged_total, "windows": windows_total,
              "max_target_db": round(loudest, 2), "per_seed": per_seed,
              "folder": os.fspath(run)}
    _harness_json(root, run / "negative_control.json", result)
    _weights.record_negative_control(model, weights["sha256"], result)
    return result
