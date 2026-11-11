# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""HARK — find a voice by its pitch track, measure how far this file can be
trusted, and audit every restoration (FORENSICS_PLAN §15, HARK_PLAN.md).

Bill, 2026-11-10: *"I want to add something that is designed specifically to
pull sounds and other noises to include speech from the noise using some
form of advanced detection … it must be a push button process entirely,
easy for the operator."* — then *"would you like to build it?"*

HARK runs on a Restore Audio analysis (its working copy — the combined
channels when there are several) and never changes it. One button, one
choice of time budget; seven stages, each its own worker run,
each saved before the next starts, so a day-long run that is stopped or
interrupted picks up at the stage it reached (`resume=`):

1. **HUNT** (Move 1) — voiced sound found by its pitch track, far below where
   an energy gate or a listener finds it, with the false-alarm rate
   MEASURED on this file's own noise (surrogates) — "detected" means noise
   alone makes a track that strong less than once in ten hours of it. A map
   (`hark.png`) shows each track on the whitened spectrogram.
2. **CALIBRATE** (Move 5) — the file's own CEP: voice-like probes, and real
   phrases when a folder of clean speech is given (ATK: LibriSpeech
   test-clean, CC BY 4.0, which get_speechbrain.bat fetches), injected into
   the file's own voice-free stretches at stepped levels and hunted exactly
   as the file was. It says at what level a voice is found half the time and
   nine times in ten, how intelligible real speech is unprocessed at each
   level (ESTOI), and corrects the hunt's level estimate so each track can be
   placed on that curve. The mixtures exist only in the worker's memory.
3. **EXTRACT** (Move 2) — each DETECTED voice pulled out along its pitch
   track: the pitch refined, its phase integrated (warped time, where the
   voice is periodic), its harmonics fitted block by block with a Wiener
   weight each. VOICE (the harmonics) and LIFT (the voice plus everything
   else through a Wiener filter on the file's noise) become a restoration
   result of the run — tier **Cleaned**, with residual, recipe and sidecar,
   in the results table beside every other option.
4. **CENSUS** (Move 8) — every other sound, the way passive sonar finds
   ships: the rates at which the noise's loudness pulses (DEMON — engines,
   propellers, rotors, fans, footsteps), each with its false-alarm rate;
   and the hunt's steady machine tracks taken out along their own pitch
   (Move 2 in reverse), a restoration result (Cleaned).
5. **SELFTRAIN** (Move 3) — GTCRN, a 48 000-parameter speech denoiser,
   trained on THIS recording: a stretch of it with more of its own noise
   added goes in, a target made from the recording comes out, so the
   network learns this file's noise — not the microphone noise every other
   denoiser was trained on. Fine-tuned from GTCRN's published weights; on
   Overnight and Full day also trained from nothing (M4: everything it knows
   about speech then came from this file). Its output becomes a restoration
   result, tier **Inferred**. It trains on one half of the file's noise and
   is scored on a probe built from the other half.
6. **SCORE** (increment 2b) — a probe made of the file's own noise with
   clean phrases hidden in it at the calibration's levels; every candidate
   restoration chain run on it exactly as Restore Audio runs it, and Move 2
   run on it as on the file; each scored against the clean phrases (ESTOI,
   scale-invariant SNR, noise left in the pauses). The best for THIS file
   is the one that recovers the hidden phrases best at the level of the
   file's own voices — measured, not ranked by rule.
7. **AUDIT** (Move 6) — every restoration output and residual of the run
   (Moves 2 and 3 included) hunted the same way: the speaker's pitch track in
   what a chain REMOVED; a confident track in its OUTPUT that the input's
   hunt did not find, with no trace along that exact pitch path in the
   input — a linear filter cannot create harmonic evidence, so that chain
   MADE it; and a track the input only suspected (possible) that the output
   makes clear (REVEALED — a good sign).

**Tiers.** Hunt, calibrate, score and audit are **Measured**: they describe
the recording and change nothing. Move 2's outputs are **Cleaned**: linear
given the track, they can remove detail (the residual keeps it) but cannot
add any. Move 3's are **Inferred**: a trained network decides what is
speech. Findings go to the examiner as plain sentences.

Everything lives in `<case>/restoration/<run>/hark/<hark-id>/`, with
`media.hark.*` custody and every step in the run's recipe.
"""

from __future__ import annotations

import json
import math
import os
import random
from pathlib import Path

from .. import hashing
from .. import case as _case
from .. import extract as _extract
from ..errors import Cancelled, MediaError
from ..timeutil import utc_now
from . import lab as _lab
from . import proc as _proc
from . import recipe as _recipe
from . import restore as _restore
from . import voiceprint as _vp
from . import wav as _wav

HARK_DIR = "hark"
STATE_FILE = "hark.json"
MAP_FILE = "hark.png"
PHRASE_DIR = "phrases"
WORKER = Path(__file__).with_name("hark_worker.py")
SELFTRAIN_WORKER = Path(__file__).with_name("selftrain_worker.py")
HUNT_TOOL = "forensics_workshop hark_worker pitch-track hunter"
EXTRACT_TOOL = "forensics_workshop hark_worker harmonic extraction"
PROBE_TOOL = "forensics_workshop hark_worker probe"
SELFTRAIN_TOOL = "forensics_workshop selftrain_worker GTCRN trained on this file"
GTCRN_TOOL = "forensics_workshop selftrain_worker GTCRN published weights"
MACHINE_TOOL = "forensics_workshop hark_worker machine cancellation"
STAGES = ("hunt", "calibrate", "loop", "extract", "census", "selftrain",
          "score", "audit")
#: Move 7, the speaker loop: learn the strongest voice's pitch range from
#: what the hunt DETECTED (5th-95th percentile, LOOP_MARGIN either side, at
#: least LOOP_MIN_OCTAVES wide) and hunt again in that range only.
#: the hunter's whole pitch range (the worker's F0_MIN, F0_MAX)
F0_MIN_HZ, F0_MAX_HZ = 60.0, 500.0
LOOP_MIN_SEED_S = 1.0
LOOP_MARGIN = 1.12
LOOP_MIN_OCTAVES = 0.5
#: a round converges when its range moved less than this at both ends
LOOP_SETTLED = 1.03
#: the loop's synthetic test voices start inside the range, so their own
#: contour (x0.85 to x1.12 of where it starts) stays in it
LOOP_PROBE_INSET = (1.18, 1.14)
#: Move 8's restoration result: the steady machine sounds taken out along
#: their own pitch tracks ("without"), and the machines alone.
MACHINE_OPTION = "hark-machine"
MACHINE_LABEL = "HARK — steady machine sound taken out along its track " \
    "(Move 8)"
#: The restoration result Move 2's outputs land in (one per run: a newer
#: HARK run's extraction replaces it in the table; its files stay).
RESULT_OPTION = "hark"
RESULT_LABEL = "HARK — the voice along its pitch track (Move 2)"
PROBE_DIR = "probe"
#: Move 3's results: GTCRN fine-tuned from its published weights on this
#: file's noise, and (Overnight, Full day, or with no weights installed)
#: trained from nothing on this file alone — HARK's mad move M4.
SELFTRAIN = {
    "finetune": {"option": "hark-selftrained",
                 "label": "HARK — denoiser trained on this file (Move 3)"},
    "scratch": {"option": "hark-fileonly",
                "label": "HARK — denoiser trained on this file alone, no "
                         "outside speech (M4)"},
    # what Move 3 starts from, untouched: the yardstick for the training
    "base": {"option": "hark-gtcrn",
             "label": "GTCRN, published weights — what Move 3 starts from"},
}
#: GTCRN's published DNS3 weights as ATK's get_speechbrain.bat fetches them
#: (github.com/Xiaobin-Rong/gtcrn, MIT, commit 502ebfab64da).
GTCRN_REPO = "Xiaobin-Rong/gtcrn"
GTCRN_COMMIT = "502ebfab64da7c4a9af78dcb9c6ceef1ebb01c73"
GTCRN_FILE = "model_trained_on_dns3.tar"
GTCRN_SHA256 = ("a630d992cf792daf4ce2bb5bcf9c4d389f740a8f09c6e0971184697fe63"
                "71b79")
#: Less of the file's own noise than this (seconds, for training) and Move 3
#: does not train — the worker's own floor, held by a test.
SELFTRAIN_MIN_NOISE_S = 4.0
#: A restoration is named best for this file only when it beats leaving the
#: recording alone by at least this much ESTOI at the voices' level.
CHAIN_MIN_GAIN = 0.02
PHRASE_EXTS = (".flac", ".wav", ".mp3", ".ogg", ".m4a")
PHRASE_SECONDS = 3.5
MAX_PHRASES = 24
#: Voice band the levels are stated in — the hunter's band (60 Hz to 4 kHz,
#: or the file's content top below that).
BAND_WORDS = "in the voice band (60 Hz–4 kHz)"

#: The time budget sets how hard each stage searches — never which stages
#: run or what a finding may claim. Pitch slopes are in steps of the pitch
#: grid per 10 ms frame at 36 steps an octave.
BUDGETS = {
    "quick": {
        "label": "Quick",
        "steps_per_octave": 36, "slopes": [0.0, 0.25, -0.25], "tracks": 1,
        "surrogates": 4, "min_null_hours": 0.25, "max_surrogates": 40,
        "levels": [0.0, -5.0, -10.0, -15.0, -20.0, -25.0],
        "probes_per_level": 2, "phrases_per_level": 1, "audit_surrogates": 2,
        "probe_per_level": 1, "score_chains": "run",
        "selftrain_minutes": 4.0, "selftrain_steps": 400,
        "selftrain_scratch": False, "census_surrogates": 3,
        "loop_rounds": 1, "loop_probes": 3},
    "thorough": {
        "label": "Thorough",
        "steps_per_octave": 36,
        "slopes": [0.0, 0.2, -0.2, 0.4, -0.4], "tracks": 2,
        "surrogates": 20, "min_null_hours": 2.0, "max_surrogates": 200,
        "levels": [5.0 - 2.5 * i for i in range(13)],
        "probes_per_level": 6, "phrases_per_level": 2, "audit_surrogates": 4,
        "probe_per_level": 2, "score_chains": "all",
        "selftrain_minutes": 30.0, "selftrain_steps": 4000,
        "selftrain_scratch": False, "census_surrogates": 6,
        "loop_rounds": 2, "loop_probes": 6},
    "overnight": {
        "label": "Overnight",
        "steps_per_octave": 36,
        "slopes": [0.0, 0.15, -0.15, 0.3, -0.3, 0.45, -0.45], "tracks": 3,
        "surrogates": 100, "min_null_hours": 10.0, "max_surrogates": 400,
        "levels": [5.0 - 2.5 * i for i in range(13)],
        "probes_per_level": 30, "phrases_per_level": 10,
        "audit_surrogates": 10, "probe_per_level": 4, "score_chains": "all",
        "selftrain_minutes": 240.0, "selftrain_steps": 40000,
        "selftrain_scratch": True, "census_surrogates": 12,
        "loop_rounds": 3, "loop_probes": 16},
    "day": {
        "label": "Full day",
        "steps_per_octave": 36,
        "slopes": [0.0, 0.15, -0.15, 0.3, -0.3, 0.45, -0.45], "tracks": 3,
        "surrogates": 300, "min_null_hours": 24.0, "max_surrogates": 400,
        "levels": [5.0 - 1.25 * i for i in range(25)],
        "probes_per_level": 60, "phrases_per_level": 20,
        "audit_surrogates": 20, "probe_per_level": 4, "score_chains": "all",
        "selftrain_minutes": 600.0, "selftrain_steps": 100000,
        "selftrain_scratch": True, "census_surrogates": 20,
        "loop_rounds": 4, "loop_probes": 30},
}
#: Rough worker seconds per second of audio hunted (file or surrogate) on a
#: two-core CPU, measured 2026-11-10 — the timeouts allow ten times that.
SECONDS_PER_AUDIO_SECOND = 0.05
#: Move 2 per second of audio, and a restoration chain per second of probe
#: (the SpeechBrain models are the slow ones on a CPU), roughly.
EXTRACT_SECONDS_PER_AUDIO_SECOND = 0.15
CHAIN_SECONDS_PER_AUDIO_SECOND = 0.5
#: How many chains the estimate assumes are scored: the ones already run
#: (about two) or all of the analysis's options (about eight).
CHAINS_ASSUMED = {"run": 2, "all": 8}


def probe_seconds(params: dict) -> float:
    """About how long the probe is: each phrase with its noise either side."""
    return len(params.get("levels") or []) * int(
        params.get("probe_per_level", 1)) * (PHRASE_SECONDS + 2.0)


def estimate_minutes(budget_name: str, seconds: float) -> float:
    """A rough run time in minutes on a two-core CPU (a GPU and more cores
    are faster) — what the page shows beside the budget."""
    p = budget(budget_name)
    n = _surrogates_expected(p, seconds)
    hunt = seconds * (n + 8)
    cal = 8.0 * len(p["levels"]) * (p["probes_per_level"]
                                     + p["phrases_per_level"])
    probe = probe_seconds(p)
    work = (SECONDS_PER_AUDIO_SECOND * (hunt + cal + probe * 8) * 3.0
            + EXTRACT_SECONDS_PER_AUDIO_SECOND * (seconds + probe)
            + CHAIN_SECONDS_PER_AUDIO_SECOND * probe
            * CHAINS_ASSUMED.get(p.get("score_chains", "all"), 8)
            + 60.0 * float(p.get("selftrain_minutes", 0.0)))
    # Move 7: each round a hunt in the speaker's range (about half the
    # pitches) and two calibrations on the same test voices
    loop_cal = 8.0 * len(p["levels"]) * int(p.get("loop_probes", 0)) * 2
    work += (SECONDS_PER_AUDIO_SECOND * (0.5 * hunt + loop_cal) * 3.0
             * int(p.get("loop_rounds", 0)))
    return round(work / 60.0, 1)


#: Status words the page shows.
STATUS_WORDS = {"detected": "DETECTED", "possible": "possible"}


# ---------------------------------------------------------------------------
# the case side
# ---------------------------------------------------------------------------

def hark_root(case, run_id: str) -> Path:
    return _restore.runs_root(case) / _vp._safe_id(run_id) / HARK_DIR


def budget(name: str) -> dict:
    if name not in BUDGETS:
        raise MediaError(f"{name!r} is not a HARK budget "
                         f"({', '.join(BUDGETS)}).")
    return dict(BUDGETS[name])


def _worker_argv(python, worker, script=WORKER) -> list[str]:
    if worker:
        return [os.fspath(a) for a in worker]
    if not python:
        raise MediaError("No Python with torch was given for HARK's worker. "
                         + _restore.INSTALL_HINT)
    if not Path(python).is_file():
        raise MediaError(f"HARK's worker Python is not at {python}. "
                         + _restore.INSTALL_HINT)
    return [os.fspath(python), "-I", os.fspath(script)]


def _call_worker(request: dict, folder: Path, name: str, *, case, python,
                 worker, scratch, log, writes, should_cancel, heartbeat,
                 timeout_s: float, script=WORKER) -> dict:
    spot = _vp._CaseSpot(case)
    req_path = folder / f"{name}.request.json"
    resp_path = folder / f"{name}.response.json"
    spot.json(req_path, request)
    argv = _worker_argv(python, worker, script)
    scratch = _vp.make_scratch(scratch)
    log_path = getattr(log, "name", None)

    def beat(elapsed):
        if heartbeat is not None:
            heartbeat(f"HARK {name}: running {_proc.clock(elapsed)} · "
                      f"{_proc.last_line(log_path) or 'nothing printed yet'}")

    outcome = _proc.run_process(
        argv + [os.fspath(req_path), os.fspath(resp_path)], log=log,
        timeout_s=timeout_s, writes=list(writes) + [resp_path],
        guard=spot.guard, should_cancel=should_cancel,
        env=_vp.worker_env(scratch), heartbeat=beat if heartbeat else None)
    if outcome["state"] == "cancelled":
        raise Cancelled(f"HARK stopped during {name}")
    if outcome["state"] != "completed" or not resp_path.is_file():
        why = {"timeout": f"it ran past {timeout_s:.0f} s"}.get(
            outcome["state"], "the worker " +
            _proc.exit_sentence(outcome["returncode"]))
        raise MediaError(f"HARK {name} did not finish: {why}. It said: "
                         f"{_proc.log_tail(log_path) or '(nothing)'} — log "
                         f"{log_path}.")
    with open(resp_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _response(folder: Path, name: str) -> dict | None:
    path = folder / f"{name}.response.json"
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _surrogates_expected(params: dict, seconds: float) -> int:
    n = int(params.get("surrogates", 4))
    hours = seconds / 3600.0
    if hours > 0:
        n = max(n, math.ceil(float(params.get("min_null_hours", 0.0))
                             / hours))
    return min(n, int(params.get("max_surrogates", 400)))


def _timeout(seconds: float, audio_seconds: float) -> float:
    return 1800.0 + 10.0 * SECONDS_PER_AUDIO_SECOND * audio_seconds + seconds


def list_phrases(folder) -> list[Path]:
    """Clean-speech files under a folder (LibriSpeech's speaker/chapter
    folders included), sorted so a seed always picks the same ones."""
    root = Path(folder)
    if not root.is_dir():
        return []
    out = [p for p in root.rglob("*") if p.is_file()
           and p.suffix.lower() in PHRASE_EXTS]
    return sorted(out, key=lambda p: p.as_posix().lower())


def _prepare_phrases(case, folder: Path, parts, phrases_dir, rate: int,
                     n: int, seed: int, *, ffmpeg, log,
                     should_cancel) -> list[dict]:
    """Up to n clean phrases, PHRASE_SECONDS each, mono at the working rate,
    copied into the case as calibration probes (not evidence, not outputs)."""
    found = list_phrases(phrases_dir)
    if not found or not ffmpeg:
        return []
    rng = random.Random(seed)
    pick = rng.sample(found, min(n, len(found)))
    _case.make_case_dirs(case.root, *parts, PHRASE_DIR)
    out = []
    for i, src in enumerate(pick, 1):
        dest = folder / PHRASE_DIR / f"phrase{i:02d}.wav"
        if not dest.is_file():
            _restore._ffmpeg(ffmpeg, [src], dest, rate=rate,
                             seconds=PHRASE_SECONDS, log=log, case=case,
                             should_cancel=should_cancel)
        out.append({"file": f"{PHRASE_DIR}/{dest.name}",
                    "source": src.relative_to(phrases_dir).as_posix(),
                    "sha256": hashing.hash_case_file(dest).sha256,
                    "path": os.fspath(dest)})
    return out


def _targets(report: dict) -> list[dict]:
    """Every output (and the residual beside it) of the run's restoration
    results, as audit targets."""
    out = []
    folder = Path(report["folder"]) if report.get("folder") else None
    ref16 = folder / "input16k.wav" if folder else None
    for r in report.get("results") or []:
        if r.get("error"):
            continue
        res = (r.get("residual") or {}).get("path")
        outs = r.get("outputs") or []
        for k, o in enumerate(outs):
            tid = r["option"] + (f":{o.get('stem')}" if len(outs) > 1 else "")
            out.append({"id": tid, "option": r["option"],
                        "label": r.get("label", r["option"]),
                        "stem": o.get("stem", ""), "tier": o.get("tier", ""),
                        "output": o.get("path"),
                        "residual": res if k == 0 else None,
                        # what a chain run at 16 kHz was measured against
                        "reference": os.fspath(ref16) if ref16 is not None
                        and ref16.is_file() else None,
                        "speech_only": bool(r.get("speech_only"))})
    return [t for t in out if t["output"] and Path(t["output"]).is_file()]


def run(case, run_id: str, *, budget_name: str = "quick", python=None,
        worker=None, scratch, ffmpeg=None, phrases=None,
        device: str = "auto", resume: str = "", stages=STAGES,
        models_root=None, restore_worker=None, deepfilter=None,
        rnnoise_model=None, gtcrn_weights=None, selftrain_worker=None,
        progress=None, heartbeat=None, should_cancel=None) -> dict:
    """Run HARK over a Restore Audio analysis. `phrases`: a folder of clean
    speech for the calibration and the chain scoring (ATK: models\\
    speechbrain\\reference\\LibriSpeech\\test-clean); without it the
    calibration uses voice-like probes only and no chain is scored.
    `resume`: a HARK id whose finished stages are kept. `models_root`,
    `deepfilter`, `rnnoise_model`: what the restoration chains need when
    they are scored on the probe (as for restore.run); `restore_worker`:
    an argv in place of restore_worker.py (the suite's fake).
    `gtcrn_weights`: GTCRN's published weights (ATK: models\\gtcrn\\
    model_trained_on_dns3.tar) for Move 3; `selftrain_worker`: an argv in
    place of selftrain_worker.py."""
    said = []

    def say(line):
        said.append(line)
        if progress is not None:
            progress(line)

    params = budget(budget_name)
    _worker_argv(python, worker)
    report = _restore.load_run(case, run_id)
    run_dir = Path(report["folder"])
    working = run_dir / report.get("working", "analysis.wav")
    if not working.is_file():
        raise MediaError(f"The analysis's working copy {working.name} is "
                         "missing; run the analysis again.")
    w_sha = hashing.hash_case_file(working).sha256
    try:
        info = _wav.read_info(working)
        seconds, rate = info.frames / max(1, info.rate), info.rate
    except Exception as exc:                              # noqa: BLE001
        raise MediaError(f"The working copy cannot be read: {exc}") from exc
    hark_id = _vp._safe_id(resume) if resume else _vp._new_id("hk")
    folder = _case.make_case_dirs(case.root, _restore.RESTORE_DIR,
                                  _vp._safe_id(run_id), HARK_DIR, hark_id)
    state = _load_state(folder) if resume else None
    if state is None:
        state = {"schema": 1, "kind": "forensics_workshop.hark",
                 "hark_id": hark_id, "run_id": run_id, "budget": budget_name,
                 "params": params, "created_at": utc_now(),
                 "examiner": case.examiner, "working": report.get(
                     "working", "analysis.wav"), "working_sha256": w_sha,
                 "duration_s": round(seconds, 3), "rate": rate,
                 "stages": {}, "phrases": [], "tier": "measured"}
    elif state.get("working_sha256") != w_sha:
        raise MediaError("The analysis's working copy changed since this HARK "
                         "run started; start a new run instead of resuming.")
    params = state.get("params") or params
    content = ((report.get("analysis") or {}).get("content") or {})
    top_hz = content.get("cutoff_hz") or None
    case.custody.record("media.hark.started", actor=case.actor(),
                        target=hark_id,
                        detail={"run_id": run_id, "hark_id": hark_id,
                                "budget": budget_name, "resume": bool(resume),
                                "working": state["working"],
                                "folder": os.fspath(folder)})
    try:
        with _lab._case_log(case, folder / f"hark-{len(state['stages']) + 1}"
                            f".log") as log:
            if "hunt" in stages and "hunt" not in state["stages"]:
                n_surr = _surrogates_expected(params, seconds)
                say(f"HARK: hunting pitch tracks ({params['label']}; "
                    f"{n_surr} surrogate noise copies for the false-alarm "
                    "rate)…")
                req = {"op": "hunt", "wav": os.fspath(working),
                       "png": os.fspath(folder / MAP_FILE),
                       "params": params, "device": device,
                       "content_top_hz": top_hz}
                hunt = _call_worker(
                    req, folder, "hunt", case=case, python=python,
                    worker=worker, scratch=scratch, log=log,
                    writes=[folder / MAP_FILE], should_cancel=should_cancel,
                    heartbeat=heartbeat,
                    timeout_s=_timeout(seconds, seconds * (n_surr + 8)))
                state["stages"]["hunt"] = {"done_at": utc_now(),
                                           "elapsed_s": hunt.get("elapsed_s")}
                _save_state(case, folder, state)
                say(hunt_sentence(hunt))
            hunt = _response(folder, "hunt")
            if hunt is None:
                raise MediaError("The hunt has not run, so there is nothing "
                                 "to calibrate or audit.")
            if "calibrate" in stages and "calibrate" not in state["stages"]:
                n_ph = min(MAX_PHRASES, max(
                    0, int(params.get("phrases_per_level", 0))
                    * len(params.get("levels") or [])))
                ph = []
                if phrases and n_ph:
                    say("HARK: preparing clean phrases for the calibration…")
                    ph = _prepare_phrases(
                        case, folder, (_restore.RESTORE_DIR,
                                       _vp._safe_id(run_id), HARK_DIR,
                                       hark_id),
                        Path(phrases).resolve(), rate, n_ph,
                        int(params.get("seed", 4321)), ffmpeg=ffmpeg,
                        log=log, should_cancel=should_cancel)
                state["phrases"] = [{k: v for k, v in p.items()
                                     if k != "path"} for p in ph]
                n_inj = len(params.get("levels") or []) * (
                    int(params.get("probes_per_level", 0))
                    + (int(params.get("phrases_per_level", 0)) if ph else 0))
                say(f"HARK: calibrating — {n_inj} probes injected into this "
                    "file's own noise…")
                req = {"op": "calibrate", "wav": os.fspath(working),
                       "hunt": hunt, "phrases": [p["path"] for p in ph],
                       "params": params, "device": device}
                cal = _call_worker(
                    req, folder, "calibrate", case=case, python=python,
                    worker=worker, scratch=scratch, log=log, writes=[],
                    should_cancel=should_cancel, heartbeat=heartbeat,
                    timeout_s=_timeout(seconds, 8.0 * max(1, n_inj)))
                state["stages"]["calibrate"] = {
                    "done_at": utc_now(), "elapsed_s": cal.get("elapsed_s")}
                _save_state(case, folder, state)
                say(cep_sentence(cal))
            if "loop" in stages and "loop" not in state["stages"]:
                state["stages"]["loop"] = _loop(
                    case, folder, hunt, params, working, seconds,
                    python=python, worker=worker, scratch=scratch,
                    device=device, log=log, say=say, heartbeat=heartbeat,
                    should_cancel=should_cancel)
                _save_state(case, folder, state)
                say(loop_sentence(state["stages"]["loop"]))
            # the voice's hunt from here on: the speaker loop's, when it
            # found more of the voice and tested better; otherwise the hunt's
            vhunt = voice_hunt(folder, hunt, state["stages"].get("loop"))
            if "extract" in stages and "extract" not in state["stages"]:
                segs = vhunt.get("segments") or []
                det = [g for g in segs if g.get("status") == "detected"]
                voice = [g for g, m in zip(segs, machine_flags(segs))
                         if g.get("status") == "detected" and not m]
                if not voice:
                    note = ("only steady machine-like tracks DETECTED — the "
                            "census takes those out" if det else
                            "no DETECTED voice to pull out")
                    state["stages"]["extract"] = {
                        "done_at": utc_now(), "skipped": True, "note": note}
                    say(f"HARK: {note}.")
                else:
                    say("HARK: pulling the voice out along its pitch track "
                        "(Move 2)…")
                    sub = f"extract-{hark_id}"
                    xdir = _case.make_case_dirs(
                        case.root, _restore.RESTORE_DIR,
                        _vp._safe_id(run_id), HARK_DIR, hark_id, sub)
                    raw = {"voice": xdir / "voice.raw.wav",
                           "lift": xdir / "lift.raw.wav"}
                    ex = _call_worker(
                        {"op": "extract", "wav": os.fspath(working),
                         "hunt": vhunt, "device": device,
                         "content_top_hz": top_hz,
                         "outputs": {k: os.fspath(v)
                                     for k, v in raw.items()}},
                        folder, "extract", case=case, python=python,
                        worker=worker, scratch=scratch, log=log,
                        writes=list(raw.values()),
                        should_cancel=should_cancel, heartbeat=heartbeat,
                        timeout_s=_timeout(seconds, seconds * 4))
                    entry = _register_extraction(
                        case, run_id, hark_id, xdir, raw, ex, w_sha,
                        python=python, restore_worker=restore_worker,
                        scratch=scratch, log=log, heartbeat=heartbeat,
                        should_cancel=should_cancel)
                    state["stages"]["extract"] = {
                        "done_at": utc_now(), "elapsed_s":
                        ex.get("elapsed_s"), "voiced_s": ex.get("voiced_s"),
                        "folder": sub, "option": RESULT_OPTION,
                        "outputs": [o["file"] for o in entry["outputs"]]}
                    _save_state(case, folder, state)
                    say(extract_sentence(ex))
                report = _restore.load_run(case, run_id)
            if "census" in stages and "census" not in state["stages"]:
                state["stages"]["census"] = _census(
                    case, run_id, hark_id, folder, hunt, params, working,
                    w_sha, seconds, python=python, worker=worker,
                    restore_worker=restore_worker, scratch=scratch,
                    device=device, log=log, say=say, heartbeat=heartbeat,
                    should_cancel=should_cancel)
                _save_state(case, folder, state)
                say(census_sentence(_response(folder, "census"),
                                    state["stages"]["census"]))
                report = _restore.load_run(case, run_id)
            if "selftrain" in stages and "selftrain" not in state["stages"]:
                state["stages"]["selftrain"] = _selftrain(
                    case, run_id, hark_id, folder, report, vhunt, params,
                    w_sha, gtcrn_weights=gtcrn_weights, python=python,
                    selftrain_worker=selftrain_worker,
                    restore_worker=restore_worker, scratch=scratch,
                    ffmpeg=ffmpeg, device=device, log=log, say=say,
                    heartbeat=heartbeat, should_cancel=should_cancel)
                _save_state(case, folder, state)
                say(selftrain_sentence(state["stages"]["selftrain"]))
                report = _restore.load_run(case, run_id)
            if "score" in stages and "score" not in state["stages"]:
                ph = [folder / p["file"] for p in state.get("phrases") or []
                      if (folder / p["file"]).is_file()]
                if not ph:
                    state["stages"]["score"] = {
                        "done_at": utc_now(), "skipped": True,
                        "note": "no clean speech to hide in the noise "
                                "(LibriSpeech test-clean, fetched by "
                                "get_speechbrain.bat)"}
                    say("HARK: no clean phrases — the restorations are not "
                        "scored.")
                else:
                    state["stages"]["score"] = _score_chains(
                        case, run_id, hark_id, folder, report, vhunt, ph,
                        params, working, rate, python=python, worker=worker,
                        restore_worker=restore_worker, scratch=scratch,
                        ffmpeg=ffmpeg, models_root=models_root,
                        deepfilter=deepfilter, rnnoise_model=rnnoise_model,
                        device=device, log=log, say=say,
                        heartbeat=heartbeat, should_cancel=should_cancel,
                        seconds=seconds,
                        trained=(state["stages"].get("selftrain") or {})
                        .get("models") or {},
                        selftrain_worker=selftrain_worker)
                    _save_state(case, folder, state)
                    choice = chain_choice(load(case, run_id, hark_id))
                    if choice:
                        say(choice["sentence"])
            if "audit" in stages and "audit" not in state["stages"]:
                targets = _targets(report)
                if not targets:
                    state["stages"]["audit"] = {
                        "done_at": utc_now(), "skipped": True,
                        "note": "no restoration has run on this analysis "
                                "yet — run options, then HARK again to audit "
                                "them"}
                    say("HARK: no restoration outputs to audit yet.")
                else:
                    say(f"HARK: auditing {len(targets)} restoration output(s)"
                        "…")
                    a_sur = int(params.get("audit_surrogates", 2))
                    req = {"op": "audit", "wav": os.fspath(working),
                           "hunt": vhunt, "params": params, "device": device,
                           "targets": [{k: t[k] for k in ("id", "output",
                                                          "residual",
                                                          "reference")}
                                       for t in targets]}
                    aud = _call_worker(
                        req, folder, "audit", case=case, python=python,
                        worker=worker, scratch=scratch, log=log, writes=[],
                        should_cancel=should_cancel, heartbeat=heartbeat,
                        timeout_s=_timeout(seconds, seconds * len(targets)
                                           * 2 * (a_sur + 4)))
                    state["stages"]["audit"] = {
                        "done_at": utc_now(), "elapsed_s":
                        aud.get("elapsed_s"),
                        "targets": [{k: t[k] for k in
                                     ("id", "option", "label", "stem",
                                      "tier", "speech_only")}
                                    for t in targets]}
                _save_state(case, folder, state)
        produced = _record_map(case, run_dir, folder, w_sha, report, state)
        state["finished_at"] = utc_now()
        _save_state(case, folder, state)
    except Cancelled:
        _save_state(case, folder, state)
        case.custody.record("media.hark.stopped", actor=case.actor(),
                            target=hark_id,
                            detail={"run_id": run_id, "hark_id": hark_id,
                                    "stages_done": sorted(state["stages"])})
        raise
    except Exception as exc:
        _save_state(case, folder, state)
        case.custody.record("media.hark.failed", actor=case.actor(),
                            target=hark_id,
                            detail={"run_id": run_id, "hark_id": hark_id,
                                    "error": str(exc),
                                    "stages_done": sorted(state["stages"])})
        raise
    result = load(case, run_id, hark_id)
    case.custody.record(
        "media.hark.done", actor=case.actor(), target=hark_id,
        hashes=produced,
        detail={"run_id": run_id, "hark_id": hark_id, "budget": budget_name,
                "stages_done": sorted(state["stages"]),
                "detected_s": sum(t.get("detected_s", 0.0) for t in
                                  (result.get("hunt") or {}).get("tracks")
                                  or []),
                "flags": len(result.get("flags") or []),
                "folder": os.fspath(folder)})
    for line in result.get("verdict") or []:
        if line not in said:
            say(line)
    return result


#: The file's own noise, for Move 3 and the probe: everything outside its
#: voices (DETECTED or possible) by NOISE_MARGIN_S, in stretches of at least
#: NOISE_MIN_S. A machine — an engine, a fan — is part of the noise: on one
#: track, segments less than MACHINE_GAP_S apart make a run; a run at least
#: MACHINE_MIN_S long, voiced for MACHINE_COVER of it, whose pitch hardly
#: moves (its 90th percentile within MACHINE_SPREAD of its 10th) is a
#: machine. A voice's pitch wanders more, and a voice pauses. The worker
#: holds the same rule (a test keeps the two equal).
NOISE_MARGIN_S = 0.3
NOISE_MIN_S = 1.0
MACHINE_MIN_S = 5.0
MACHINE_SPREAD = 1.15
MACHINE_GAP_S = 2.0
MACHINE_COVER = 0.5


def _steady(group: list) -> bool:
    a = min(float(g["start_s"]) for g in group)
    b = max(float(g["end_s"]) for g in group)
    voiced = sum(float(g["end_s"]) - float(g["start_s"]) for g in group)
    if b - a < MACHINE_MIN_S or voiced < MACHINE_COVER * (b - a):
        return False
    f = sorted(v for g in group for v in g.get("f0_hz") or [] if v)
    if len(f) < 10:
        return False
    return f[(9 * len(f)) // 10] / max(1e-9, f[len(f) // 10]) < MACHINE_SPREAD


def _machine_runs(segs) -> list[list[int]]:
    """Indices of each machine's run of segments in a hunt's segments."""
    tracks: dict = {}
    for i, g in enumerate(segs):
        if g.get("status") in ("detected", "possible"):
            tracks.setdefault(g.get("track", 1), []).append(i)
    out = []
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
        out += [r for r in runs if _steady([segs[i] for i in r])]
    return out


def machine_flags(segs) -> list[bool]:
    """For each segment of a hunt: is it part of a machine's run?"""
    segs = list(segs or [])
    flags = [False] * len(segs)
    for run in _machine_runs(segs):
        for i in run:
            flags[i] = True
    return flags


def machine_summary(hunt: dict) -> list[dict]:
    """Each machine the hunt holds: its track, span and pitch."""
    segs = hunt.get("segments") or []
    out = []
    for run in _machine_runs(segs):
        f = sorted(v for i in run for v in segs[i].get("f0_hz") or [] if v)
        out.append({"track": segs[run[0]].get("track", 1),
                    "start_s": round(min(float(segs[i]["start_s"])
                                         for i in run), 2),
                    "end_s": round(max(float(segs[i]["end_s"])
                                       for i in run), 2),
                    "segments": len(run),
                    "f0_median_hz": round(f[len(f) // 2], 1),
                    "f0_p10_hz": round(f[len(f) // 10], 1),
                    "f0_p90_hz": round(f[(9 * len(f)) // 10], 1)})
    return sorted(out, key=lambda m: m["start_s"])


def machines(hunt: dict) -> list[dict]:
    """The hunt's segments that are machines."""
    segs = hunt.get("segments") or []
    return [g for g, m in zip(segs, machine_flags(segs)) if m]


def noise_stretches(hunt: dict) -> list[list[float]]:
    """[[start s, end s]] of the recording that hold no voice HARK found —
    its noise (a steady machine counts as noise)."""
    dur = float(hunt.get("duration_s") or 0.0)
    segs = hunt.get("segments") or []
    spans = sorted((max(0.0, float(g["start_s"]) - NOISE_MARGIN_S),
                    min(dur, float(g["end_s"]) + NOISE_MARGIN_S))
                   for g, m in zip(segs, machine_flags(segs))
                   if g.get("status") in ("detected", "possible") and not m)
    out, t = [], 0.0
    for a, b in spans:
        if a - t >= NOISE_MIN_S:
            out.append([round(t, 3), round(a, 3)])
        t = max(t, b)
    if dur - t >= NOISE_MIN_S:
        out.append([round(t, 3), round(dur, 3)])
    return out


def split_noise(stretches) -> tuple[list, list]:
    """(to train on, to build the probe from): the stretches dealt out so
    each half holds about half the noise — a single stretch is cut in two —
    so the probe never holds the very noise the denoiser was trained on."""
    if not stretches:
        return [], []
    if len(stretches) == 1:
        a, b = stretches[0]
        m = round(0.5 * (a + b), 3)
        return [[a, m]], [[m, b]]
    train, probe, tt, tp = [], [], 0.0, 0.0
    for a, b in sorted(stretches, key=lambda s: -(s[1] - s[0])):
        if tt <= tp:
            train.append([a, b])
            tt += b - a
        else:
            probe.append([a, b])
            tp += b - a
    return sorted(train), sorted(probe)


def _log_rel(log, run_dir: Path) -> str:
    name = getattr(log, "name", "")
    try:
        return Path(name).relative_to(run_dir).as_posix()
    except (TypeError, ValueError):
        return ""


def _register_result(case, run_id: str, hark_id: str, xdir: Path,
                     raw: dict, *, option: str, label: str, derive,
                     reference: Path, ref_rel: str, python, restore_worker,
                     scratch, log, heartbeat, should_cancel,
                     device: str = "", speech_only: bool = True) -> dict:
    """HARK's own outputs as a restoration result of the run, like any
    option's: cut to the reference's length by the restoration worker
    (which also writes the residual — the reference less the FIRST output —
    and measures what changed), each with its recipe steps and sidecar.

    `raw`: {stem: file} the worker wrote, the residual's stem first;
    `derive(recipe, rel, raw_sha)`: appends the steps that made them and
    returns their indices; `reference`: what they are measured against (the
    working copy, or its 16 kHz copy for a 16 kHz model)."""
    report = _restore.load_run(case, run_id)
    run_dir = Path(report["folder"])
    duration = float(report["analysis"].get("duration_s", 0.0) or 0.0)
    recipe = _recipe.load_recipe(run_dir)
    upstream = report.get("upstream_tier", "")
    rel = xdir.relative_to(run_dir)
    raw_sha = {k: hashing.hash_case_file(v).sha256 for k, v in raw.items()}
    chain = list(report.get("working_chain") or [0, 1]) + \
        list(derive(recipe, rel, raw_sha))
    tier = _recipe.output_tier([recipe["steps"][i] for i in chain], upstream)
    stems = list(raw)
    finals = {k: xdir / _recipe.output_name(k, tier) for k in stems}
    residual = xdir / _recipe.output_name("residual", tier)
    common = dict(case=case, python=python, worker=restore_worker,
                  scratch=scratch, log=log, should_cancel=should_cancel,
                  heartbeat=heartbeat, timeout_s=900.0 + 2.0 * duration)
    finished = []
    for k, stem in enumerate(stems):
        finished.append(_restore._call_worker(
            {"op": "finish", "reference": os.fspath(reference),
             "outputs": [os.fspath(raw[stem])],
             "aligned": [os.fspath(finals[stem])],
             "residual": os.fspath(residual) if k == 0 else None,
             "align": False},
            xdir, f"finish-{stem}",
            writes=[finals[stem]] + ([residual] if k == 0 else []),
            **common))
    rate_out = finished[0].get("rate") or 0
    log_rel = _log_rel(log, run_dir)
    entries, first_align = [], None
    for stem in stems:
        path = finals[stem]
        sha = hashing.hash_case_file(path).sha256
        recipe["steps"].append(_recipe.step(
            _restore.ALIGN_TOOL, tier="measured",
            params={"lag_samples": 0, "rate": rate_out, "lag_ms": 0.0},
            inputs={(rel / raw[stem].name).as_posix(): raw_sha[stem],
                    ref_rel: ""},
            outputs={(rel / path.name).as_posix(): sha},
            note="cut to the input's length — it keeps time by "
                 "construction"))
        step_i = len(recipe["steps"]) - 1
        if first_align is None:
            first_align = step_i
        entry = {"file": (rel / path.name).as_posix(), "sha256": sha,
                 "stem": stem, "seed": None, "tier": tier,
                 "chain": chain + [step_i], "size": os.path.getsize(path),
                 "sidecar": _recipe.sidecar_path(path.name).name,
                 "log": log_rel}
        recipe["outputs"].append(entry)
        _restore._write_sidecar(case, path, entry, recipe, upstream)
        entries.append({"stem": stem, "file": entry["file"], "sha256": sha,
                        "tier": tier})
    res_sha = hashing.hash_case_file(residual).sha256
    res_entry = {"file": (rel / residual.name).as_posix(), "sha256": res_sha,
                 "stem": "residual", "seed": None, "tier": tier,
                 "chain": chain + [first_align],
                 "size": os.path.getsize(residual),
                 "sidecar": _recipe.sidecar_path(residual.name).name,
                 "log": log_rel}
    recipe["outputs"].append(res_entry)
    _restore._write_sidecar(case, residual, res_entry, recipe, upstream)
    change = finished[0].get("change") or {}
    result = {"option": option, "label": label, "tier": tier,
              "outputs": entries,
              "residual": {"file": res_entry["file"], "sha256": res_sha},
              "measured": {"removed": {k: change.get(k) for k in
                                       ("during_speech_db",
                                        "during_pauses_db")},
                           "added": {"speech_db":
                                     change.get("added_speech_db"),
                                     "pauses_db":
                                     change.get("added_pauses_db")},
                           "lags": [0] * len(stems), "rate": rate_out,
                           "outputs": [o for f in finished
                                       for o in f.get("outputs") or []]},
              "device": device, "error": "", "speech_only": speech_only,
              "hark_id": hark_id}
    results = [r for r in report.get("results") or []
               if r.get("option") != option] + [result]
    order = {o["id"]: i for i, o in enumerate(report.get("options") or [])}
    results.sort(key=lambda r: order.get(r["option"], 99))
    report["results"] = results
    report["measured_best"] = _restore.measured_best(results,
                                                     report["analysis"])
    for r in results:
        r["measured_score"] = _restore.measured_score(r, report["analysis"])
    recipe["state"] = "restored"
    tiers = [o["tier"] for o in recipe["outputs"]]
    recipe["tier"] = _recipe.highest_tier(tiers) if tiers else ""
    _case.write_json_atomic(case.root, run_dir / _recipe.RECIPE_FILE, recipe)
    _case.write_json_atomic(case.root, run_dir / "analysis.json",
                            {k: v for k, v in report.items()
                             if k != "folder"})
    case.custody.record(
        "media.hark.derived", actor=case.actor(), target=hark_id,
        hashes={e["file"]: e["sha256"] for e in entries}
        | {res_entry["file"]: res_sha},
        detail={"run_id": run_id, "hark_id": hark_id, "option": option,
                "tier": tier,
                "steps": [recipe["steps"][i]["tool"] for i in chain
                          if i >= 2],
                "outputs": [e["file"] for e in entries],
                "folder": os.fspath(xdir)})
    return result


def _register_extraction(case, run_id: str, hark_id: str, xdir: Path,
                         raw: dict, ex: dict, w_sha: str, *, python,
                         restore_worker, scratch, log, heartbeat,
                         should_cancel) -> dict:
    """Move 2's VOICE and LIFT as a restoration result, tier Cleaned."""
    report = _restore.load_run(case, run_id)
    working_rel = report.get("working", "analysis.wav")
    versions = ex.get("versions") or {}

    def derive(recipe, rel, raw_sha):
        recipe["steps"].append(_recipe.step(
            EXTRACT_TOOL, tier="cleaned",
            version=f"torch {versions.get('torch', '')}",
            params={"hark_id": hark_id, "label": RESULT_LABEL,
                    "cycles": ex.get("cycles"), "top_hz": ex.get("top_hz"),
                    "runs": len(ex.get("runs") or []),
                    "voiced_s": ex.get("voiced_s"),
                    "tracks": ex.get("tracks"),
                    "device": versions.get("device", "")},
            inputs={working_rel: w_sha},
            outputs={(rel / v.name).as_posix(): raw_sha[k]
                     for k, v in raw.items()},
            note="each DETECTED track's pitch refined and its phase "
                 "integrated (warped time); its harmonics fitted in "
                 "six-cycle blocks, each weighted by a Wiener gain from the "
                 "noise between harmonics; LIFT adds the rest through a "
                 "Wiener filter on the file's own noise — linear given the "
                 "track: it can remove, never add"))
        return [len(recipe["steps"]) - 1]

    return _register_result(
        case, run_id, hark_id, xdir, raw, option=RESULT_OPTION,
        label=RESULT_LABEL, derive=derive,
        reference=Path(report["folder"]) / working_rel, ref_rel=working_rel,
        python=python, restore_worker=restore_worker, scratch=scratch,
        log=log, heartbeat=heartbeat, should_cancel=should_cancel,
        device=versions.get("device", ""))


def _input16k(case, report: dict, *, ffmpeg, log, should_cancel
              ) -> tuple[Path, str, bool]:
    """(the working copy at 16 kHz, its name in the run, whether it is a
    resampled copy) — the run's input16k.wav, made with FFmpeg when no
    16 kHz model has made it yet."""
    run_dir = Path(report["folder"])
    working_rel = report.get("working", "analysis.wav")
    if int(report["analysis"].get("rate") or 0) == 16000:
        return run_dir / working_rel, working_rel, False
    ref = run_dir / "input16k.wav"
    if not ref.is_file():
        if not ffmpeg:
            raise MediaError("Move 3 needs the recording at 16 kHz and no "
                             "FFmpeg was given to make that copy.")
        _restore._ffmpeg(ffmpeg, [run_dir / working_rel], ref, rate=16000,
                         log=log, case=case, should_cancel=should_cancel)
    return ref, "input16k.wav", True


def _register_selftrained(case, run_id: str, hark_id: str, xdir: Path,
                          raw: Path, st: dict, mode: str, ref: Path,
                          ref_rel: str, resampled: bool, w_sha: str,
                          weights_info: dict, *, ffmpeg, python,
                          restore_worker, scratch, log, heartbeat,
                          should_cancel) -> dict:
    """Move 3's output as a restoration result of the run, tier Inferred,
    measured against the 16 kHz copy (as Restore Audio's 16 kHz models)."""
    report = _restore.load_run(case, run_id)
    working_rel = report.get("working", "analysis.wav")
    versions = st.get("versions") or {}
    spec = SELFTRAIN[mode]

    def derive(recipe, rel, raw_sha):
        steps = []
        if resampled:
            recipe["steps"].append(_recipe.step(
                "ffmpeg", tier="measured",
                version=_restore._tool_version(ffmpeg) if ffmpeg else "",
                params={"args": ["-ar", "16000"], "label": "The input at "
                        "16 kHz, for the 16 kHz network"},
                inputs={working_rel: w_sha},
                outputs={ref_rel: hashing.hash_case_file(ref).sha256},
                note="resampled only"))
            steps.append(len(recipe["steps"]) - 1)
        inputs = {ref_rel: hashing.hash_case_file(ref).sha256}
        if mode == "base":
            tool, params = GTCRN_TOOL, {"hark_id": hark_id,
                                        "label": spec["label"],
                                        "device": versions.get("device", "")}
            model = dict(weights_info, trained_on="DNS Challenge 3 "
                         "(published weights), nothing of this file")
            note = ("GTCRN as published, run on the recording — the "
                    "yardstick the denoiser trained on this file is measured "
                    "against")
        else:
            tool = SELFTRAIN_TOOL
            params = {"hark_id": hark_id, "label": spec["label"],
                      "mode": mode, "method": "remix (RemixIT): teacher's "
                      "speech plus this file's own noise in, the teacher's "
                      "speech out",
                      "teacher": "the published model's output on this file"
                      if mode == "finetune" else "Move 2's LIFT on this file",
                      "steps": st.get("steps"),
                      "best_step": st.get("best_step"),
                      "check_first": st.get("check_first"),
                      "check_best": st.get("check_best"),
                      "noise_s": st.get("noise_s"),
                      "train_s": st.get("train_s"),
                      "device": versions.get("device", "")}
            model = weights_info if mode == "finetune" else {
                "repo": GTCRN_REPO, "licence": "MIT",
                "weights": "none — trained from random weights on this file "
                           "alone"}
            note = ("GTCRN trained on this recording: its teacher's cleaned "
                    "speech plus more of the recording's own noise in, the "
                    "cleaned speech out — a network decides what is speech")
            if mode == "scratch":
                lift = next((o for r in report.get("results") or []
                             if r.get("option") == RESULT_OPTION
                             for o in r.get("outputs") or []
                             if o.get("stem") == "lift"), None)
                if lift:
                    inputs[lift["file"]] = lift["sha256"]
        recipe["steps"].append(_recipe.step(
            tool, tier="inferred",
            version=f"torch {versions.get('torch', '')}", params=params,
            model=model, inputs=inputs,
            outputs={(rel / raw.name).as_posix(): raw_sha["output"]},
            note=note))
        steps.append(len(recipe["steps"]) - 1)
        return steps

    return _register_result(
        case, run_id, hark_id, xdir, {"output": raw}, option=spec["option"],
        label=spec["label"], derive=derive, reference=ref, ref_rel=ref_rel,
        python=python, restore_worker=restore_worker, scratch=scratch,
        log=log, heartbeat=heartbeat, should_cancel=should_cancel,
        device=versions.get("device", ""))


def weights_info(path) -> dict:
    """What the recipe says of the GTCRN weights used: where from, the
    licence, and whether they are the pinned published file."""
    sha = _restore._file_sha(path)
    return {"repo": GTCRN_REPO, "commit": GTCRN_COMMIT, "file":
            Path(path).name, "sha256": sha, "pinned": sha == GTCRN_SHA256,
            "licence": "MIT", "trained_on": "DNS Challenge 3 (published "
            "weights), then this file's own noise"}


def speaker_range(hunt: dict) -> dict | None:
    """The strongest voice's pitch range, learnt from what the hunt
    DETECTED (machines left out): its track, seconds, 5th-95th percentile
    pitch and the range Move 7 searches — or None when no track holds
    LOOP_MIN_SEED_S of DETECTED voice."""
    segs = hunt.get("segments") or []
    by: dict = {}
    for g, m in zip(segs, machine_flags(segs)):
        if g.get("status") == "detected" and not m:
            t = by.setdefault(g.get("track", 1), {"s": 0.0, "f0": []})
            t["s"] += float(g["end_s"]) - float(g["start_s"])
            t["f0"] += [v for v in g.get("f0_hz") or [] if v]
    good = {k: v for k, v in by.items()
            if v["s"] >= LOOP_MIN_SEED_S and len(v["f0"]) >= 10}
    if not good:
        return None
    track, best = max(good.items(), key=lambda kv: kv[1]["s"])
    f = sorted(best["f0"])
    p5, p95 = f[len(f) // 20], f[(19 * len(f)) // 20]
    lo, hi = p5 / LOOP_MARGIN, p95 * LOOP_MARGIN
    if hi / lo < 2.0 ** LOOP_MIN_OCTAVES:
        c = math.sqrt(lo * hi)
        lo, hi = c / 2.0 ** (LOOP_MIN_OCTAVES / 2), \
            c * 2.0 ** (LOOP_MIN_OCTAVES / 2)
    lo, hi = max(F0_MIN_HZ, lo), min(F0_MAX_HZ, hi)
    return {"track": track, "seed_s": round(best["s"], 2),
            "p5_hz": round(p5, 1), "p95_hz": round(p95, 1),
            "lo_hz": round(lo, 1), "hi_hz": round(hi, 1)}


def _voice_seconds(hunt: dict) -> list[tuple[float, float]]:
    segs = hunt.get("segments") or []
    return sorted((float(g["start_s"]), float(g["end_s"]))
                  for g, m in zip(segs, machine_flags(segs))
                  if g.get("status") == "detected" and not m)


def _new_seconds(narrow: dict, broad: dict) -> float:
    """Seconds of voice the narrowed search DETECTED that the whole-range
    search did not."""
    old = _voice_seconds(broad)
    total = 0.0
    for a, b in _voice_seconds(narrow):
        cover = sum(max(0.0, min(b, d) - max(a, c)) for c, d in old)
        total += max(0.0, (b - a) - cover)
    return round(total, 2)


def _cep_gain(narrow: dict, broad: dict) -> tuple[float | None, str]:
    """(dB the narrowed search's CEP gains on the whole-range one, at which
    share): positive = it finds the same test voices quieter."""
    for key, words in (("pd50_db", "half the time"),
                       ("pd90_db", "nine times in ten")):
        a, b = narrow.get(key), broad.get(key)
        if a is not None and b is not None:
            return round(b - a, 2), words
    pa = [r["pd"] for r in narrow.get("levels") or []]
    pb = [r["pd"] for r in broad.get("levels") or []]
    if pa and pb and len(pa) == len(pb):
        return (0.0 if sum(pa) == sum(pb) else
                (0.5 if sum(pa) > sum(pb) else -0.5)), "overall"
    return None, ""


def merge_hunts(broad: dict, narrow: dict) -> dict:
    """The whole-range hunt with its voice replaced by the narrowed
    search's: the narrowed segments (marked "loop"), and every whole-range
    segment no narrowed one overlaps (other voices, machines). The grid,
    noise and null stay the whole-range hunt's."""
    nseg = [dict(g, loop=True) for g in narrow.get("segments") or []
            if g.get("status") in ("detected", "possible")]
    keep = [g for g in broad.get("segments") or []
            if not any(float(g["start_s"]) < float(n["end_s"])
                       and float(n["start_s"]) < float(g["end_s"])
                       for n in nseg)]
    out = dict(broad)
    out["segments"] = sorted(keep + nseg, key=lambda g: float(g["start_s"]))
    out["loop"] = {"f0_min_hz": narrow["grid"].get("f0_min_hz"),
                   "f0_max_hz": narrow["grid"].get("f0_max_hz"),
                   "thresholds": narrow.get("thresholds")}
    return out


LOOP_HUNT = "loop.hunt.json"


def voice_hunt(folder: Path, hunt: dict, st: dict | None) -> dict:
    """The hunt the voice stages use: the speaker loop's merged hunt when a
    round was adopted, else the hunt."""
    if st and st.get("adopted"):
        path = folder / LOOP_HUNT
        if path.is_file():
            return json.loads(path.read_text("utf-8"))
    return hunt


def _loop(case, folder: Path, hunt: dict, params: dict, working,
          seconds: float, *, python, worker, scratch, device, log, say,
          heartbeat, should_cancel) -> dict:
    """Move 7, the speaker loop — the part that needs nothing outside this
    file: learn the strongest voice's pitch range from what was DETECTED,
    hunt again in that range only (fewer pitches, so a lower line at the
    same false-alarm rate, measured on this file's noise over the same
    range), and test both searches on the SAME synthetic voices in that
    range, injected into the same stretches. A round is kept only when the
    narrowed search tests no worse and finds more voice or finds the test
    voices quieter; otherwise it is rolled back. Rounds repeat until the
    range settles."""
    rng = speaker_range(hunt)
    if rng is None:
        note = (f"no voice track holds {LOOP_MIN_SEED_S:.0f} s of DETECTED "
                "voice to learn a speaker from")
        say(f"HARK: speaker loop skipped — {note}.")
        return {"done_at": utc_now(), "skipped": True, "note": note}
    rounds, adopted, best = [], None, None
    for r in range(1, int(params.get("loop_rounds", 1)) + 1):
        say(f"HARK: speaker loop round {r} — the voice on track "
            f"{rng['track']}, hunting {rng['lo_hz']:.0f}–{rng['hi_hz']:.0f} "
            "Hz only (Move 7)…")
        n_surr = _surrogates_expected(params, seconds)
        narrow = _call_worker(
            {"op": "hunt", "wav": os.fspath(working), "device": device,
             "params": dict(params, tracks=1, f0_min_hz=rng["lo_hz"],
                            f0_max_hz=rng["hi_hz"]),
             "content_top_hz": (hunt.get("grid") or {}).get("top_hz")},
            folder, f"loop{r}-hunt", case=case, python=python, worker=worker,
            scratch=scratch, log=log, writes=[], should_cancel=should_cancel,
            heartbeat=heartbeat,
            timeout_s=_timeout(seconds, seconds * (n_surr + 8)))
        lo, hi = rng["lo_hz"] * LOOP_PROBE_INSET[0], \
            rng["hi_hz"] / LOOP_PROBE_INSET[1]
        if hi <= lo:
            lo = hi = math.sqrt(rng["lo_hz"] * rng["hi_hz"])
        cparams = dict(params, probes_per_level=int(params.get(
            "loop_probes", 3)), phrases_per_level=0, probe_f0_hz=[lo, hi],
            seed=int(params.get("seed", 4321)) + 101 * r)
        n_inj = len(params.get("levels") or []) * cparams["probes_per_level"]
        cals = {}
        for name, h in (("narrow", narrow), ("broad", hunt)):
            cals[name] = _call_worker(
                {"op": "calibrate", "wav": os.fspath(working), "hunt": h,
                 "free": hunt.get("free") or [], "phrases": [],
                 "params": cparams, "device": device},
                folder, f"loop{r}-cal-{name}", case=case, python=python,
                worker=worker, scratch=scratch, log=log, writes=[],
                should_cancel=should_cancel, heartbeat=heartbeat,
                timeout_s=_timeout(seconds, 8.0 * max(1, n_inj)))
        gain, at = _cep_gain(cals["narrow"], cals["broad"])
        new_s = _new_seconds(narrow, adopted or hunt)
        keep = gain is not None and gain >= 0.0 and (gain > 0.0 or new_s > 0)
        row = dict(rng, round=r, gain_db=gain, gain_at=at, new_s=new_s,
                   pd50_narrow_db=cals["narrow"].get("pd50_db"),
                   pd50_broad_db=cals["broad"].get("pd50_db"),
                   pd90_narrow_db=cals["narrow"].get("pd90_db"),
                   pd90_broad_db=cals["broad"].get("pd90_db"),
                   detect_narrow=(narrow.get("thresholds") or {}).get(
                       "detect_score"),
                   detect_broad=(hunt.get("thresholds") or {}).get(
                       "detect_score"),
                   kept=keep, probe_f0_hz=[round(lo, 1), round(hi, 1)],
                   injections=n_inj)
        rounds.append(row)
        if not keep:
            break
        adopted, best = narrow, row
        nxt = speaker_range(narrow)
        if nxt is None or (max(nxt["lo_hz"], rng["lo_hz"])
                           / min(nxt["lo_hz"], rng["lo_hz"]) < LOOP_SETTLED
                           and max(nxt["hi_hz"], rng["hi_hz"])
                           / min(nxt["hi_hz"], rng["hi_hz"]) < LOOP_SETTLED):
            row["settled"] = True
            break
        rng = nxt
    st = {"done_at": utc_now(), "rounds": rounds,
          "adopted": best["round"] if best else None}
    if adopted is not None:
        merged = merge_hunts(hunt, adopted)
        _case.write_json_atomic(case.root, folder / LOOP_HUNT, merged)
        st["voice_s"] = round(sum(b - a for a, b in _voice_seconds(merged)),
                              2)
    return st


def loop_sentence(st: dict | None) -> str:
    """Move 7 in words."""
    if not st:
        return "The speaker loop has not run."
    if st.get("skipped"):
        return f"Speaker loop (Move 7) skipped: {st.get('note', '')}."
    rounds = st.get("rounds") or []
    first = rounds[0]
    text = (f"Speaker loop (Move 7): the voice on track {first['track']} "
            f"({first['seed_s']:.1f} s DETECTED, pitch "
            f"{first['p5_hz']:.0f}–{first['p95_hz']:.0f} Hz). ")
    if st.get("adopted"):
        r = next(x for x in rounds if x["round"] == st["adopted"])
        g = r.get("gain_db")
        text += (f"Hunting only its range ({r['lo_hz']:.0f}–{r['hi_hz']:.0f} "
                 "Hz), test voices in that range are found "
                 + (f"{g:.1f} dB quieter {r['gain_at']} than by the "
                    "whole-range search" if g and g > 0 else
                    "as well as by the whole-range search")
                 + (f", and {r['new_s']:.1f} s more of this voice is "
                    "DETECTED" if r.get("new_s") else "")
                 + f" (round {r['round']} of {len(rounds)}"
                 + ("; the range settled" if r.get("settled") else "")
                 + "). Its false-alarm rate is measured on this file's noise "
                 "over the same range. Move 2, the self-trained denoiser's "
                 "noise, the probe and the audit use the narrowed search")
        if not rounds[-1].get("kept"):
            text += (f"; round {rounds[-1]['round']} tested worse and was "
                     "rolled back")
    else:
        r = rounds[-1]
        text += (f"Hunting only {r['lo_hz']:.0f}–{r['hi_hz']:.0f} Hz found "
                 "no more of the voice and tested no better on the same "
                 "test voices, so it was rolled back: the rest of HARK uses "
                 "the whole-range hunt")
    return text + (". Not yet: steering a target-speaker extractor with the "
                   "speaker's own voice profile (it needs ClearerVoice).")


def _census(case, run_id: str, hark_id: str, folder: Path, hunt: dict,
            params: dict, working, w_sha: str, seconds: float, *, python,
            worker, restore_worker, scratch, device, log, say, heartbeat,
            should_cancel) -> dict:
    """Move 8: the census of every other sound — what pulses (DEMON), what
    hums (the hunt's steady tracks: machines) — and the machines taken out
    along their own pitch tracks, a restoration result (Cleaned)."""
    found = machines(hunt)
    summary = machine_summary(hunt)
    say(f"HARK: the census — what pulses, and {len(summary)} steady "
        "machine(s)…")
    sub = f"census-{hark_id}"
    xdir = _case.make_case_dirs(case.root, _restore.RESTORE_DIR,
                                _vp._safe_id(run_id), HARK_DIR, hark_id, sub)
    raw = {"without": xdir / "without.raw.wav",
           "machine": xdir / "machine.raw.wav"} if found else {}
    n_surr = int(params.get("census_surrogates", 3))
    res = _call_worker(
        {"op": "census", "wav": os.fspath(working), "hunt": hunt,
         "machines": found, "params": params, "device": device,
         "outputs": {k: os.fspath(v) for k, v in raw.items()}},
        folder, "census", case=case, python=python, worker=worker,
        scratch=scratch, log=log, writes=list(raw.values()),
        should_cancel=should_cancel, heartbeat=heartbeat,
        timeout_s=_timeout(seconds, seconds * (n_surr + 2) * 4))
    items = pitched(((res.get("modulated") or {}).get("items") or []), hunt)
    st = {"done_at": utc_now(), "elapsed_s": res.get("elapsed_s"),
          "machines": summary, "items": items,
          "pulsing": len([i for i in items if not i.get("track")]),
          "lines": [{k: l.get(k) for k in ("hz", "prominence_db", "series")}
                    for l in sorted(_restore.tonal_lines(
                        _restore.load_run(case, run_id).get("analysis")
                        or {}), key=lambda l: -l.get("z", 0.0))[:8]]}
    if raw and all(v.is_file() for v in raw.values()):
        report = _restore.load_run(case, run_id)
        working_rel = report.get("working", "analysis.wav")
        versions = res.get("versions") or {}

        def derive(recipe, rel, raw_sha):
            recipe["steps"].append(_recipe.step(
                MACHINE_TOOL, tier="cleaned",
                version=f"torch {versions.get('torch', '')}",
                params={"hark_id": hark_id, "label": MACHINE_LABEL,
                        "machines": summary,
                        "runs": [{k: m.get(k) for k in
                                  ("start_s", "end_s", "f0_median_hz",
                                   "refined_pct")}
                                 for m in res.get("machines") or []]},
                inputs={working_rel: w_sha},
                outputs={(rel / v.name).as_posix(): raw_sha[k]
                         for k, v in raw.items()},
                note="each machine (a track whose pitch hardly moves for at "
                     f"least {MACHINE_MIN_S:.0f} s) joined across the moments "
                     "the hunt lost it, fitted along its refined pitch in "
                     f"warped time over {res.get('cycles', 24):g} cycles, as "
                     "Move 2 fits a voice over 6, and subtracted — linear "
                     "given the track"))
            return [len(recipe["steps"]) - 1]

        _register_result(
            case, run_id, hark_id, xdir, raw, option=MACHINE_OPTION,
            label=MACHINE_LABEL, derive=derive,
            reference=Path(report["folder"]) / working_rel,
            ref_rel=working_rel, python=python,
            restore_worker=restore_worker, scratch=scratch, log=log,
            heartbeat=heartbeat, should_cancel=should_cancel,
            device=versions.get("device", ""), speech_only=False)
        st["option"] = MACHINE_OPTION
    return st


#: A pulsing rate within this of a pitch track's range, while the track
#: sounds, is that track: a harmonic stack's loudness pulses at its pitch.
PITCH_MATCH = 1.04


def pitched(items: list, hunt: dict) -> list[dict]:
    """The census's pulsing rates, each that is a pitch track's own pitch
    marked with the track (and whether it is a machine): the same sound,
    seen twice — not another one."""
    segs = hunt.get("segments") or []
    flags = machine_flags(segs)
    out = []
    for it in items:
        it = dict(it)
        for g, mach in zip(segs, flags):
            if g.get("status") not in ("detected", "possible"):
                continue
            if not (float(g["start_s"]) < it["end_s"]
                    and it["start_s"] < float(g["end_s"])):
                continue
            f = [v for v in g.get("f0_hz") or [] if v]
            lo = float(g.get("f0_min_hz") or (min(f) if f else 0.0))
            hi = float(g.get("f0_max_hz") or (max(f) if f else 0.0))
            if lo / PITCH_MATCH <= it["rate_hz"] <= hi * PITCH_MATCH:
                it["track"], it["machine"] = g.get("track", 1), bool(mach)
                break
        out.append(it)
    return out


def census_sentence(res: dict | None, st: dict | None = None) -> str:
    """The census in words: what pulses, what hums, what holds a tone."""
    if not res:
        return "The census has not run."
    st = st or {}
    items = st.get("items")
    if items is None:
        items = (res.get("modulated") or {}).get("items") or []
    parts = []
    for it in items[:6]:
        sure = "DETECTED" if it.get("status") == "detected" else "possible"
        mult = it.get("multiples") or []
        same = ""
        if it.get("track"):
            same = (f" — the pitch of the machine on track {it['track']}"
                    if it.get("machine") else
                    f" — the pitch of track {it['track']}, the same sound")
        parts.append(f"loudness pulsing {it['rate_hz']:g} times a second at "
                     f"{it['start_s']:.0f}–{it['end_s']:.0f} s ({sure}"
                     + (f"; seen at {len(mult)} multiples" if len(mult) > 1
                        else "") + ")" + same)
    text = "Census of other sounds (Move 8). What pulses: "
    if parts:
        text += "; ".join(parts) + (" — and more" if len(items) > 6 else "")
        text += (". Engines, propellers, rotors, fans and footsteps pulse "
                 "like this; HARK names the rate, not the source")
    else:
        text += "nothing in the noise pulses at a steady rate"
    machines = st.get("machines")
    if machines is None:
        machines = res.get("machines") or []
    if machines:
        each = "; ".join(
            f"track {m.get('track', 1)} around {m['f0_median_hz']:.0f} Hz"
            + (f" ({m['f0_p10_hz']:.0f}–{m['f0_p90_hz']:.0f})"
               if m.get("f0_p10_hz") and round(m["f0_p90_hz"])
               > round(m["f0_p10_hz"]) else "")
            + f" at {m['start_s']:.0f}–{m['end_s']:.0f} s"
            for m in machines[:4])
        text += (f". What hums: {len(machines)} machine(s) — {each} — taken "
                 "out along the pitch in the restoration results: the "
                 "recording without it, and the machine alone (CLEANED)")
    else:
        text += ". What hums: no pitch track steady enough to be a machine"
    lines = st.get("lines") or []
    if lines:
        text += (". Steady tones (the analysis's lines): " + ", ".join(
            f"{l['hz']:.0f} Hz (+{l.get('prominence_db') or 0:.0f} dB)"
            for l in lines[:4]) + (" and more" if len(lines) > 4 else ""))
    return text + "."


def _selftrain(case, run_id: str, hark_id: str, folder: Path, report: dict,
               hunt: dict, params: dict, w_sha: str, *, gtcrn_weights,
               python, selftrain_worker, restore_worker, scratch, ffmpeg,
               device, log, say, heartbeat, should_cancel) -> dict:
    """Move 3: GTCRN trained on this file's own noise — fine-tuned from its
    published weights, and on Overnight and Full day (or with no weights)
    also trained from nothing (M4). Each output becomes a restoration result
    of the run, tier Inferred."""
    noise = noise_stretches(hunt)
    train_free, probe_free = split_noise(noise)
    train_s = sum(b - a for a, b in train_free)
    have = bool(gtcrn_weights) and Path(gtcrn_weights).is_file()
    modes = (["finetune"] if have else []) + (
        ["scratch"] if params.get("selftrain_scratch") else [])
    base = {"done_at": utc_now(), "noise_s": round(sum(b - a for a, b in
                                                       noise), 2),
            "train_noise_s": round(train_s, 2),
            "probe_noise_s": round(sum(b - a for a, b in probe_free), 2)}
    if not modes:
        return dict(base, skipped=True,
                    note="GTCRN's published weights are not installed "
                         "(get_speechbrain.bat fetches them); Overnight and "
                         "Full day also train one from nothing")
    # what the worker itself counts: each stretch less its trimmed ends
    usable = sum(max(0.0, b - a - 0.2) for a, b in train_free
                 if b - a - 0.2 > 0.5)
    if usable < SELFTRAIN_MIN_NOISE_S:
        return dict(base, skipped=True,
                    note=f"only {usable:.1f} s of this recording is free of "
                         f"voice to learn its noise from — Move 3 needs at "
                         f"least {SELFTRAIN_MIN_NOISE_S:.0f} s (about 30 s "
                         "or more trains well)")
    try:
        ref, ref_rel, resampled = _input16k(case, report, ffmpeg=ffmpeg,
                                            log=log,
                                            should_cancel=should_cancel)
    except MediaError as exc:
        return dict(base, skipped=True, note=str(exc).rstrip("."))
    voiced = [[g["start_s"], g["end_s"]] for g in hunt.get("segments") or []
              if g.get("status") == "detected"]
    # M4's teacher: Move 2's LIFT at 16 kHz — HARK's own signal processing
    # on this file, so the network trained from nothing learns speech from
    # this recording alone
    lift = next((o for r in report.get("results") or []
                 if r.get("option") == RESULT_OPTION
                 for o in r.get("outputs") or [] if o.get("stem") == "lift"),
                None)
    failed = {}
    if "scratch" in modes and not (lift and Path(lift["path"]).is_file()):
        modes.remove("scratch")
        failed["scratch"] = ("it learns from Move 2's LIFT, and no DETECTED "
                             "voice was pulled out")
        if not modes:
            return dict(base, skipped=True,
                        note="GTCRN's published weights are not installed "
                             "and the network trained from nothing needs "
                             "Move 2's LIFT, which found no voice to pull "
                             "out")
    minutes = float(params.get("selftrain_minutes", 4.0)) / len(modes)
    steps = int(params.get("selftrain_steps", 400))
    winfo = weights_info(gtcrn_weights) if have else {}
    models, runs = {}, {}
    for mode in modes:
        spec = SELFTRAIN[mode]
        if should_cancel is not None and should_cancel():
            raise Cancelled("HARK stopped before training")
        sub = f"selftrain-{mode}"
        xdir = _case.make_case_dirs(case.root, _restore.RESTORE_DIR,
                                    _vp._safe_id(run_id), HARK_DIR, hark_id,
                                    sub)
        model, raw = xdir / "model.pt", xdir / "output.raw.wav"
        base_raw = xdir / "base.raw.wav"
        teacher = None
        if mode == "scratch":
            teacher = xdir / "teacher16k.wav"
            if not teacher.is_file():
                if not ffmpeg:
                    failed[mode] = "no FFmpeg to make LIFT's 16 kHz copy"
                    continue
                _restore._ffmpeg(ffmpeg, [Path(lift["path"])], teacher,
                                 rate=16000, log=log, case=case,
                                 should_cancel=should_cancel)
        say(f"HARK: training {spec['label']} on {train_s:.0f} s of this "
            f"file's own noise (up to {minutes:.0f} min)…")
        try:
            # a failure here (out of memory on the GPU, say) costs Move 3
            # only: the scoring and the audit still run
            st = _call_worker(
                {"op": "selftrain", "wav": os.fspath(ref),
                 "free": train_free, "voiced": voiced,
                 "weights": os.fspath(gtcrn_weights) if mode == "finetune"
                 else None,
                 "teacher": os.fspath(teacher) if teacher else None,
                 "params": {"minutes": minutes, "max_steps": steps * (
                     3 if mode == "scratch" else 1),
                     "seed": int(params.get("seed", 4321))},
                 "device": device,
                 "outputs": dict({"model": os.fspath(model),
                                  "output": os.fspath(raw)},
                                 **({"base": os.fspath(base_raw)}
                                    if mode == "finetune" else {}))},
                folder, sub, case=case, python=python,
                worker=selftrain_worker, scratch=scratch, log=log,
                writes=[model, raw] + ([base_raw] if mode == "finetune"
                                       else []),
                should_cancel=should_cancel, heartbeat=heartbeat,
                timeout_s=1800.0 + 90.0 * minutes, script=SELFTRAIN_WORKER)
            if mode == "finetune" and base_raw.is_file():
                # the yardstick first: the published model on this file
                bdir = _case.make_case_dirs(
                    case.root, _restore.RESTORE_DIR, _vp._safe_id(run_id),
                    HARK_DIR, hark_id, "gtcrn-base")
                _register_selftrained(
                    case, run_id, hark_id, bdir, base_raw, st, "base", ref,
                    ref_rel, resampled, w_sha, winfo, ffmpeg=ffmpeg,
                    python=python, restore_worker=restore_worker,
                    scratch=scratch, log=log, heartbeat=heartbeat,
                    should_cancel=should_cancel)
                models["base"] = {"weights": os.fspath(gtcrn_weights)}
            _register_selftrained(
                case, run_id, hark_id, xdir, raw, st, mode, ref, ref_rel,
                resampled, w_sha, winfo, ffmpeg=ffmpeg, python=python,
                restore_worker=restore_worker, scratch=scratch, log=log,
                heartbeat=heartbeat, should_cancel=should_cancel)
        except Cancelled:
            raise
        except Exception as exc:                          # noqa: BLE001
            failed[mode] = str(exc)
            continue
        models[mode] = {"model": f"{sub}/model.pt",
                        "sha256": hashing.hash_case_file(model).sha256}
        runs[mode] = {k: st.get(k) for k in
                      ("steps", "best_step", "check_first", "check_best",
                       "improved", "train_s", "noise_s", "curve")}
        runs[mode]["device"] = (st.get("versions") or {}).get("device", "")
    return dict(base, models=models, runs=runs, failed=failed,
                weights=winfo)


def selftrain_sentence(st: dict | None) -> str:
    if not st:
        return "Move 3 has not run."
    if st.get("skipped"):
        return "Move 3 (a denoiser trained on this file): " + \
            st.get("note", "skipped") + "."
    parts = []
    for mode, r in (st.get("runs") or {}).items():
        what = SELFTRAIN[mode]["label"].split(" (")[0].replace("HARK — ", "")
        better = ("its check loss fell from {a} to {b}".format(
            a=r.get("check_first"), b=r.get("check_best"))
            if r.get("improved") else
            "training did not improve on where it started — the output is "
            "the starting model's")
        parts.append(f"{what}: {r.get('steps')} steps on "
                     f"{float(r.get('noise_s') or 0):.0f} s of this file's "
                     f"own noise ({r.get('device') or 'cpu'}), {better}")
    if not parts:
        return "Move 3 could not train: " + "; ".join(
            f"{SELFTRAIN[m]['label']} — {why}"
            for m, why in (st.get("failed") or {}).items()) + "."
    text = ("Move 3 trained GTCRN on this recording's own noise — "
            + "; ".join(parts)
            + ". Its output is in the restoration results, tier INFERRED "
            "(a network decides what is speech).")
    if "base" in (st.get("models") or {}):
        text += (" GTCRN as published is beside it in the results, the "
                 "yardstick for what the training added.")
    for mode, why in (st.get("failed") or {}).items():
        text += f" {SELFTRAIN[mode]['label']}: not run — {why}."
    return text


def _score_candidates(report: dict, params: dict) -> list[dict]:
    """The chains scored on the probe: the analysis's restoration options
    (never a faint-sound option or a moved band — they are not for the
    voice) — the ones already run on a Quick budget (the recommended one
    when none has run), every one otherwise."""
    opts = [o for o in report.get("options") or []
            if not _restore.is_faint_option(o["id"]) and not o.get("shift")]
    if params.get("score_chains", "all") == "run":
        ran = {r["option"] for r in report.get("results") or []
               if not r.get("error")}
        chosen = [o for o in opts if o["id"] in ran]
        if not chosen and report.get("best"):
            chosen = [o for o in opts if o["id"] == report["best"]]
        return chosen
    return opts


def _missing_for(opt: dict, *, ffmpeg, models_root, deepfilter,
                 rnnoise_model) -> str:
    """Why a chain cannot run here, or ''."""
    if not ffmpeg:
        return "FFmpeg was not given"
    for st in opt.get("steps") or []:
        if st.get("model") and not models_root:
            return "the SpeechBrain models folder was not given"
        if st.get("kind") == "deepfilter" and not deepfilter:
            return "DeepFilterNet (deep-filter.exe) was not given"
        if st.get("kind") == "rnnoise" and not rnnoise_model:
            return "RNNoise's model was not given"
    return ""


def _probe_recipe(hark_id: str, p_sha: str, working_rel: str,
                  w_sha: str) -> dict:
    """The probe's own recipe, beside the chains run on it — so every
    sidecar there names a recipe that exists."""
    st = _recipe.step(
        PROBE_TOOL, tier="measured", inputs={working_rel: w_sha},
        outputs={"probe.wav": p_sha},
        note="this file's own noise (its voice-free stretches, extended by "
             "surrogates when short) with clean phrases at the "
             "calibration's levels — a test recording, never evidence")
    return {"schema": _recipe.SCHEMA,
            "kind": "forensics_workshop.media.recipe",
            "recipe_id": f"{hark_id}-{PROBE_DIR}", "created_at": utc_now(),
            "state": "scored", "purpose": "HARK chain scoring",
            "original": {"file": "probe.wav", "sha256": p_sha,
                         "note": "a HARK probe — a test recording made of "
                                 "the file's own noise, not evidence"},
            "input_sha256": p_sha, "upstream_tier": "",
            "steps": [st, dict(st)], "outputs": [], "tier": "", "notes": []}


def _score_chains(case, run_id: str, hark_id: str, folder: Path,
                  report: dict, hunt: dict, phrases: list, params: dict,
                  working, rate: int, *, python, worker, restore_worker,
                  scratch, ffmpeg, models_root, deepfilter, rnnoise_model,
                  device, log, say, heartbeat, should_cancel,
                  seconds: float, trained=None,
                  selftrain_worker=None) -> dict:
    """Increment 2b: the probe, every candidate chain run on it exactly as
    Restore Audio runs it (same steps, same parameters), Move 2 run on it
    as on the file (its tracks hunted with the file's context), and every
    output scored against the clean phrases."""
    parts = (_restore.RESTORE_DIR, _vp._safe_id(run_id), HARK_DIR, hark_id,
             PROBE_DIR)
    pdir = _case.make_case_dirs(case.root, *parts)
    probe, clean = pdir / "probe.wav", pdir / "clean.wav"
    say(f"HARK: building the probe — {len(phrases)} clean phrase(s) hidden "
        f"in this file's own noise at {len(params.get('levels') or [])} "
        "levels…")
    p_len = probe_seconds(params)
    # the probe's noise: the half of the file's noise Move 3 did not train
    # on, so a self-trained denoiser is never scored on noise it has seen
    _train, probe_free = split_noise(noise_stretches(hunt))
    pr = _call_worker(
        {"op": "probe", "wav": os.fspath(working), "hunt": hunt,
         "free": probe_free,
         "phrases": [os.fspath(p) for p in phrases], "params": params,
         "device": device,
         "outputs": {"probe": os.fspath(probe), "clean": os.fspath(clean)}},
        folder, "probe", case=case, python=python, worker=worker,
        scratch=scratch, log=log, writes=[probe, clean],
        should_cancel=should_cancel, heartbeat=heartbeat,
        timeout_s=_timeout(seconds, p_len * 4))
    p_sha = hashing.hash_case_file(probe).sha256
    working_rel = Path(working).name
    recipe = _probe_recipe(hark_id, p_sha, working_rel,
                           hashing.hash_case_file(working).sha256)
    probe_report = {"analysis": {"duration_s": pr.get("duration_s", 0.0),
                                 "rate": pr.get("rate") or rate},
                    "working_chain": [0, 1], "upstream_tier": ""}
    cands = _score_candidates(report, params)
    outputs, failed, labels = [], {}, {}
    for n, opt in enumerate(cands, 1):
        if should_cancel is not None and should_cancel():
            raise Cancelled("HARK stopped while scoring the restorations")
        labels[opt["id"]] = {"label": opt["label"], "tier": opt["tier"],
                             "speech_only": bool(opt.get("speech_only"))}
        why = _missing_for(opt, ffmpeg=ffmpeg, models_root=models_root,
                           deepfilter=deepfilter, rnnoise_model=rnnoise_model)
        if why:
            failed[opt["id"]] = why
            continue
        say(f"HARK: scoring {opt['label']} on the probe ({n} of "
            f"{len(cands)})…")
        try:
            r = _restore._run_option(
                case, pdir, recipe, opt, probe, p_sha, "", probe_report,
                ffmpeg=ffmpeg, models_root=models_root, python=python,
                worker=restore_worker, scratch=scratch, device=device,
                force=True, say=lambda _l: None, heartbeat=heartbeat,
                should_cancel=should_cancel, deepfilter=deepfilter,
                rnnoise_model=rnnoise_model, folder_parts=parts,
                record=False)
            outputs.append({"id": opt["id"],
                            "paths": [os.fspath(pdir / o["file"])
                                      for o in r.get("outputs") or []]})
        except Cancelled:
            raise
        except Exception as exc:                          # noqa: BLE001
            failed[opt["id"]] = str(exc)
            say(f"HARK: {opt['label']} could not be scored: {exc}")
    labels[RESULT_OPTION] = {"label": RESULT_LABEL, "tier": "cleaned",
                             "speech_only": True, "stem": "lift"}
    hv, hl = pdir / "hark-voice.wav", pdir / "hark-lift.wav"
    say("HARK: running Move 2 on the probe…")
    content = ((report.get("analysis") or {}).get("content") or {})
    try:
        _call_worker(
            {"op": "extract", "wav": os.fspath(probe), "hunt": hunt,
             "rehunt": True, "device": device,
             "content_top_hz": content.get("cutoff_hz") or None,
             "outputs": {"voice": os.fspath(hv), "lift": os.fspath(hl)}},
            folder, "probe-extract", case=case, python=python,
            worker=worker, scratch=scratch, log=log, writes=[hv, hl],
            should_cancel=should_cancel, heartbeat=heartbeat,
            timeout_s=_timeout(seconds, p_len * 4))
        outputs.append({"id": RESULT_OPTION, "paths": [os.fspath(hl)]})
    except Cancelled:
        raise
    except Exception as exc:                              # noqa: BLE001
        failed[RESULT_OPTION] = str(exc)
    for mode, info in (trained or {}).items():
        spec = SELFTRAIN[mode]
        model_path = info["weights"] if mode == "base" else \
            os.fspath(folder / info["model"])
        labels[spec["option"]] = {"label": spec["label"], "tier": "inferred",
                                  "speech_only": True}
        say(f"HARK: running {spec['label']} on the probe…")
        try:
            p16 = pdir / "probe16k.wav"
            if pr.get("rate") != 16000 and not p16.is_file():
                if not ffmpeg:
                    raise MediaError("no FFmpeg to make the probe's 16 kHz "
                                     "copy")
                _restore._ffmpeg(ffmpeg, [probe], p16, rate=16000, log=log,
                                 case=case, should_cancel=should_cancel)
            src = p16 if pr.get("rate") != 16000 else probe
            out = pdir / f"{spec['option']}.wav"
            _call_worker(
                {"op": "apply", "model": model_path,
                 "wav": os.fspath(src), "output": os.fspath(out),
                 "device": device},
                folder, f"probe-{mode}", case=case, python=python,
                worker=selftrain_worker, scratch=scratch, log=log,
                writes=[out], should_cancel=should_cancel,
                heartbeat=heartbeat, timeout_s=_timeout(seconds, p_len * 4),
                script=SELFTRAIN_WORKER)
            outputs.append({"id": spec["option"], "paths": [os.fspath(out)]})
        except Cancelled:
            raise
        except Exception as exc:                          # noqa: BLE001
            failed[spec["option"]] = str(exc)
    say(f"HARK: scoring {len(outputs)} restoration(s) against the clean "
        "phrases…")
    sc = _call_worker(
        {"op": "score", "clean": os.fspath(clean), "probe": os.fspath(probe),
         "phrases": pr.get("phrases") or [], "outputs": outputs},
        folder, "score", case=case, python=python, worker=worker,
        scratch=scratch, log=log, writes=[], should_cancel=should_cancel,
        heartbeat=heartbeat,
        timeout_s=_timeout(seconds, p_len * (len(outputs) + 1)))
    _case.write_json_atomic(case.root, pdir / _recipe.RECIPE_FILE, recipe)
    case.custody.record(
        "media.hark.scored", actor=case.actor(), target=hark_id,
        hashes={f"{PROBE_DIR}/probe.wav": p_sha},
        detail={"run_id": run_id, "hark_id": hark_id,
                "scored": [o["id"] for o in outputs], "failed": failed,
                "phrases": len(pr.get("phrases") or []),
                "probe_s": pr.get("duration_s")})
    return {"done_at": utc_now(), "elapsed_s": sc.get("elapsed_s"),
            "candidates": labels, "failed": failed,
            "probe_s": pr.get("duration_s"),
            "phrases": len(pr.get("phrases") or []),
            "noise_from_file_s": pr.get("noise_from_file_s"),
            "noise_surrogate_s": pr.get("noise_surrogate_s")}


def _load_state(folder: Path) -> dict | None:
    try:
        with open(folder / STATE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save_state(case, folder: Path, state: dict) -> None:
    _case.write_json_atomic(case.root, folder / STATE_FILE, state)


def _record_map(case, run_dir: Path, folder: Path, w_sha: str, report: dict,
                state: dict) -> dict:
    """The map's step in the run's recipe (Measured — a picture of where
    the tracks are), once."""
    png = folder / MAP_FILE
    if not png.is_file():
        return {}
    sha = hashing.hash_case_file(png).sha256
    rel = png.relative_to(run_dir).as_posix()
    if state.get("map_sha256") == sha:
        return {rel: sha}
    recipe = _recipe.load_recipe(run_dir)
    recipe["steps"].append(_recipe.step(
        HUNT_TOOL, tier="measured",
        params={"budget": state.get("budget"),
                "hark_id": state.get("hark_id"),
                "surrogates": (_response(folder, "hunt") or {})
                .get("surrogates")},
        inputs={report.get("working", "analysis.wav"): w_sha},
        outputs={rel: sha},
        note="voiced sound found by its pitch track, false alarms measured "
             "on this file's own noise — a measurement, nothing changed"))
    _case.write_json_atomic(case.root, run_dir / _recipe.RECIPE_FILE, recipe)
    state["map_sha256"] = sha
    return {rel: sha}


# ---------------------------------------------------------------------------
# reading a HARK run back, and saying what it found
# ---------------------------------------------------------------------------

def list_harks(case, run_id: str) -> list[dict]:
    root = hark_root(case, run_id)
    rows = []
    try:
        folders = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return rows
    for f in folders:
        st = _load_state(f) or {}
        rows.append({"hark_id": f.name, "budget": st.get("budget", ""),
                     "created_at": st.get("created_at", ""),
                     "stages": sorted((st.get("stages") or {}).keys()),
                     "finished": bool(st.get("finished_at"))})
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows


def load(case, run_id: str, hark_id: str) -> dict:
    folder = hark_root(case, run_id) / _vp._safe_id(hark_id)
    state = _load_state(folder)
    if state is None:
        raise MediaError(f"The HARK run {hark_id} cannot be read.")
    hunt = _response(folder, "hunt")
    cal = _response(folder, "calibrate")
    aud = _response(folder, "audit")
    out = dict(state, folder=os.fspath(folder), hunt=hunt, calibrate=cal,
               extract=_response(folder, "extract"),
               census=_response(folder, "census"),
               score=_response(folder, "score"), audit=aud)
    if hunt is not None:
        vh = voice_hunt(folder, hunt, (state.get("stages") or {}).get("loop"))
        if vh is not hunt:
            out["loop_hunt"] = vh
    if (folder / MAP_FILE).is_file():
        out["map_path"] = os.fspath(folder / MAP_FILE)
    out["flags"] = audit_flags(aud, state)
    out["choice"] = chain_choice(out)
    out["verdict"] = verdict(out)
    return out


def export_map(case, run_id: str, hark_id: str) -> dict:
    """Copy a HARK run's map to `<case>/exports/restoration/<run-id>/` as
    `<hark-id>-hark.png`, with a custody record. Exporting it again returns
    the copy already there."""
    folder = hark_root(case, run_id) / _vp._safe_id(hark_id)
    src = folder / MAP_FILE
    if not src.is_file():
        raise MediaError(f"The HARK run {hark_id} has no map.")
    dest = Path(case.root).joinpath(*_restore.EXPORT_DIR,
                                    _vp._safe_id(run_id),
                                    f"{_vp._safe_id(hark_id)}-{MAP_FILE}")
    src_sha = hashing.hash_case_file(src).sha256
    if dest.is_file():
        if hashing.hash_case_file(dest).sha256 == src_sha:
            return {"path": os.fspath(dest), "sha256": src_sha,
                    "already": True}
        raise MediaError(f"{dest} exists and differs from the map; it was "
                         "not overwritten.")
    copied = _extract.copy_within_case(case, src, dest)
    case.custody.record(
        "media.hark.exported", actor=case.actor(), target=hark_id,
        hashes={dest.name: copied.sha256},
        detail={"run_id": run_id, "hark_id": hark_id, "file": MAP_FILE,
                "to": os.fspath(dest)})
    return {"path": os.fspath(dest), "sha256": copied.sha256,
            "already": False}


def corrected_level(seg: dict, cal: dict | None) -> float | None:
    """A track's level against the noise, its estimate corrected by what the
    calibration measured of the estimator's error."""
    est = seg.get("level_est_db")
    if est is None:
        return None
    off = (cal or {}).get("level_offset_db")
    return round(est - off, 1) if off is not None else round(est, 1)


def hunt_sentence(hunt: dict | None) -> str:
    if not hunt:
        return "The hunt has not run."
    tracks = hunt.get("tracks") or []
    det = sum(t.get("detected_s", 0.0) for t in tracks)
    pos = sum(t.get("possible_s", 0.0) for t in tracks)
    null_min = (hunt.get("null") or {}).get("hours", 0.0) * 60.0
    if not tracks:
        return ("No voiced sound found: no pitch track stands out of this "
                f"file's own noise ({null_min:.0f} min of surrogate noise "
                "measured). Unvoiced sounds (s, f, t) and one-off sounds "
                "are not what this looks for — see the salience map.")
    voices = "; ".join(
        f"track {t['track']}: pitch around {t['f0_median_hz']:.0f} Hz "
        f"({t['f0_p10_hz']:.0f}–{t['f0_p90_hz']:.0f})"
        for t in tracks if t.get("f0_median_hz"))
    found = machines(hunt)
    steady = ""
    if found:
        secs = sum(float(g["end_s"]) - float(g["start_s"]) for g in found)
        steady = (f" {secs:.1f} s of it is steady — pitch hardly moving for "
                  f"{MACHINE_MIN_S:.0f} s or more, as an engine or a fan "
                  "holds it and a voice does not: the census (Move 8) treats "
                  "that as a machine, not a voice.")
    return (f"Voiced sound found by its pitch track: {det:.1f} s DETECTED "
            f"and {pos:.1f} s possible on {len(tracks)} track(s) — {voices}. "
            "DETECTED: noise alone makes a track that strong less than once "
            "in ten hours of this file's noise (possible: under ten an hour), "
            f"measured on {null_min:.0f} min of surrogate noise." + steady)


def cep_sentence(cal: dict | None) -> str:
    if not cal:
        return "Not calibrated."
    if not cal.get("levels"):
        return ("Not calibrated: " + (cal.get("note") or "no injections "
                                      "could be placed") + ".")
    p50, p90 = cal.get("pd50_db"), cal.get("pd90_db")
    parts = []
    if p90 is not None:
        parts.append(f"nine times in ten down to {p90:+.1f} dB")
    if p50 is not None:
        parts.append(f"half the time down to {p50:+.1f} dB")
    found = (" and ".join(parts) if parts else
             "at none of the levels tried")
    text = (f"This file's own CEP: a voice-like sound injected into its "
            f"noise is found {found} {BAND_WORDS} "
            f"({cal.get('injections', 0)} injections).")
    eh = cal.get("estoi_half_db")
    rows = [r for r in cal["levels"] if r.get("estoi_raw") is not None]
    if eh is not None:
        text += (f" Real speech stays intelligible unprocessed (ESTOI 0.5) "
                 f"down to about {eh:+.1f} dB.")
    elif rows:
        best = max(rows, key=lambda r: r["level_db"])
        text += (f" Real speech is hard to follow unprocessed even at "
                 f"{best['level_db']:+.0f} dB (ESTOI {best['estoi_raw']:.2f}"
                 "; 0.5 and up is generally intelligible).")
    return text


def extract_sentence(ex: dict | None) -> str:
    if not ex:
        return "Move 2 has not run."
    secs = float(ex.get("voiced_s") or 0.0)
    if secs <= 0:
        return ("Move 2 found no voiced stretch long enough to pull out "
                "along its track.")
    return (f"Move 2 pulled {secs:.1f} s of DETECTED voice out along its "
            "pitch track: VOICE (its harmonics only) and LIFT (the voice "
            "with everything else through a Wiener filter on this file's "
            "noise, so consonants survive) are in the restoration results, "
            "tier CLEANED; its residual holds everything it left.")


def target_level(result: dict) -> tuple[float, str]:
    """The level the restorations are judged at: the median of the DETECTED
    voices' levels (corrected by the calibration), else where HARK finds
    half the hidden voices, else -5 dB."""
    cal = result.get("calibrate")
    lv = sorted(v for v in (corrected_level(g, cal) for g in
                            (result.get("hunt") or {}).get("segments") or []
                            if g.get("status") == "detected")
                if v is not None)
    if lv:
        return lv[len(lv) // 2], "the level of its DETECTED voices"
    p50 = (cal or {}).get("pd50_db")
    if p50 is not None:
        return float(p50), "where HARK finds half the voices hidden in it"
    return -5.0, "a faint voice in this noise"


def _estoi_at(by_level, target: float) -> float | None:
    """ESTOI at `target` dB, interpolated between the levels either side
    (held at the ends)."""
    pts = sorted((float(b["level_db"]), float(b["estoi"]))
                 for b in by_level or [] if b.get("estoi") is not None)
    if not pts:
        return None
    if target <= pts[0][0]:
        return pts[0][1]
    if target >= pts[-1][0]:
        return pts[-1][1]
    for (l0, e0), (l1, e1) in zip(pts, pts[1:]):
        if l0 <= target <= l1:
            return e0 + (target - l0) / max(1e-9, l1 - l0) * (e1 - e0)
    return pts[-1][1]


def chain_choice(result: dict) -> dict | None:
    """Increment 2b's answer: every scored restoration's intelligibility
    (ESTOI) on clean phrases hidden in this file's own noise, at the level
    of the file's voices, against leaving it alone — best first."""
    sc = (result.get("score") or {}).get("scores") or {}
    raw = sc.get("unprocessed")
    if raw is None:
        return None
    target, why = target_level(result)
    st = (result.get("stages") or {}).get("score") or {}
    labels = st.get("candidates") or {}
    raw_e = _estoi_at(raw.get("by_level"), target)
    rows = []
    for cid, v in sc.items():
        if cid == "unprocessed":
            continue
        e = _estoi_at(v.get("by_level"), target)
        meta = labels.get(cid) or {}
        rows.append({"id": cid, "label": meta.get("label", cid),
                     "tier": meta.get("tier", ""),
                     "speech_only": bool(meta.get("speech_only")),
                     "estoi": None if e is None else round(e, 3),
                     "gain": None if e is None or raw_e is None
                     else round(e - raw_e, 3),
                     "noise_left_db": v.get("noise_left_db"),
                     "by_level": v.get("by_level") or []})
    rows.sort(key=lambda r: -1.0 if r["estoi"] is None else -r["estoi"])
    top = rows[0] if rows else None
    best = top if top and top["gain"] is not None and \
        top["gain"] >= CHAIN_MIN_GAIN else None
    failed = st.get("failed") or {}
    n = len(rows)
    raw_txt = "–" if raw_e is None else f"{raw_e:.2f}"
    if best:
        sentence = (f"Best restoration for this file, measured on clean "
                    f"phrases hidden in its own noise at about "
                    f"{target:+.0f} dB ({why}): {best['label']} — ESTOI "
                    f"{best['estoi']:.2f} against {raw_txt} unprocessed "
                    f"({n} restoration(s) scored; 0.5 and up is generally "
                    "intelligible).")
    elif top:
        sentence = (f"None of the {n} restoration(s) scored beats leaving "
                    f"the recording alone at about {target:+.0f} dB "
                    f"({why}): ESTOI {raw_txt} unprocessed, the best "
                    f"({top['label']}) "
                    + ("–" if top["estoi"] is None else
                       f"{top['estoi']:.2f}") + ".")
    else:
        sentence = ("No restoration could be scored on the probe"
                    + (": " + "; ".join(f"{k} — {v}" for k, v in
                                        failed.items()) if failed else "")
                    + ".")
    if failed and rows:
        sentence += (" Not scored: " + "; ".join(
            f"{(labels.get(k) or {}).get('label', k)} ({v})"
            for k, v in failed.items()) + ".")
    return {"target_db": round(target, 1), "target_why": why,
            "raw_estoi": None if raw_e is None else round(raw_e, 3),
            "unprocessed": {"by_level": raw.get("by_level") or [],
                            "noise_left_db": raw.get("noise_left_db")},
            "rows": rows, "best": best["id"] if best else "",
            "failed": failed, "sentence": sentence}


def audit_flags(aud: dict | None, state: dict) -> list[dict]:
    """One flag per finding, worst first: made, removed, revealed."""
    if not aud:
        return []
    labels = {t["id"]: t for t in (state.get("stages") or {})
              .get("audit", {}).get("targets") or []}
    out = []
    for t in aud.get("targets") or []:
        meta = labels.get(t["id"], {})
        name = meta.get("label") or t["id"]
        if meta.get("stem") and ":" in t["id"]:
            name += f" ({meta['stem']})"
        for m in t.get("made") or []:
            out.append({"kind": "made", "severity": "high", "target": t["id"],
                        "label": name, "start_s": m["start_s"],
                        "end_s": m["end_s"],
                        "text": f"{name} MADE voice-like sound at "
                                f"{m['start_s']:.1f}–{m['end_s']:.1f} s "
                                f"(pitch {m['f0_median_hz']:.0f} Hz): no "
                                "trace along that pitch path in the input "
                                f"(support {m['input_support']:+.1f} σ). "
                                "Treat anything heard there in this output "
                                "as invented."})
        for r in t.get("removed") or []:
            share = r.get("share_db")
            pct = (None if share is None else
                   max(1, min(100, round(100 * 10 ** (share / 10)))))
            if pct is None:
                how = "the speaker's pitch track is in its residual"
            elif r.get("share_basis") == "output":
                how = (f"its output lost about {pct}% of the voice's harmonic "
                       "energy along the track, into its residual")
            else:
                how = (f"about {pct}% of the voice's harmonic energy there is "
                       "in its residual")
            out.append({"kind": "removed",
                        "severity": ("medium" if pct is None or pct >= 25
                                     else "low"),
                        "target": t["id"], "label": name,
                        "start_s": r["start_s"], "end_s": r["end_s"],
                        "share_pct": pct,
                        "text": f"{name} REMOVED voice at {r['start_s']:.1f}"
                                f"–{r['end_s']:.1f} s (pitch "
                                f"{r['f0_median_hz']:.0f} Hz): {how}. Listen "
                                "to the residual there, or use another option "
                                "for that stretch."})
        for r in t.get("revealed") or []:
            out.append({"kind": "revealed", "severity": "good",
                        "target": t["id"], "label": name,
                        "start_s": r["start_s"], "end_s": r["end_s"],
                        "text": f"{name} REVEALED a voice at "
                                f"{r['start_s']:.1f}–{r['end_s']:.1f} s "
                                f"(pitch {r['f0_median_hz']:.0f} Hz) that the "
                                "input's hunt only marked possible — worth a "
                                "listen in this output."})
    rank = {"made": 0, "removed": 1, "revealed": 2}
    out.sort(key=lambda f: (rank[f["kind"]], f["start_s"]))
    return out


def placement(seg: dict, cal: dict | None) -> str:
    """Where a track sits against this file's CEP, in words."""
    lvl = corrected_level(seg, cal)
    if lvl is None:
        return ""
    eh = (cal or {}).get("estoi_half_db")
    text = f"about {lvl:+.0f} dB"
    if eh is not None:
        text += (" — at or above the level where real speech stays "
                 "intelligible unprocessed" if lvl >= eh else
                 " — below the level where real speech stays intelligible "
                 "unprocessed: words heard here are leads")
    return text


def verdict(result: dict) -> list[str]:
    """The plain-language summary, in the order the page shows it."""
    lines = [hunt_sentence(result.get("hunt"))]
    if result.get("calibrate"):
        lines.append(cep_sentence(result["calibrate"]))
    stages = result.get("stages") or {}
    xs = stages.get("extract") or {}
    if xs.get("skipped"):
        lines.append("Move 2: " + xs.get("note", "skipped") + ".")
    elif result.get("extract") is not None:
        lines.append(extract_sentence(result["extract"]))
    if stages.get("loop"):
        lines.append(loop_sentence(stages["loop"]))
    if result.get("census") is not None:
        lines.append(census_sentence(result["census"], stages.get("census")))
    if stages.get("selftrain"):
        lines.append(selftrain_sentence(stages["selftrain"]))
    ss = stages.get("score") or {}
    if ss.get("skipped"):
        lines.append("Restorations not scored: " + ss.get("note", "") + ".")
    elif result.get("choice"):
        lines.append(result["choice"]["sentence"])
    st = stages.get("audit") or {}
    if st.get("skipped"):
        lines.append("Audit: " + st.get("note", "skipped") + ".")
    elif result.get("audit") is not None:
        flags = result.get("flags") or []
        made = sum(f["kind"] == "made" for f in flags)
        removed = sum(f["kind"] == "removed" for f in flags)
        revealed = sum(f["kind"] == "revealed" for f in flags)
        n = len((result["audit"] or {}).get("targets") or [])
        if not flags:
            lines.append(f"Audit of {n} restoration output(s): none removed "
                         "the voice the hunter found, none made voice the "
                         "input lacks.")
        else:
            lines.append(f"Audit of {n} restoration output(s): {made} made "
                         f"voice the input lacks, {removed} removed voice, "
                         f"{revealed} made a possible voice clear — each "
                         "listed below.")
    lines.append("Not yet: the generative lane (Move 4).")
    return lines


def segment_rows(result: dict) -> list[dict]:
    """The tracks' stretches for the page: when, pitch, status, false-alarm
    rate, level against the noise and where that sits on the CEP — and what
    kind: a machine, or a stretch the speaker loop found (its false-alarm
    rate then measured over the speaker's range)."""
    hunt = result.get("loop_hunt") or result.get("hunt") or {}
    cal = result.get("calibrate")
    rows = []
    segs = hunt.get("segments") or []
    for s, mach in zip(segs, machine_flags(segs)):
        rows.append({"track": s["track"], "start_s": s["start_s"],
                     "kind": ("machine" if mach else
                              "speaker loop" if s.get("loop") else ""),
                     "end_s": s["end_s"], "status": s["status"],
                     "f0_median_hz": s["f0_median_hz"],
                     "f0_range": f"{s['f0_min_hz']:.0f}–{s['f0_max_hz']:.0f}",
                     "fa_per_hour": s.get("fa_per_hour"),
                     "fa_extrapolated": s.get("fa_extrapolated"),
                     "level_db": corrected_level(s, cal),
                     "placement": placement(s, cal)})
    return rows

