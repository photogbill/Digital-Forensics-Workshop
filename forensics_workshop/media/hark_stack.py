# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""M5 — stack a voice across a case (HARK's case-level move).

A case may hold forty voice memos from one phone, or a bug's daily files. The
same faint voice may sit in several, too weak to convince in any one. M5
gathers every recording HARK has run on in the case (the latest finished
HARK run of each restoration run, one per recording) and, the way pulsar
surveys stack observations:

1. embeds every voice stretch HARK found (DETECTED or possible, machines
   left out) with the case's voice model (ECAPA, §13.1) — through the same
   worker and 16 kHz copy Voice Comparison uses;
2. makes one voice of every recording's strong (DETECTED) voice whose
   embedding and pitch agree;
3. for each voice, looks in every other recording for faint stretches —
   possible voices, or DETECTED ones too short to stand alone — whose
   embedding and pitch match it, and STACKS them: their embeddings averaged
   across all the recordings, weighted by seconds, compared with the voice.

The result is a lead for the review queue — "this voice is present, faintly,
in 9 of 40 recordings" — never audio. Scores are the voice model's raw
cosine; a case calibration (§13.1) turns them into probabilities when one
exists for the model. Channel differences between recordings can dominate an
embedding; that is why every match also needs the pitch to agree, and why
the result says which recordings carry it so each can be checked.

Everything is written inside the case: ``hark_stack/<id>/`` holds the 16 kHz
copies, the worker's request and answer, its log and ``stack.json``; custody
records ``media.hark.stacked``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ..errors import Cancelled, MediaError
from ..timeutil import utc_now
from . import hark as _hark
from . import restore as _restore
from . import voiceprint as _vp

STACK_DIR = "hark_stack"
STACK_FILE = "stack.json"
#: a voice stretch shorter than this carries too little for the voice model
MIN_SEGMENT_S = 0.5
#: two recordings' strong voices are one voice when their embeddings agree
#: this well (raw cosine) and their pitch within PITCH_MATCH
SAME = 0.40
#: a faint stack matches a voice from here (the voice model's own threshold)
FAINT = _vp.RAW_THRESHOLD
PITCH_MATCH = 1.25
#: a strong voice needs this much DETECTED speech in one recording
STRONG_S = 2.0
TOOL = "forensics_workshop hark_stack voice stacking (M5)"


def stack_root(case) -> Path:
    return Path(case.root) / STACK_DIR


def gather(case) -> list[dict]:
    """The recordings HARK has run on: the latest finished HARK run of each
    restoration run, one entry per working file (the same file analysed
    twice counts once)."""
    out, seen = [], set()
    for run in _restore.list_runs(case):
        run_id = run["run_id"]
        harks = [h for h in _hark.list_harks(case, run_id)
                 if h["finished"] and "hunt" in h["stages"]]
        if not harks:
            continue
        hid = harks[0]["hark_id"]
        try:
            res = _hark.load(case, run_id, hid)
            report = _restore.load_run(case, run_id)
        except (MediaError, OSError, ValueError):
            continue
        hunt = res.get("loop_hunt") or res.get("hunt") or {}
        working = Path(report["folder"]) / report.get("working",
                                                      "analysis.wav")
        if not working.is_file():
            continue
        key = (report.get("working_sha256") or "") or os.fspath(working)
        if key in seen:
            continue
        seen.add(key)
        segs = hunt.get("segments") or []
        voice = [dict(g) for g, m in zip(segs, _hark.machine_flags(segs))
                 if g.get("status") in ("detected", "possible") and not m
                 and float(g["end_s"]) - float(g["start_s"]) >= MIN_SEGMENT_S]
        out.append({"run_id": run_id, "hark_id": hid,
                    "input": run.get("input", "") or working.name,
                    "working": working, "segments": voice,
                    "duration_s": float(hunt.get("duration_s") or 0.0)})
    return out


def _median(values) -> float:
    v = sorted(values)
    return v[len(v) // 2] if v else 0.0


def _pitch_ok(a: float, b: float) -> bool:
    return bool(a and b) and max(a, b) / min(a, b) <= PITCH_MATCH


def _groups(rec: dict, embs: list) -> list[dict]:
    """Per track of one recording: its strong part (DETECTED seconds) and
    faint part (possible, or DETECTED too short to stand alone), each with a
    seconds-weighted mean embedding and the median pitch."""
    by: dict = {}
    for seg, emb in zip(rec["segments"], embs):
        t = by.setdefault(seg.get("track", 1), {"det": [], "pos": []})
        t["det" if seg["status"] == "detected" else "pos"].append((seg, emb))
    out = []
    for track, parts in by.items():
        det_s = sum(float(s["end_s"]) - float(s["start_s"])
                    for s, _e in parts["det"])
        strong = parts["det"] if det_s >= STRONG_S else []
        faint = parts["pos"] + ([] if strong else parts["det"])
        for kind, items in (("strong", strong), ("faint", faint)):
            if not items:
                continue
            secs = [float(s["end_s"]) - float(s["start_s"]) for s, _e in items]
            out.append({
                "track": track, "kind": kind, "seconds": round(sum(secs), 2),
                "segments": len(items),
                "pitch_hz": round(_median([v for s, _e in items
                                           for v in s.get("f0_hz") or []
                                           if v]), 1),
                "embedding": _vp.mean_embedding([e for _s, e in items],
                                                secs)})
    return out


def _cluster(recs: list[dict]) -> list[dict]:
    """Voices: every recording's strong voice, joined where embedding and
    pitch agree — strongest first, each joining the voice it matches best."""
    strong = sorted(((r, g) for r in recs for g in r["groups"]
                     if g["kind"] == "strong"),
                    key=lambda rg: -rg[1]["seconds"])
    voices: list[dict] = []
    for rec, g in strong:
        best, score = None, SAME
        for v in voices:
            if any(m["run_id"] == rec["run_id"] for m in v["members"]):
                continue
            c = _vp.cosine(g["embedding"], v["embedding"])
            if c >= score and _pitch_ok(g["pitch_hz"], v["pitch_hz"]):
                best, score = v, c
        if best is None:
            best = {"members": [], "embedding": g["embedding"],
                    "pitch_hz": g["pitch_hz"]}
            voices.append(best)
            score = 1.0
        best["members"].append({"run_id": rec["run_id"],
                                "hark_id": rec["hark_id"],
                                "input": rec["input"], "track": g["track"],
                                "seconds": g["seconds"],
                                "pitch_hz": g["pitch_hz"],
                                "score": round(score, 3), "status": "strong"})
        ws = [m["seconds"] for m in best["members"]]
        embs = [next(x["embedding"] for r in recs if r["run_id"] == m["run_id"]
                     for x in r["groups"] if x["kind"] == "strong"
                     and x["track"] == m["track"]) for m in best["members"]]
        best["embedding"] = _vp.mean_embedding(embs, ws)
        best["pitch_hz"] = round(_median([m["pitch_hz"]
                                          for m in best["members"]]), 1)
    return voices


def _faint(voices: list[dict], recs: list[dict]) -> None:
    """Each voice's faint presence: in every recording that does not hold it
    strongly, the faint group that matches it best (pitch must agree), and
    the stack of all of them."""
    for v in voices:
        held = {m["run_id"] for m in v["members"]}
        found = []
        for rec in recs:
            if rec["run_id"] in held:
                continue
            best, score = None, -1.0
            for g in rec["groups"]:
                if not _pitch_ok(g["pitch_hz"], v["pitch_hz"]):
                    continue
                c = _vp.cosine(g["embedding"], v["embedding"])
                if c > score:
                    best, score = g, c
            if best is not None and score >= FAINT:
                found.append((rec, best, score))
        for rec, g, score in found:
            v["members"].append({"run_id": rec["run_id"],
                                 "hark_id": rec["hark_id"],
                                 "input": rec["input"], "track": g["track"],
                                 "seconds": g["seconds"],
                                 "pitch_hz": g["pitch_hz"],
                                 "score": round(score, 3), "status": "faint"})
        if found:
            stacked = _vp.mean_embedding([g["embedding"] for _r, g, _s in found],
                                         [g["seconds"] for _r, g, _s in found])
            v["stacked"] = {"recordings": len(found),
                            "seconds": round(sum(g["seconds"]
                                                 for _r, g, _s in found), 2),
                            "score": round(_vp.cosine(stacked,
                                                      v["embedding"]), 3)}


def stack(case, *, model_dir, ffmpeg, python=None, worker=None, scratch=None,
          device: str = "auto", progress=None, heartbeat=None,
          should_cancel=None) -> dict:
    """M5 over every recording HARK has run on in the case."""
    say = progress or (lambda _l: None)
    _vp.check_model(model_dir)
    _vp.worker_argv(python, worker)
    _vp.require_ffmpeg(ffmpeg)
    recs = gather(case)
    with_voice = [r for r in recs if r["segments"]]
    if len(recs) < 2:
        raise MediaError(
            "M5 stacks a voice across recordings: HARK has finished on "
            f"{len(recs)} recording(s) in this case. Run HARK on at least "
            "two.")
    if not with_voice:
        raise MediaError("HARK found no voice stretch long enough to embed "
                         f"(at least {MIN_SEGMENT_S:g} s) in any of the "
                         f"{len(recs)} recordings.")
    sid = _vp._new_id("st")
    spot = _vp._CaseSpot(case)
    folder = spot.dirs(STACK_DIR, sid)
    try:
        with spot.log(folder / "stack.log") as log:
            items = []
            for i, rec in enumerate(with_voice, 1):
                if should_cancel and should_cancel():
                    raise Cancelled("M5 was stopped")
                say(f"M5: recording {i} of {len(with_voice)} at 16 kHz…")
                wav16 = folder / f"r{i:03d}.wav"
                _vp.to_16k(ffmpeg, rec["working"], wav16, log=log,
                           guard=spot.guard, should_cancel=should_cancel)
                rec["id"] = f"r{i:03d}"
                items.append({"id": rec["id"], "wav": wav16, "segments": [
                    {"start": float(s["start_s"]), "end": float(s["end_s"])}
                    for s in rec["segments"]]})
            data = _vp.embed(items, spot=spot, run_dir=folder,
                             model_dir=model_dir, python=python,
                             worker=worker, scratch=scratch, device=device,
                             log=log, should_cancel=should_cancel,
                             heartbeat=heartbeat, say=say)
        back = {it["id"]: it for it in data["items"]}
        for rec in with_voice:
            rec["groups"] = _groups(rec, back[rec["id"]]["embeddings"])
        voices = _cluster(with_voice)
        _faint(voices, with_voice)
        voices.sort(key=lambda v: (-len(v["members"]),
                                   -sum(m["seconds"] for m in v["members"])))
        for n, v in enumerate(voices):
            v["name"] = _voice_name(n)
            v.pop("embedding", None)
        result = {
            "schema": 1, "kind": "forensics_workshop.hark.stack", "id": sid,
            "created_at": utc_now(), "examiner": case.examiner,
            "tool": TOOL, "tier": "measured",
            "model": {"id": _vp.MODEL_ID, "licence": _vp.MODEL_LICENCE,
                      "fingerprint": _vp.model_fingerprint(model_dir)},
            "device": data.get("device", ""),
            "thresholds": {"same": SAME, "faint": FAINT,
                           "pitch_match": PITCH_MATCH, "strong_s": STRONG_S,
                           "min_segment_s": MIN_SEGMENT_S},
            "recordings": [{"run_id": r["run_id"], "hark_id": r["hark_id"],
                            "input": r["input"],
                            "segments": len(r["segments"])} for r in recs],
            "voices": voices}
        spot.json(folder / STACK_FILE, result)
    except Exception as exc:
        case.custody.record("media.hark.stack_failed", actor=case.actor(),
                            target=sid, detail={"error": str(exc),
                                                "folder": os.fspath(folder)})
        raise
    case.custody.record(
        "media.hark.stacked", actor=case.actor(), target=sid,
        detail={"recordings": len(recs), "voices": len(voices),
                "model": result["model"]["fingerprint"],
                "folder": os.fspath(folder)})
    for line in stack_sentences(result):
        say(line)
    return dict(result, folder=os.fspath(folder))


def _voice_name(n: int) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    return "Voice " + (letters[n] if n < 26 else f"{n + 1}")


def stack_sentences(result: dict) -> list[str]:
    """M5 in words, one line per voice."""
    total = len(result.get("recordings") or [])
    voices = result.get("voices") or []
    if not voices:
        return [f"M5: no voice strong enough to stack from in {total} "
                "recordings (a voice needs "
                f"{STRONG_S:g} s DETECTED in one of them)."]
    lines = []
    for v in voices:
        strong = [m for m in v["members"] if m["status"] == "strong"]
        faint = [m for m in v["members"] if m["status"] == "faint"]
        text = (f"{v['name']} (pitch about {v['pitch_hz']:.0f} Hz): DETECTED "
                f"in {len(strong)} recording(s)")
        if faint:
            st = v.get("stacked") or {}
            text += (f", faintly in {len(faint)} more — of {total} "
                     f"recordings; stacked, those {st.get('seconds', 0):.0f} "
                     f"s score {st.get('score', 0):.2f} against the voice "
                     f"(the voice model's threshold is {FAINT:.2f})")
        else:
            text += f" of {total}, and nowhere else faintly"
        lines.append(text + ". A lead for the review queue, never audio.")
    return lines


def list_stacks(case) -> list[dict]:
    root = stack_root(case)
    rows = []
    try:
        folders = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return rows
    for f in folders:
        try:
            data = json.loads((f / STACK_FILE).read_text("utf-8"))
        except (OSError, ValueError):
            continue
        rows.append(dict(data, folder=os.fspath(f)))
    rows.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return rows


def member_rows(result: dict) -> list[dict]:
    """Every voice's recordings, for a table."""
    rows = []
    for v in result.get("voices") or []:
        for m in v["members"]:
            rows.append(dict(m, voice=v["name"], voice_pitch_hz=v["pitch_hz"]))
    return rows
