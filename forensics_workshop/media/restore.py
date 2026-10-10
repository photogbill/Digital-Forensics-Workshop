# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Audio restoration — analyse, recommend, run, compare, export
(FORENSICS_PLAN §13.3–13.4).

Bill, 2026-10-09: *"it will do analysis first, determine what is needed,
select the optimal restoration option, and then run that and export the
result. If its multiple options, either run the best one or have an option to
run both or all, to see which comes out best."* — he listens to them all.

**1. ANALYSE — measured, no model.** The recording is read once through the
read-only door into the case, made mono at its own rate by FFmpeg (a measured
step), and `restore_worker.py` measures it: noise floor and speech level of
25 ms frames and the SNR between them, mains hum (50/60 Hz and harmonics,
measured in the pauses), rumble, DC offset, clipping, clicks, the bandwidth
the speech occupies, level. `issues()` turns those numbers into findings
with a severity — every one quoting the measurement behind it.

**2. RECOMMEND.** `options()` builds restoration recipes from the issues and
ranks them by what they fix against how invasive they are: the least
invasive recipe that deals with everything serious wins. Filters first — the
fixes every option shares (high-pass, hum notches, de-click, de-clip, band
limit) — then either FFmpeg's FFT noise reduction (Cleaned) or a SpeechBrain
model (MetricGAN+ or SepFormer-DNS4, Inferred), then level. Two-voice
separation (SepFormer WHAMR!) is always offered and never the default. Each
option says what it can get you and what it risks.

**3. RUN** the best, the ones chosen, or all. Each option is its own folder:
the output (two for separation), the RESIDUAL — what the chain took away,
playable — and a recipe sidecar beside every file with its tier. Filters run
in FFmpeg; models in the worker (GPU when torch sees one). The tier of an
output is the highest of its steps (§12.2): FFT noise reduction makes it
Cleaned, a model Inferred, an Invented input keeps it Invented.

**4. COMPARE.** After a run every output is measured again, and the residual
says how much energy was taken from the pauses and how much while speech
was present: a good clean-up takes a lot from the pauses and little more
from the speech than the noise that was in it. `measured_best()` ranks the
outputs on that — a measurement to point the ear, never a verdict.

**5. EXPORT** copies a chosen output (and its sidecar) to the case's
`exports/restoration/` folder with a custody record.

**FAINT SOUNDS (§13.8)** — Bill, 2026-10-09: *"pull extremely faint noises
from audio, stuff that would previously have been unrecoverable."* Three
routes that add real information or show where it is, all in the analysis:
every CHANNEL kept, and channels that carry one sound combined so their
independent noise does not add (Recovered, the working copy from then on);
a SALIENCE MAP — each frequency band against its own noise, averaged over
windows up to 16 s, so a sound that persists shows far below where any
moment of it does — with a clip of each faint event, masked to its band and
brought up; TONAL LINES in the long-term spectrum; and REPEATS: a sound
that repeats sample for sample is averaged (N repeats, 10·log10 N dB less
noise, Recovered), a repeating background is lifted off what does not
repeat (Cleaned). Options: listen in the faint band (Measured), keep only
what stands out (Cleaned), average the repeats, lift off the background,
the combination alone.

**SPEECH DENOISERS** beside SpeechBrain's: DeepFilterNet 3 (full band,
deep-filter.exe as its own process) and RNNoise (FFmpeg's arnndn, light).
Every speech model — these and MetricGAN+ and SepFormer-DNS4 — carries
SPEECH_ONLY on its option, its step and the page (Bill, 2026-10-09:
*"clearly state that IT specifically made for speech and will likely remove
other audio that may or may not be important"*).

**WHAT THE FILE REALLY HOLDS, AND SHIFT INTO HEARING (§13.9)** — the
analysis says where the file's real content ends against the top its rate
allows (a codec's or a telephone's cut, a lower rate stored at a higher one,
the anti-alias filter, or no roll-off at all — folded ultrasound possible)
and whether there is energy below 20 Hz; above 12 kHz a second, linear map.
A band out of hearing is moved into it — every frequency by the same
amount, so it keeps time with the recording — with a slowed copy (above
hearing) or a sped-up one (below it). Measured: nothing added, nothing
judged; no residual, because nothing was taken away.

Everything lives in the case, `<case>/restoration/<run-id>/`, with
`media.restore.*` custody; the run's `recipe.json` is the same format as a
SAM run's, so a restored file fed back into the Media Lab or the voice
comparison keeps its tier.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path

from .. import blocker, hashing
from .. import case as _case
from .. import extract as _extract
from ..errors import Cancelled, MediaError
from ..timeutil import utc_now
from . import lab as _lab
from . import recipe as _recipe
from . import sam_audio as _sam
from . import voiceprint as _vp
from . import wav as _wav

RESTORE_DIR = "restoration"
EXPORT_DIR = ("exports", "restoration")
WORKER = Path(__file__).with_name("restore_worker.py")
INSTALL_HINT = "Run get_speechbrain.bat in the ATK folder."
DOOR_TOOL = "forensics_workshop read-only door (hashed copy)"
ALIGN_TOOL = "forensics_workshop restore_worker alignment"
COMBINE_TOOL = "forensics_workshop restore_worker channel combining"
SALIENCE_TOOL = "forensics_workshop restore_worker salience map"
DSP_TOOLS = {"mask": "forensics_workshop restore_worker salience mask",
             "average": "forensics_workshop restore_worker repeat averaging",
             "repet": "forensics_workshop restore_worker "
                      "repeating-pattern separation",
             "shift": "forensics_workshop restore_worker frequency shift"}
DSP_TIERS = {"mask": "cleaned", "average": "recovered", "repet": "cleaned",
             "shift": "measured"}
FAINT_DIR = "faint"
MAX_CLIPS = 8
#: The linear high-frequency map is drawn when the top is above this.
HIGH_MAP_MIN_NYQ = 14000.0

#: Speech denoisers beside SpeechBrain's (§13.4). RNNoise runs inside FFmpeg
#: (its arnndn filter) with the "somnolent-hogwash" model (speech, recording
#: noise — GregorR/rnnoise-models, not subject to copyright); DeepFilterNet 3
#: is its own program, deep-filter.exe, the model built in (MIT or
#: Apache-2.0). Both fetched by get_speechbrain.bat, each against a pinned
#: SHA-256. Both mix a little of the input back (RNNoise 10%, DeepFilterNet
#: at most 20 dB down), so nothing is taken away completely.
RNNOISE_TOOL = "ffmpeg arnndn (RNNoise)"
RNNOISE_MIX = 0.9
RNNOISE_SHA256 = ("70bb6685eb0c2a1d18e2918dca3fbfbd39317010b1802eb1b6ea73a92f3"
                  "fdec0")
DFN_TOOL = "deepfilternet deep-filter"
DFN_ATTEN_DB = 20
DFN_BUILDS = {"75e11fa16445f560cb6b021521ddb89e89270d13b83089705d98776f58fd"
              "7915": "0.5.6 (x86_64-pc-windows-msvc)"}
#: Every speech-only option says this — on the option, on its step, and on
#: the page (Bill, 2026-10-09: "clearly state that IT specifically made for
#: speech and will likely remove other audio that may or may not be
#: important").
SPEECH_ONLY = ("Made for speech. It removes whatever it does not judge to be "
               "speech: footsteps, engines, doors, even a second faint voice "
               "may go with the noise. Its residual keeps all of it. Search "
               "for faint sounds in the original, never in this output.")
SPEECH_ONLY_OPTIONS = ("metricgan", "sepformer-dns4", "rnnoise", "dfn")
#: A 16 kHz model throws away everything above 8 kHz: on a recording whose
#: speech reaches higher, its score pays for that.
NARROW_MODEL_PENALTY = 0.2

#: Shift into hearing (§13.9): a band from SHIFT_HIGH_HZ up — where most
#: adults hear little or nothing — moved down so it starts at SHIFT_TO_HZ;
#: below 20 Hz moved up by SHIFT_LOW_BY; a copy played EXPAND (slower) or
#: SPEED_FACTOR times faster.
SHIFT_HIGH_HZ = 12000.0
SHIFT_TO_HZ = 1000.0
SHIFT_LOW_BAND = (2.0, 20.0)
SHIFT_LOW_BY = 300.0
SPEED_FACTOR = 16
MAX_SHIFT_EVENTS = 3
#: Faint options end by lifting the quiet parts: FFmpeg's dynamic
#: normaliser, at most +20 dB, a level operation (Measured).
LIFT = "dynaudnorm=f=250:g=15:p=0.9:m=10"

#: The SpeechBrain models a recipe may use, each in its own folder under the
#: models root (ATK: models\speechbrain\), fetched by get_speechbrain.bat.
MODELS = {
    "metricgan": {
        "folder": "metricgan-plus-voicebank",
        "repo": "speechbrain/metricgan-plus-voicebank",
        "files": ("hyperparams.yaml", "enhance_model.ckpt"),
        "tool": "speechbrain metricgan-plus-voicebank",
        "label": "MetricGAN+ enhancement", "outputs": ("output",),
        "licence": "Apache-2.0"},
    "sepformer-dns4": {
        "folder": "sepformer-dns4-16k-enhancement",
        "repo": "speechbrain/sepformer-dns4-16k-enhancement",
        "files": ("hyperparams.yaml", "masknet.ckpt", "encoder.ckpt",
                  "decoder.ckpt"),
        "tool": "speechbrain sepformer-dns4-16k-enhancement",
        "label": "SepFormer enhancement (DNS4)", "outputs": ("output",),
        "licence": "Apache-2.0"},
    "sepformer-whamr": {
        "folder": "sepformer-whamr16k",
        "repo": "speechbrain/sepformer-whamr16k",
        "files": ("hyperparams.yaml", "masknet.ckpt", "encoder.ckpt",
                  "decoder.ckpt"),
        "tool": "speechbrain sepformer-whamr16k",
        "label": "SepFormer two-voice separation (WHAMR!)",
        "outputs": ("voice1", "voice2"), "licence": "Apache-2.0"},
}

SEVERITY_WEIGHT = {"high": 3.0, "medium": 2.0, "low": 1.0, "info": 0.0}
TIER_PENALTY = {"measured": 0.0, "recovered": 0.0, "cleaned": 0.3,
                "inferred": 0.8, "invented": 2.0}
TARGET_SPEECH_DB = -20.0
HEADROOM_DB = -1.0


# ---------------------------------------------------------------------------
# pure: findings from measurements
# ---------------------------------------------------------------------------

def _issue(iid, label, severity, measured, fix="", **extra):
    return dict({"id": iid, "label": label, "severity": severity,
                 "measured": measured, "fix": fix}, **extra)


def issues(a: dict) -> list[dict]:
    """What is wrong with a recording, from its measurements — each with a
    severity (high / medium / low / info) and the number behind it."""
    out = []
    if not a or a.get("empty"):
        return [_issue("empty", "No audio", "high", "the file holds no samples")]
    rate = float(a.get("rate") or 0)
    if a.get("speech_fraction", 1.0) < 0.05:
        out.append(_issue("no-speech", "Little or no speech found", "info",
                          f"{a.get('speech_fraction', 0) * 100:.0f}% of the "
                          "recording is above the speech gate",
                          "check this is the right recording"))
    snr = a.get("snr_db")
    if snr is not None:
        sev = "high" if snr < 10 else "medium" if snr < 20 else \
            "low" if snr < 30 else ""
        if sev:
            steady = a.get("noise_steadiness_db", 0.0) < 3.0
            out.append(_issue(
                "noise", "Background noise" + (" (steady)" if steady else
                                               " (changing)"), sev,
                f"speech about {snr:.0f} dB above a noise floor of "
                f"{a.get('noise_db', a.get('floor_db', 0)):.0f} dBFS",
                "noise reduction"))
    hum = a.get("hum") or {}
    if hum.get("prominence_db", 0) >= 10 and hum.get("harmonics", 0) >= 3:
        out.append(_issue(
            "hum", f"Mains hum at {hum['hz']} Hz",
            "high" if hum["prominence_db"] >= 18 else "medium",
            f"{hum['prominence_db']:.0f} dB above its surroundings, "
            f"{hum['harmonics']} harmonics", "notch filters",
            hz=int(hum["hz"])))
    if a.get("rumble_db", -99) > -3.0:
        out.append(_issue("rumble", "Low-frequency rumble", "medium",
                          f"as much energy below 80 Hz as above it in the "
                          f"pauses ({a['rumble_db']:+.0f} dB)",
                          "high-pass filter"))
    dc = abs(a.get("dc_offset", 0.0))
    if dc > 0.003:
        out.append(_issue("dc", "DC offset", "medium" if dc > 0.01 else "low",
                          f"mean sample value {a['dc_offset']:+.4f}",
                          "high-pass filter"))
    clip = a.get("clipped_fraction", 0.0)
    if clip > 0.0001:
        out.append(_issue("clipping", "Clipping", "high" if clip > 0.001
                          else "medium",
                          f"{clip * 100:.2f}% of samples flat at the peak in "
                          f"{a.get('clipped_runs', 0)} runs", "de-clipping"))
    clicks = a.get("clicks_per_s", 0.0)
    if clicks > 0.5:
        out.append(_issue("clicks", "Clicks and crackle",
                          "high" if clicks > 2 else "medium",
                          f"{clicks:.1f} impulsive jumps per second",
                          "de-click"))
    bw = a.get("bandwidth_hz")
    if bw and rate and bw < 0.8 * rate / 2:
        kind = "Telephone band" if bw <= 4500 else "Narrow band"
        out.append(_issue("band", kind, "info",
                          f"speech occupies up to about {bw:.0f} Hz of "
                          f"{rate / 2:.0f} Hz",
                          "cut the hiss above the band; restoring the "
                          "missing band would be invention"))
    if a.get("speech_db") is not None and a["speech_db"] < -35:
        out.append(_issue("quiet", "Speech is quiet", "medium",
                          f"speech at {a['speech_db']:.0f} dBFS",
                          "level"))
    out.extend(content_issues(a))
    out.extend(faint_issues(a))
    return out


CONTENT_SHORT = {"telephone": "telephone band", "codec": "a codec's cut",
                 "upsampled": "made at a lower rate",
                 "anti-alias": "full band", "open": "content to the very top",
                 "rolloff": "no hard cut", "cut": "a filter's cut"}


def content_issues(a: dict) -> list[dict]:
    """What the file really holds (§13.9): the highest real content against
    the top the rate allows, and the bottom — measured, for information."""
    c = a.get("content") or {}
    out = []
    if c.get("kind"):
        nyq = float(c.get("nyquist_hz") or 0)
        top = float(c.get("cutoff_hz") or c.get("top_hz") or nyq)
        measured = c.get("label", "")
        if c.get("low_cut_hz"):
            measured += (f"; at the bottom the recorder's high-pass, about "
                         f"{c['low_cut_hz']:.0f} Hz — nothing below it")
        if c["kind"] == "open":
            fix = ("listen for folded ultrasound: the shift options move the "
                   "top of the band down into hearing")
        elif top < SHIFT_HIGH_HZ:
            fix = (f"nothing above {top / 1000:.1f} kHz is in the file to "
                   "recover — no shift into hearing up there")
        elif nyq > SHIFT_HIGH_HZ + 2000:
            fix = (f"real content up to {top / 1000:.1f} kHz: the top can be "
                   "shifted into hearing")
        else:
            fix = ""
        out.append(_issue("content", "What the file holds: "
                          + CONTENT_SHORT.get(c["kind"], c["kind"]), "info",
                          measured, fix, kind=c["kind"],
                          top_hz=round(top, 1)))
    if c.get("infrasound"):
        out.append(_issue(
            "infrasound", "Energy below 20 Hz", "info",
            f"{c.get('infrasound_db', 0):+.0f} dB per hertz against 50-200 Hz"
            " — wind, vents, traffic, machinery, a door or a pressure wave",
            "shift it up into hearing, or play it "
            f"{SPEED_FACTOR}x faster"))
    return out


def faint_events(a: dict) -> list[dict]:
    return [e for e in ((a.get("faint") or {}).get("events") or [])
            if e.get("faint")]


def tonal_lines(a: dict) -> list[dict]:
    return [l for l in ((a.get("faint") or {}).get("lines") or [])
            if not l.get("mains")]


def faint_issues(a: dict) -> list[dict]:
    """The faint-sound findings (§13.8): the channels, sounds under the
    noise, steady tones, repeats — each with the measurement behind it."""
    out = []
    ch = a.get("channels") or {}
    if (ch.get("count") or 1) > 1:
        n = ch["count"]
        comb = ch.get("combination") or {}
        lags = ", ".join(f"channel {p['channel'] + 1} {p['lag_ms']:+.1f} ms"
                         for p in ch.get("pairs") or [])
        if ch.get("used"):
            out.append(_issue(
                "channels", f"{n} channels hold the same sound — combined",
                "info", f"{comb.get('gain_db', 0):+.1f} dB less noise than the "
                f"best channel (channel {ch.get('reference', 0) + 1}); {lags}",
                "every option starts from the combination (Recovered)"))
        elif ch.get("kind") == "unrelated":
            out.append(_issue(
                "channels", f"{n} channels carry different sound", "medium",
                "little of either channel is in the other — the two sides of "
                "a call, or two places", "the working copy mixes them; to keep "
                "them apart, restore each channel as its own file"))
        elif ch.get("kind") == "copies":
            out.append(_issue("channels", f"{n} identical channels", "info",
                              "the same samples in every channel",
                              "nothing to combine"))
        else:
            out.append(_issue(
                "channels", f"{n} channels — combining not used", "info",
                ch.get("why") or "it measured no better than the plain mix",
                "the plain mix of the channels is the working copy"))
    events = faint_events(a)
    if events:
        top = max(events, key=lambda e: e["z"])
        detected = [e for e in events if e.get("confidence") == "detected"]
        out.append(_issue(
            "faint", "Faint sounds under the noise",
            "medium" if detected else "low",
            f"{len(events)} found ({len(detected)} certain); the strongest at "
            f"{top['start_s']:.1f} s, {top['f_lo']:.0f}–{top['f_hi']:.0f} Hz, "
            f"{-top['broadband_snr_db']:.0f} dB under the noise (z {top['z']:.1f})",
            "listen to its clip; the faint-sound options lift them"))
    lines = tonal_lines(a)
    if lines:
        shown = ", ".join(f"{l['hz']:.0f} Hz (+{l['prominence_db']:.0f} dB)"
                          for l in sorted(lines, key=lambda l: -l["z"])[:4])
        more = f" and {len(lines) - 4} more" if len(lines) > 4 else ""
        series = sorted({l["series"] for l in lines if l.get("series")})
        out.append(_issue(
            "lines", "Steady tones", "info", shown + more + (
                f"; harmonic series at {', '.join(series)}" if series else ""),
            "a motor, a whine or a carrier: listen in its band"))
    rep = a.get("repeats") or {}
    if rep.get("found"):
        if rep.get("waveform"):
            out.append(_issue(
                "repeats", "A sound repeats, sample for sample", "medium",
                f"every {rep['period_s']:.3f} s, {rep.get('used', 0)} times, "
                f"waveforms matching (r {rep.get('waveform_r', 0):.2f})",
                f"average the repeats: about {rep.get('expected_gain_db', 0):.0f}"
                " dB less noise on them", period_s=rep["period_s"]))
        else:
            out.append(_issue(
                "repeats", "A repeating background", "low",
                f"a pattern every {rep['period_s']:.2f} s (strength "
                f"{rep.get('strength', 0):.2f})", "lift the repeating "
                "background off what does not repeat",
                period_s=rep["period_s"]))
    return out


def _by_id(found):
    return {i["id"]: i for i in found}


# ---------------------------------------------------------------------------
# pure: recipes from findings
# ---------------------------------------------------------------------------

def _filter_step(kind: str, filters: list[str], tier: str, label: str,
                 why: str) -> dict:
    return {"kind": kind, "tool": "ffmpeg", "filters": filters,
            "tier": tier, "label": label, "why": why}


def _model_step(model: str) -> dict:
    spec = MODELS[model]
    return {"kind": f"model:{model}", "tool": spec["tool"], "model": model,
            "tier": "inferred", "label": spec["label"],
            "why": "a discriminative model keeps what it judges to be speech"}


def _gain_db(a: dict) -> float:
    """Gain putting speech at TARGET_SPEECH_DB, never pushing the input's
    peak past HEADROOM_DB. With no speech found, the peak alone decides,
    and never by more than 20 dB."""
    room = HEADROOM_DB - float(a.get("peak_dbfs", HEADROOM_DB))
    speech = a.get("speech_db", TARGET_SPEECH_DB)
    if speech is None:
        return round(min(20.0, room), 1)
    want = TARGET_SPEECH_DB - float(speech)
    return round(min(want, room), 1)


def shared_fixes(a: dict, found: list[dict]) -> list[dict]:
    """The filters every option starts with: the faithful fixes for what
    the analysis found besides broadband noise."""
    f = _by_id(found)
    steps = []
    if "rumble" in f or "dc" in f:
        steps.append(_filter_step("highpass", ["highpass=f=80:poles=2"],
                                  "measured", "High-pass at 80 Hz",
                                  "removes rumble and DC offset"))
    if "hum" in f:
        hz = int(f["hum"].get("hz") or 60)
        top = min(1000.0, 0.45 * float(a.get("rate") or 16000))
        notches = [f"bandreject=f={k * hz}:width_type=q:w=30"
                   for k in range(1, 21) if k * hz <= top]
        steps.append(_filter_step("notch", notches, "cleaned",
                                  f"Notch {hz} Hz hum and {len(notches) - 1} "
                                  "harmonics", "narrow notches at the mains "
                                  "frequency and its multiples"))
    if "clicks" in f:
        steps.append(_filter_step("declick", ["adeclick"], "cleaned",
                                  "De-click", "detects impulses and "
                                  "interpolates across them"))
    if "clipping" in f:
        steps.append(_filter_step("declip", ["adeclip"], "inferred",
                                  "De-clip", "rebuilds flat-topped peaks "
                                  "from the waveform around them"))
    if "band" in f and a.get("bandwidth_hz"):
        cut = int(min(float(a["rate"]) / 2 - 100, a["bandwidth_hz"] + 200))
        steps.append(_filter_step("lowpass", [f"lowpass=f={cut}:poles=2"],
                                  "measured", f"Low-pass at {cut} Hz",
                                  "the band the speech occupies ends near "
                                  f"{a['bandwidth_hz']:.0f} Hz; above it is "
                                  "only hiss"))
    return steps


def _level_step(a: dict) -> list[dict]:
    g = _gain_db(a)
    if g < 1.0:
        return []
    return [_filter_step("gain", [f"volume={g:.1f}dB"], "measured",
                         f"Gain +{g:.1f} dB", "brings speech to about "
                         f"{TARGET_SPEECH_DB:.0f} dBFS, peaks kept under "
                         f"{HEADROOM_DB:.0f} dBFS")]


def _denoise_step(a: dict, severity: str) -> dict:
    nr = {"high": 20, "medium": 12}.get(severity, 8)
    nf = int(max(-80, min(-20, round(a.get("noise_db", a.get("floor_db",
                                                             -50))))))
    return _filter_step("denoise", [f"afftdn=nr={nr}:nf={nf}:tn=1"],
                        "cleaned", f"FFT noise reduction ({nr} dB)",
                        f"FFmpeg's afftdn, noise floor {nf} dB, tracked")


def _effect(option: str, found: dict) -> float:
    """How completely `option` deals with what was found, severity-weighted."""
    total = 0.0
    for iid, issue in found.items():
        w = SEVERITY_WEIGHT[issue["severity"]]
        if iid == "noise":
            steady = "(steady)" in issue["label"]
            eff = {"filters": {"high": 0.4, "medium": 0.8, "low": 0.9}.get(
                       issue["severity"], 0.9),
                   "metricgan": 0.8 if steady else 0.6,
                   "sepformer-dns4": 0.9, "separate": 0.3,
                   "dfn": 0.85 if steady else 0.8,
                   "rnnoise": 0.55 if steady else 0.5,
                   "fixes-only": 0.0}.get(option, 0.0)
        elif iid == "faint":
            eff = {"faint-mask": 0.8, "faint-band": 0.6}.get(option, 0.0)
        elif iid == "repeats":
            eff = {"average-repeats": 1.0, "repeating-apart": 0.7}.get(
                option, 0.0)
        elif iid in ("hum", "rumble", "dc", "clicks", "clipping", "quiet",
                     "band"):
            eff = 1.0
        else:
            eff = 0.0
        total += w * eff
    return total


def option_tier(steps, base: str = "measured") -> str:
    return _recipe.highest_tier([s["tier"] for s in steps] + [base])


#: Options whose purpose is the faint sounds, not the main content (and
#: every "shift-…" option: a band moved into hearing).
FAINT_OPTIONS = ("faint-band", "faint-mask", "average-repeats",
                 "repeating-apart")


def is_faint_option(oid: str) -> bool:
    return oid in FAINT_OPTIONS or oid.startswith("shift-")


def _rnnoise_step() -> dict:
    return {"kind": "rnnoise", "tool": RNNOISE_TOOL, "filters": [],
            "tier": "inferred", "speech_only": True,
            "label": "RNNoise speech denoiser (FFmpeg arnndn, 10% of the "
                     "input kept)",
            "why": "a small recurrent network trained on speech over "
                   "recording noise (fans, air conditioning, computers) "
                   "turns each band down by how much speech it hears there. "
                   + SPEECH_ONLY}


def _deepfilter_step() -> dict:
    return {"kind": "deepfilter", "tool": DFN_TOOL, "tier": "inferred",
            "speech_only": True,
            "label": f"DeepFilterNet 3 speech enhancement (48 kHz, at most "
                     f"{DFN_ATTEN_DB} dB taken off)",
            "why": "a learned model of speech keeps what it judges to be "
                   "speech, full band, its delay put back. " + SPEECH_ONLY,
            "params": {"atten_lim_db": DFN_ATTEN_DB,
                       "compensate_delay": True}}


def _shift_step(lo: float, hi: float, by: float, label: str, why: str,
                copy: dict | None = None) -> dict:
    return _dsp_step("shift", label, why, band=[round(lo, 1), round(hi, 1)],
                     shift_hz=round(by, 1), copy=copy or None)


def shift_options_for(a: dict) -> list[dict]:
    """(id, label, step, gets, copy stem) for each band worth moving into
    hearing: up to three sounds found above SHIFT_HIGH_HZ, the strongest
    steady tone up there, everything up there, and below 20 Hz."""
    c = a.get("content") or {}
    rate = float(a.get("rate") or 0)
    nyq = rate / 2
    if not rate:
        return []
    top = min(float(c.get("cutoff_hz") or nyq), 0.995 * nyq)
    out = []
    every = (a.get("faint") or {}).get("events") or []
    lows = [e for e in every if e.get("f_hi", 0) < SHIFT_HIGH_HZ]

    def heard_below(e) -> bool:
        # the top of a sound that is also heard below SHIFT_HIGH_HZ at the
        # same moment — a click, a door, a plosive — is not worth moving:
        # the sound itself is already audible (seen 2026-10-09: a voice's
        # clicks took every slot from a beacon that was only up there)
        peak = e.get("peak_s", 0.5 * (e["start_s"] + e["end_s"]))
        return any(l["start_s"] <= peak <= l["end_s"] for l in lows)

    events = [e for e in every if e.get("f_lo", 0) >= SHIFT_HIGH_HZ
              and e["f_lo"] < top and not heard_below(e)]
    for e in sorted(events, key=lambda e: -e["z"])[:MAX_SHIFT_EVENTS]:
        pad = max(200.0, 0.1 * (e["f_hi"] - e["f_lo"]))
        lo = max(0.9 * SHIFT_HIGH_HZ, e["f_lo"] - pad)
        hi = min(top, e["f_hi"] + pad)
        by = SHIFT_TO_HZ - lo
        step = _shift_step(
            lo, hi, by, f"Move {lo / 1000:.1f}-{hi / 1000:.1f} kHz down by "
            f"{-by / 1000:.1f} kHz", "every frequency in the band moved by the "
            "same amount, so a pattern up there is heard down here at the "
            "same moment; a copy of the event played slower beside it",
            copy={"kind": "expand",
                  "start_s": max(0.0, round(e["start_s"] - 1.0, 3)),
                  "end_s": round(e["end_s"] + 1.0, 3)})
        out.append((f"shift-ev{e['n']}",
                    f"Hear sound {e['n']} — {e['f_lo'] / 1000:.1f}-"
                    f"{e['f_hi'] / 1000:.1f} kHz moved down into hearing",
                    step, [f"sound {e['n']} ({e['start_s']:.1f}-"
                           f"{e['end_s']:.1f} s) heard at "
                           f"{SHIFT_TO_HZ / 1000:.0f}-{(hi + by) / 1000:.1f} "
                           "kHz, in time with the recording, and a slowed "
                           "copy of it"], "expanded"))
    lines = [l for l in (a.get("faint") or {}).get("lines") or []
             if not l.get("mains") and SHIFT_HIGH_HZ <= l["hz"] < top]
    if lines:
        l = max(lines, key=lambda l: l["z"])
        lo, hi = max(0.9 * SHIFT_HIGH_HZ, l["hz"] - 500.0), min(top,
                                                              l["hz"] + 500.0)
        by = SHIFT_TO_HZ - lo
        step = _shift_step(lo, hi, by, f"Move the {l['hz'] / 1000:.2f} kHz "
                           f"tone down to {(l['hz'] + by) / 1000:.2f} kHz",
                           "the tone and 500 Hz either side moved down: what "
                           "changes it — a beacon's data, a motor's load — "
                           "heard as it happens; a slowed copy of its loudest "
                           "30 s beside it", copy={"kind": "expand"})
        out.append(("shift-line", f"Hear the {l['hz'] / 1000:.2f} kHz tone",
                    step, [f"the steady tone at {l['hz']:.0f} Hz "
                           f"(+{l['prominence_db']:.0f} dB) heard at "
                           f"{(l['hz'] + by):.0f} Hz with whatever "
                           "modulates it"], "expanded"))
    if top >= SHIFT_HIGH_HZ + 2000.0:
        by = SHIFT_TO_HZ - SHIFT_HIGH_HZ
        step = _shift_step(SHIFT_HIGH_HZ, top, by,
                           f"Move {SHIFT_HIGH_HZ / 1000:.0f}-{top / 1000:.1f} "
                           f"kHz down by {-by / 1000:.0f} kHz",
                           "everything the file holds above "
                           f"{SHIFT_HIGH_HZ / 1000:.0f} kHz moved down, "
                           "nothing chosen; a slowed copy of its loudest "
                           "30 s beside it", copy={"kind": "expand"})
        out.append(("shift-top", f"Hear everything above "
                    f"{SHIFT_HIGH_HZ / 1000:.0f} kHz", step,
                    [f"{SHIFT_HIGH_HZ / 1000:.0f}-{top / 1000:.1f} kHz heard at "
                     f"{SHIFT_TO_HZ / 1000:.0f}-{(top + by) / 1000:.1f} kHz"],
                    "expanded"))
    if c.get("infrasound"):
        lo, hi = SHIFT_LOW_BAND
        step = _shift_step(lo, hi, SHIFT_LOW_BY,
                           f"Move {lo:.0f}-{hi:.0f} Hz up by "
                           f"{SHIFT_LOW_BY:.0f} Hz",
                           "below 20 Hz moved up to where it can be heard, in "
                           f"time with the recording; a copy {SPEED_FACTOR}x "
                           "faster, its pattern kept",
                           copy={"kind": "speed", "factor": SPEED_FACTOR})
        out.append(("shift-low", "Hear below 20 Hz", step,
                    [f"{lo:.0f}-{hi:.0f} Hz heard at {lo + SHIFT_LOW_BY:.0f}-"
                     f"{hi + SHIFT_LOW_BY:.0f} Hz, and the whole recording "
                     f"{SPEED_FACTOR}x faster ({lo * SPEED_FACTOR:.0f}-"
                     f"{hi * SPEED_FACTOR:.0f} Hz)"], "sped-up"))
    return out


def _dsp_step(kind: str, label: str, why: str, **params) -> dict:
    return {"kind": f"dsp:{kind}", "tool": DSP_TOOLS[kind], "dsp": kind,
            "tier": DSP_TIERS[kind], "label": label, "why": why,
            "params": params}


def _lift_step() -> dict:
    return _filter_step("gain", [LIFT], "measured",
                        "Lift the quiet parts (dynamic normaliser, at most "
                        "+20 dB)", "a level operation that follows the "
                        "sound: quiet stretches raised, loud ones left")


def _band_step(e: dict, rate: float) -> dict:
    lo = max(20, int(e["f_lo"] * 0.8))
    hi = int(min(0.98 * rate / 2, e["f_hi"] * 1.25))
    return _filter_step("bandpass", [f"highpass=f={lo}:poles=2",
                                     f"highpass=f={lo}:poles=2",
                                     f"lowpass=f={hi}:poles=2",
                                     f"lowpass=f={hi}:poles=2"], "measured",
                        f"Band {lo}–{hi} Hz", "the band the strongest faint "
                        "sound occupies, a little wider; everything outside "
                        "it turned down")


def options(a: dict, found: list[dict] | None = None) -> list[dict]:
    """Ranked restoration options for these measurements; the first is the
    recommendation. Each: id, label, steps, tier, what it can get you, what
    it risks, score, recommended."""
    found = issues(a) if found is None else found
    f = _by_id(found)
    shared = shared_fixes(a, found)
    level = _level_step(a)
    noise = f.get("noise")
    out = []
    ch = a.get("channels") or {}
    base = "recovered" if ch.get("used") else "measured"

    narrow = float(a.get("bandwidth_hz") or 0) > 8500.0

    def add(oid, label, steps, gets, risks, outputs=("output",), **extra):
        tier = option_tier(steps, base)
        score = _effect(oid, f) - TIER_PENALTY[tier]
        if narrow and any(s["kind"] == "to16k" for s in steps) and \
                oid != "separate":
            score -= NARROW_MODEL_PENALTY
        speech_only = oid in SPEECH_ONLY_OPTIONS
        if speech_only:
            risks = risks + ". " + SPEECH_ONLY
        out.append(dict({"id": oid, "label": label, "steps": steps,
                         "tier": tier, "gets": gets, "risks": risks,
                         "outputs": list(outputs), "score": round(score, 3),
                         "recommended": False, "speech_only": speech_only,
                         "purpose": "faint" if is_faint_option(oid)
                         else "main"}, **extra))

    fixed = [s["label"] for s in shared]
    if noise:
        add("filters", "Clean-up with filters",
            shared + [_denoise_step(a, noise["severity"])] + level,
            fixed + [f"steady noise lowered by about "
                     f"{ {'high': 20, 'medium': 12}.get(noise['severity'], 8)} "
                     "dB, voice kept natural"],
            "FFT noise reduction can leave a watery, 'musical' texture and "
            "dull consonants when the noise is loud")
        add("metricgan", "Model enhancement — MetricGAN+",
            shared + [{"kind": "to16k", "tool": "ffmpeg",
                       "filters": ["aresample=16000"], "tier": "measured",
                       "label": "Resample to 16 kHz mono",
                       "why": "the models take 16 kHz"},
                      _model_step("metricgan")] + level,
            fixed + ["stronger noise removal on steady noise; trained to "
                     "maximise speech quality (PESQ)"],
            "a learned model shapes what is kept: it can thin a voice or "
            "drop quiet syllables; output is 16 kHz")
        add("sepformer-dns4", "Model enhancement — SepFormer (DNS4)",
            shared + [{"kind": "to16k", "tool": "ffmpeg",
                       "filters": ["aresample=16000"], "tier": "measured",
                       "label": "Resample to 16 kHz mono",
                       "why": "the models take 16 kHz"},
                      _model_step("sepformer-dns4")] + level,
            fixed + ["the strongest noise removal here, including changing "
                     "noise (trained on ~1,300 h of DNS-4 noise)"],
            "the most invasive: at very low SNR it can remove or blur speech; "
            "output is 16 kHz")
        add("dfn", "Speech enhancement — DeepFilterNet 3 (full band)",
            shared + [_deepfilter_step()] + level,
            fixed + ["strong removal of steady and changing noise at the "
                     "recording's own rate — nothing above 8 kHz thrown away; "
                     "at most 20 dB taken off, so a trace of everything stays"],
            "a learned model shapes what is kept: it can thin a voice or "
            "swallow a quiet word")
        add("rnnoise", "Speech denoiser — RNNoise (light)",
            shared + [_rnnoise_step()] + level,
            fixed + ["light, fast noise removal for fans, air conditioning "
                     "and computers; 10% of the input kept in"],
            "gentler than the other models and easily fooled by changing "
            "noise; it can leave a gated, underwater sound between words")
        if shared:
            add("fixes-only", "Only the fixes, noise left in", list(shared)
                + level, fixed + ["the faithful baseline: hum/clicks/rumble "
                                  "fixed, everything else untouched"],
                "the noise stays — compare against it to hear what noise "
                "reduction costs")
    else:
        steps = shared + level
        if steps:
            add("filters", "Clean-up with filters", steps,
                fixed + ([] if level == [] else [level[0]["label"]]),
                "minimal — every step is a filter or a gain")
    if ch.get("used"):
        add("combine", "Channels combined — nothing else", list(level),
            [f"{ch['count']} channels added in phase: "
             f"{(ch.get('combination') or {}).get('gain_db', 0):+.1f} dB less "
             "noise, the shared sound untouched"],
            "none to the sound they share; what one channel alone holds is "
            "weighed down — compare with the best channel (its residual)",
            outputs=("combined",), reference="best_channel")
    events = faint_events(a)
    rate = float(a.get("rate") or 16000)
    if events:
        top = max(events, key=lambda e: e["z"])
        add("faint-band", "Faint sounds — listen in their band",
            shared + [_band_step(top, rate), _lift_step()],
            fixed + [f"the band of the strongest faint sound "
                     f"({top['f_lo']:.0f}–{top['f_hi']:.0f} Hz) on its own, "
                     "lifted — nothing else changed"],
            "everything outside the band is turned down with it, including "
            "other faint sounds; the lift raises the noise too")
        add("faint-mask", "Faint sounds — keep only what stands out",
            shared + [_dsp_step("mask", "Keep what stands out of the noise",
                                "each cell kept by how far it stands out of "
                                "its own band's noise, the rest 30 dB down"),
                      _lift_step()],
            fixed + [f"{len(events)} faint sound(s) kept, the steady noise "
                     "around them taken down 30 dB, then lifted"],
            "anything fainter than the detector can see is taken down with "
            "the noise — the residual holds it; listen there too")
    rep = a.get("repeats") or {}
    if rep.get("found") and rep.get("waveform"):
        add("average-repeats", "Average the repeats",
            shared + [_dsp_step("average", f"Average {rep.get('used', 0)} "
                                f"repeats ({rep['period_s']:.3f} s apart)",
                                "each repeat aligned to the others and all of "
                                "them averaged; the average laid back where "
                                "each one was")] + level,
            fixed + [f"the repeating sound with about "
                     f"{rep.get('expected_gain_db', 0):.0f} dB less noise; what "
                     "does not repeat is in the residual — listen to both"],
            "only a sound that repeats sample for sample (a tone, a played "
            "recording, a machine cycle) survives; a voice saying the same "
            "words again does not repeat like that")
    if rep.get("found"):
        add("repeating-apart", "Lift off the repeating background",
            shared + [_dsp_step("repet", "Lift off what repeats every "
                                f"{rep['period_s']:.2f} s", "the spectrum at "
                                "the same point of every period, its median, "
                                "is the repeating background; what stands "
                                "above it is kept",
                                period_s=rep["period_s"])] + level,
            fixed + ["what does not repeat — a voice or an event over a "
                     "repeating machine — with the machine taken down; the "
                     "repeating part is the residual"],
            "a soft mask: some of the background stays, and a sound that "
            "itself repeats at that period goes with the background")
    for oid, label, step, gets, stem in shift_options_for(a):
        add(oid, label, [step, _lift_step()], gets,
            "a moved band no longer sounds like itself — its pitch is "
            "wrong by the shift, its harmonics no longer line up; it shows "
            "WHAT happens WHEN, not what it sounded like. The lift raises "
            "the band's own noise too. No residual: nothing was taken away",
            copy_stem=stem, shift=True)
    add("separate", "Separate two voices — SepFormer (WHAMR!)",
        shared + [{"kind": "to16k", "tool": "ffmpeg",
                   "filters": ["aresample=16000"], "tier": "measured",
                   "label": "Resample to 16 kHz mono",
                   "why": "the models take 16 kHz"},
                  _model_step("sepformer-whamr")],
        fixed + ["two outputs, one per voice — for overlapping talkers or a "
                 "voice under another (trained with noise and reverberation)"],
        "a voice can leak into the other output or swap at a pause; only for "
        "two talkers", outputs=MODELS["sepformer-whamr"]["outputs"])
    # The main content first, unless the faint sounds are all there is to
    # work on (nothing serious otherwise, or no speech at all).
    main_serious = [i for i in found if i["severity"] in ("high", "medium")
                    and i["id"] not in ("faint", "repeats", "channels")]
    primary = "faint" if not main_serious and any(
        i["id"] in ("faint", "repeats") and i["severity"] == "medium"
        for i in found) else "main"
    out.sort(key=lambda o: (o["id"] == "separate",
                            o["purpose"] != primary, -o["score"],
                            _recipe.tier_rank(o["tier"])))
    serious = [i for i in found if i["severity"] in ("high", "medium")]
    if out and serious and out[0]["id"] != "separate" and \
            out[0]["score"] > 0:
        out[0]["recommended"] = True
    return out


def best_option(opts: list[dict]) -> str:
    for o in opts:
        if o.get("recommended"):
            return o["id"]
    return ""


# ---------------------------------------------------------------------------
# pure: after a run — which output measured best
# ---------------------------------------------------------------------------

def share(db) -> float | None:
    """A removal figure in dB (residual relative to input) as the fraction of
    the input's energy that was taken away."""
    if db is None:
        return None
    return max(0.0, min(1.0, 10.0 ** (float(db) / 10.0)))


def measured_score(result: dict, input_analysis: dict) -> float | None:
    """Energy taken from the pauses, minus three times whatever was taken
    during speech beyond the noise that was in it, minus twice any energy
    the process ADDED (a model making sound). A pointer for the ear."""
    measured = result.get("measured") or {}
    removed = measured.get("removed") or {}
    pauses = share(removed.get("during_pauses_db"))
    speech = share(removed.get("during_speech_db"))
    if pauses is None or speech is None:
        return None
    snr = input_analysis.get("snr_db")
    noise_in_speech = 10.0 ** (-float(snr) / 10.0) if snr is not None else 0.0
    added = measured.get("added") or {}
    made = (share(added.get("speech_db")) or 0.0) + \
        (share(added.get("pauses_db")) or 0.0)
    return round(pauses - 3.0 * max(0.0, speech - noise_in_speech)
                 - 2.0 * made, 4)


def measured_best(results: list[dict], input_analysis: dict) -> str:
    """The restoration of the main content that measured best. Separation,
    combining alone and the faint-sound options answer other questions and
    are not ranked against it."""
    scored = [(measured_score(r, input_analysis), r["option"])
              for r in results if not r.get("error")
              and r["option"] not in ("separate", "combine")
              and not is_faint_option(r["option"])]
    scored = [s for s in scored if s[0] is not None]
    return max(scored)[1] if scored else ""


# ---------------------------------------------------------------------------
# the case side
# ---------------------------------------------------------------------------

def runs_root(case) -> Path:
    return Path(case.root) / RESTORE_DIR


def models_missing(models_root, which=None) -> dict:
    """{model: [missing files]} for the restoration models under the root."""
    out = {}
    for key in which or MODELS:
        spec = MODELS[key]
        folder = Path(models_root) / spec["folder"]
        gone = [f for f in spec["files"] if not (folder / f).is_file()]
        if gone:
            out[key] = gone
    return out


def _worker_argv(python, worker) -> list[str]:
    if worker:
        return [os.fspath(a) for a in worker]
    if not python:
        raise MediaError("No Python with torch was given for the restoration "
                         "worker. " + INSTALL_HINT)
    if not Path(python).is_file():
        raise MediaError(f"The restoration worker's Python is not at "
                         f"{python}. " + INSTALL_HINT)
    return [os.fspath(python), "-I", os.fspath(WORKER)]


def _call_worker(request: dict, run_dir: Path, name: str, *, case, python,
                 worker, scratch, log, writes, should_cancel, heartbeat,
                 timeout_s: float) -> dict:
    spot = _vp._CaseSpot(case)
    req_path = run_dir / f"{name}.request.json"
    resp_path = run_dir / f"{name}.response.json"
    spot.json(req_path, request)
    argv = _worker_argv(python, worker)
    scratch = _vp.make_scratch(scratch)
    log_path = getattr(log, "name", None)

    def beat(elapsed):
        if heartbeat is not None:
            heartbeat(f"{name}: running {_sam.clock(elapsed)} · worker: "
                      f"{_sam.last_line(log_path) or 'nothing printed yet'}")

    outcome = _sam.run_process(
        argv + [os.fspath(req_path), os.fspath(resp_path)], log=log,
        timeout_s=timeout_s, writes=list(writes) + [resp_path],
        guard=spot.guard, should_cancel=should_cancel,
        env=_vp.worker_env(scratch), heartbeat=beat if heartbeat else None)
    if outcome["state"] == "cancelled":
        raise Cancelled(f"stopped during {name}")
    if outcome["state"] != "completed" or not resp_path.is_file():
        why = {"timeout": f"it ran past {timeout_s:.0f} s"}.get(
            outcome["state"], "the worker " +
            _sam.exit_sentence(outcome["returncode"]))
        raise MediaError(f"{name} did not finish: {why}. It said: "
                         f"{_sam.log_tail(log_path) or '(nothing)'} — log "
                         f"{log_path}.")
    with open(resp_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _ffmpeg(ffmpeg, inputs, out, *, filters=None, complex_filter=None,
            rate=None, channels: int | None = 1, seconds=None, log, case,
            should_cancel) -> None:
    """FFmpeg over the first audio stream: `channels` channels (None: as
    many as it has), an optional rate, filters and duration."""
    argv = _vp.require_ffmpeg(ffmpeg) + ["-hide_banner", "-nostdin", "-n"]
    for path in inputs:
        argv += ["-i", os.fspath(path)]
    if complex_filter:
        argv += ["-filter_complex", complex_filter]
    else:
        argv += ["-map", "0:a:0", "-vn", "-sn", "-dn"]
        if channels:
            argv += ["-ac", str(int(channels))]
        if filters:
            argv += ["-af", ",".join(filters)]
    if rate:
        argv += ["-ar", str(int(rate))]
    if seconds:
        argv += ["-t", f"{float(seconds):g}"]
    argv += ["-c:a", "pcm_f32le", os.fspath(out)]
    outcome = _sam.run_process(
        argv, log=log, timeout_s=3600.0, writes=[out],
        guard=lambda p: blocker.assert_case_path(case.root, p),
        should_cancel=should_cancel)
    if outcome["state"] == "cancelled":
        raise Cancelled("stopped while FFmpeg ran")
    if outcome["state"] != "completed" or not Path(out).is_file():
        raise MediaError(
            f"FFmpeg could not make {Path(out).name} "
            f"({_sam.exit_sentence(outcome['returncode'])}): "
            f"{_sam.log_tail(getattr(log, 'name', '')) or outcome['error']}"
            f" — log {getattr(log, 'name', '')}.")


def _tool_version(ffmpeg) -> str:
    try:
        return _lab._tool_version(_sam.runtime_argv(ffmpeg))
    except Exception:                                     # noqa: BLE001
        return ""


def analyse(case, source, *, ffmpeg, python=None, worker=None, scratch,
            evidence_id: str = "", faint: bool = True, progress=None,
            heartbeat=None, should_cancel=None) -> dict:
    """Measure a recording and rank what could restore it. Nothing is
    restored yet: this writes the run folder, the copy, the working WAVs,
    analysis.json and the run's recipe.json — and, for faint sounds
    (§13.8), the salience map, a clip of each faint event and, when the
    channels carry one sound, their combination."""
    say = progress or (lambda _l: None)
    _vp.require_ffmpeg(ffmpeg)
    _worker_argv(python, worker)
    original = _lab.resolve_input(case, source, evidence_id)
    upstream_id, upstream_tier, basis = _lab.upstream_of_input(
        case, original["path"])
    run_id = _vp._new_id("rs")
    run_dir = _case.make_case_dirs(case.root, RESTORE_DIR, run_id)
    case.custody.record("media.restore.started", actor=case.actor(),
                        target=run_id, detail={"run_id": run_id,
                                               "input": original,
                                               "folder": os.fspath(run_dir)})
    try:
        with _lab._case_log(case, run_dir / "analyse.log") as log:
            say("Copying the recording into the case through the read-only "
                "door…")
            copy = run_dir / "source" / original["name"]
            hashes = _lab._copy_in(case, original["path"], copy)
            original.update(sha256=hashes.sha256, size=hashes.size)
            version = _tool_version(ffmpeg)
            src_rel = f"source/{original['name']}"
            steps = [_recipe.step(
                DOOR_TOOL, tier="measured", params={"from": original["kind"]},
                inputs={"original": hashes.sha256},
                outputs={src_rel: hashes.sha256},
                note="the original's bytes, unchanged")]
            probe = run_dir / "probe.wav"
            _ffmpeg(ffmpeg, [copy], probe, channels=None, seconds=0.05,
                    log=log, case=case, should_cancel=should_cancel)
            n_channels = _wav.read_info(probe).channels
            steps.append(_recipe.step(
                "ffmpeg", tier="measured", version=version,
                params={"args": ["-map", "0:a:0", "-t", "0.05"]},
                inputs={src_rel: hashes.sha256},
                outputs={"probe.wav": hashing.hash_case_file(probe).sha256},
                note=f"50 ms, to read the channel count: {n_channels}"))
            analysis_wav = run_dir / "analysis.wav"
            say("Making a mono working copy at the recording's own rate…")
            _ffmpeg(ffmpeg, [copy], analysis_wav, log=log, case=case,
                    should_cancel=should_cancel)
            aw_sha = hashing.hash_case_file(analysis_wav).sha256
            steps.append(_recipe.step(
                "ffmpeg", tier="measured", version=version,
                params={"args": ["-map", "0:a:0", "-ac", "1", "-c:a",
                                 "pcm_f32le"]},
                inputs={src_rel: hashes.sha256},
                outputs={"analysis.wav": aw_sha},
                note="first audio stream mixed to mono, 32-bit float, the "
                     "recording's own rate"))
            analysis_step = len(steps) - 1
            item = {"id": "input", "wav": os.fspath(analysis_wav)}
            writes = []
            channels_wav = run_dir / "channels.wav"
            if n_channels > 1:
                say(f"Keeping all {n_channels} channels to see whether they "
                    "hold the same sound…")
                _ffmpeg(ffmpeg, [copy], channels_wav, channels=n_channels,
                        log=log, case=case, should_cancel=should_cancel)
                cw_sha = hashing.hash_case_file(channels_wav).sha256
                steps.append(_recipe.step(
                    "ffmpeg", tier="measured", version=version,
                    params={"args": ["-map", "0:a:0", "-ac", str(n_channels),
                                     "-c:a", "pcm_f32le"]},
                    inputs={src_rel: hashes.sha256},
                    outputs={"channels.wav": cw_sha},
                    note="every channel, 32-bit float, the recording's own "
                         "rate"))
                channels_step = len(steps) - 1
                item.update(channels=os.fspath(channels_wav),
                            combined=os.fspath(run_dir / "combined.wav"),
                            best_channel=os.fspath(run_dir / "bestch.wav"))
                writes += [run_dir / "combined.wav", run_dir / "bestch.wav"]
            clips = []
            try:
                info = _wav.read_info(analysis_wav)
                seconds, rate = info.frames / max(1, info.rate), info.rate
            except Exception:                             # noqa: BLE001
                seconds, rate = 0.0, 0
            if faint:
                _case.make_case_dirs(case.root, RESTORE_DIR, run_id, FAINT_DIR)
                clips = [run_dir / FAINT_DIR / f"faint{i:02d}.wav"
                         for i in range(1, MAX_CLIPS + 1)]
                item["faint"] = {"png": os.fspath(run_dir / "salience.png"),
                                 "clips": [os.fspath(c) for c in clips]}
                item["repeats"] = True
                writes += [run_dir / "salience.png"] + clips
                if rate / 2 > HIGH_MAP_MIN_NYQ:
                    item["faint"]["png_high"] = os.fspath(
                        run_dir / "salience_high.png")
                    writes.append(run_dir / "salience_high.png")
            say("Measuring noise, hum, clipping, clicks, bandwidth and level"
                + (", the channels" if n_channels > 1 else "")
                + (", and looking for faint sounds and repeats" if faint
                   else "") + "…")
            data = _call_worker(
                {"op": "analyse", "items": [item]}, run_dir, "analyse",
                case=case, python=python, worker=worker, scratch=scratch,
                log=log, writes=writes, should_cancel=should_cancel,
                heartbeat=heartbeat, timeout_s=900.0 + 3.0 * seconds)
        measurements = data["items"][0]["analysis"]
        working, working_chain = "analysis.wav", [0, analysis_step]
        produced = {"analysis.wav": aw_sha}
        ch = measurements.get("channels") or {}
        if ch.get("used") and (run_dir / "combined.wav").is_file():
            comb_sha = hashing.hash_case_file(run_dir / "combined.wav").sha256
            outs = {"combined.wav": comb_sha}
            if (run_dir / "bestch.wav").is_file():
                outs["bestch.wav"] = hashing.hash_case_file(
                    run_dir / "bestch.wav").sha256
            steps.append(_recipe.step(
                COMBINE_TOOL, tier="recovered",
                params={"reference_channel": ch.get("reference"),
                        "lags": [p.get("lag_samples") for p in
                                 ch.get("pairs") or []],
                        "measured_gain_db": (ch.get("combination") or {})
                        .get("gain_db"), "kind": ch.get("kind")},
                inputs={"channels.wav": cw_sha}, outputs=outs,
                note="each channel shifted by its measured lag and weighted "
                     "per frequency so the sound they share passes at its "
                     "level in the best channel (maximal-ratio); bestch.wav is the "
                     "best channel alone, aligned, to compare with"))
            working = "combined.wav"
            working_chain = [0, channels_step, len(steps) - 1]
            produced.update(outs)
        fa = measurements.get("faint")
        clip_entries = []
        recipe_outputs = []
        if fa is not None:
            png = run_dir / "salience.png"
            if png.is_file():
                png_sha = hashing.hash_case_file(png).sha256
                steps.append(_recipe.step(
                    SALIENCE_TOOL, tier="measured",
                    params={"thresholds": fa.get("thresholds"),
                            "scales": fa.get("scales"),
                            "frame": fa.get("frame")},
                    inputs={working: produced[working]},
                    outputs={"salience.png": png_sha},
                    note="where each band stands out of its own noise, over "
                         "windows from 0.25 s to 16 s — a measurement, "
                         "nothing changed"))
                fa.setdefault("map", {})["file"] = "salience.png"
                produced["salience.png"] = png_sha
            high = run_dir / "salience_high.png"
            if fa.get("map_high") is not None and high.is_file():
                high_sha = hashing.hash_case_file(high).sha256
                steps.append(_recipe.step(
                    SALIENCE_TOOL, tier="measured",
                    params={"thresholds": fa.get("thresholds"),
                            "scales": fa.get("scales"),
                            "frame": fa.get("frame"),
                            "from_hz": fa["map_high"].get("f_min"),
                            "frequency_scale": "linear"},
                    inputs={working: produced[working]},
                    outputs={"salience_high.png": high_sha},
                    note="the same map from 12 kHz to the top, linear in "
                         "frequency, where the mel map squeezes it — a "
                         "measurement, nothing changed"))
                fa["map_high"]["file"] = "salience_high.png"
                produced["salience_high.png"] = high_sha
            for clip in fa.get("clips") or []:
                path = run_dir / FAINT_DIR / clip["file"]
                if not path.is_file():
                    continue
                sha = hashing.hash_case_file(path).sha256
                rel = f"{FAINT_DIR}/{clip['file']}"
                steps.append(_recipe.step(
                    DSP_TOOLS["mask"], tier="cleaned",
                    params={"event": clip["n"], "start_s": clip["start_s"],
                            "end_s": clip["end_s"], "band_hz": [
                                clip["f_lo"], clip["f_hi"]],
                            "gain_db": clip["gain_db"]},
                    inputs={working: produced[working]},
                    outputs={rel: sha},
                    note="the stretch around one faint event, kept to its "
                         "band by how far each cell stands out of the noise, "
                         f"then a gain of {clip['gain_db']:+.1f} dB to "
                         "-3 dBFS peak"))
                chain = working_chain + [len(steps) - 1]
                tier = _recipe.output_tier([steps[i] for i in chain],
                                           upstream_tier)
                clip.update(file=rel, sha256=sha, tier=tier)
                entry = {"file": rel, "sha256": sha, "stem": f"faint event "
                         f"{clip['n']}", "seed": None, "tier": tier,
                         "chain": chain, "size": os.path.getsize(path),
                         "sidecar": _recipe.sidecar_path(path.name).name,
                         "log": "analyse.log"}
                recipe_outputs.append(entry)
                clip_entries.append((path, entry))
                produced[rel] = sha
            fa["clips"] = [c for c in fa.get("clips") or [] if c.get("sha256")]
        found = issues(measurements)
        opts = options(measurements, found)
        recipe = {"schema": _recipe.SCHEMA,
                  "kind": "forensics_workshop.media.recipe",
                  "recipe_id": run_id, "created_at": utc_now(),
                  "examiner": case.examiner, "state": "analysed",
                  "purpose": "restoration", "original": original,
                  "input_sha256": hashes.sha256,
                  "upstream": {"recipe_id": upstream_id,
                               "tier": upstream_tier, "basis": basis},
                  "upstream_tier": upstream_tier, "steps": steps,
                  "outputs": recipe_outputs, "tier": "", "notes": []}
        _case.write_json_atomic(case.root, run_dir / _recipe.RECIPE_FILE,
                                recipe)
        for path, entry in clip_entries:
            _write_sidecar(case, path, entry, recipe, upstream_tier)
        report = {"schema": 1, "kind": "forensics_workshop.restore.analysis",
                  "run_id": run_id, "created_at": recipe["created_at"],
                  "original": original, "input_sha256": hashes.sha256,
                  "upstream_tier": upstream_tier, "analysis": measurements,
                  "working": working, "working_chain": working_chain,
                  "channels": n_channels,
                  "issues": found, "options": opts,
                  "best": best_option(opts), "results": [],
                  "worker": {k: data.get(k) for k in ("elapsed_s",)}}
        _case.write_json_atomic(case.root, run_dir / "analysis.json", report)
    except Exception as exc:
        case.custody.record("media.restore.failed", actor=case.actor(),
                            target=run_id,
                            detail={"run_id": run_id, "stage": "analyse",
                                    "error": str(exc),
                                    "folder": os.fspath(run_dir)})
        raise
    case.custody.record(
        "media.restore.analysed", actor=case.actor(), target=run_id,
        hashes=dict({"original": hashes.sha256}, **produced),
        detail={"run_id": run_id, "input": original, "working": working,
                "options": [o["id"] for o in opts],
                "faint_events": len(faint_events(measurements)),
                "folder": os.fspath(run_dir)})
    if found:
        say("Found: " + "; ".join(f"{i['label']} ({i['severity']})"
                                  for i in found))
    else:
        say("Nothing measured needs fixing.")
    return load_run(case, run_id)


def load_run(case, run_id: str) -> dict:
    folder = runs_root(case) / _vp._safe_id(run_id)
    try:
        with open(folder / "analysis.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise MediaError(f"The restoration {run_id} cannot be read: {exc}"
                         ) from exc
    for r in data.get("results") or []:
        for out in r.get("outputs") or []:
            out["path"] = os.fspath(folder / out["file"])
        if r.get("residual"):
            r["residual"]["path"] = os.fspath(folder / r["residual"]["file"])
    fa = (data.get("analysis") or {}).get("faint") or {}
    for clip in fa.get("clips") or []:
        clip["path"] = os.fspath(folder / clip["file"])
    for key in ("map", "map_high"):
        if (fa.get(key) or {}).get("file"):
            fa[key]["path"] = os.fspath(folder / fa[key]["file"])
    return dict(data, folder=os.fspath(folder))


def faint_files(report: dict) -> set[str]:
    """The faint-sound files of an analysis: its clips and its maps."""
    fa = (report.get("analysis") or {}).get("faint") or {}
    out = {c["file"] for c in fa.get("clips") or [] if c.get("file")}
    for key in ("map", "map_high"):
        if (fa.get(key) or {}).get("file"):
            out.add(fa[key]["file"])
    return out


def list_runs(case) -> list[dict]:
    rows = []
    try:
        folders = sorted(p for p in runs_root(case).iterdir() if p.is_dir())
    except OSError:
        return rows
    for folder in folders:
        try:
            d = load_run(case, folder.name)
            rows.append({"run_id": d["run_id"],
                         "created_at": d.get("created_at", ""),
                         "input": (d.get("original") or {}).get("name", ""),
                         "issues": len(d.get("issues") or []),
                         "best": d.get("best", ""),
                         "ran": [r["option"] for r in d.get("results") or []
                                 if not r.get("error")],
                         "measured_best": d.get("measured_best", ""),
                         "error": ""})
        except MediaError as exc:
            rows.append({"run_id": folder.name, "created_at": "", "input": "",
                         "issues": 0, "best": "", "ran": [],
                         "measured_best": "", "error": str(exc)})
    rows.sort(key=lambda r: r["created_at"], reverse=True)
    return rows


def _choose(report: dict, which) -> list[dict]:
    opts = {o["id"]: o for o in report["options"]}
    if which in (None, "", "best"):
        best = report.get("best")
        if not best:
            raise MediaError("Nothing the analysis measured needs fixing, so "
                             "no option is recommended. Choose an option to "
                             "run it anyway.")
        return [opts[best]]
    if which == "all":
        return list(report["options"])
    chosen = []
    for oid in which:
        if oid not in opts:
            raise MediaError(f"{oid!r} is not one of this analysis's options "
                             f"({', '.join(opts)}).")
        chosen.append(opts[oid])
    return chosen


def run(case, run_id: str, which="best", *, ffmpeg, models_root, python=None,
        worker=None, scratch, device: str = "auto", force: bool = False,
        deepfilter=None, rnnoise_model=None, progress=None, heartbeat=None,
        should_cancel=None) -> dict:
    """Run restoration options from an analysis: "best", "all", or a list
    of option ids. Each lands in its own folder with its residual and a
    sidecar; a failing option is recorded and the others still run.
    `deepfilter`: deep-filter.exe (or an argv prefix, as the suite drives
    a fake); `rnnoise_model`: the RNNoise model file (sh.rnnn)."""
    say = progress or (lambda _l: None)
    report = load_run(case, run_id)
    run_dir = Path(report["folder"])
    chosen = _choose(report, which)
    need = sorted({s["model"] for o in chosen for s in o["steps"]
                   if s.get("model")})
    gone = models_missing(models_root, need) if need else {}
    if gone and not worker:
        raise MediaError("The restoration models are not all installed: "
                         + "; ".join(f"{MODELS[k]['folder']} lacks "
                                     f"{', '.join(v)}" for k, v in gone.items())
                         + ". " + INSTALL_HINT)
    _vp.require_ffmpeg(ffmpeg)
    _worker_argv(python, worker)
    recipe = _recipe.load_recipe(run_dir)
    done = {r["option"]: r for r in report.get("results") or []
            if not r.get("error")}
    results = [r for r in report.get("results") or []
               if r["option"] not in {o["id"] for o in chosen}]
    working = run_dir / report.get("working", "analysis.wav")
    w_sha = hashing.hash_case_file(working).sha256
    upstream_tier = report.get("upstream_tier", "")
    for n, opt in enumerate(chosen, 1):
        if opt["id"] in done and not force:
            say(f"{opt['label']}: already run — kept.")
            results.append(done[opt["id"]])
            continue
        if _cancelled(should_cancel):
            raise Cancelled("the restoration was stopped")
        say(f"Option {n} of {len(chosen)}: {opt['label']}…")
        try:
            results.append(_run_option(
                case, run_dir, recipe, opt, working, w_sha,
                upstream_tier, report, ffmpeg=ffmpeg, models_root=models_root,
                python=python, worker=worker, scratch=scratch, device=device,
                force=force, say=say, heartbeat=heartbeat,
                should_cancel=should_cancel, deepfilter=deepfilter,
                rnnoise_model=rnnoise_model))
        except Cancelled:
            raise
        except Exception as exc:                          # noqa: BLE001
            case.custody.record(
                "media.restore.failed", actor=case.actor(), target=run_id,
                detail={"run_id": run_id, "option": opt["id"],
                        "error": str(exc)})
            results.append({"option": opt["id"], "label": opt["label"],
                            "tier": opt["tier"], "outputs": [],
                            "error": str(exc)})
            say(f"{opt['label']} failed: {exc}")
    order = {o["id"]: i for i, o in enumerate(report["options"])}
    results.sort(key=lambda r: order.get(r["option"], 99))
    report["results"] = results
    report["measured_best"] = measured_best(results, report["analysis"])
    for r in results:
        r["measured_score"] = measured_score(r, report["analysis"])
    recipe["state"] = "restored"
    tiers = [o["tier"] for o in recipe["outputs"]]
    recipe["tier"] = _recipe.highest_tier(tiers) if tiers else ""
    _case.write_json_atomic(case.root, run_dir / _recipe.RECIPE_FILE, recipe)
    stripped = {k: v for k, v in report.items() if k != "folder"}
    _case.write_json_atomic(case.root, run_dir / "analysis.json", stripped)
    best = report["measured_best"]
    if best:
        label = next((r["label"] for r in results if r["option"] == best), best)
        say(f"Done. Measured best: {label} — listen to every output; the "
            "measurement points the ear, it does not decide.")
    return load_run(case, run_id)


def _cancelled(should_cancel) -> bool:
    return bool(should_cancel is not None and should_cancel())


def _file_sha(path) -> str:
    """SHA-256 of a tool's own file (a model, an executable) outside the
    case — read only."""
    with open(path, "rb") as fh:
        return hashing.hash_stream(fh)[0].sha256


def arnndn_filter(model) -> str:
    """FFmpeg's arnndn with the model at `model`, quoted for the filter
    graph: forward slashes, the drive colon escaped, the whole value in
    single quotes (spaces, commas and brackets are safe inside them; a
    single quote is not, and such a path is refused)."""
    if not model:
        raise MediaError("The RNNoise model was not given. " + INSTALL_HINT)
    path = Path(model)
    if not path.is_file():
        raise MediaError(f"The RNNoise model is not at {path}. "
                         + INSTALL_HINT)
    text = os.fspath(path).replace("\\", "/")
    if "'" in text:
        raise MediaError(f"The RNNoise model's path holds a quote, which "
                         f"FFmpeg's filter syntax cannot carry: {text}")
    text = text.replace(":", "\\:")
    return f"arnndn=m='{text}':mix={RNNOISE_MIX:g}"


def deepfilter_argv(deepfilter) -> list[str]:
    if isinstance(deepfilter, (list, tuple)) and deepfilter:
        return [os.fspath(a) for a in deepfilter]
    if not deepfilter or not Path(deepfilter).is_file():
        raise MediaError(f"DeepFilterNet's deep-filter.exe is not at "
                         f"{deepfilter or '(not given)'}. " + INSTALL_HINT)
    return [os.fspath(deepfilter)]


def _deepfilter(case, run_dir: Path, folder_name: str, rel: Path, n: int,
                s: dict, current, current_rel: str, current_sha: str,
                recipe: dict, chain: list, deepfilter, *, log, scratch,
                duration: float, say, label: str, heartbeat,
                should_cancel) -> tuple:
    """DeepFilterNet 3 over `current`: deep-filter.exe as its own process,
    told to write one file into a fresh folder of the option (it names its
    output after its input), declared before it starts like every child's
    writes. It works at 48 kHz and writes 16-bit PCM at the input's rate,
    its delay put back (-D). (path, relative path, sha256) of its output."""
    argv = deepfilter_argv(deepfilter)
    exe_sha = _file_sha(argv[-1])
    out_dir = _case.make_case_dirs(case.root, RESTORE_DIR, run_dir.name,
                                   folder_name, f"dfn{n}")
    produced = out_dir / Path(current).name
    args = ["-a", str(DFN_ATTEN_DB), "-D", "-o", os.fspath(out_dir)]
    say(f"{label}: {s['label']} (on the CPU)…")
    log_path = getattr(log, "name", None)

    def beat(elapsed):
        if heartbeat is not None:
            heartbeat(f"DeepFilterNet: running {_sam.clock(elapsed)} · "
                      f"{_sam.last_line(log_path) or 'nothing printed yet'}")

    outcome = _sam.run_process(
        argv + args + [os.fspath(current)], log=log,
        timeout_s=1800.0 + 3.0 * duration, writes=[produced],
        guard=lambda p: blocker.assert_case_path(case.root, p),
        should_cancel=should_cancel,
        env=_sam.child_env(_vp.make_scratch(scratch)),
        heartbeat=beat if heartbeat else None)
    if outcome["state"] == "cancelled":
        raise Cancelled("stopped while DeepFilterNet ran")
    if outcome["state"] != "completed" or not produced.is_file():
        why = {"timeout": "it ran past its time"}.get(
            outcome["state"], _sam.exit_sentence(outcome["returncode"]))
        raise MediaError(f"DeepFilterNet did not finish ({why}): "
                         f"{_sam.log_tail(log_path) or outcome.get('error')}"
                         f" — log {log_path}.")
    sha = hashing.hash_case_file(produced).sha256
    out_rel = (rel / out_dir.name / produced.name).as_posix()
    recipe["steps"].append(_recipe.step(
        DFN_TOOL, tier="inferred",
        version=DFN_BUILDS.get(exe_sha, "unrecorded build"),
        params=dict(s.get("params") or {}, args=args[:3],
                    label=s["label"]),
        model={"name": "DeepFilterNet3 (built into deep-filter)",
               "repo": "Rikorose/DeepFilterNet",
               "licence": "MIT OR Apache-2.0", "exe_sha256": exe_sha},
        inputs={current_rel: current_sha}, outputs={out_rel: sha},
        note=s["why"]))
    chain.append(len(recipe["steps"]) - 1)
    return produced, out_rel, sha


def _run_option(case, run_dir: Path, recipe: dict, opt: dict, working,
                w_sha: str, upstream_tier: str, report: dict, *, ffmpeg,
                models_root, python, worker, scratch, device, force, say,
                heartbeat, should_cancel, deepfilter=None,
                rnnoise_model=None) -> dict:
    """One option: its chain from the working copy (analysis.wav, or the
    combined channels), aligned to and subtracted from its reference — or,
    for a band moved into hearing, cut to its length with no residual."""
    working_rel = Path(working).name
    duration = float(report["analysis"].get("duration_s", 0.0) or 0.0)
    work_rate = int(report["analysis"].get("rate") or 0) or None
    moved = bool(opt.get("shift"))
    copy = None
    folder_name = f"opt-{opt['id']}"
    if force and (run_dir / folder_name).exists():
        folder_name = f"opt-{opt['id']}-{_vp._new_id('x')[2:]}"
    folder = _case.make_case_dirs(case.root, RESTORE_DIR, run_dir.name,
                                  folder_name)
    rel = Path(folder_name)
    with _lab._case_log(case, folder / "restore.log") as log:
        current, current_rel, current_sha = working, working_rel, w_sha
        chain = list(report.get("working_chain") or [0, 1])
        rate16 = False
        pending: list[dict] = []
        outputs = []
        n = 0

        def filters_of(s):
            return [arnndn_filter(rnnoise_model)] if s["kind"] == "rnnoise" \
                else s["filters"]

        def flush_filters():
            nonlocal current, current_rel, current_sha, n
            if not pending:
                return
            n += 1
            out = folder / f"step{n}.wav"
            filters = [f for s in pending for f in filters_of(s)]
            to16 = any(s["kind"] == "to16k" for s in pending)
            # arnndn works at 48 kHz (FFmpeg converts into it); its output
            # goes back to the recording's own rate
            back = any(s["kind"] == "rnnoise" for s in pending)
            _ffmpeg(ffmpeg, [current], out,
                    filters=[f for f in filters if not f.startswith(
                        "aresample")],
                    rate=16000 if to16 else work_rate if back else None,
                    log=log, case=case, should_cancel=should_cancel)
            sha = hashing.hash_case_file(out).sha256
            for s in pending:
                model = {}
                if s["kind"] == "rnnoise":
                    msha = _file_sha(rnnoise_model)
                    model = {"file": Path(rnnoise_model).name,
                             "sha256": msha,
                             "pinned": msha == RNNOISE_SHA256,
                             "source": "GregorR/rnnoise-models "
                                       "somnolent-hogwash-2018-09-01",
                             "licence": "not subject to copyright "
                                        "(rnnoise-models README)"}
                recipe["steps"].append(_recipe.step(
                    s.get("tool", "ffmpeg"), tier=s["tier"],
                    version=_tool_version(ffmpeg),
                    params={"filters": filters_of(s), "label": s["label"]}
                    | ({"rate": work_rate} if s["kind"] == "rnnoise" else {}),
                    model=model, inputs={current_rel: current_sha},
                    outputs={(rel / out.name).as_posix(): sha},
                    note=s["why"]))
                chain.append(len(recipe["steps"]) - 1)
            current, current_rel, current_sha = out, (rel / out.name
                                                      ).as_posix(), sha
            pending.clear()

        model_outputs = None
        for s in opt["steps"]:
            if s["kind"].startswith("model:"):
                flush_filters()
                rate16 = True
                spec = MODELS[s["model"]]
                names = [folder / f"{stem}.model.wav" for stem in
                         spec["outputs"]]
                say(f"{opt['label']}: {spec['label']} on the GPU when there "
                    "is one…")
                data = _call_worker(
                    {"op": "model", "model": s["model"],
                     "model_dir": os.fspath(Path(models_root)
                                            / spec["folder"]),
                     "device": device, "input": os.fspath(current),
                     "outputs": [os.fspath(p) for p in names]},
                    folder, "model", case=case, python=python, worker=worker,
                    scratch=scratch, log=log, writes=names,
                    should_cancel=should_cancel, heartbeat=heartbeat,
                    timeout_s=1800.0 + 20.0 * report["analysis"].get(
                        "duration_s", 0.0))
                shas = {p.name: hashing.hash_case_file(p).sha256
                        for p in names}
                recipe["steps"].append(_recipe.step(
                    spec["tool"], tier="inferred",
                    version=f"speechbrain {data.get('speechbrain', '')}, "
                            f"torch {data.get('torch', '')}",
                    params={"device": data.get("device", ""),
                            "gpu": data.get("gpu", ""),
                            "chunks_s": None, "label": s["label"]},
                    model={"repo": spec["repo"], "licence": spec["licence"],
                           "folder": spec["folder"]},
                    inputs={current_rel: current_sha},
                    outputs={(rel / k).as_posix(): v for k, v in shas.items()},
                    note="each chunk rescaled to the input by least squares"))
                chain.append(len(recipe["steps"]) - 1)
                model_outputs = names
                report.setdefault("devices", {})[opt["id"]] = \
                    data.get("device", "")
            elif s["kind"] == "deepfilter":
                flush_filters()
                n += 1
                current, current_rel, current_sha = _deepfilter(
                    case, run_dir, folder_name, rel, n, s, current,
                    current_rel, current_sha, recipe, chain, deepfilter,
                    log=log, scratch=scratch, duration=duration, say=say,
                    label=opt["label"], heartbeat=heartbeat,
                    should_cancel=should_cancel)
            elif s["kind"].startswith("dsp:"):
                flush_filters()
                n += 1
                out = folder / f"step{n}.wav"
                writes = [out]
                params = dict(s.get("params") or {})
                if params.get("copy"):
                    copy_path = folder / f"step{n}.copy.wav"
                    params["copy"] = dict(params["copy"],
                                          output=os.fspath(copy_path))
                    writes.append(copy_path)
                say(f"{opt['label']}: {s['label']}…")
                data = _call_worker(
                    dict({"op": "dsp", "dsp": s["dsp"],
                          "input": os.fspath(current),
                          "output": os.fspath(out)}, **params),
                    folder, f"dsp{n}", case=case, python=python, worker=worker,
                    scratch=scratch, log=log, writes=writes,
                    should_cancel=should_cancel, heartbeat=heartbeat,
                    timeout_s=900.0 + 3.0 * duration)
                sha = hashing.hash_case_file(out).sha256
                outs = {(rel / out.name).as_posix(): sha}
                if len(writes) > 1 and writes[1].is_file():
                    copy = {"path": writes[1],
                            "sha256": hashing.hash_case_file(writes[1]).sha256,
                            "info": (data.get("info") or {}).get("copy") or {}}
                    outs[(rel / writes[1].name).as_posix()] = copy["sha256"]
                recipe["steps"].append(_recipe.step(
                    s["tool"], tier=s["tier"],
                    params=dict(s.get("params") or {}, label=s["label"],
                                measured=data.get("info") or {}),
                    inputs={current_rel: current_sha},
                    outputs=outs, note=s["why"]))
                chain.append(len(recipe["steps"]) - 1)
                if copy is not None and "chain" not in copy:
                    copy["chain"] = list(chain)
                current, current_rel, current_sha = \
                    out, (rel / out.name).as_posix(), sha
            else:
                pending.append(s)
        # Level is a measured gain applied to each final output; it is kept
        # OUT of the residual, which says what the chain took away.
        level = [s for s in pending if s["kind"] == "gain"]
        pending[:] = [s for s in pending if s["kind"] != "gain"]
        flush_filters()
        if model_outputs is None:
            finals = [(opt["outputs"][0], current, current_sha)]
        else:
            finals = [(stem, path, shas[path.name])
                      for stem, path in zip(opt["outputs"], model_outputs)]
        tier = _recipe.output_tier([recipe["steps"][i] for i in chain],
                                   upstream_tier)
        # the reference every output is aligned to and subtracted from
        reference, ref_rel, ref_chain = working, working_rel, []
        if opt.get("reference") == "best_channel" and \
                (run_dir / "bestch.wav").is_file():
            # combining alone: what it took is the best channel less it
            reference, ref_rel = run_dir / "bestch.wav", "bestch.wav"
        if rate16:
            reference, ref_rel = run_dir / "input16k.wav", "input16k.wav"
            if not reference.is_file():
                _ffmpeg(ffmpeg, [working], reference, rate=16000,
                        log=log, case=case, should_cancel=should_cancel)
            recipe["steps"].append(_recipe.step(
                "ffmpeg", tier="measured", version=_tool_version(ffmpeg),
                params={"args": ["-ar", "16000"], "label": "The input at "
                        "16 kHz, to align to and subtract from"},
                inputs={working_rel: w_sha},
                outputs={"input16k.wav":
                         hashing.hash_case_file(reference).sha256},
                note="resampled only"))
            ref_chain = [len(recipe["steps"]) - 1]
        residual_name = _recipe.output_name("residual", tier)
        # a band moved in frequency is not aligned (it no longer correlates
        # with where it came from — the shift keeps time on its own) and has
        # no residual: the input less a moved band is not what was taken
        residual = None if moved else folder / residual_name
        aligned = [folder / f"{stem}.aligned.wav" for stem, _p, _s in finals]
        say(f"{opt['label']}: " + ("cutting to the input's length…" if moved
                                   else "aligning to the input and measuring "
                                   "what changed…"))
        finished = _call_worker(
            {"op": "finish", "reference": os.fspath(reference),
             "outputs": [os.fspath(p) for _st, p, _sh in finals],
             "aligned": [os.fspath(p) for p in aligned],
             "residual": os.fspath(residual) if residual else None,
             "align": not moved},
            folder, "finish", case=case, python=python, worker=worker,
            scratch=scratch, log=log,
            writes=aligned + ([residual] if residual else []),
            should_cancel=should_cancel, heartbeat=heartbeat,
            timeout_s=900.0 + 2.0 * duration)
        lags = list(finished.get("lags") or [0] * len(finals))
        rate_out = finished.get("rate") or 0
        align_steps = []
        for (stem, src, src_sha), dst, lag in zip(finals, aligned, lags):
            src_rel = current_rel if src == current else \
                working_rel if src == working else (rel / src.name).as_posix()
            recipe["steps"].append(_recipe.step(
                ALIGN_TOOL, tier="measured",
                params={"lag_samples": int(lag), "rate": rate_out,
                        "lag_ms": round(1000.0 * lag / rate_out, 2)
                        if rate_out else None},
                inputs={src_rel: src_sha, ref_rel: ""},
                outputs={(rel / dst.name).as_posix():
                         hashing.hash_case_file(dst).sha256},
                note="cut to the input's length — a moved band keeps time "
                     "by itself" if moved else
                     "shifted back by the measured lag and cut to the input's "
                     "length, so the restored file lines up with the original"))
            align_steps.append(len(recipe["steps"]) - 1)
        for (stem, _src, _sh), dst, a_step in zip(finals, aligned, align_steps):
            name = _recipe.output_name(stem, tier)
            dest = folder / name
            filters = [f for s in level for f in s["filters"]] or ["anull"]
            _ffmpeg(ffmpeg, [dst], dest, filters=filters, log=log, case=case,
                    should_cancel=should_cancel)
            sha = hashing.hash_case_file(dest).sha256
            recipe["steps"].append(_recipe.step(
                "ffmpeg", tier="measured", version=_tool_version(ffmpeg),
                params={"filters": filters,
                        "label": level[0]["label"] if level else
                        "Copied to its labelled name"},
                inputs={(rel / dst.name).as_posix():
                        hashing.hash_case_file(dst).sha256},
                outputs={(rel / name).as_posix(): sha},
                note=level[0]["why"] if level else "no change to the samples"))
            outputs.append((stem, dest, sha,
                            chain + [a_step, len(recipe["steps"]) - 1], dst))
        if copy is not None and opt.get("copy_stem"):
            # the slowed (or sped-up) copy, under its labelled name, at its
            # own rate — the same samples, nothing else done to them
            name = _recipe.output_name(opt["copy_stem"], tier)
            dest = folder / name
            _ffmpeg(ffmpeg, [copy["path"]], dest, filters=["anull"], log=log,
                    case=case, should_cancel=should_cancel)
            sha = hashing.hash_case_file(dest).sha256
            info = copy.get("info") or {}
            recipe["steps"].append(_recipe.step(
                "ffmpeg", tier="measured", version=_tool_version(ffmpeg),
                params={"filters": ["anull"],
                        "label": "Copied to its labelled name"},
                inputs={(rel / copy["path"].name).as_posix(): copy["sha256"]},
                outputs={(rel / name).as_posix(): sha},
                note=("the band played {f:g}x {how}, heard at {lo:.0f}-{hi:.0f}"
                      " Hz").format(f=info.get("factor") or 0,
                                    how="slower" if info.get("kind") ==
                                    "expand" else "faster",
                                    lo=(info.get("heard_hz") or [0, 0])[0],
                                    hi=(info.get("heard_hz") or [0, 0])[1])))
            outputs.append((opt["copy_stem"], dest, sha,
                            copy["chain"] + [len(recipe["steps"]) - 1],
                            copy["path"]))
        residual_chain = chain + ref_chain + align_steps
        res_sha = hashing.hash_case_file(residual).sha256 if residual else ""
    entries = []
    for stem, path, sha, own, _src in outputs:
        entry = {"file": (rel / path.name).as_posix(), "sha256": sha,
                 "stem": stem, "seed": None, "tier": tier, "chain": own,
                 "size": os.path.getsize(path),
                 "sidecar": _recipe.sidecar_path(path.name).name,
                 "log": (rel / "restore.log").as_posix()}
        recipe["outputs"].append(entry)
        _write_sidecar(case, path, entry, recipe, upstream_tier)
        entries.append({"stem": stem, "file": entry["file"], "sha256": sha,
                        "tier": tier})
    res_entry = None
    if residual is not None:
        res_entry = {"file": (rel / residual_name).as_posix(),
                     "sha256": res_sha, "stem": "residual", "seed": None,
                     "tier": tier, "chain": residual_chain,
                     "size": os.path.getsize(residual),
                     "sidecar": _recipe.sidecar_path(residual_name).name,
                     "log": (rel / "restore.log").as_posix()}
        recipe["outputs"].append(res_entry)
        _write_sidecar(case, residual, res_entry, recipe, upstream_tier)
    change = finished.get("change") or {}
    result = {"option": opt["id"], "label": opt["label"], "tier": tier,
              "outputs": entries,
              "residual": {"file": res_entry["file"], "sha256": res_sha}
              if res_entry else None,
              "measured": {"removed": {k: change.get(k) for k in
                                       ("during_speech_db",
                                        "during_pauses_db")},
                           "added": {"speech_db":
                                     change.get("added_speech_db"),
                                     "pauses_db":
                                     change.get("added_pauses_db")},
                           "lags": lags, "rate": rate_out,
                           "outputs": finished.get("outputs") or []},
              "device": (report.get("devices") or {}).get(opt["id"], ""),
              "error": ""}
    if copy is not None and copy.get("info"):
        result["copy"] = dict(copy["info"], stem=opt.get("copy_stem", ""))
    if opt.get("speech_only"):
        result["speech_only"] = True
    case.custody.record(
        "media.restore.derived", actor=case.actor(), target=run_dir.name,
        hashes={e["file"]: e["sha256"] for e in entries} | (
            {res_entry["file"]: res_sha} if res_entry else {}),
        detail={"run_id": run_dir.name, "option": opt["id"], "tier": tier,
                "steps": [recipe["steps"][i]["tool"] for i in chain],
                "outputs": [e["file"] for e in entries],
                "folder": os.fspath(folder)})
    return result


def _write_sidecar(case, path: Path, entry: dict, recipe: dict,
                   upstream_tier: str) -> None:
    data = _recipe.sidecar(
        recipe_id=recipe["recipe_id"], file=path.name, sha256=entry["sha256"],
        stem=entry["stem"], chain=[recipe["steps"][i] for i in entry["chain"]],
        input_sha256=recipe["input_sha256"], original=recipe["original"],
        upstream_tier=upstream_tier, written_at=utc_now())
    data["recipe"] = "../" + _recipe.RECIPE_FILE
    _case.write_json_atomic(case.root, _recipe.sidecar_path(path), data)


def export(case, run_id: str, file: str) -> dict:
    """Copy one output (and its sidecar) to `<case>/exports/restoration/
    <run-id>/`, with a custody record. Exporting the same file again returns
    the copy already there."""
    report = load_run(case, run_id)
    folder = Path(report["folder"])
    rel = Path(str(file))
    if rel.is_absolute() or ".." in rel.parts:
        raise MediaError(f"{file!r} is not a file of this restoration.")
    known = {o["file"] for r in report.get("results") or []
             for o in r.get("outputs") or []} | {
        r["residual"]["file"] for r in report.get("results") or []
        if r.get("residual")} | faint_files(report)
    if rel.as_posix() not in known:
        raise MediaError(f"{file!r} is not an output of restoration {run_id}.")
    src = folder / rel
    dest_dir = Path(case.root).joinpath(*EXPORT_DIR, run_id)
    name = f"{rel.parent.name}-{rel.name}" if rel.parent.name else rel.name
    dest = dest_dir / name
    src_sha = hashing.hash_case_file(src).sha256
    if dest.is_file():
        if hashing.hash_case_file(dest).sha256 == src_sha:
            return {"path": os.fspath(dest), "sha256": src_sha,
                    "already": True}
        raise MediaError(f"{dest} exists and differs from {file}; it was not "
                         "overwritten.")
    copied = _extract.copy_within_case(case, src, dest)
    side = _recipe.sidecar_path(src)
    if side.is_file():
        _extract.copy_within_case(case, side, _recipe.sidecar_path(dest))
    case.custody.record(
        "media.restore.exported", actor=case.actor(), target=run_id,
        hashes={name: copied.sha256},
        detail={"run_id": run_id, "file": rel.as_posix(),
                "to": os.fspath(dest)})
    return {"path": os.fspath(dest), "sha256": copied.sha256,
            "already": False}


def capability_note() -> str:
    return ("Restoration analyses with restore_worker.py (torch) and runs "
            "FFmpeg filters, SpeechBrain models, DeepFilterNet and RNNoise "
            "(speech only, marked so); every output keeps its tier, residual "
            "and recipe. Faint sounds: channels combined, a salience map "
            "(and a linear one above 12 kHz) with a clip per faint event, "
            "tonal lines, repeats averaged or lifted off. What the file "
            "really holds, and bands out of hearing moved into it.")
