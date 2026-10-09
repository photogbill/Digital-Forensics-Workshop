# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Where several seeds of a generative separation disagree — FORENSICS_PLAN §12.9.

audio.cpp's port of SAM Audio has no candidate ranker (Meta's "Judge" is not
ported), so ATK does not pick a winner: it runs several seeds and SHOWS where
they disagree, window by window. Choosing a candidate is the examiner's act.
**Disagreement is a measured warning, agreement is not proof**: two seeds can
agree on a word neither of them heard.

Two measures, and the result always names which one ran:

* **RMS-envelope spread** (standard library). Each seed's target is cut into
  `WINDOW_S` windows; the spread is the loudest seed's level minus the
  quietest seed's, in dB. Crude: two seeds that put DIFFERENT sounds at the
  same level read as agreeing.
* **Band-energy spread** (numpy, when it imports). The same windows, split
  into octave bands by an STFT; the spread is the largest disagreement in any
  band that carries sound. A seed that swapped a voice for a hiss at the same
  loudness shows up here and not in the envelope.

Both also flag **presence**: a window where one seed has sound
(>= `AUDIBLE_DB`) and another is silent (<= `SILENT_DB`) — "one seed has
sound where another is silent", the strongest sign the model is guessing.

The thresholds are presentation choices, not physics, and are reported with
every result: `FLAG_DB` = 6 dB is a doubling of amplitude — well above the
rounding jitter of two runs of one seed, well below the difference between
speech and no speech; -60 dBFS is where a stem is silent for listening, and
-45 dBFS is quiet speech in a normalised recording.
"""

from __future__ import annotations

import importlib
import math

from ..errors import MediaError
from . import wav

WINDOW_S = 0.25
FLAG_DB = 6.0
SILENT_DB = -60.0
AUDIBLE_DB = -45.0

ENVELOPE = "RMS-envelope spread (stdlib)"
BANDS = "band-energy spread (numpy STFT, 2048/512 Hann, octave bands)"

#: Octave band edges in Hz for the numpy measure; the top edge is clipped to
#: the file's Nyquist frequency.
BAND_EDGES = (50, 100, 200, 400, 800, 1600, 3200, 6400, 12800, 24000)


def _numpy():
    """numpy if it imports, else None — reached through importlib, at call
    time, so a bare interpreter imports this module without it and the
    engine's isolation rule (no third-party import statement) still holds."""
    try:
        return importlib.import_module("numpy")
    except ImportError:
        return None


def method_available(method: str = "auto") -> str:
    """Which measure `compare` would run: `bands` when asked for or `auto`
    and numpy is present, else `envelope`."""
    if method == "envelope":
        return "envelope"
    if method in ("auto", "bands"):
        if _numpy() is not None:
            return "bands"
        if method == "bands":
            raise MediaError("The band-energy measure needs numpy, which is "
                             "not installed here; use the envelope measure.")
        return "envelope"
    raise MediaError(f"{method!r} is not a disagreement measure "
                     "(auto, envelope or bands).")


def _envelope_levels(paths: list, window_s: float) -> list[list[float]]:
    return [wav.window_levels(p, window_s)[1] for p in paths]


def _band_levels(paths: list, window_s: float, np) -> tuple[list, list]:
    """(per-seed total levels, per-seed per-window per-band levels) in dB."""
    totals, bands = [], []
    n_fft, hop = 2048, 512
    win = np.hanning(n_fft).astype(np.float64)
    norm = n_fft * float(np.sum(win ** 2)) / 2.0
    for path in paths:
        info, x = wav.read_array(path, np)
        x = x.astype(np.float64)
        per = max(1, int(round(info.rate * window_s)))
        n_win = max(1, math.ceil(len(x) / per))
        edges = [e for e in BAND_EDGES if e < info.rate / 2] + [info.rate / 2]
        freqs = np.fft.rfftfreq(n_fft, 1.0 / info.rate)
        masks = [(freqs >= lo) & (freqs < hi)
                 for lo, hi in zip(edges[:-1], edges[1:])]
        seed_totals, seed_bands = [], []
        for w in range(n_win):
            seg = x[w * per:(w + 1) * per]
            seed_totals.append(wav.to_db(float(np.mean(seg ** 2))
                                         if len(seg) else 0.0))
            # Frames stay INSIDE the window (zero-padded at its own end), so
            # a sound that starts in the next window cannot leak back into
            # this one and widen a span.
            padded = np.concatenate([seg, np.zeros(n_fft)])
            starts = range(0, max(1, len(seg) - n_fft + 1), hop)
            power = np.zeros(len(freqs))
            frames = 0
            for s in starts:
                spec = np.fft.rfft(padded[s:s + n_fft] * win)
                power += np.abs(spec) ** 2
                frames += 1
            power /= max(1, frames) * norm
            seed_bands.append([wav.to_db(float(np.sum(power[m])))
                               for m in masks])
        totals.append(seed_totals)
        bands.append(seed_bands)
    return totals, bands


def _windows(levels: list[list[float]]) -> int:
    return min(len(series) for series in levels) if levels else 0


def spread_series(totals: list[list[float]], seeds: list,
                  band_levels: list | None = None) -> list[dict]:
    """One row per window: the spread in dB, and which seeds were loud and
    which silent when one had sound and another did not."""
    rows = []
    for w in range(_windows(totals)):
        level = [series[w] for series in totals]
        if band_levels is None:
            spread = max(level) - min(level)
        else:
            spread = 0.0
            for b in range(len(band_levels[0][w])):
                vals = [band_levels[s][w][b] for s in range(len(seeds))]
                if max(vals) >= SILENT_DB:      # the band carries something
                    spread = max(spread, max(vals) - max(min(vals),
                                                         wav.FLOOR_DB))
        loud = [seeds[i] for i, v in enumerate(level) if v >= AUDIBLE_DB]
        silent = [seeds[i] for i, v in enumerate(level) if v <= SILENT_DB]
        rows.append({"window": w, "spread_db": round(spread, 2),
                     "presence": bool(loud and silent),
                     "loud": loud, "silent": silent,
                     "levels_db": [round(v, 2) for v in level]})
    return rows


def find_spans(rows: list[dict], window_s: float,
               flag_db: float = FLAG_DB) -> list[dict]:
    """Consecutive flagged windows merged into spans, in seconds."""
    spans: list[dict] = []
    current = None
    for row in rows:
        flagged = row["presence"] or row["spread_db"] >= flag_db
        if not flagged:
            current = None
            continue
        start = round(row["window"] * window_s, 3)
        end = round((row["window"] + 1) * window_s, 3)
        if current is None:
            current = {"start_s": start, "end_s": end,
                       "max_spread_db": row["spread_db"],
                       "kind": "presence" if row["presence"] else "level",
                       "loud": list(row["loud"]), "silent": list(row["silent"])}
            spans.append(current)
            continue
        current["end_s"] = end
        if row["presence"]:
            current["kind"] = "presence"
        if row["spread_db"] > current["max_spread_db"]:
            current["max_spread_db"] = row["spread_db"]
            if row["presence"] or current["kind"] != "presence":
                current["loud"], current["silent"] = (list(row["loud"]),
                                                      list(row["silent"]))
    return spans


def span_sentence(span: dict) -> str:
    """`12.25–13.00 s: seed 2 has sound where seed 1 is silent (up to 31 dB)`."""
    where = f"{span['start_s']:.2f}–{span['end_s']:.2f} s"
    if span["kind"] == "presence":
        loud = ", ".join(str(s) for s in span["loud"])
        silent = ", ".join(str(s) for s in span["silent"])
        return (f"{where}: seed {loud} has sound where seed {silent} is "
                f"silent (up to {span['max_spread_db']:.0f} dB apart)")
    return (f"{where}: the seeds differ by up to "
            f"{span['max_spread_db']:.0f} dB")


def compare(targets: dict, *, window_s: float = WINDOW_S,
            method: str = "auto", flag_db: float = FLAG_DB) -> dict:
    """Compare each seed's target. `targets` maps seed -> WAV path.

    Fewer than two seeds is not an error — it is a run with nothing to
    compare, and the result says so rather than reporting agreement.
    """
    seeds = sorted(targets)
    base = {"window_s": window_s, "seeds": seeds,
            "thresholds": {"flag_db": flag_db, "silent_db": SILENT_DB,
                           "audible_db": AUDIBLE_DB},
            "series": [], "spans": []}
    if len(seeds) < 2:
        return dict(base, method="", compared_s=0.0, notes=[],
                    summary="One seed: nothing to compare. Disagreement needs "
                            "two or more seeds, and a single generative run "
                            "shows no measure of where it is guessing.")
    chosen = method_available(method)
    paths = [targets[s] for s in seeds]
    infos = [wav.read_info(p) for p in paths]
    empty = [s for s, i in zip(seeds, infos) if i.frames == 0]
    if empty:
        raise MediaError(f"Seed(s) {empty} wrote an empty target; an empty "
                         "stem is a broken run, never agreement.")
    notes = []
    if len({i.rate for i in infos}) > 1:
        raise MediaError("The seeds' targets are at different sample rates "
                         f"({sorted({i.rate for i in infos})}); they cannot be "
                         "compared window by window.")
    if len({i.frames for i in infos}) > 1:
        notes.append("the targets differ in length; compared over the "
                     "shortest")
    if chosen == "bands":
        np = _numpy()
        totals, band_levels = _band_levels(paths, window_s, np)
        name = BANDS
    else:
        totals, band_levels = _envelope_levels(paths, window_s), None
        name = ENVELOPE
    rows = spread_series(totals, seeds, band_levels)
    spans = find_spans(rows, window_s, flag_db)
    compared = min(len(rows) * window_s, min(i.duration_s for i in infos))
    flagged = sum(s["end_s"] - s["start_s"] for s in spans)
    summary = (f"{len(seeds)} seeds, {name}: "
               + (f"{len(spans)} span(s) where they disagree, "
                  f"{flagged:.2f} s of {compared:.2f} s."
                  if spans else
                  f"no window disagrees by {flag_db:g} dB or more over "
                  f"{compared:.2f} s — agreement, which is not proof."))
    return dict(base, method=name, compared_s=round(compared, 3), notes=notes,
                series=[{"t": round(r["window"] * window_s, 3),
                         "spread_db": r["spread_db"],
                         "presence": r["presence"]} for r in rows],
                spans=spans, summary=summary)
