# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The prompted-separator interface — so SAM is one adapter, not a dependency.

FORENSICS_PLAN §12.9: SAM Audio sits behind ONE adapter implementing a
generic *prompted separator*, so that ClearerVoice's AV-TSE (Apache-2.0, the
faithful-lane twin) can implement the same interface later — and so removing
SAM, should ATK ever go to defense-related work (the SAM License's trigger),
removes one adapter, one manifest entry and one capability row, and nothing
else.

A prompted separator takes one WAV and a prompt — words, time anchors, or
both — and returns two stems: the TARGET (what was asked for) and the
RESIDUAL (everything it took away). The residual is not optional: it is
§12.2's removed-sound stem, and hearing words in it is how an examiner learns
the separator ate speech.

    separate(input_wav, *, text=None, anchors=(), seed, out_dir, log, guard,
             should_cancel=None, **options)
        -> {"target": path, "residual": path, "argv": [...], "returncode": 0,
            "elapsed_s": 12.3, "tool": "...", "tool_version": "...",
            "params": {...}, "tier": "invented"}

An adapter WRITES NOTHING ITSELF: the separator process writes into
`out_dir`, which the caller has made inside a case (or a harness folder),
and the caller moves and labels what it finds. `guard` is the caller's
case or harness check, applied to `out_dir` before the child starts
(`blocker.assert_child_writes`). That keeps every file this engine writes —
its children's included — behind a function `blocker.WRITERS` names.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..errors import MediaError

INCLUDE, EXCLUDE = "+", "-"

_ANCHOR = re.compile(
    r"^\s*([+-])\s*(\d+(?:\.\d+)?)\s*(?::|\s|,|-|–|to)\s*(\d+(?:\.\d+)?)\s*$")


@dataclass(frozen=True)
class Anchor:
    """A time span in seconds: `+` where the wanted sound is audible (best
    where it is alone or loudest), `-` where the unwanted one is."""

    sign: str
    start: float
    end: float

    def as_list(self) -> list:
        return [self.sign, self.start, self.end]

    def label(self) -> str:
        what = "include" if self.sign == INCLUDE else "exclude"
        return f"{self.sign}{self.start:g}–{self.end:g} s ({what})"


def make_anchor(sign: str, start, end) -> Anchor:
    """One anchor, checked: a sign of + or -, and 0 <= start < end — the
    rule audio.cpp's SAM port enforces, refused here with a sentence instead
    of a failed run."""
    sign = str(sign).strip()
    if sign in ("include", "inc", "plus"):
        sign = INCLUDE
    elif sign in ("exclude", "exc", "minus", "−"):
        sign = EXCLUDE
    if sign not in (INCLUDE, EXCLUDE):
        raise MediaError(f"An anchor is + (include) or - (exclude), not "
                         f"{sign!r}.")
    try:
        a, b = float(start), float(end)
    except (TypeError, ValueError):
        raise MediaError(f"An anchor's start and end are seconds; "
                         f"{start!r} to {end!r} is not.") from None
    if not (math.isfinite(a) and math.isfinite(b)) or a < 0 or b <= a:
        raise MediaError(f"The anchor {sign}{a:g}–{b:g} s is not a span: it "
                         "needs 0 <= start < end.")
    return Anchor(sign, round(a, 4), round(b, 4))


def parse_anchor(text: str) -> Anchor:
    """`+0.5:2.0`, `-3 4`, `+1.25-2` — the command line's spellings."""
    m = _ANCHOR.match(str(text or ""))
    if not m:
        raise MediaError(f"{text!r} is not an anchor. Write it as +START:END "
                         "(include) or -START:END (exclude), in seconds, "
                         "e.g. +0.5:2.0")
    return make_anchor(m.group(1), m.group(2), m.group(3))


def check_anchors(anchors, duration_s: float | None = None) -> tuple:
    """Every anchor valid, and — when the input's length is known — inside it.
    A span past the end of the recording is almost always a typing slip, and
    the model would otherwise be steered by a stretch that does not exist."""
    out = []
    for a in anchors or ():
        anchor = a if isinstance(a, Anchor) else (
            parse_anchor(a) if isinstance(a, str) else make_anchor(*a))
        if duration_s is not None and anchor.start >= duration_s:
            raise MediaError(f"The anchor {anchor.label()} starts after the "
                             f"recording ends ({duration_s:.2f} s).")
        out.append(anchor)
    return tuple(out)


class PromptedSeparator:
    """The interface. An adapter sets `name` and `tier` and implements
    `separate` and `describe`."""

    name = ""
    tier = "invented"

    def describe(self) -> dict:                      # pragma: no cover
        raise NotImplementedError

    def separate(self, input_wav, *, text=None, anchors=(), seed: int,
                 out_dir, log, guard, should_cancel=None, **options) -> dict:
        raise NotImplementedError                    # pragma: no cover
