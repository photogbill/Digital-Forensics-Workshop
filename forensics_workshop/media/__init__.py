# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Media recovery — FORENSICS_PLAN.md §12: faint voices, the person in the
background, before the cut. Built 2026-10-05 as far as SAM Audio needs it.

    recipe.py         the five trust tiers, recipes and their sidecars (§12.2–3)
    wav.py            a RIFF/WAVE reader that also reads IEEE float
    disagreement.py   where several seeds of a generative run disagree
    separator.py      the prompted-separator interface and time anchors
    sam_audio.py      SAM Audio through audio.cpp's `audiocpp_cli`, a SUBPROCESS
    weights.py        the model manifest: pinned hashes, the negative control
    lab.py            a whole run into a case, replay, and the negative control

**THIS FILE IMPORTS NOTHING**, for the reason the package's own `__init__`
gives: a defect in `sam_audio.py` must surface as a defect in `sam_audio.py`,
with its file and line, and never make the rest of the media spine — or the
engine — look absent.

**Not for court; for leads and lifesaving recovery** (Bill, 2026-09-30). That
loosens most rules and tightens one: an invented syllable must never look
like a recovered one. Every output here carries its tier, every generative
output says `.invented` in its filename, and the residual — what the
separator took away — is always kept beside it.

**Standard library only in a bare interpreter.** numpy is reached for in one
place (`disagreement._numpy`), through `importlib` at call time, for the finer
of the two disagreement measures; without it the cruder measure runs and the
result names which one did. GPU work never runs in this process: audio.cpp
and FFmpeg are separate processes, so a CUDA fault takes down a child, never
the engine or ATK.
"""
