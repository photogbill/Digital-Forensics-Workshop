# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Media recovery — FORENSICS_PLAN.md §12 and §13: restoration of poor
recordings, faint sounds, and voice comparison.

    recipe.py          the five trust tiers, recipes and their sidecars (§12.2–3)
    wav.py             a RIFF/WAVE reader that also reads IEEE float
    proc.py            running a child process (FFmpeg, the workers) and
                       saying how it ended
    lab.py             the input, one read of it, and the files this lane writes
    restore.py         measure, recommend, run, compare, export (§13.3–13.9)
    restore_worker.py  the restoration worker, its own process
    voiceprint.py      voice comparison through a calibration (§13.1)
    vp_worker.py       the speaker-embedding worker, its own process

**SAM AUDIO WAS REMOVED (Bill, 2026-10-29).** Its adapter, the prompted-
separator interface, the weights manifest and seed disagreement went with
it. A case made before then may still hold SAM runs under `<case>/media/`;
they are left alone and still read back as Invented.

**THIS FILE IMPORTS NOTHING**, for the reason the package's own `__init__`
gives: a defect in one module must surface as a defect in that module, with
its file and line, and never make the rest of the media lane — or the
engine — look absent.

**Not for court; for leads and lifesaving recovery** (Bill, 2026-09-30). That
loosens most rules and tightens one: an invented syllable must never look
like a recovered one. Every output here carries its tier.

**Standard library only in a bare interpreter.** GPU work never runs in this
process: FFmpeg and the workers are separate processes, so a CUDA fault
takes down a child, never the engine or ATK.
"""
