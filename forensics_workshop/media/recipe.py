# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The five trust tiers, and recipes — FORENSICS_PLAN.md §12.2 and §12.3.

**An invented syllable must never look like a recovered one.** That is the
one hard rule of media recovery, and this module is where it becomes data:

    measured    level, tone and geometry operations     cannot add content
    recovered   more real data combined                 adds REAL information
    cleaned     deterministic non-linear removal        cannot add; can remove
    inferred    discriminative / mask models            rarely adds
    invented    generative models (SAM Audio)           CAN ADD what never was

**An output carries the highest tier of any step in its recipe**
(`highest_tier`): one generative step makes the whole chain Invented, and a
later faithful step cannot launder it back down.

**A recipe, not a render.** Every derived item is an ordered list of steps —
tool, tool version, model file SHA-256, parameters, seed, region and time
range — plus the SHA-256 of the input and of every output, so it can be run
again against the untouched original and compared. A sidecar
(`<output>.recipe.json`) sits beside every output with the chain that made
it and its tier; the whole run is `recipe.json` in the run's folder.

**Invented output is labelled where a person meets it**: `.invented` in the
filename (`invented_name`), the tier in the sidecar and in the custody note.
A model's own watermark is never relied on: audio.cpp v0.9.0 may watermark
(its SAM session passes a 32-bit message into the decoder), and nothing here
relies on it either way.

**A tier is a property of the TOOL, not of what a file says about itself.**
`TOOL_TIERS` gives each tool the lowest tier its step may claim — SAM is
always Invented — and `check_recipe` refuses a recipe or sidecar whose steps,
outputs or `.invented` filenames disagree with it, so a hand-edited recipe
cannot launder an invented stem into a measured one.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .. import blocker
from ..errors import MediaError

TIERS = ("measured", "recovered", "cleaned", "inferred", "invented")

#: What each tier means to the person who meets the output — the sentence a
#: sidecar carries and a page shows beside the file.
TIER_NOTES = {
    "measured": "simple level, tone or format operations — adds nothing",
    "recovered": "more real observations combined — adds real information "
                 "only",
    "cleaned": "deterministic removal — adds nothing, but can remove real "
               "detail; listen to the residual",
    "inferred": "a discriminative model kept or dropped parts of the input — "
                "rarely adds content",
    "invented": "A GENERATIVE MODEL PRODUCED THIS. It can contain sound that "
                "was never recorded. A lead, never a reading: a word heard "
                "only here is unconfirmed until a faithful method agrees "
                "(FORENSICS_PLAN §12.2).",
}

SCHEMA = 1
RECIPE_FILE = "recipe.json"

#: tool -> the LOWEST tier a step by that tool may carry. A tool not listed
#: is refused: a step nobody registered cannot vouch for its own tier.
TOOL_TIERS = {
    "forensics_workshop read-only door (hashed copy)": "measured",
    "ffmpeg": "measured",
    "audiocpp_cli sam_audio": "invented",
}
#: A generative separator, whatever its name gets spelled as.
_ALWAYS_INVENTED = ("sam_audio", "sam audio")
SIDECAR_SUFFIX = ".recipe.json"


def tier_rank(tier: str) -> int:
    """0 for measured … 4 for invented. An unknown tier is refused, because
    a tier nobody defined cannot be compared and must not pass as low."""
    try:
        return TIERS.index(tier)
    except ValueError:
        raise MediaError(f"{tier!r} is not a trust tier; the tiers are "
                         f"{', '.join(TIERS)}.") from None


def highest_tier(tiers) -> str:
    """The tier an output carries: the highest of every step behind it."""
    found = [t for t in tiers if t]
    if not found:
        raise MediaError("A recipe with no steps has no tier.")
    return max(found, key=tier_rank)


def invented_name(stem: str, seed: int) -> str:
    """`seed2.target.invented.wav` — the label is in the NAME, so a file
    copied out of the case and played anywhere still says what it is."""
    return f"seed{int(seed)}.{stem}.invented.wav"


def output_name(stem: str, tier: str, seed: int | None = None) -> str:
    """The filename for an output of `tier`. Invented output always gets
    `.invented`; nothing else may (a faithful file that said `.invented`
    would teach the eye to skip the label)."""
    tier_rank(tier)
    if tier == "invented":
        if seed is None:
            return f"{stem}.invented.wav"
        return invented_name(stem, seed)
    base = stem if seed is None else f"seed{int(seed)}.{stem}"
    return f"{base}.wav"


def sidecar_path(output) -> Path:
    """`seed2.target.invented.wav` -> `seed2.target.invented.wav.recipe.json`."""
    p = Path(output)
    return p.with_name(p.name + SIDECAR_SUFFIX)


def tool_floor(tool: str) -> str:
    """The lowest tier `tool` may claim — or MediaError for an unknown tool."""
    name = str(tool or "")
    if any(mark in name.lower() for mark in _ALWAYS_INVENTED):
        return "invented"
    if name not in TOOL_TIERS:
        raise MediaError(f"{name!r} is not a registered media tool, so its "
                         "step cannot vouch for its tier.")
    return TOOL_TIERS[name]


def check_step(entry: dict) -> None:
    """A step's tier is at least its tool's floor."""
    floor = tool_floor(entry.get("tool", ""))
    if tier_rank(entry.get("tier", "")) < tier_rank(floor):
        raise MediaError(f"A {entry.get('tool')} step is recorded as "
                         f"{entry.get('tier')!r}; that tool is never below "
                         f"{floor!r}. A tier is never lowered.")


def step(tool: str, *, tier: str, version: str = "", params: dict | None = None,
         seed: int | None = None, model: dict | None = None,
         time_range: list | None = None, region=None, inputs: dict | None = None,
         outputs: dict | None = None, note: str = "") -> dict:
    """One step of a recipe, every field present even when empty, so two
    recipes can be compared key by key. Its tier is held to its tool's."""
    tier_rank(tier)
    check_step({"tool": tool, "tier": tier})
    return {"tool": tool, "version": version, "tier": tier,
            "params": dict(params or {}), "seed": seed,
            "model": dict(model or {}), "time_range": time_range,
            "region": region, "inputs": dict(inputs or {}),
            "outputs": dict(outputs or {}), "note": note}


def output_tier(chain: list[dict], upstream_tier: str = "") -> str:
    """The tier of an output made by `chain` from an input of
    `upstream_tier` (an input that is itself a derived item keeps its tier)."""
    return highest_tier([upstream_tier] + [s.get("tier", "") for s in chain])


def sidecar(*, recipe_id: str, file: str, sha256: str, stem: str,
            chain: list[dict], input_sha256: str, original: dict,
            upstream_tier: str = "", seed: int | None = None,
            written_at: str = "") -> dict:
    """What sits beside one output: its tier, the chain that made it, and
    where the whole run's recipe is."""
    tier = output_tier(chain, upstream_tier)
    return {"schema": SCHEMA, "kind": "forensics_workshop.media.sidecar",
            "recipe_id": recipe_id, "file": file, "sha256": sha256,
            "stem": stem, "seed": seed, "tier": tier,
            "tier_note": TIER_NOTES[tier], "chain": chain,
            "input_sha256": input_sha256, "original": dict(original),
            "upstream_tier": upstream_tier, "recipe": RECIPE_FILE,
            "written_at": written_at}


def check_recipe(data: dict) -> dict:
    """A recipe read back is held to the shape it was written in — and to
    the tier rule, so a hand-edited recipe that lowered a tier is refused."""
    if not isinstance(data, dict) or data.get("kind") != \
            "forensics_workshop.media.recipe":
        raise MediaError("This is not a media recipe written by this engine.")
    if data.get("schema") != SCHEMA:
        raise MediaError(f"Recipe schema {data.get('schema')} is not one this "
                         f"engine reads (schema {SCHEMA}).")
    for key in ("recipe_id", "input_sha256", "steps", "outputs", "original"):
        if key not in data:
            raise MediaError(f"The recipe has no {key!r}; it cannot be "
                             "replayed.")
    steps = data["steps"]
    if not isinstance(steps, list):
        raise MediaError("The recipe's steps are not a list.")
    for entry in steps:
        check_step(entry)
    for out in data["outputs"]:
        index = out.get("chain", [])
        if not all(isinstance(i, int) and 0 <= i < len(steps) for i in index):
            raise MediaError(f"{out.get('file')} names steps that are not in "
                             "the recipe; it has been edited.")
        check_output(out.get("file", ""), out.get("tier", ""),
                     [steps[i] for i in index], data.get("upstream_tier", ""))
    tiers = [o.get("tier", "") for o in data["outputs"]]
    if data.get("tier") and tiers and data["tier"] != highest_tier(tiers):
        raise MediaError(f"The recipe says its tier is {data['tier']!r} but "
                         f"its outputs make it {highest_tier(tiers)!r}.")
    return data


def check_output(file: str, tier: str, chain: list[dict],
                 upstream_tier: str = "") -> None:
    """One output's recorded tier against the steps behind it — and against
    its own name: a file called `.invented` is Invented, whatever it says."""
    expected = output_tier(chain, upstream_tier) if chain else (
        upstream_tier or "")
    if ".invented." in str(file).lower():
        expected = "invented"
    if expected and tier != expected:
        raise MediaError(
            f"{file} is recorded as {tier!r} but the steps behind it (and its "
            f"name) make it {expected!r}. A tier is never lowered; this "
            "recipe has been edited.")


def check_sidecar(data: dict, file_name: str) -> dict:
    """A sidecar read back, held to the same rules as a recipe."""
    if not isinstance(data, dict) or data.get("kind") != \
            "forensics_workshop.media.sidecar":
        raise MediaError(f"The sidecar beside {file_name} is not one this "
                         "engine wrote.")
    chain = data.get("chain") or []
    for entry in chain:
        check_step(entry)
    check_output(file_name, data.get("tier", ""), chain,
                 data.get("upstream_tier", ""))
    tier_rank(data.get("tier", ""))
    return data


def load_recipe(path) -> dict:
    """Read a recipe (or the folder holding one) through the read-only door."""
    p = Path(path)
    if p.is_dir():
        p = p / RECIPE_FILE
    try:
        with blocker.open_evidence(os.fspath(p)) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except FileNotFoundError:
        raise MediaError(f"No recipe at {p}.") from None
    except (OSError, ValueError) as exc:
        raise MediaError(f"The recipe at {p} cannot be read: {exc}") from exc
    return check_recipe(data)


def upstream_of(path) -> tuple[str, str]:
    """(recipe id, tier) when `path` is itself a derived item — so running a
    separator on a SAM output keeps it Invented — else ('', '').

    From its sidecar when there is one (held to `check_sidecar`); else from
    its NAME: a file called `….invented.wav` that lost its sidecar is still
    Invented. A renamed one is caught by hash in `lab.upstream_of_input`."""
    side = sidecar_path(path)
    if not side.is_file():
        if ".invented." in Path(path).name.lower():
            return "", "invented"
        return "", ""
    try:
        with blocker.open_evidence(os.fspath(side)) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise MediaError(
            f"{side} sits beside the input but cannot be read ({exc}). It may "
            "say the input is invented; refusing rather than guessing.") from exc
    check_sidecar(data, Path(path).name)
    tier = data.get("tier", "")
    if ".invented." in Path(path).name.lower():
        tier = "invented"
    return str(data.get("recipe_id", "")), tier
