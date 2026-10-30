# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""What restoration and voice comparison share: the input, said the way
custody will say it; one read of it through the read-only door; whether it
is itself a derived item; and the few files this lane writes itself.

**SAM AUDIO WAS REMOVED (Bill, 2026-10-29).** This module used to run SAM
Audio, its windows, replay and the negative control. All of that is gone;
what is left here is what `restore.py` and `voiceprint.py` were already
using. A case made before the removal may still hold SAM runs under
`<case>/media/`: nothing here deletes them, and `upstream_of_input` still
reads their recipes, so an INVENTED stem fed back in stays Invented.

**THE ORIGINAL IS NEVER TOUCHED.** It is read once, through
`blocker.open_evidence`, into a hashed working copy inside the case — the
copy and its hash are one read, so what was hashed is what was copied. A
file inside a disk image is reached by recovering it into the case first;
that recovered file is then the input.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .. import blocker, hashing
from .. import extract as _extract
from ..errors import MediaError
from . import proc as _proc
from . import recipe as _recipe

MEDIA_DIR = "media"

COPY_CHUNK = 1 << 20

_FFMPEG_VERSION: dict = {}



def runs_root(case) -> Path:
    return Path(case.root) / MEDIA_DIR



def _tool_version(argv: list[str]) -> str:
    """`ffmpeg -version`'s first line, cached; never raises."""
    key = tuple(argv)
    if key not in _FFMPEG_VERSION:
        _FFMPEG_VERSION[key] = _proc.probe_version(argv, "-version").split(
            " | ")[0]
    return _FFMPEG_VERSION[key]



# ---------------------------------------------------------------------------
# the writers — every file this module itself writes passes through these
# ---------------------------------------------------------------------------

def _case_log(case, path):
    """Open a new log inside the case for a child's stdout and stderr."""
    target = blocker.assert_case_path(case.root, path)
    return open(target, "xb")



def _harness_dirs(root, name) -> Path:
    target = blocker.assert_harness_path(root, Path(root) / name)
    target.mkdir(parents=True, exist_ok=True)
    return target



def _harness_log(root, path):
    return open(blocker.assert_harness_path(root, path), "xb")



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
    # Restoration runs (restore.py) and any earlier SAM runs still in an
    # older case keep the same recipe format, so both are searched.
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
