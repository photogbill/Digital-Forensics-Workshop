# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Which weights may run — the model manifest, FORENSICS_PLAN §12.9.

**Before it is trusted (one time):** a parity run of the GGUF against Meta's
official Python on a test clip; then the GGUF's SHA-256 is PINNED here and a
file with any other hash is refused. GGUF is data with no executable
payload, so the risk is wrong weights, not code — a re-quantised or
corrupted file that runs and quietly separates worse.

Three states, and every result names its state in so many words:

    no pin in the folder  ALLOWED, and every result says
                          "weights: unverified (parity not run)" — the normal
                          state until Bill runs the parity check
    hash is a pinned one  "weights: pinned (sha256 …)"
    anything else         REFUSED, before anything runs — once ANY file in
                          the folder is pinned, only pinned BYTES run: an
                          unpinned BF16 beside a pinned Q8_0 is refused, and a
                          pinned file renamed is still the pinned file

**WHERE THE MANIFEST LIVES — beside the weights, `model_manifest.json` in the
model's own folder** (ATK: `models\\sam-audio\\`). Chosen over ATK's data
folder because a pin is a statement about those exact bytes: it travels with
the folder when ATK is copied to another drive or `forensics.sam_model_dir`
points somewhere else, the engine's command line finds it from the model path
alone with no knowledge of ATK's layout, and get_sam.bat downloads into the
same place. It never lives in a case and never in evidence (`assert_manifest_path`).

**Hashing 5 GB is slow**, so the hash is cached in the manifest by (size,
mtime, file id). A changed file misses the cache and is hashed again; the
pin itself is always taken from a fresh read. The manifest also records the
NEGATIVE CONTROL (§12.12) per model file and hash, so a surface can say
"not yet negative-control tested" until it has been run.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from .. import blocker, hashing
from ..errors import MediaError
from ..timeutil import utc_now

MANIFEST_NAME = "model_manifest.json"
SCHEMA = 1
UNVERIFIED = "weights: unverified (parity not run)"
NOT_TESTED = "not yet negative-control tested"


def manifest_path(model) -> Path:
    """The manifest beside `model` — derived, never chosen, so nothing can
    point the writer at an arbitrary file."""
    return Path(os.path.abspath(os.fspath(model))).with_name(MANIFEST_NAME)


def assert_manifest_path(model, target) -> Path:
    """The run-time half of the ratchet for the manifest writer: the target
    is exactly the manifest beside `model`, and not inside a case."""
    expected = manifest_path(model)
    if os.path.normcase(os.path.abspath(os.fspath(target))) != \
            os.path.normcase(os.fspath(expected)):
        raise MediaError(f"Refusing to write {target}: the model manifest is "
                         f"only ever {expected}.")
    for parent in [expected.parent, *expected.parent.parents]:
        if (parent / "case.json").is_file():
            raise MediaError(f"Refusing to write a model manifest inside the "
                             f"case at {parent}; model weights do not belong "
                             "in a case.")
    return expected


def _empty() -> dict:
    return {"schema": SCHEMA, "kind": "forensics_workshop.media.models",
            "about": "Pinned SHA-256 per model file (FORENSICS_PLAN §12.9). "
                     "A file whose hash differs from its pin is refused.",
            "pins": {}, "observed": {}, "negative_control": {}}


def load_manifest(model) -> dict:
    """The manifest, or an empty one. A manifest that exists but cannot be
    read is REFUSED, not treated as empty: an unreadable file must not turn
    a pinned model back into an unpinned one."""
    path = manifest_path(model)
    if not path.is_file():
        return _empty()
    try:
        with blocker.open_evidence(path) as fh:
            data = json.loads(fh.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise MediaError(f"The model manifest {path} cannot be read ({exc}). "
                         "Fix or remove it; the pins in it cannot be "
                         "checked.") from exc
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise MediaError(f"{path} is not a model manifest this engine reads.")
    for key in ("pins", "observed", "negative_control"):
        data.setdefault(key, {})
    return data


def _write_manifest(model, data: dict) -> Path:
    """Write the manifest beside the model, all-or-nothing (temp + rename)."""
    target = assert_manifest_path(model, manifest_path(model))
    temp = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
    payload = (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
               + "\n").encode("utf-8")
    try:
        with open(temp, "xb") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, target)
    except OSError as exc:
        raise MediaError(
            f"The model manifest {target} cannot be written ({exc}). Pins, the "
            "hash cache and negative-control results live there, beside the "
            "weights; make that folder writable.") from exc
    return target


def _identity(model) -> dict:
    st = os.stat(model)
    return {"size": st.st_size, "mtime_ns": st.st_mtime_ns,
            "file_id": int(getattr(st, "st_ino", 0) or 0)}


def model_sha256(model, *, fresh: bool = False,
                 should_cancel=None) -> tuple[str, bool]:
    """(SHA-256 of the model file, whether it came from the cache).

    The cache entry must match size, mtime AND file id; a copied-over or
    re-downloaded file misses it. `fresh=True` always reads the file.
    """
    path = Path(model)
    if not path.is_file():
        raise MediaError(f"The model file {path} does not exist. Run "
                         "get_sam.bat in the ATK folder to download it.")
    name = path.name
    ident = _identity(path)
    data = load_manifest(path)
    seen = data["observed"].get(name)
    if not fresh and seen and all(seen.get(k) == v for k, v in ident.items()):
        return seen["sha256"], True
    digest = hashing.hash_evidence(path, should_cancel=should_cancel).sha256
    data["observed"][name] = dict(ident, sha256=digest, hashed_at=utc_now())
    _write_manifest(path, data)
    return digest, False


def weights_status(model, sha256: str | None = None,
                   should_cancel=None) -> dict:
    """{"state": unverified|pinned|refused, "sentence", "sha256", "pin",
    "pinned"}. Matched by HASH against every pin in the folder."""
    path = Path(model)
    digest = sha256 or model_sha256(path, should_cancel=should_cancel)[0]
    pins = load_manifest(path)["pins"]
    if not pins:
        return {"state": "unverified", "sentence": UNVERIFIED,
                "sha256": digest, "pin": None, "pinned": []}
    named = sorted(pins)
    match = next((n for n in named if pins[n].get("sha256") == digest), None)
    if match is not None:
        pin = pins[match]
        alias = "" if match == path.name else f", pinned as {match}"
        return {"state": "pinned",
                "sentence": f"weights: pinned (sha256 {digest[:16]}…, pinned "
                            f"{pin.get('pinned_at', '')[:10]} by "
                            f"{pin.get('pinned_by', '?')}{alias})",
                "sha256": digest, "pin": pin, "pinned": named}
    return {"state": "refused",
            "sentence": f"weights: REFUSED — {path.name} hashes to "
                        f"{digest[:16]}…, which is not a pinned file (pinned "
                        f"here: {', '.join(named)})",
            "sha256": digest, "pin": pins.get(path.name), "pinned": named}


def check_weights(model, should_cancel=None) -> dict:
    """The status, or MediaError when pins exist and this file's hash is not
    one of them. The first hash of a 5 GB file honours `should_cancel`."""
    status = weights_status(model, should_cancel=should_cancel)
    if status["state"] == "refused":
        raise MediaError(
            f"{Path(model).name} is not a file that was pinned after the "
            f"parity check: its SHA-256 is {status['sha256']}, and the pinned "
            f"files here are {', '.join(status['pinned'])}. Once any model is "
            "pinned, only pinned weights run. Re-download it with get_sam.bat, "
            "or — if this IS a newly checked file — run the parity check and "
            "pin it with media-pin.")
    return status


def pin_model(model, *, by: str, note: str = "",
              replace: bool = False) -> dict:
    """Pin the model's SHA-256 — after the parity check against Meta's Python.

    Always a fresh read of the file. Replacing an existing, different pin
    needs `replace=True`: re-pinning other bytes is a decision, not a
    side effect.
    """
    who = (by or "").strip()
    if not who:
        raise MediaError("A pin says who ran the parity check; name them.")
    path = Path(model)
    digest, _cached = model_sha256(path, fresh=True)
    data = load_manifest(path)
    old = data["pins"].get(path.name)
    if old and old.get("sha256") != digest and not replace:
        raise MediaError(f"{path.name} is already pinned to a different hash "
                         f"({old.get('sha256')}). Pass replace to re-pin it.")
    data["pins"][path.name] = {"sha256": digest, "size": path.stat().st_size,
                               "pinned_at": utc_now(), "pinned_by": who,
                               "note": note.strip(), "replaced": old or None}
    _write_manifest(path, data)
    return {"model": os.fspath(path), "sha256": digest,
            "manifest": os.fspath(manifest_path(path)),
            "pin": data["pins"][path.name]}


def record_negative_control(model, sha256: str, result: dict) -> None:
    """File a negative-control result against this model file and hash."""
    path = Path(model)
    data = load_manifest(path)
    runs = data["negative_control"].setdefault(path.name, [])
    runs.append(dict(result, sha256=sha256))
    _write_manifest(path, data)


def negative_control_status(model, sha256: str) -> dict:
    """{"state": not-run|quiet-on-noise|speaks-on-noise, "sentence"}: the
    latest negative control run against THESE bytes. A run against another
    hash of the same filename does not count."""
    runs = [r for r in load_manifest(model)["negative_control"].get(
        Path(model).name, []) if r.get("sha256") == sha256]
    if not runs:
        return {"state": "not-run", "sentence": NOT_TESTED, "run": None}
    last = runs[-1]
    when = str(last.get("at", ""))[:10]
    if last.get("speaks_on_noise"):
        return {"state": "speaks-on-noise", "run": last,
                "sentence": f"SPEAKS ON NOISE — the negative control on "
                            f"{when} put sound in the target from speech-absent "
                            f"noise (up to {last.get('max_target_db', 0):.0f} "
                            "dBFS); treat every target as possibly invented "
                            "throughout"}
    return {"state": "quiet-on-noise", "run": last,
            "sentence": f"negative control {when}: quiet on noise (energy "
                        "check only — the ASR check is still to come)"}
