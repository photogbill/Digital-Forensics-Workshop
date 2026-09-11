# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Copying out of evidence, with the hash taken from the copy's own read.

**Hash on ingest, hash on export.** A copy is made and hashed in ONE read of
the source — every chunk written is a chunk hashed — so the digest describes
exactly the bytes that landed in the case, not a second read that might
have seen something different. The result is compared with the manifest:
a live file that changed since it was ingested says so, rather than being
silently exported as though it had not.

Every copy is exclusive-create. Nothing in a case is overwritten; a second
export of a changed file gets a new name beside the first.

`reason` is keyword-only with no default. A custody record says why a file
left the evidence, and a caller that has not decided why should not be
exporting it.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath

from . import blocker, hashing
from . import manifest as _manifest
from .errors import EvidenceError
from .hashing import Hashes


def safe_relpath(relpath: str) -> PurePosixPath:
    """A manifest path, refused if it could climb out of wherever it is joined."""
    rel = PurePosixPath(str(relpath).replace("\\", "/"))
    unsafe = (not rel.parts or rel.is_absolute() or ".." in rel.parts
              or ":" in rel.parts[0])
    if unsafe:
        raise EvidenceError(f"{relpath!r} is not a safe relative path.")
    return rel


def copy_evidence_to_case(case, source, dest) -> Hashes:
    """Copy one evidence file into the case, hashing what is written."""
    target = blocker.assert_case_path(case.root, dest)
    blocker.refuse_evidence_path(target, case.evidence_roots())
    target.parent.mkdir(parents=True, exist_ok=True)
    with blocker.open_evidence(source) as src, open(target, "xb") as out:
        hashes, _head = hashing.hash_stream(src, sink=out)
        out.flush()
        os.fsync(out.fileno())
    return hashes


def copy_within_case(case, source, dest) -> Hashes:
    """Copy a file the case already holds (a working copy of a working copy)."""
    src = blocker.assert_case_path(case.root, source)
    target = blocker.assert_case_path(case.root, dest)
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as fh, open(target, "xb") as out:
        hashes, _head = hashing.hash_stream(fh, sink=out)
        out.flush()
        os.fsync(out.fileno())
    return hashes


def copy_stream_to_case(case, chunks, dest) -> Hashes:
    """Write bytes read out of evidence (an image's clusters, a carved range)
    into a new file in the case, hashing exactly what is written."""
    target = blocker.assert_case_path(case.root, dest)
    blocker.refuse_evidence_path(target, case.evidence_roots())
    target.parent.mkdir(parents=True, exist_ok=True)
    hasher = hashing.Hasher()
    with open(target, "xb") as out:
        for chunk in chunks:
            hasher.update(chunk)
            out.write(chunk)
        out.flush()
        os.fsync(out.fileno())
    return hasher.result()


def free_name(path: Path) -> Path:
    """`path`, or `name~2.ext`, `name~3.ext` … — the first that does not exist."""
    return _free_name(path)


def _free_name(path: Path) -> Path:
    if not path.exists():
        return path
    n = 2
    while True:
        candidate = path.with_name(f"{path.stem}~{n}{path.suffix}")
        if not candidate.exists():
            return candidate
        n += 1


@dataclass(frozen=True)
class Extracted:
    evidence_id: str
    relpath: str
    dest: str
    hashes: dict
    manifest_sha256: str | None
    matches_manifest: bool | None
    reused: bool

    def as_dict(self) -> dict:
        return asdict(self)


def extract_file(case, evidence_id: str, relpath: str, *, reason: str,
                 folder: str = "files", record: bool = True) -> Extracted:
    """Copy one file out of the evidence into `extracted/<id>/<folder>/…`."""
    if not (reason or "").strip():
        raise EvidenceError("An extraction needs a reason; custody records why.")
    item = case.evidence_item(evidence_id)
    rel = safe_relpath(relpath)
    source = Path(item.source).joinpath(*rel.parts)
    if not blocker.is_inside(source, item.source):
        raise EvidenceError(f"{relpath!r} resolves outside {evidence_id}.")
    if not source.is_file():
        raise EvidenceError(f"{source} is not a file (or is no longer there).")
    row = _manifest.lookup(case, evidence_id, rel.as_posix())
    expected = row["sha256"] if row else None
    dest = case.path("extracted", evidence_id, *PurePosixPath(folder).parts,
                     *rel.parts)
    # Reuse an earlier copy only when the SOURCE still looks as it did at
    # ingest. Comparing the old copy with the manifest alone would hand back
    # yesterday's bytes for a file that has changed since, and say they match.
    st = source.stat()
    source_unchanged = bool(row and row["size"] == st.st_size
                            and row["mtime_ns"] == st.st_mtime_ns)
    if dest.exists() and expected and source_unchanged:
        existing = hashing.hash_case_file(dest)
        if existing.sha256 == expected:
            result = Extracted(evidence_id, rel.as_posix(), os.fspath(dest),
                               existing.as_dict(), expected, True, True)
            if record:
                case.custody.record(
                    "file.extract_reused", actor=case.actor(),
                    target=f"{evidence_id}:{rel.as_posix()}",
                    hashes={"sha256": existing.sha256},
                    detail={"dest": os.fspath(dest), "reason": reason})
            return result
    dest = _free_name(dest)
    hashes = copy_evidence_to_case(case, source, dest)
    matches = None if expected is None else hashes.sha256 == expected
    result = Extracted(evidence_id, rel.as_posix(), os.fspath(dest),
                       hashes.as_dict(), expected, matches, False)
    if record:
        case.custody.record(
            "file.extracted", actor=case.actor(),
            target=f"{evidence_id}:{rel.as_posix()}",
            hashes=hashes.as_dict(),
            detail={"dest": os.fspath(dest), "reason": reason,
                    "manifest_sha256": expected,
                    "matches_manifest": matches})
    return result
