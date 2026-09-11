# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The case store — the spine everything else plugs into.

    <case>/
        case.json          identifier, examiner, when, where — written once
        custody.jsonl      append-only: every action, actor, time, hashes
        index.db           the queryable manifest and artefacts (derived)
        evidence/          one sidecar per registered source (E001.json …)
        extracted/         everything copied out, by evidence item
        findings/          hunt findings and analyst decisions (phase 3)
        reports/

**A CASE LIVES WHERE THE EXAMINER PUTS IT, NOT INSIDE ATK.** ATK's standing
rule is that its results live in its own folder; this is the deliberate
exception, written down so nobody "fixes" it. A case is the operator's, is
often on another volume, is frequently larger than the application, and is
sometimes required to sit on media handled under its own rules. ATK keeps
only an index of where cases are (`caseindex.py`).

**`case.json` is written once.** Its SHA-256 goes into the `case.created`
custody record, and every `Case.open` compares the file against it — so a
case file edited after the fact is reported the moment the case is opened,
not discovered in a courtroom.

**The evidence source is never copied on registration and never written.**
A logical folder is registered by path, hashed in place through
`blocker.open_evidence`, and the sidecar records the volume it was on and
whether that volume was read-only at the time. A disk image is registered
the same way — by the path of its first segment, with every segment named in
the sidecar — after its signature has been checked, so a container that is
not a raw disk (E01, VHDX, VMDK) is refused before anything reads it as one.
"""

from __future__ import annotations

import json
import os
import platform
import re
import sys
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from . import blocker
from . import custody as _custody
from . import hashing
from . import image as _image
from . import index as _index
from .errors import CaseError, EvidenceError
from .timeutil import local_offset, utc_now

CASE_FILE = "case.json"
LAYOUT = ("evidence", "extracted", "findings", "reports")
CASE_SCHEMA = 1

_CASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$")


def write_json_atomic(case_root, target, data: dict) -> str:
    """Write a JSON file inside the case, durably and all-or-nothing.

    Exclusive-create a temporary file beside the target, fsync it, then
    rename over. A crash leaves either the old file or the new one, never
    half of one. Returns the SHA-256 of the bytes written.
    """
    root = Path(case_root)
    final = blocker.assert_case_path(root, target)
    temp = blocker.assert_case_path(
        root, final.with_name(f".{final.name}.{uuid.uuid4().hex}.tmp"))
    payload = (json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
               + "\n").encode("utf-8")
    with open(temp, "xb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp, final)
    return hashing.hash_bytes(payload).sha256


def make_case_dirs(case_root, *parts) -> Path:
    """Create a folder inside the case (and its parents, inside the case)."""
    root = Path(case_root)
    target = blocker.assert_case_path(root, root.joinpath(*parts))
    target.mkdir(parents=True, exist_ok=True)
    return target


@dataclass(frozen=True)
class CaseInfo:
    schema: int
    case_id: str
    description: str
    created_at: str
    created_by: str
    tool: str
    host: str
    platform: str
    python: str
    utc_offset_at_creation: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    kind: str
    source: str
    label: str
    added_at: str
    volume: dict
    platform: str

    def as_dict(self) -> dict:
        return asdict(self)


class Case:
    """An open case, and the examiner who opened it.

    Construct with `Case.create` or `Case.open`; both require a named
    examiner, because every write a case makes is a custody record and a
    custody record says who.
    """

    def __init__(self, root: Path, info: CaseInfo, examiner: str,
                 integrity: list[str]) -> None:
        self.root = root
        self.info = info
        self.examiner = examiner
        self.custody = _custody.CustodyLog(root)
        self._integrity = list(integrity)

    # -- lifecycle ----------------------------------------------------------

    @staticmethod
    def is_case(root) -> bool:
        return (Path(root) / CASE_FILE).is_file()

    @classmethod
    def create(cls, root, *, case_id: str, examiner: str,
               description: str = "") -> "Case":
        actor = _custody.examiner(examiner)
        case_id = (case_id or "").strip()
        if not _CASE_ID.match(case_id):
            raise CaseError(
                f"{case_id!r} is not a usable case identifier: letters, "
                "digits, space, dot, dash and underscore, starting with a "
                "letter or digit, at most 64 characters.")
        root = Path(root).absolute()
        if cls.is_case(root):
            raise CaseError(f"{root} is already a case. Open it instead.")
        if root.exists() and (not root.is_dir() or any(root.iterdir())):
            raise CaseError(
                f"{root} exists and is not an empty folder. A new case gets "
                "a folder of its own, so nothing already in it is mistaken "
                "for case material.")
        info = CaseInfo(
            schema=CASE_SCHEMA, case_id=case_id,
            description=(description or "").strip(),
            created_at=utc_now(), created_by=actor.name,
            tool=f"forensics_workshop {__version__}",
            host=platform.node(), platform=platform.platform(),
            python=platform.python_version(),
            utc_offset_at_creation=local_offset())
        make_case_dirs(root)
        for sub in LAYOUT:
            make_case_dirs(root, sub)
        digest = write_json_atomic(root, root / CASE_FILE, info.as_dict())
        _index.connect(root).close()
        case = cls(root, info, actor.name, [])
        case.custody.record(
            "case.created", actor=actor, target=case_id,
            hashes={CASE_FILE: digest},
            detail={"root": os.fspath(root), "layout": list(LAYOUT),
                    "host": info.host, "platform": info.platform,
                    "utc_offset": info.utc_offset_at_creation})
        return case

    @classmethod
    def open(cls, root, *, examiner: str, anchor=None) -> "Case":
        """Open a case, check it, and record that it was opened.

        `anchor` is a (seq, sha256) custody head kept OUTSIDE the case — ATK
        keeps one per case in its case index. Problems are collected rather
        than raised: an examiner must be able to open a case that has been
        interfered with in order to see that it has.
        """
        actor = _custody.examiner(examiner)
        root = Path(root).absolute()
        path = root / CASE_FILE
        if not path.is_file():
            raise CaseError(f"{root} is not a case (no {CASE_FILE}).")
        raw = path.read_bytes()
        try:
            data = json.loads(raw.decode("utf-8"))
            info = CaseInfo(**{k: data[k] for k in CaseInfo.__dataclass_fields__})
        except (ValueError, KeyError, TypeError) as exc:
            raise CaseError(f"{path} is not a readable case file: {exc}") from exc
        if info.schema != CASE_SCHEMA:
            raise CaseError(f"{path} is case schema {info.schema}; this "
                            f"engine reads schema {CASE_SCHEMA}.")
        integrity: list[str] = []
        log = _custody.CustodyLog(root)
        created = next((r for r in log.rows()
                        if r.get("action") == "case.created"), None)
        digest = hashing.hash_bytes(raw).sha256
        if created is None:
            integrity.append("the custody log has no case.created record")
        elif (created.get("hashes") or {}).get(CASE_FILE) != digest:
            integrity.append(f"{CASE_FILE} has changed since the case was "
                             "created")
        chain = log.verify(anchor=anchor)
        integrity.extend(chain.problems)
        case = cls(root, info, actor.name, integrity)
        case.custody.record(
            "case.opened", actor=actor, target=info.case_id,
            hashes={CASE_FILE: digest},
            detail={"root": os.fspath(root), "host": platform.node(),
                    "chain_ok": chain.ok, "integrity_problems": integrity})
        _index.connect(root).close()
        return case

    # -- helpers ------------------------------------------------------------

    def actor(self) -> _custody.Actor:
        return _custody.examiner(self.examiner)

    def path(self, *parts) -> Path:
        """A path inside this case. Refuses anything that would leave it."""
        return blocker.assert_case_path(self.root, self.root.joinpath(*parts))

    def connect(self):
        return _index.connect(self.root)

    def integrity(self) -> list[str]:
        """What `open` found wrong. Empty for a case that checks out."""
        return list(self._integrity)

    # -- evidence -----------------------------------------------------------

    def evidence(self) -> list[EvidenceItem]:
        folder = self.root / "evidence"
        items = []
        for sidecar in sorted(folder.glob("E*.json")):
            try:
                data = json.loads(sidecar.read_text(encoding="utf-8"))
                items.append(EvidenceItem(
                    **{k: data[k] for k in EvidenceItem.__dataclass_fields__}))
            except (ValueError, KeyError, TypeError, OSError):
                continue
        return items

    def evidence_item(self, evidence_id: str) -> EvidenceItem:
        for item in self.evidence():
            if item.id == evidence_id:
                return item
        raise EvidenceError(f"No evidence item {evidence_id!r} in this case.")

    def sidecar(self, evidence_id: str) -> dict:
        """The full sidecar of one evidence item, including what its kind
        adds (an image's segments and format)."""
        path = self.root / "evidence" / f"{evidence_id}.json"
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise EvidenceError(f"The sidecar for {evidence_id} cannot be "
                                f"read: {exc}") from exc

    def evidence_roots(self) -> list[Path]:
        """Every path that IS evidence — each segment of a split image too,
        since a write anywhere near any of them is refused."""
        roots = []
        for item in self.evidence():
            if item.kind == "raw-image":
                segments = self.sidecar(item.id).get("segments") or []
                roots.extend(Path(seg["path"]) for seg in segments)
                if not segments:
                    roots.append(Path(item.source))
            else:
                roots.append(Path(item.source))
        return roots

    def _next_evidence_id(self) -> str:
        existing = [int(i.id[1:]) for i in self.evidence() if i.id[1:].isdigit()]
        return f"E{(max(existing) + 1) if existing else 1:03d}"

    def add_folder(self, source, *, label: str = "") -> EvidenceItem:
        """Register a logical folder as evidence. Reads nothing inside it yet."""
        given = Path(source)
        if not given.is_dir():
            raise EvidenceError(f"{given} is not a folder.")
        resolved = Path(os.path.realpath(given))
        blocker.check_layout(self.root, resolved)
        for item in self.evidence():
            if os.path.normcase(item.source) == os.path.normcase(
                    os.fspath(resolved)):
                raise EvidenceError(
                    f"{resolved} is already registered as {item.id}.")
            if (blocker.is_inside(resolved, item.source)
                    or blocker.is_inside(item.source, resolved)):
                raise EvidenceError(
                    f"{resolved} overlaps {item.id} ({item.source}). Two "
                    "evidence items that share files would hash them twice "
                    "under two identities; register the outer folder once.")
        evidence_id = self._next_evidence_id()
        item = EvidenceItem(
            id=evidence_id, kind="logical-folder",
            source=os.fspath(resolved), label=(label or "").strip(),
            added_at=utc_now(),
            volume=blocker.volume_state(resolved).as_dict(),
            platform=sys.platform)
        sidecar = dict(item.as_dict(), given_path=os.fspath(given),
                       registered_by=self.examiner, host=platform.node())
        digest = write_json_atomic(self.root,
                                   self.root / "evidence" / f"{evidence_id}.json",
                                   sidecar)
        with _index.session(self.root) as conn:
            conn.execute(
                "INSERT INTO evidence (id, kind, source, label, added_at, "
                "sidecar_sha256) VALUES (?, ?, ?, ?, ?, ?)",
                (item.id, item.kind, item.source, item.label, item.added_at,
                 digest))
        self.custody.record(
            "evidence.registered", actor=self.actor(), target=evidence_id,
            hashes={"sidecar": digest},
            detail={"kind": item.kind, "source": item.source,
                    "given_path": os.fspath(given), "label": item.label,
                    "volume": item.volume})
        return item

    def add_image(self, source, *, label: str = "") -> EvidenceItem:
        """Register a RAW/DD disk image — one file or a split set — as evidence.

        Pass the FIRST segment. Refused: a segment part-way through a set, a
        set with a gap, and any container that is not a raw disk. Nothing but
        the first sector and the last is read here; hashing happens when the
        image is ingested, so that its custody record says when.
        """
        given = Path(source)
        if not given.is_file():
            raise EvidenceError(f"{given} is not a file.")
        first = Path(os.path.realpath(given))
        info = _image.describe(_image.discover_segments(first))
        for seg in info.segments:
            blocker.check_layout(self.root, seg.path)
        inside = []
        for item in self.evidence():
            if item.kind == "raw-image":
                taken = {os.path.normcase(s["path"]) for s in
                         self.sidecar(item.id).get("segments") or []}
                if any(os.path.normcase(seg.path) in taken
                       for seg in info.segments):
                    raise EvidenceError(
                        f"{first} (or one of its segments) is already "
                        f"registered as {item.id}.")
            elif item.kind == "logical-folder" and blocker.is_inside(
                    first, item.source):
                inside.append(item.id)
        evidence_id = self._next_evidence_id()
        item = EvidenceItem(
            id=evidence_id, kind="raw-image", source=os.fspath(first),
            label=(label or "").strip(), added_at=utc_now(),
            volume=blocker.volume_state(first).as_dict(),
            platform=sys.platform)
        sidecar = dict(item.as_dict(), given_path=os.fspath(given),
                       registered_by=self.examiner, host=platform.node(),
                       image=info.as_dict(),
                       segments=[s.as_dict() for s in info.segments],
                       inside_evidence=inside)
        digest = write_json_atomic(self.root,
                                   self.root / "evidence" / f"{evidence_id}.json",
                                   sidecar)
        with _index.session(self.root) as conn:
            conn.execute(
                "INSERT INTO evidence (id, kind, source, label, added_at, "
                "sidecar_sha256) VALUES (?, ?, ?, ?, ?, ?)",
                (item.id, item.kind, item.source, item.label, item.added_at,
                 digest))
        self.custody.record(
            "evidence.registered", actor=self.actor(), target=evidence_id,
            hashes={"sidecar": digest},
            detail={"kind": item.kind, "source": item.source,
                    "given_path": os.fspath(given), "label": item.label,
                    "format": info.format, "disk_bytes": info.size,
                    "segments": [s.as_dict() for s in info.segments],
                    "head_type": info.head_type, "notes": list(info.notes),
                    "inside_evidence": inside, "volume": item.volume})
        return item
