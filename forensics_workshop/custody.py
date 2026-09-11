# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The chain-of-custody log: append-only, fsynced, hash-chained.

    <case>/custody.jsonl     one JSON record per line, never rewritten

**THE RECORD IS APPEND-ONLY AND IT NEVER STATES A CONCLUSION.** That is the
rule CyberWolf's actor ledger arrived at, and here it is enforced rather
than hoped for:

* **Nothing in this module can rewrite, truncate or delete a line.** The
  only write is an append. A line cut off by a crash is not repaired — it is
  left exactly where it is and ACKNOWLEDGED by the next record, which names
  its offset, length and hash. Repairing it would mean guessing, and a
  custody log that guesses is not one.

* **Every record is flushed and fsynced before `record` returns.** `flush()`
  alone only reaches the operating system's cache: enough for a crashed
  process, not for a lost machine. A log that survives only a clean shutdown
  does not survive the situations it exists for.

* **Every record carries the SHA-256 of the line before it.** Editing,
  deleting or reordering any line breaks the chain at that point, and
  `verify` names where. What a chain cannot stop is someone rewriting the
  whole file and every hash after the edit — so `head()` is small enough to
  be anchored OUTSIDE the case (ATK's case index keeps it), and `verify`
  accepts that anchor and checks the log still contains it.

* **Only an examiner or the tool can act.** `Actor` kinds are a closed set.
  A model is not an actor that takes custodial actions, and an attempt to
  record one as the actor raises `CustodyRefused`.

* **No conclusions.** A detail key that states one — `finding`, `verdict`,
  `conclusion`, `assessment` … — is refused at any depth. Findings live in
  `findings/`, with their author and their model; this file records what
  was DONE to the evidence and by whom.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__
from . import blocker
from .errors import CustodyError, CustodyRefused
from .timeutil import utc_now

FILENAME = "custody.jsonl"
LOCKNAME = "custody.lock"
GENESIS = "0" * 64

ACTOR_KINDS = ("examiner", "tool")

#: Keys that state a conclusion. Refused anywhere inside `detail`/`hashes`.
CONCLUSION_KEYS = frozenset({
    "assessment", "conclusion", "conclusions", "determination", "finding",
    "findings", "opinion", "verdict"})

_ACTION = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")

UNREADABLE_NOTE = (
    "A line here is not a complete record — most often a write cut off by a "
    "crash or a lost machine. It is left in place and acknowledged; this "
    "log is never rewritten.")


@dataclass(frozen=True)
class Actor:
    kind: str
    name: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name}


def examiner(name: str) -> Actor:
    """The person taking the action. Named, always — "who" is half of custody."""
    clean = (name or "").strip()
    if not clean:
        raise CustodyRefused(
            "An examiner must be named. Every custody record says who took "
            "the action, and an unnamed one cannot.")
    if any(ch in clean for ch in "\r\n\t"):
        raise CustodyRefused("An examiner's name must be a single line.")
    return Actor("examiner", clean)


def tool() -> Actor:
    """The engine itself, for what it does unprompted (acknowledging a torn line)."""
    return Actor("tool", f"forensics_workshop {__version__}")


def line_hash(line: bytes) -> str:
    """SHA-256 of one record's bytes, excluding the newline."""
    return hashlib.sha256(line).hexdigest()


def _encode(row: dict) -> bytes:
    return json.dumps(row, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _refuse_conclusions(value, where: str) -> None:
    if isinstance(value, dict):
        for key, inner in value.items():
            if str(key).lower() in CONCLUSION_KEYS:
                raise CustodyRefused(
                    f"{where}.{key}: the custody log records what was done "
                    "and by whom, never what it means. Put findings in the "
                    "findings store, where they carry their author.")
            _refuse_conclusions(inner, f"{where}.{key}")
    elif isinstance(value, (list, tuple)):
        for i, inner in enumerate(value):
            _refuse_conclusions(inner, f"{where}[{i}]")


@dataclass
class _Tail:
    seq: int = 0
    head: str = GENESIS
    garbage: list = field(default_factory=list)     # [(offset, bytes)]
    unterminated: bool = False


def _parse_record(segment: bytes):
    try:
        row = json.loads(segment.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if (isinstance(row, dict) and isinstance(row.get("seq"), int)
            and isinstance(row.get("prev"), str)):
        return row
    return None


def _scan_tail(path: Path) -> _Tail:
    """Find the last complete record by reading backwards from the end.

    Cost is proportional to the tail, not the file, so a case with a long
    history does not get slower to append to.
    """
    try:
        size = os.path.getsize(path)
    except FileNotFoundError:
        return _Tail()
    if size == 0:
        return _Tail()
    block = 65536
    with open(path, "rb") as fh:
        while True:
            start = max(0, size - block)
            fh.seek(start)
            data = fh.read(size - start)
            tail = _Tail(unterminated=not data.endswith(b"\n"))
            pieces = data.split(b"\n")
            if not tail.unterminated:
                pieces.pop()                    # the empty piece after "\n"
            offsets, pos = [], start
            for piece in pieces:
                offsets.append(pos)
                pos += len(piece) + 1
            usable = range(1 if start > 0 else 0, len(pieces))
            for i in reversed(usable):
                row = _parse_record(pieces[i])
                if row is not None:
                    tail.seq = row["seq"]
                    tail.head = line_hash(pieces[i])
                    tail.garbage = [(offsets[j], pieces[j])
                                    for j in range(i + 1, len(pieces))
                                    if pieces[j]]
                    return tail
            if start == 0:
                tail.garbage = [(offsets[j], pieces[j])
                                for j in range(len(pieces)) if pieces[j]]
                return tail
            block *= 4


if sys.platform == "win32":                           # pragma: no cover
    import msvcrt

    def _lock(fh) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)

    def _unlock(fh) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fh) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)

    def _unlock(fh) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)


@dataclass(frozen=True)
class ChainReport:
    ok: bool
    records: int
    head_seq: int
    head_sha256: str
    problems: tuple
    notes: tuple

    def as_dict(self) -> dict:
        return {"ok": self.ok, "records": self.records,
                "head_seq": self.head_seq, "head_sha256": self.head_sha256,
                "problems": list(self.problems), "notes": list(self.notes)}


class CustodyLog:
    """One case's custody log."""

    def __init__(self, case_root) -> None:
        self.case_root = Path(case_root)
        self.path = self.case_root / FILENAME
        self._thread_lock = threading.Lock()

    # -- writing -----------------------------------------------------------

    def record(self, action: str, *, actor: Actor, target: str = "",
               hashes: dict | None = None,
               detail: dict | None = None) -> dict:
        """Append one record, durably, and return it.

        Everything is validated BEFORE anything is written, so a refused
        record leaves no trace — including a detail that will not serialise.
        """
        if not isinstance(actor, Actor) or actor.kind not in ACTOR_KINDS:
            raise CustodyRefused(
                f"{actor!r} cannot act on custody. Actors are one of "
                f"{ACTOR_KINDS}; a model's output is attributed where it is "
                "stored, and never recorded here as an action.")
        if not isinstance(action, str) or not _ACTION.match(action):
            raise CustodyRefused(f"{action!r} is not a valid action name.")
        _refuse_conclusions(detail or {}, "detail")
        _refuse_conclusions(hashes or {}, "hashes")
        try:
            _encode({"detail": detail or {}, "hashes": hashes or {},
                     "target": str(target)})
        except (TypeError, ValueError) as exc:
            raise CustodyError(f"record is not serialisable: {exc}") from exc

        with self._thread_lock:
            return self._append(action, actor, target, hashes, detail)

    def _append(self, action, actor, target, hashes, detail) -> dict:
        """THE ONE WRITE THIS LOG MAKES: append, flush, fsync.

        The tail is re-read under an exclusive lock on every call, so two
        processes appending to one case (ATK and the command line, say)
        cannot both chain to the same predecessor. The lock is a SEPARATE
        file because Windows byte-range locks are mandatory: locking the
        log itself would make every reader of it fail while a record was
        being written.
        """
        blocker.assert_case_path(self.case_root, self.path)
        lock_path = blocker.assert_case_path(self.case_root,
                                             self.case_root / LOCKNAME)
        with open(lock_path, "a+b") as lock:
            _lock(lock)
            try:
                tail = _scan_tail(self.path)
                seq, prev = tail.seq, tail.head
                lines: list[bytes] = []
                at = utc_now()
                for offset, segment in tail.garbage:
                    seq += 1
                    notice = {"seq": seq, "at": at,
                              "actor": tool().as_dict(),
                              "action": "custody.unreadable_line",
                              "target": FILENAME,
                              "hashes": {"sha256": line_hash(segment)},
                              "detail": {"offset": offset,
                                         "length": len(segment),
                                         "note": UNREADABLE_NOTE},
                              "prev": prev}
                    encoded = _encode(notice)
                    prev = line_hash(encoded)
                    lines.append(encoded)
                seq += 1
                row = {"seq": seq, "at": at, "actor": actor.as_dict(),
                       "action": action, "target": str(target),
                       "hashes": hashes or {}, "detail": detail or {},
                       "prev": prev}
                lines.append(_encode(row))
                prefix = b"\n" if tail.unterminated else b""
                existed = self.path.exists()
                with open(self.path, "ab") as fh:
                    fh.write(prefix + b"\n".join(lines) + b"\n")
                    fh.flush()
                    os.fsync(fh.fileno())
                if not existed and sys.platform != "win32":
                    # A new file is durable only once its directory entry is.
                    dfd = os.open(os.fspath(self.case_root), os.O_RDONLY)
                    try:
                        os.fsync(dfd)
                    finally:
                        os.close(dfd)
                return row
            finally:
                _unlock(lock)

    # -- reading -----------------------------------------------------------

    def _segments(self):
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            return []
        out, pos = [], 0
        for piece in data.split(b"\n"):
            if piece:
                out.append((pos, piece))
            pos += len(piece) + 1
        return out

    def rows(self) -> list[dict]:
        """Every complete record, in order. Unreadable lines are skipped
        here and REPORTED by `verify` — a reader is not an auditor."""
        return [row for _off, seg in self._segments()
                if (row := _parse_record(seg)) is not None]

    def head(self) -> tuple[int, str]:
        tail = _scan_tail(self.path)
        return tail.seq, tail.head

    def last(self, action: str | None = None,
             target: str | None = None) -> dict | None:
        for row in reversed(self.rows()):
            if action is not None and row.get("action") != action:
                continue
            if target is not None and row.get("target") != target:
                continue
            return row
        return None

    def verify(self, anchor: tuple[int, str] | None = None) -> ChainReport:
        """Walk the whole chain. `anchor` is a (seq, sha256) kept elsewhere."""
        problems: list[str] = []
        notes: list[str] = []
        prev, expected, records, last_at = GENESIS, 1, 0, ""
        head_seq, head_hash = 0, GENESIS
        acknowledged: dict[int, str] = {}
        unreadable: list[tuple[int, bytes]] = []
        anchor_seen = anchor is None
        segments = self._segments()
        for offset, segment in segments:
            row = _parse_record(segment)
            if row is None:
                unreadable.append((offset, segment))
                continue
            records += 1
            seq = row["seq"]
            if row["prev"] != prev:
                problems.append(
                    f"record {seq} (byte {offset}) does not chain to the "
                    "record before it: a line was edited, removed or "
                    "reordered")
            if seq != expected:
                problems.append(f"record at byte {offset} is numbered {seq}; "
                                f"{expected} was expected")
            kind = (row.get("actor") or {}).get("kind")
            if kind not in ACTOR_KINDS:
                problems.append(f"record {seq} names actor kind {kind!r}, "
                                "which the log never writes")
            at = str(row.get("at", ""))
            if last_at and at < last_at:
                notes.append(f"record {seq} is timestamped before the one "
                             "preceding it (the clock moved backwards)")
            last_at = at or last_at
            if row.get("action") == "custody.unreadable_line":
                d = row.get("detail") or {}
                acknowledged[int(d.get("offset", -1))] = str(
                    (row.get("hashes") or {}).get("sha256", ""))
            head_hash = line_hash(segment)
            head_seq = seq
            if anchor is not None and seq == anchor[0]:
                anchor_seen = True
                if head_hash != anchor[1]:
                    problems.append(
                        f"record {seq} no longer matches the hash recorded "
                        "outside the case: the log was rewritten from that "
                        "point on")
            prev, expected = head_hash, seq + 1
        if not anchor_seen:
            problems.append(f"the anchored record {anchor[0]} is no longer in "
                            "the log")
        last_record_offset = max((o for o, s in segments
                                  if _parse_record(s) is not None), default=-1)
        for offset, segment in unreadable:
            if acknowledged.get(offset) == line_hash(segment):
                notes.append(f"unreadable line at byte {offset} is "
                             "acknowledged by a later record")
            elif offset > last_record_offset:
                notes.append(f"incomplete line at byte {offset} after the "
                             "last record — an interrupted write; the next "
                             "record will acknowledge it")
            else:
                problems.append(f"unreadable line at byte {offset} was never "
                                "acknowledged")
        return ChainReport(not problems, records, head_seq, head_hash,
                           tuple(problems), tuple(notes))
