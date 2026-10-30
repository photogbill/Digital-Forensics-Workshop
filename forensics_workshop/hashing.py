# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""MD5, SHA-1 and SHA-256 in one pass.

All three, every time, because they answer different people: SHA-256 is the
one worth trusting, MD5 and SHA-1 are the ones older reports, hash sets and
other examiners' tools will quote back. Computing them in a single read
means asking for a legacy hash never costs a second pass over a 40 GB file.

**THE THREE RUN SIDE BY SIDE** (2026-10-29). Python's hashlib lets go of
the interpreter lock while it digests a buffer, so for a big chunk the
three digests are computed on three threads at once and the chunk costs
the slowest of them, not the sum. Measured on Bill's machine (its Linux
VM, two cores): 350 MB/s one after another, 556 MB/s side by side — MD5
is then the limit. Each digest still sees every chunk in order: an update
waits for all three before the next chunk is fed. Small chunks are hashed
in line, where a thread hand-off would cost more than it saves.

**MD5 and SHA-1 are identifiers here, not security.** They are constructed
with `usedforsecurity=False`, which is both the truth and what lets this
module run on an interpreter built in FIPS mode.
"""

from __future__ import annotations

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from typing import BinaryIO, Callable

from . import blocker
from .errors import Cancelled

CHUNK = 1 << 20
ALGORITHMS = ("md5", "sha1", "sha256")
#: a chunk at least this big is hashed on three threads at once
PARALLEL_MIN = 256 << 10

_POOL: ThreadPoolExecutor | None = None
_POOL_LOCK = threading.Lock()


def _pool() -> ThreadPoolExecutor:
    global _POOL
    with _POOL_LOCK:
        if _POOL is None:
            _POOL = ThreadPoolExecutor(max_workers=6,
                                       thread_name_prefix="dfw-digest")
        return _POOL


def _hashers():
    try:
        md5 = hashlib.md5(usedforsecurity=False)
        sha1 = hashlib.sha1(usedforsecurity=False)
    except TypeError:                                  # pragma: no cover
        md5, sha1 = hashlib.md5(), hashlib.sha1()
    return md5, sha1, hashlib.sha256()


class Hasher:
    """All three digests over bytes fed in pieces — for a stream that is not
    one file, such as a split image whose segments are hashed one by one AND
    as the whole disk, in a single read."""

    def __init__(self) -> None:
        self._md5, self._sha1, self._sha256 = _hashers()
        self.size = 0

    def update(self, chunk: bytes) -> None:
        if len(chunk) >= PARALLEL_MIN:
            pool = _pool()
            done = [pool.submit(h.update, chunk)
                    for h in (self._md5, self._sha1, self._sha256)]
            for f in done:
                f.result()
        else:
            self._md5.update(chunk)
            self._sha1.update(chunk)
            self._sha256.update(chunk)
        self.size += len(chunk)

    def digests(self) -> tuple:
        return self._md5, self._sha1, self._sha256

    def result(self) -> "Hashes":
        return Hashes(self._md5.hexdigest(), self._sha1.hexdigest(),
                      self._sha256.hexdigest(), self.size)


def update_all(hashers, chunk: bytes) -> None:
    """Feed one chunk to several Hashers at once — a split image's segment
    and the whole disk, say — every digest of every one side by side."""
    if len(hashers) == 1:
        hashers[0].update(chunk)
        return
    pool = _pool()
    done = [pool.submit(d.update, chunk) for h in hashers for d in h.digests()]
    for f in done:
        f.result()
    for h in hashers:
        h.size += len(chunk)


@dataclass(frozen=True)
class Hashes:
    md5: str
    sha1: str
    sha256: str
    size: int

    def as_dict(self) -> dict:
        return asdict(self)

    def matches(self, other: "Hashes") -> bool:
        """All three digests AND the size. A size that disagrees while the
        digests agree is not a thing that happens, and if it ever did it
        would be the more important half of the report."""
        return (self.md5 == other.md5 and self.sha1 == other.sha1
                and self.sha256 == other.sha256 and self.size == other.size)


def hash_stream(fh: BinaryIO, *, head_bytes: int = 0,
                should_cancel: Callable[[], bool] | None = None,
                sink: BinaryIO | None = None) -> tuple[Hashes, bytes]:
    """Hash everything `fh` yields, keeping the first `head_bytes`.

    The head comes out of the same read, which is what lets type
    identification cost nothing extra. `sink`, when given, receives every
    chunk as it is hashed — a copy and its hash are then one read of the
    source, so what was hashed is by construction what was copied.
    """
    hasher = Hasher()
    head = bytearray()
    while True:
        if should_cancel is not None and should_cancel():
            raise Cancelled("hashing was cancelled")
        chunk = fh.read(CHUNK)
        if not chunk:
            break
        hasher.update(chunk)
        if sink is not None:
            sink.write(chunk)
        if len(head) < head_bytes:
            head += chunk[: head_bytes - len(head)]
    return hasher.result(), bytes(head)


def hash_bytes(data: bytes) -> Hashes:
    hasher = Hasher()
    hasher.update(data)
    return hasher.result()


def hash_evidence(path, *, should_cancel=None) -> Hashes:
    """Hash an evidence file through the one read-only door."""
    with blocker.open_evidence(path) as fh:
        return hash_stream(fh, should_cancel=should_cancel)[0]


def hash_case_file(path) -> Hashes:
    """Hash a file the case itself produced."""
    with open(path, "rb") as fh:
        return hash_stream(fh)[0]
