# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Parsing on every core (2026-10-29: Bill, "make it the most badass and
efficient setup").

The parsers are pure Python, and one Python process runs Python on one core
at a time. Measured on Bill's machine (bench.bat), event logs render at
about 4,000 records a second on one core — the slowest step of a Windows
pass. This module runs the PARSING in worker processes, one per spare core,
while the reading stays where it was: in this process, through the
read-only door, one file after another.

**WHAT A WORKER IS.** The same Python that runs the engine, started
isolated (`-I`: no user site, no PYTHONPATH, no current folder), importing
only `forensics_workshop`. It reads jobs — bytes the parent already read
from the evidence, and which parser to run — from its stdin, and writes the
rows back on its stdout. It opens nothing, writes nothing, and is told no
paths at all (`blocker.assert_child_writes` with no targets says so). A job
that raises is answered with the error; a worker that dies is replaced and
its job reported as failed, never silently dropped.

**THE ORDER IS KEPT.** Results come back in the order the jobs were made,
so a run's rows are stored the same way whether it used one core or twelve.
Where workers cannot start, everything runs here, in order, as before.
"""

from __future__ import annotations

import os
import pickle
import queue
import struct
import subprocess
import sys
import threading
from pathlib import Path

from . import blocker
from .errors import Cancelled

#: workers used unless told otherwise: every core but two (the GUI and the
#: reader), at most twelve
def default_workers() -> int:
    return max(0, min(12, (os.cpu_count() or 1) - 2))


#: at most this many bytes of jobs are in flight at once, whatever the
#: number of workers (the parent holds each job until its answer comes back);
#: one job is always allowed, however big
MAX_INFLIGHT_BYTES = 1 << 30
#: bytes objects larger than this travel out of band — written to the pipe
#: from the original, not copied into the pickle first
OUT_OF_BAND = 64 << 10

_BOOT = ("import sys; sys.path.insert(0, sys.argv[1]); "
         "from forensics_workshop.parallel import child_main; child_main()")
_LEN = struct.Struct("<Q")


def _oob(obj):
    """Large bytes inside a job travel out of band (pickle protocol 5)."""
    if isinstance(obj, (bytes, bytearray)) and len(obj) > OUT_OF_BAND:
        return pickle.PickleBuffer(obj)
    if isinstance(obj, tuple):
        return tuple(_oob(x) for x in obj)
    return obj


def _read_exact(stream, n: int) -> bytes:
    data = stream.read(n)
    if len(data) < n:
        raise EOFError("the other side closed its pipe mid-message")
    return data


def _send(stream, obj) -> None:
    """Length-prefixed: the pickle, then each out-of-band buffer as is —
    a 400 MB hive is written from the bytes the parent already holds, not
    from a second copy inside the pickle."""
    buffers: list = []
    head = pickle.dumps(_oob(obj), protocol=5, buffer_callback=buffers.append)
    stream.write(_LEN.pack(len(head)))
    stream.write(head)
    stream.write(_LEN.pack(len(buffers)))
    for b in buffers:
        view = b.raw()
        stream.write(_LEN.pack(view.nbytes))
        stream.write(view)
    stream.flush()


def _recv(stream):
    head = stream.read(_LEN.size)
    if len(head) < _LEN.size:
        raise EOFError("the other side closed its pipe")
    data = _read_exact(stream, _LEN.unpack(head)[0])
    count = _LEN.unpack(_read_exact(stream, _LEN.size))[0]
    buffers = [_read_exact(stream, _LEN.unpack(_read_exact(stream, _LEN.size))[0])
               for _ in range(count)]
    return pickle.loads(data, buffers=buffers)   # our own child's, nothing else


def _job_bytes(job) -> int:
    _func, args = job
    return sum(len(a) for a in args if isinstance(a, (bytes, bytearray)))


def run_job(job) -> tuple:
    """(ok, payload) for one job, here or in a worker: ok=True and the rows,
    or ok=False and (exception type name, message)."""
    func, args = job
    try:
        if func == "winartifacts":
            from . import winartifacts
            return True, winartifacts._parse_job(*args)
        raise ValueError(f"unknown job {func!r}")
    except Exception as exc:                          # noqa: BLE001 — reported
        return False, (type(exc).__name__, str(exc))


def child_main() -> None:
    """A worker's whole life: answer jobs until stdin closes."""
    stdin, stdout = sys.stdin.buffer, sys.stdout.buffer
    sys.stdout = sys.stderr                     # a stray print cannot corrupt
    while True:
        try:
            job = _recv(stdin)
        except EOFError:
            return
        _send(stdout, run_job(job))


def _start_worker():
    """THE ONE SPAWN: a worker that is told no paths and writes nothing."""
    blocker.assert_child_writes(None, ())
    root = str(Path(__file__).resolve().parents[1])
    from .media.proc import _no_window
    return subprocess.Popen([sys.executable, "-I", "-c", _BOOT, root],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            creationflags=_no_window())


class Pool:
    """`workers` processes; `imap(items)` yields results in order."""

    def __init__(self, workers: int) -> None:
        self.workers = max(0, int(workers))
        self._inq: queue.Queue = queue.Queue()
        self._done: dict = {}
        self._cond = threading.Condition()
        self._threads: list = []
        self._procs: list = []
        self.started = 0
        self.restarts = 0
        self.error = ""
        self._closing = False
        for _ in range(self.workers):
            try:
                proc = _start_worker()
            except OSError as exc:
                self.error = f"could not start a worker: {exc}"
                break
            self._procs.append(proc)
            t = threading.Thread(target=self._serve, args=(len(self._procs) - 1,),
                                 daemon=True, name="dfw-parse-feeder")
            self._threads.append(t)
            t.start()
        self.started = len(self._procs)

    def _serve(self, slot: int) -> None:
        while True:
            item = self._inq.get()
            if item is None:
                return
            seq, job = item
            proc = self._procs[slot]
            alive = True
            try:
                _send(proc.stdin, job)
                result = _recv(proc.stdout)
            except BaseException as exc:          # noqa: BLE001 — ALWAYS answer
                # Whatever went wrong — a dead worker, a broken pipe, memory —
                # this job gets an answer, or imap would wait for it forever.
                result = (False, ("WorkerDied",
                                  f"the parsing worker failed on this file "
                                  f"({type(exc).__name__}: {exc}); it was not "
                                  "parsed"))
                self._kill(proc)
                alive = False
            with self._cond:
                self._done[seq] = result
                self._cond.notify_all()
            if not alive:
                if self._closing:
                    return
                try:
                    self._procs[slot] = _start_worker()
                    self.restarts += 1
                except BaseException:             # noqa: BLE001
                    self._fail_queue()
                    return

    def _fail_queue(self) -> None:
        """No worker left for this slot: answer what is queued, so nothing
        waits forever (the other slots, if any, keep serving)."""
        if any(t.is_alive() for t in self._threads
               if t is not threading.current_thread()):
            return
        while True:
            try:
                item = self._inq.get_nowait()
            except queue.Empty:
                return
            if item is None:
                continue
            with self._cond:
                self._done[item[0]] = (False, ("WorkerDied",
                                               "no parsing worker could be "
                                               "started; it was not parsed"))
                self._cond.notify_all()

    @staticmethod
    def _kill(proc) -> None:
        """End a worker and let go of everything it held."""
        try:
            proc.kill()
        except OSError:
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def imap(self, items, *, should_cancel=None, inflight: int | None = None):
        """`items` yields ("job", job) or ("ready", result). Results are
        yielded in the same order, each as (ok, payload)."""
        if not self.started:
            for kind, value in items:
                if should_cancel is not None and should_cancel():
                    raise Cancelled("cancelled")
                yield run_job(value) if kind == "job" else value
            return
        limit = inflight or 2 * self.started
        it = iter(items)
        seq = out = 0
        exhausted = False
        sizes: dict = {}                   # seq -> bytes held for that job
        while True:
            while not exhausted and seq - out < limit and (
                    not sizes or sum(sizes.values()) < MAX_INFLIGHT_BYTES):
                if should_cancel is not None and should_cancel():
                    raise Cancelled("cancelled")
                try:
                    kind, value = next(it)
                except StopIteration:
                    exhausted = True
                    break
                if kind == "job":
                    sizes[seq] = _job_bytes(value)
                    self._inq.put((seq, value))
                else:
                    with self._cond:
                        self._done[seq] = value
                seq += 1
            if exhausted and out == seq:
                return
            with self._cond:
                while out not in self._done:
                    if should_cancel is not None and should_cancel():
                        raise Cancelled("cancelled")
                    self._cond.wait(0.25)
                result = self._done.pop(out)
            sizes.pop(out, None)
            out += 1
            yield result

    def close(self, *, kill: bool = False) -> None:
        """Stop the workers. `kill` (after a cancel or a failure) ends them
        at once instead of letting a busy one finish its file."""
        self._closing = True
        while True:                       # jobs nobody will wait for now
            try:
                self._inq.get_nowait()
            except queue.Empty:
                break
        for _ in self._threads:
            self._inq.put(None)
        if kill:
            for proc in self._procs:
                self._kill(proc)
        for proc in self._procs:
            try:
                proc.stdin.close()
            except (OSError, ValueError):
                pass
        for proc in self._procs:
            try:
                proc.wait(timeout=0 if kill else 5)
            except subprocess.TimeoutExpired:
                self._kill(proc)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
        for th in self._threads:
            th.join(timeout=5)

    def __enter__(self) -> "Pool":
        return self

    def __exit__(self, exc_type, *exc) -> None:
        self.close(kill=exc_type is not None)
