# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Running a child process for the media lane — FFmpeg, the SpeechBrain and
DeepFilterNet workers — and saying how it ended.

Moved here from the SAM Audio module when SAM was removed (Bill,
2026-10-29): restoration and voice comparison were already using this
runner, and nothing in it was ever specific to SAM.

**NEVER SILENT WHILE IT RUNS.** A child that prints nothing for minutes gets
a heartbeat from the parent every `HEARTBEAT_S` seconds — elapsed time and
the last line the child wrote — and every log closes with one
`[forensics_workshop]` line saying how the child ended (exit code, killed at
the timeout, stopped by the examiner), so a log that just stops is never the
whole story.

**WHAT A CHILD WRITES IS GUARDED BEFORE IT STARTS.** No syntax tree can see
a child's writes, so `run_process` is a `spawn` writer: every path the child
is told to write goes through the case (or harness) guard first, with
`blocker.assert_child_writes`.
"""

from __future__ import annotations

import os
import re
import subprocess
import time

from .. import blocker
from ..errors import MediaError

#: Seconds between "still running" lines while a child runs.
HEARTBEAT_S = 10.0

#: Lines this package writes into a child's log start with this, so the
#: tail that quotes the child never quotes us instead.
OWN_LINE = "[forensics_workshop]"


def runtime_argv(program) -> list[str]:
    """The command that starts the runtime: an executable path, or an argv
    prefix (`[python, fake_tool.py]` — how the suite drives a fake through
    the very same subprocess path)."""
    if isinstance(program, (list, tuple)):
        if not program:
            raise MediaError("No program was given to run.")
        return [os.fspath(a) for a in program]
    if not program:
        raise MediaError("No program was given to run.")
    return [os.fspath(program)]



def child_env(scratch) -> dict:
    """This process's environment with TMP/TEMP/TMPDIR moved to `scratch`."""
    env = dict(os.environ)
    for name in ("TMP", "TEMP", "TMPDIR"):
        env[name] = os.fspath(scratch)
    return env



def clock(seconds: float) -> str:
    """`48 s`, `4 min 05 s`, `1 h 02 min` — elapsed time for a sentence."""
    s = int(max(0.0, float(seconds)))
    if s < 60:
        return f"{s} s"
    if s < 3600:
        return f"{s // 60} min {s % 60:02d} s"
    return f"{s // 3600} h {(s % 3600) // 60:02d} min"



def _no_window() -> int:
    return getattr(subprocess, "CREATE_NO_WINDOW", 0)



def probe_version(argv: list[str], flag: str) -> str:
    """`<tool> --version` (or `-version`), its non-empty lines joined. A child
    that writes nothing of ours: it names no targets. Never raises — an
    unknown version is recorded as unknown, with the reason."""
    blocker.assert_child_writes(None, ())
    try:
        done = subprocess.run(argv + [flag], capture_output=True, timeout=60,
                              creationflags=_no_window(),
                              stdin=subprocess.DEVNULL)
        text = (done.stdout or done.stderr).decode("utf-8", "replace").strip()
        return " | ".join(l.strip() for l in text.splitlines() if l.strip()
                          )[:400] or f"unknown ({exit_sentence(done.returncode)})"
    except (OSError, subprocess.SubprocessError) as exc:
        return f"unknown ({type(exc).__name__}: {exc})"



#: Windows' crash codes (NTSTATUS) for the ways a native child dies, said in
#: words. Python reports them as the unsigned 32-bit exit code.
NTSTATUS = {
    0xC0000135: "a DLL it needs was not found (most often the CUDA runtime or "
                "the MSVC/OpenMP runtime) — reinstall the tool",
    0xC0000005: "it crashed with an access violation — often a model file it "
                "cannot read correctly, or a GPU driver fault",
    0xC0000409: "it stopped itself (a fail-fast: an assertion or abort inside "
                "the runtime — the log's last lines say where)",
    0x40000015: "it called abort() — the log's last lines say why",
    0xC000001D: "an illegal instruction: it was built for a CPU feature this "
                "machine lacks (AVX2/AVX-512) — rebuild or reinstall it here",
    0xC00000FD: "a stack overflow inside the runtime",
    0xC0000142: "a DLL failed to initialise — often a GPU driver mismatch",
    0xC0000017: "the system ran out of memory",
    3: "it called abort() (an MSVC abort exits with code 3) — the log's last "
       "lines say why",
}



def exit_sentence(returncode) -> str:
    """`exited with code 3221225781 (0xC0000135): a DLL it needs …` — the raw
    code always kept, the meaning added where it is known."""
    if returncode is None:
        return "did not start"
    code = int(returncode) & 0xFFFFFFFF
    meaning = NTSTATUS.get(code)
    raw = f"exited with code {returncode} (0x{code:08X})"
    return f"{raw}: {meaning}" if meaning else raw



def _own_line(log, text: str) -> None:
    """One `[forensics_workshop]` line at the END of the child's log. The
    child shared the handle and moved its position, so seek to the end
    first. Never raises: a footer must not turn a result into a failure."""
    try:
        log.seek(0, os.SEEK_END)
        log.write(f"{OWN_LINE} {text}\n".encode("utf-8"))
        log.flush()
    except (OSError, ValueError, AttributeError):
        pass



def _ending(state: str, returncode, elapsed: float, timeout_s: float) -> str:
    took = f"after {clock(elapsed)} ({elapsed:.1f} s)"
    if state == "completed":
        return f"the child exited 0 {took}"
    if state == "cancelled":
        return f"the child was KILLED {took}: stopped by the examiner"
    if state == "timeout":
        return (f"the child was KILLED {took}: it ran past the "
                f"{timeout_s:.0f} s limit and was called hung")
    return f"the child {exit_sentence(returncode)} {took}"



def run_process(argv: list[str], *, log, timeout_s: float, writes, guard,
                should_cancel=None, cwd=None, env=None, heartbeat=None,
                heartbeat_s: float | None = None) -> dict:
    """Run one child to completion, its stdout and stderr into `log` (an open
    binary file the caller made). Polled, so a cancel or a hang kills the
    child within half a second and the run says which.

    `writes` names every path the child has been told to write and `guard`
    is the case (or harness) check they must pass — BEFORE the child starts,
    because once it runs, no syntax tree can see what it writes.

    `env` (optional) is the child's whole environment. `heartbeat(elapsed_s)`
    is called every `heartbeat_s` seconds while the child runs. Whatever
    happens, the log ends with one line saying how the child ended."""
    blocker.assert_child_writes(guard, writes)
    log.write(("$ " + subprocess.list2cmdline(argv) + "\n").encode("utf-8"))
    if env is not None and env.get("TEMP"):
        log.write(f"{OWN_LINE} TMP/TEMP for the child: {env['TEMP']}\n"
                  .encode("utf-8"))
    log.flush()
    started = time.monotonic()
    interval = HEARTBEAT_S if heartbeat_s is None else float(heartbeat_s)
    try:
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                                stdin=subprocess.DEVNULL, cwd=cwd, env=env,
                                creationflags=_no_window())
    except OSError as exc:
        error = f"could not start {argv[0]}: {exc}"
        _own_line(log, error)
        return {"state": "failed", "returncode": None, "elapsed_s": 0.0,
                "error": error}
    state = "completed"
    next_beat = started + interval
    while True:
        try:
            proc.wait(timeout=0.5)
            break
        except subprocess.TimeoutExpired:
            now = time.monotonic()
            if should_cancel is not None and should_cancel():
                state = "cancelled"
            elif now - started > timeout_s:
                state = "timeout"
            else:
                if heartbeat is not None and now >= next_beat:
                    next_beat = now + interval
                    try:
                        heartbeat(now - started)
                    except Exception:                     # noqa: BLE001
                        pass      # a status line must never stop the run
                continue
            proc.kill()
            proc.wait()
            break
    elapsed = round(time.monotonic() - started, 3)
    if state == "completed" and proc.returncode != 0:
        state = "failed"
    _own_line(log, _ending(state, proc.returncode, elapsed, timeout_s))
    return {"state": state, "returncode": proc.returncode, "elapsed_s": elapsed,
            "error": ""}



_LOG_PREFIX = re.compile(r"^\[(?:TRACE|TIMING|DEBUG|INFO|WARN\w*|ERROR)"
                         r"(?:\s+ts=[^\]]*)?\]\s*")



def _log_lines(path) -> list[str]:
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, os.fstat(fh.fileno()).st_size - 8192))
            text = fh.read().decode("utf-8", "replace")
    except (OSError, TypeError):
        return []
    return [l.strip() for l in text.splitlines()
            if l.strip() and not l.strip().startswith(OWN_LINE)]



def log_tail(path, lines: int = 6) -> str:
    """The last lines of a run's log — what the child said before it stopped
    (never this package's own closing line)."""
    return " / ".join(_log_lines(path)[-lines:])



def last_line(path) -> str:
    """The last thing the CHILD wrote, its `[TIMING ts=…]` stamp removed —
    "" while it has printed nothing but the command line."""
    kept = [l for l in _log_lines(path) if not l.startswith("$ ")]
    return _LOG_PREFIX.sub("", kept[-1])[:160] if kept else ""
