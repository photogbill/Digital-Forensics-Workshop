# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""SAM Audio through audio.cpp — the one adapter (FORENSICS_PLAN §12.9).

Meta's SAM Audio (December 2025) separates a sound chosen by a text
description and/or time anchors, by flow matching in a codec latent space:
a GENERATIVE separator, so everything it writes is **Invented** tier.

**RUN AS A SUBPROCESS, NEVER IN-PROCESS.** `audiocpp_cli` is C++ on ggml with
a CUDA backend; a CUDA fault or an out-of-memory abort takes down the child,
and this process — the ATK worker — reads its exit code and says what
happened. Nothing is linked and nothing is loaded here.

**PINNED: audio.cpp v0.9.0** (2026-09-30, commit 795c45f), the first release
with SAM Audio (PR #711), built from source by ATK's get_sam.bat. Every flag
below was read from that tag's own documentation, 2026-10-05:

    docs/models/sam_audio.md   --task s2s --family sam_audio --model <gguf>
                               --audio <wav> --text "<description>"
                               --seed N --out-dir <dir>  ->  target.wav and
                               residual.wav, mono 48 kHz (may be padded to
                               the next 40 ms codec frame); --text is
                               REQUIRED, anchors or not;
                               --request-option anchors=[["+",s,e],["-",s,e]]
                               (0 <= start < end; later spans win overlaps);
                               --session-option sam_audio.memory_bounded=true
                               with --model-spec-override
                               model_specs/sam_audio.json (provisional name;
                               the GGUFs predate the option)
    docs/usage.md, app/cli     --backend cpu|cuda|vulkan|best, --log,
                               --metrics, --out-format pcm16|pcm24|float32,
                               --version

    https://github.com/0xShug0/audio.cpp/blob/v0.9.0/docs/models/sam_audio.md
    https://github.com/0xShug0/audio.cpp/blob/v0.9.0/docs/usage.md

**`--out-format float32`, always.** The default PCM16 writer hard-clips at
full scale (src/framework/audio/wav_writer.cpp); float32 is written as the
model produced it, so a clipped peak is never something this tool did.

**Memory-bounded mode above `MEMORY_BOUNDED_ABOVE_S` (30 s).** The default
path holds the whole recording on the GPU and "memory use grows with its
length". The only measured figure is the publisher's — Large Q8_0 peaking at
9,378 MiB on a 15-second clip — and nothing says how fast it grows, while
the 3080 Ti has 16 GB that Whisper or the LLM may partly hold. Bounded mode
costs speed and "small floating-point differences", never correctness, and
ran 180 s on Large where Meta's Python ran out of memory. So: automatic for
anything longer than twice the one measured length, and the recipe records
which mode ran. It does not extend the model's context limit.

**THE CONTEXT LIMIT: 400 s AT ONCE (`MAX_AUDIO_S`).** The transformer takes
at most `transformer.max_positions` = 10,000 latent frames (the pinned GGUF's
`config.json`), and a frame is the codec's 1,920 samples at 48 kHz (encoder
rates 2·8·10·12) = 40 ms. Bounded mode refuses more — "SAM Audio bounded mode
exceeds the model's maximum audio position count", `src/models/sam_audio/
dit.cpp` — and it says so only AFTER encoding the whole recording: a 99 min
55 s video ran the codec for 3 min 47 s first (Bill, 2026-10-09). The Media
Lab therefore runs anything longer as overlapping WINDOWS and joins them
(`lab.plan_windows`); this adapter only ever sees one window.

**THE GPU IS REQUIRED (Bill, 2026-10-09).** audio.cpp's own default backend
is `cpu`, and get_sam.bat once fell back to a CPU build without anyone
noticing: ATK then ran a 5-hour job with no GPU, silent, its log stopped at
the encoder. A CPU build (`backend=cpu` in audiocpp_build.txt) is now
REFUSED before anything is written, with the sentence saying why and the
build log to read — `allow_cpu=True` (CLI `--allow-cpu`) is the deliberate
way past it. audio.cpp itself never falls back: asked for CUDA it cannot
start, it throws.

**THE RUNTIME'S TEMP FOLDER IS BESIDE THE EXE.** audio.cpp unpacks each
GGUF's embedded config sidecars into `temp_directory_path()/audiocpp-gguf/`
(src/framework/assets/tensor_source.cpp) — on Windows that is
`%TMP%`, i.e. `C:\\Users\\…\\AppData\\Local\\Temp`, which Bill's rule forbids.
The child is started with TMP/TEMP pointing at `tmp\\` beside audiocpp_cli
(inside ATK), made by `make_scratch` and nowhere else.

**NEVER SILENT WHILE IT RUNS.** audio.cpp prints nothing during diffusion, so
the parent beats a heartbeat every `HEARTBEAT_S` seconds — elapsed time, the
backend, and the last line audio.cpp wrote — and closes every log with one
`[forensics_workshop]` line saying how the child ended (exit code, killed at
the timeout, stopped by the examiner), so a log that just stops is never the
whole story.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

from .. import blocker
from ..errors import MediaError
from . import separator as _sep

FAMILY = "sam_audio"
TASK = "s2s"
PINNED_TAG = "v0.9.0"
PINNED_COMMIT = "795c45fbde0a7d29c93b22199728ff5caaec02e5"
DOCS_URL = ("https://github.com/0xShug0/audio.cpp/blob/v0.9.0/docs/models/"
            "sam_audio.md")
OUT_FORMAT = "float32"
DEFAULT_BACKEND = "cuda"
MEMORY_BOUNDED_ABOVE_S = 30.0
#: The model's context (see the module notes): 10,000 frames of 40 ms.
MAX_POSITIONS = 10000
FRAME_S = 1920 / 48000
MAX_AUDIO_S = MAX_POSITIONS * FRAME_S
#: Relative to the folder holding audiocpp_cli; get_sam.bat copies it there
#: from the pinned checkout.
SPEC_OVERRIDE = Path("model_specs") / "sam_audio.json"
BUILD_FILE = "audiocpp_build.txt"
INSTALL_HINT = "Run get_sam.bat in the ATK folder."
#: Backends that put SAM on a GPU. `cpu` is refused unless asked for.
GPU_BACKENDS = ("cuda", "vulkan", "metal")
#: The runtime's TMP/TEMP, relative to the folder holding audiocpp_cli.
SCRATCH = Path("tmp")
#: Seconds between "still running" lines while a child runs.
HEARTBEAT_S = 10.0
#: Lines this package writes into a child's log start with this, so the
#: tail that quotes audio.cpp never quotes us instead.
OWN_LINE = "[forensics_workshop]"
BUILD_LOG_HINT = "get_sam.bat writes its build log to logs\\get_sam-build.log."

_VERSION_CACHE: dict = {}


def timeout_for(duration_s: float) -> float:
    """Seconds before a seed's run is called hung: 15 minutes plus 30 s per
    second of audio. Speed on the 3080 Ti is unmeasured; this catches a hang,
    it is not a performance budget."""
    return 900.0 + 30.0 * max(0.0, float(duration_s))


def memory_bounded_for(duration_s: float, requested: bool | None = None
                       ) -> tuple[bool, str]:
    """(use bounded mode, why) — `requested` overrides the automatic rule."""
    if requested is not None:
        return bool(requested), "set by the examiner"
    if duration_s > MEMORY_BOUNDED_ABOVE_S:
        return True, (f"automatic: {duration_s:.1f} s is longer than "
                      f"{MEMORY_BOUNDED_ABOVE_S:g} s, twice the only measured "
                      "clip length")
    return False, (f"automatic: {duration_s:.1f} s is within "
                   f"{MEMORY_BOUNDED_ABOVE_S:g} s")


def runtime_argv(audiocpp) -> list[str]:
    """The command that starts the runtime: an executable path, or an argv
    prefix (`[python, fake_cli.py]` — how the suite drives a fake through
    the very same subprocess path)."""
    if isinstance(audiocpp, (list, tuple)):
        if not audiocpp:
            raise MediaError("No audio.cpp runtime was given. " + INSTALL_HINT)
        return [os.fspath(a) for a in audiocpp]
    if not audiocpp:
        raise MediaError("No audio.cpp runtime was given. " + INSTALL_HINT)
    return [os.fspath(audiocpp)]


def runtime_dir(audiocpp) -> Path:
    return Path(runtime_argv(audiocpp)[-1]).resolve().parent


def check_runtime(audiocpp) -> list[str]:
    argv = runtime_argv(audiocpp)
    exe = Path(argv[-1])
    if not exe.is_file():
        raise MediaError(f"audiocpp_cli is not at {exe}. {INSTALL_HINT}")
    return argv


def spec_override(audiocpp) -> Path | None:
    path = runtime_dir(audiocpp) / SPEC_OVERRIDE
    return path if path.is_file() else None


def build_info(audiocpp) -> dict:
    """What get_sam.bat recorded beside the exe (tag, commit, backend)."""
    path = runtime_dir(audiocpp) / BUILD_FILE
    info: dict = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                key, sep, value = line.strip().partition("=")
                if sep:
                    info[key.strip()] = value.strip()
    except FileNotFoundError:
        return {}
    except OSError as exc:
        return {"error": f"{path} could not be read: {exc}"}
    return info


def default_backend(audiocpp) -> str:
    """The backend get_sam.bat built (it falls back to Vulkan, then CPU, when
    CUDA cannot be built), else CUDA."""
    built = build_info(audiocpp).get("backend", "")
    return built if built in ("cuda", "vulkan", "cpu") else DEFAULT_BACKEND


def backend_label(backend: str) -> str:
    """`CUDA (GPU)`, `Vulkan (GPU)`, `CPU — no GPU` — for every sentence that
    says where SAM is running, so none of them says "GPU" by habit."""
    name = str(backend or "").lower()
    if name in GPU_BACKENDS:
        return {"cuda": "CUDA", "vulkan": "Vulkan", "metal": "Metal"}[name] \
            + " (GPU)"
    if name == "cpu":
        return "CPU — no GPU"
    return f"{backend or 'unknown'} (backend)"


def build_sentence(audiocpp) -> str:
    """What get_sam.bat recorded, in one line: backend, tag, when, and — for
    a fallback build — why the GPU build did not happen."""
    info = build_info(audiocpp)
    if info.get("error"):
        return info["error"]
    if not info:
        return (f"no {BUILD_FILE} beside audiocpp_cli, so its backend is "
                "unknown (it will be asked for CUDA)")
    parts = [f"built for {info.get('backend', '?')}"]
    if info.get("tag"):
        parts.append(info["tag"])
    if info.get("built"):
        parts.append(f"on {info['built']}")
    out = ", ".join(parts)
    why = info.get("gpu_build", "")
    return f"{out} — GPU build: {why}" if why else out


def require_gpu(backend: str, audiocpp, allow_cpu: bool = False) -> None:
    """Refuse a CPU run unless it was asked for, with the sentence saying
    what to do. Called before anything is written."""
    if str(backend).lower() != "cpu" or allow_cpu:
        return
    raise MediaError(
        "SAM Audio refuses to run on the CPU: this audiocpp_cli was "
        f"{build_sentence(audiocpp)}. On a CPU, SAM takes hours for a minute "
        "of audio and the GPU is never touched. Install the NVIDIA CUDA "
        "Toolkit (with Visual Studio 2022's C++ tools), then run "
        "get_sam.bat /rebuild — " + BUILD_LOG_HINT + " To run on the CPU "
        "anyway, ask for it explicitly (engine CLI: --allow-cpu).")


def scratch_path(audiocpp) -> Path:
    """The runtime's TMP/TEMP: `tmp\\` beside audiocpp_cli, inside ATK."""
    return runtime_dir(audiocpp) / SCRATCH


def assert_runtime_scratch(audiocpp, target) -> Path:
    """The run-time guard for `make_scratch`: the target is exactly the
    scratch folder beside this runtime, and not inside a case."""
    expected = scratch_path(audiocpp)
    if os.path.normcase(os.path.abspath(os.fspath(target))) != \
            os.path.normcase(os.path.abspath(os.fspath(expected))):
        raise MediaError(f"Refusing to make {target}: the runtime's temp "
                         f"folder is only ever {expected}.")
    for parent in [expected, *expected.parents]:
        if (parent / "case.json").is_file():
            raise MediaError(f"Refusing a runtime temp folder inside the case "
                             f"at {parent}; move audiocpp_cli out of the case.")
    return expected


def make_scratch(audiocpp) -> Path:
    """Make (once) the folder the child gets as TMP/TEMP — never %TEMP% in
    the Windows profile."""
    target = assert_runtime_scratch(audiocpp, scratch_path(audiocpp))
    target.mkdir(parents=True, exist_ok=True)
    return target


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


def runtime_version(audiocpp) -> str:
    """`audiocpp_cli --version` (build version, commit, backends), cached per
    executable and modification time."""
    argv = runtime_argv(audiocpp)
    target = argv[-1]
    try:
        st = os.stat(target)
        key = (os.path.abspath(target), st.st_mtime_ns, st.st_size, tuple(argv))
    except OSError as exc:
        return f"unknown ({exc})"
    if key not in _VERSION_CACHE:
        _VERSION_CACHE[key] = probe_version(argv, "--version")
    return _VERSION_CACHE[key]


#: Windows' crash codes (NTSTATUS) for the ways a native child dies, said in
#: words. Python reports them as the unsigned 32-bit exit code.
NTSTATUS = {
    0xC0000135: "a DLL it needs was not found (most often the CUDA runtime or "
                "the MSVC/OpenMP runtime) — run get_sam.bat again",
    0xC0000005: "it crashed with an access violation — often a model file it "
                "cannot read correctly, or a GPU driver fault",
    0xC0000409: "it stopped itself (a fail-fast: an assertion or abort inside "
                "the runtime — the log's last lines say where)",
    0x40000015: "it called abort() — the log's last lines say why",
    0xC000001D: "an illegal instruction: it was built for a CPU feature this "
                "machine lacks (AVX2/AVX-512) — run get_sam.bat /rebuild here",
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


def _windows() -> bool:
    return sys.platform == "win32"


def _short_path(path: str) -> str | None:
    """The 8.3 short name of an existing path (Windows), or None."""
    if not _windows():
        return None
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get = k32.GetShortPathNameW
    get.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, wintypes.DWORD]
    get.restype = wintypes.DWORD
    size = get(path, None, 0)
    if not size:
        return None
    buf = ctypes.create_unicode_buffer(size)
    return buf.value if get(path, buf, size) else None


def ansi_path(path) -> str:
    """A path audiocpp_cli can open.

    audio.cpp v0.9.0 takes its arguments through `wmain`, converts them to
    UTF-8, and then opens files with `std::filesystem::path` built from that
    narrow string — which MSVC reads in the ANSI code page. A path with
    characters outside ASCII therefore names a file that does not exist. On
    Windows such a path is replaced by its 8.3 short name when the volume
    keeps one; otherwise it is refused with a sentence, never sent garbled.
    """
    text = os.fspath(path)
    if not _windows() or text.isascii():
        return text
    short = _short_path(text)
    if short and short.isascii():
        return short
    raise MediaError(
        f"{text} contains characters outside plain ASCII, and audio.cpp on "
        "Windows opens files through the ANSI code page, so it would look for "
        "a file that does not exist (and this volume has no short 8.3 name to "
        "use instead). Move the case or the model to a folder whose path is "
        "plain letters and digits, or rename it.")


def require_text(text) -> str:
    """The description, stripped — or the sentence saying why there must be
    one: audio.cpp's SAM port requires --text even when anchors are given."""
    words = (text or "").strip()
    if not words:
        raise MediaError(
            "SAM Audio needs a text description of the sound — even with "
            "anchors, audio.cpp's port requires --text (e.g. \"man speaking\", "
            "\"woman in the background\").")
    return words


def build_command(audiocpp, *, model, input_wav, out_dir, text: str, seed: int,
                  anchors=(), memory_bounded: bool = False, spec=None,
                  backend: str = DEFAULT_BACKEND, steps: int | None = None,
                  threads: int | None = None) -> list[str]:
    """The exact argv for one seed. Pure: nothing is checked on disk here,
    so the suite can hold every flag to the pinned documentation."""
    words = require_text(text)
    if backend not in ("cpu", "cuda", "vulkan", "metal", "best"):
        raise MediaError(f"{backend!r} is not an audio.cpp backend.")
    argv = runtime_argv(audiocpp) + [
        "--task", TASK, "--family", FAMILY,
        "--model", os.fspath(model), "--backend", backend,
        "--audio", os.fspath(input_wav), "--text", words,
        "--seed", str(int(seed)),
        "--out-dir", os.fspath(out_dir), "--out-format", OUT_FORMAT,
        "--log", "--metrics"]
    checked = _sep.check_anchors(anchors)
    if checked:
        spans = json.dumps([a.as_list() for a in checked],
                           separators=(",", ":"))
        argv += ["--request-option", f"anchors={spans}"]
    if steps is not None:
        if int(steps) < 1:
            raise MediaError("Inference steps must be at least 1.")
        argv += ["--request-option", f"num_inference_steps={int(steps)}"]
    if threads is not None:
        argv += ["--threads", str(int(threads))]
    if memory_bounded:
        if spec is None:
            raise MediaError(
                "Memory-bounded mode needs model_specs\\sam_audio.json beside "
                "audiocpp_cli (the GGUFs predate the option). " + INSTALL_HINT)
        argv += ["--model-spec-override", os.fspath(spec),
                 "--session-option", "sam_audio.memory_bounded=true"]
    return argv


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
    """The last lines of a run's log — what audio.cpp said before it stopped
    (never this package's own closing line)."""
    return " / ".join(_log_lines(path)[-lines:])


def last_line(path) -> str:
    """The last thing the CHILD wrote, its `[TIMING ts=…]` stamp removed —
    "" while it has printed nothing but the command line."""
    kept = [l for l in _log_lines(path) if not l.startswith("$ ")]
    return _LOG_PREFIX.sub("", kept[-1])[:160] if kept else ""


class SamAudioSeparator(_sep.PromptedSeparator):
    """The prompted separator over `audiocpp_cli`."""

    name = "sam_audio (audio.cpp)"
    tier = "invented"

    def __init__(self, audiocpp, model, *, backend: str | None = None,
                 steps: int | None = None, threads: int | None = None,
                 allow_cpu: bool = False) -> None:
        self.audiocpp = audiocpp
        self.model = Path(model)
        self.backend = backend or default_backend(audiocpp)
        self.steps = steps
        self.threads = threads
        self.allow_cpu = bool(allow_cpu)

    def check_backend(self) -> None:
        """Refuse a CPU backend unless asked for (see the module notes)."""
        require_gpu(self.backend, self.audiocpp, self.allow_cpu)

    def describe(self) -> dict:
        return {"tool": "audiocpp_cli", "family": FAMILY, "task": TASK,
                "pinned_tag": PINNED_TAG, "pinned_commit": PINNED_COMMIT,
                "docs": DOCS_URL, "version": runtime_version(self.audiocpp),
                "build": build_info(self.audiocpp), "backend": self.backend,
                "backend_label": backend_label(self.backend),
                "scratch": os.fspath(scratch_path(self.audiocpp)),
                "model": os.fspath(self.model), "out_format": OUT_FORMAT,
                "tier": self.tier}

    def separate(self, input_wav, *, text=None, anchors=(), seed: int,
                 out_dir, log, guard, should_cancel=None,
                 duration_s: float = 0.0, memory_bounded: bool | None = None,
                 timeout_s: float | None = None, heartbeat=None,
                 **_options) -> dict:
        """One seed. `heartbeat(elapsed_s, last_line)` is called every few
        seconds while audio.cpp runs, with the last line it wrote."""
        check_runtime(self.audiocpp)
        self.check_backend()
        if not self.model.is_file():
            raise MediaError(f"The model file {self.model} does not exist. "
                             + INSTALL_HINT)
        bounded, why = memory_bounded_for(duration_s, memory_bounded)
        spec = spec_override(self.audiocpp) if bounded else None
        note = ""
        if bounded and spec is None and memory_bounded is None:
            bounded, note = False, (
                "memory-bounded mode was wanted but model_specs\\sam_audio.json "
                "is not beside audiocpp_cli, so the default mode ran — a long "
                "clip may run out of GPU memory. " + INSTALL_HINT)
        argv = build_command(self.audiocpp, model=ansi_path(self.model),
                             input_wav=ansi_path(input_wav),
                             out_dir=ansi_path(out_dir), text=text,
                             seed=seed, anchors=anchors,
                             memory_bounded=bounded,
                             spec=ansi_path(spec) if spec else None,
                             backend=self.backend, steps=self.steps,
                             threads=self.threads)
        limit = timeout_s if timeout_s is not None else timeout_for(duration_s)
        scratch = make_scratch(self.audiocpp)
        log_path = getattr(log, "name", None)
        beat = None
        if heartbeat is not None:
            def beat(elapsed):
                heartbeat(elapsed, last_line(log_path)
                          if isinstance(log_path, (str, os.PathLike)) else "")
        outcome = run_process(argv, log=log, timeout_s=limit,
                              writes=[out_dir], guard=guard,
                              should_cancel=should_cancel,
                              cwd=os.fspath(runtime_dir(self.audiocpp)),
                              env=child_env(scratch), heartbeat=beat)
        out = Path(out_dir)
        return {"target": os.fspath(out / "target.wav"),
                "residual": os.fspath(out / "residual.wav"),
                "argv": argv, "returncode": outcome["returncode"],
                "state": outcome["state"], "error": outcome["error"],
                "elapsed_s": outcome["elapsed_s"], "timeout_s": limit,
                "tool": "audiocpp_cli", "tool_version":
                    runtime_version(self.audiocpp),
                "tier": self.tier,
                "params": {"family": FAMILY, "task": TASK,
                           "text": (text or "").strip(),
                           "anchors": [a.as_list() for a in
                                       _sep.check_anchors(anchors)],
                           "backend": self.backend,
                           "scratch": os.fspath(scratch),
                           "out_format": OUT_FORMAT,
                           "num_inference_steps": self.steps,
                           "memory_bounded": bounded,
                           "memory_bounded_why": why, "note": note,
                           "spec_override": os.fspath(spec) if spec else None}}
