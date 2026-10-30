# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Every forensics test, one command (run_tests.bat) — Bill, 2026-10-30.

Runs, one after another:
  1. this engine's whole suite (standard library unittest);
  2. ATK's Digital Forensics tests (the workspace, the pages built for real
     in Qt, the model hunts, the optional-subsystem airlock, the Cellular
     page) with ATK's own Python and pytest — when ATK sits beside this
     folder;
  3. with /all, the rest of ATK's suite too.

Everything each part prints goes to logs\\tests\\tests_<date>.txt in this
folder; the screen gets one line per part and a total at the bottom. A part
that cannot run (no ATK beside this folder, no pytest) says why and is
counted as not run, never as passed.

Scratch files go in test_tmp\ in this folder (TEMP/TMP/TMPDIR point
there for the tests) and are deleted at the end — nothing on C:\ or in
the user profile.

Optional third-party samples (real registry hives, event logs, mailboxes,
FAT images) are compared when DFW_SAMPLES names their folder; without it
those tests skip and say so.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ATK = ROOT.parent / "ATK"
ATK_FORENSICS = ("test_dfw_workspace.py", "test_dfw_pages_build.py",
                 "test_dfw_ai.py", "test_optional_subsystems.py",
                 "test_cellular_page.py")


def _env_python(root: Path) -> list[Path]:
    return [p for p in (root / "envs" / "atk_core" / "Scripts" / "python.exe",
                        root / "envs" / "atk_core" / "bin" / "python")
            if p.is_file()]


def atk_pythons() -> list[Path]:
    """Pythons that can run ATK's tests, best first: ATK's own environment;
    then an INSTALLED copy's environment beside it (ATK - Current_test, say —
    used to run the tests and never written to: no bytecode, no cache, no
    installs); then ATK's bare interpreter (.python), which has no Qt."""
    out = _env_python(ATK)
    for sibling in sorted(ROOT.parent.glob("ATK*")):
        if sibling.is_dir() and sibling.resolve() != ATK.resolve():
            out += _env_python(sibling)
    bare = ATK / ".python" / "python.exe"
    if bare.is_file():
        out.append(bare)
    return out


def atk_python() -> Path | None:
    found = atk_pythons()
    return found[0] if found else None


def has_pytest(py) -> str:
    """'' when `py` runs and has pytest, else why not."""
    try:
        r = subprocess.run([str(py), "-c", "import pytest"], capture_output=True)
    except OSError as exc:
        return f"ATK's Python ({py}) could not be started here: {exc}"
    if r.returncode != 0:
        return (f'pytest is not in ATK\'s Python. To add it: "{py}" -m pip '
                "install pytest")
    return ""


def run(label, argv, cwd, log, env) -> dict:
    print(f"  {label} ...", flush=True)
    log.write(f"\n{'=' * 78}\n{label}\n$ {' '.join(map(str, argv))}\n"
              f"{'=' * 78}\n")
    log.flush()
    t = time.monotonic()
    proc = subprocess.run([str(a) for a in argv], cwd=str(cwd), env=env,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    text = proc.stdout.decode("utf-8", "replace")
    log.write(text)
    log.flush()
    out = {"label": label, "rc": proc.returncode, "seconds": time.monotonic() - t,
           "passed": 0, "failed": 0, "skipped": 0, "errors": 0}
    m = re.search(r"Ran (\d+) tests?", text)                  # unittest
    if m:
        ran = int(m.group(1))
        f = re.search(r"failures=(\d+)", text)
        e = re.search(r"errors=(\d+)", text)
        s = re.search(r"skipped=(\d+)", text)
        out["failed"] = int(f.group(1)) if f else 0
        out["errors"] = int(e.group(1)) if e else 0
        out["skipped"] = int(s.group(1)) if s else 0
        out["passed"] = ran - out["failed"] - out["errors"] - out["skipped"]
    else:                                                     # pytest
        for key, word in (("passed", "passed"), ("failed", "failed"),
                          ("skipped", "skipped"), ("errors", "error")):
            m = re.search(rf"(\d+) {word}", text.splitlines()[-1] if text else "")
            if m:
                out[key] = int(m.group(1))
    failing = re.findall(r"^(?:FAIL|ERROR): (\S+) \(", text, re.M) + \
        re.findall(r"^FAILED (\S+::\S+)", text, re.M)
    seen: list = []
    for name in failing:                  # a sub-test fails once per case
        if name not in seen:
            seen.append(name)
    out["failing"] = seen[:25]
    return out


def main(argv) -> int:
    everything = "/all" in [a.lower() for a in argv]
    logdir = ROOT / "logs" / "tests"
    logdir.mkdir(parents=True, exist_ok=True)
    log_path = logdir / f"tests_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    # Every scratch file the tests make (their temporary cases, images and
    # folders) goes HERE, beside the code on D:, never to C:\ or the user
    # profile (%TEMP% is under AppData): TEMP/TMP/TMPDIR point the tests'
    # tempfile at test_tmp\, which is emptied before and after the run.
    scratch = ROOT / "test_tmp"
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir()
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", TEMP=str(scratch),
               TMP=str(scratch), TMPDIR=str(scratch))
    results, notes = [], []
    print(f"Forensics tests — {time.strftime('%Y-%m-%d %H:%M')}")
    with open(log_path, "w", encoding="utf-8") as log:
        log.write(f"Python {sys.version}\nWorkshop: {ROOT}\nATK: {ATK}\n"
                  f"DFW_SAMPLES: {os.environ.get('DFW_SAMPLES') or '(not set)'}\n")
        results.append(run("1. Engine (Digital Forensics Workshop)",
                           [sys.executable, "-m", "unittest", "discover", "-v",
                            "-s", "tests", "-p", "test_*.py"], ROOT, log, env))
        candidates = atk_pythons()
        py = next((c for c in candidates if not has_pytest(c)), None)
        bare = ATK / ".python" / "python.exe"
        if py is None and bare.is_file() and sys.stdin.isatty():
            print("\n  ATK's tests need pytest, and no ATK Python here has it.")
            print(f"  It can be added to ATK's own interpreter ({bare}) —")
            print("  one download, MIT licensed, nothing else changes.")
            answer = input("  Add pytest now? [Y/N] ").strip().lower()
            if answer.startswith("y"):
                r = subprocess.run([str(bare), "-m", "pip", "install", "pytest"],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                log.write("\n$ pip install pytest\n"
                          + r.stdout.decode("utf-8", "replace"))
                if not has_pytest(bare):
                    py = bare
                    print("  pytest added.\n")
                else:
                    print("  pip could not add it — see the log.\n")
        if not ATK.is_dir():
            notes.append(f"ATK not found at {ATK}: its forensics tests were NOT run.")
        elif not candidates:
            notes.append("No ATK Python was found (envs\\atk_core or .python): "
                         "run ATK's install.bat first. ATK's forensics tests were "
                         "NOT run.")
        elif py is None:
            notes.append(has_pytest(candidates[-1]) + " — ATK's forensics tests "
                         "were NOT run.")
        else:
            log.write(f"\nATK's tests run with: {py}\n")
            print(f"  (ATK's tests with {py})")
            tests = [f"tests/{n}" for n in ATK_FORENSICS if (ATK / "tests" / n).is_file()]
            results.append(run("2. ATK Digital Forensics workspace",
                               [py, "-m", "pytest", "-q", "-rs", "-p",
                                "no:cacheprovider", *tests], ATK, log, env))
            if everything:
                results.append(run("3. ATK — the whole suite",
                                   [py, "-m", "pytest", "-q", "-rs", "-p",
                                    "no:cacheprovider", "tests"], ATK, log, env))
        for n in notes:
            log.write(f"\nNOTE: {n}\n")
    shutil.rmtree(scratch, ignore_errors=True)
    print()
    total = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    for r in results:
        ok = r["rc"] == 0
        print(f"  [{'OK  ' if ok else 'FAIL'}] {r['label']}: {r['passed']:,} passed, "
              f"{r['failed'] + r['errors']:,} failed, {r['skipped']:,} skipped "
              f"({r['seconds']:.0f} s)")
        for name in r["failing"]:
            print(f"           failing: {name}")
        for k in total:
            total[k] += r[k]
    for n in notes:
        print(f"  [NOT RUN] {n}")
    print("  " + "-" * 70)
    bad = total["failed"] + total["errors"]
    all_ok = all(r["rc"] == 0 for r in results) and not notes
    print(f"  TOTAL: {total['passed']:,} passed, {bad:,} failed, "
          f"{total['skipped']:,} skipped — "
          + ("ALL PASSED" if all_ok else
             "SOMETHING FAILED OR DID NOT RUN" if bad or notes else
             "A PART ENDED WITH AN ERROR"))
    print(f"\n  Full output: {log_path}")
    print("  (Skipped tests need tools or samples this machine does not have; "
          "the log names each one and why — search it for 'skipped'.)")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
