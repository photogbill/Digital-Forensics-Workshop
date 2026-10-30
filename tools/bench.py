# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""How fast is the engine on THIS machine? (2026-10-29)

Bill gave the call on speed: "make it the most badass and efficient setup".
The rule here is measure first — a C accelerator is built only where a
number on his machine says pure Python is the bottleneck. This script makes
those numbers. Run it with bench.bat; it needs nothing but the engine.

It measures, each against its own baseline where there is one:
  1. the three digests (MD5, SHA-1, SHA-256): one after another vs side by
     side — the imager and image hashing use side by side;
  2. reading an E01: inflating chunks one at a time vs on worker threads;
  3. each parser on synthetic files built from the specs: event-log
     records, registry keys, shortcuts, Prefetch, FAT directory entries;
     and, if DFW_SAMPLES names a folder of real samples, the same on those.

Scratch files go in bench_tmp\\ beside this folder's engine and are removed
at the end; the report is written to logs\\bench\\ in the Workshop folder.
Nothing touches C:\\ or the user profile.
"""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from forensics_workshop import __version__, ewfwrite, hashing, image  # noqa: E402

LINES: list[str] = []


def say(text: str = "") -> None:
    print(text, flush=True)
    LINES.append(text)


def rate(nbytes: int, seconds: float) -> str:
    return f"{nbytes / max(seconds, 1e-9) / 1e6:,.0f} MB/s"


def timed(fn, *a, **kw):
    t = time.perf_counter()
    out = fn(*a, **kw)
    return out, time.perf_counter() - t


def bench_digests(mb: int = 512) -> None:
    say(f"1. Digests over {mb} MB in memory")
    block = os.urandom(1 << 20)
    def one_after_another():
        hs = [hashlib.md5(), hashlib.sha1(), hashlib.sha256()]
        for _ in range(mb):
            for h in hs:
                h.update(block)
    def side_by_side():
        h = hashing.Hasher()
        for _ in range(mb):
            h.update(block)
    for name in ("md5", "sha1", "sha256"):
        h = hashlib.new(name)
        _r, s = timed(lambda: [h.update(block) for _ in range(mb)])
        say(f"   {name:8} alone            {rate(mb << 20, s)}")
    _r, s1 = timed(one_after_another)
    _r, s2 = timed(side_by_side)
    say(f"   all three, one after another {rate(mb << 20, s1)}")
    say(f"   all three, side by side      {rate(mb << 20, s2)}   "
        f"(x{s1 / max(s2, 1e-9):.2f})")


def bench_e01(scratch: Path, mb: int = 256) -> None:
    say(f"2. Reading a {mb} MB E01 (half random, half compressible)")
    size = mb << 20
    base = scratch / "bench"
    def opener(path):
        return open(path, "xb")                     # scratch, never evidence
    w = ewfwrite.EwfWriter(base, open_segment=opener, size=size)
    md5, sha1 = hashlib.md5(), hashlib.sha1()
    rnd = os.urandom(1 << 20)
    text = (b"the quick brown fox jumps over the lazy dog " * 30000)[:1 << 20]
    for i in range(mb):
        piece = rnd if i % 2 else text
        w.write(piece)
        md5.update(piece)
        sha1.update(piece)
    paths = w.finish(md5.digest(), sha1.digest())
    seg_bytes = sum(os.path.getsize(p) for p in paths)
    with image.ImageSource.open(paths[0]) as src:
        def two_reads():
            # the way before 2026-10-30: chunk by chunk, then the files again
            whole = hashing.Hasher()
            pos = 0
            while pos < src.size:
                d = src.read_at(pos, 1 << 20)
                whole.update(d)
                pos += len(d)
            for p in paths:
                h = hashing.Hasher()
                with open(p, "rb") as fh:
                    while True:
                        b = fh.read(1 << 20)
                        if not b:
                            break
                        h.update(b)
        _r, s0 = timed(two_reads)
        _r, s1 = timed(lambda: [src.read_at(o, 1 << 20)
                                for o in range(0, src.size, 1 << 20)])
        _r, s2 = timed(lambda: list(src._ewf.iter_stream()))
        (whole, _per), s3 = timed(image.hash_image, src)
    ok = whole.md5 == md5.hexdigest()
    say(f"   inflate only, one chunk at a time     {rate(size, s1)}")
    say(f"   inflate only, batched on threads      {rate(size, s2)}   "
        f"(x{s1 / max(s2, 1e-9):.2f})")
    say(f"   all digests, the old way (two reads)  {rate(size, s0)}")
    say(f"   all digests, one read (hash_image)    {rate(size, s3)}   "
        f"(x{s0 / max(s3, 1e-9):.2f})  MD5 {'matches' if ok else 'DOES NOT MATCH'}")
    say(f"   ({seg_bytes / 1e6:,.0f} MB of E01 files on disk for "
        f"{size / 1e6:,.0f} MB of disk)")


def bench_raw(scratch: Path, mb: int = 512) -> None:
    say(f"3. Hashing a {mb} MB RAW image (the file is in the OS cache, so this "
        "shows the CPU side; a real drive adds its own read speed)")
    path = scratch / "bench.dd"
    block = os.urandom(1 << 20)
    with open(path, "xb") as fh:
        for _ in range(mb):
            fh.write(block)
    def plain():
        h = hashing.Hasher()
        with open(path, "rb") as fh:
            while True:
                b = fh.read(1 << 20)
                if not b:
                    break
                h.update(b)
    _r, s1 = timed(plain)
    with image.ImageSource.open(path) as src:
        _r, s2 = timed(image.hash_image, src)
    say(f"   read, then hash, in turn           {rate(mb << 20, s1)}")
    say(f"   reading ahead while hashing        {rate(mb << 20, s2)}   "
        f"(x{s1 / max(s2, 1e-9):.2f})")


def bench_parsers() -> None:
    say("4. Parsers on synthetic files built from the specifications")
    import evtxsynth as xs
    import prefetchsynth as ps
    import regsynth as rs
    import shelllinksynth as ls
    import fatsynth as fs
    from forensics_workshop import evtx, fat, prefetch, registry, shelllink

    events = [xs.logon_4624(i + 1) for i in range(400)]
    log = xs.build([xs.chunk_of(events[i:i + 100]) for i in range(0, 400, 100)])
    (rows, s) = timed(lambda: [evtx.to_rows(evtx.open_evtx(log), source_path="b")
                               for _ in range(10)])
    say(f"   event log      {4000 / s:,.0f} records/s (rendered into rows)")

    b = rs.HiveBuilder()
    for i in range(300):
        k = b.root.path(f"Software\\Bench\\K{i}")
        for j in range(10):
            k.sz(f"v{j}", f"value {i} {j}")
    hive = bytes(b.build())
    _r, s = timed(lambda: [sum(1 for _ in registry.open_hive(hive).walk())
                           for _ in range(5)])
    say(f"   registry       {5 * 300 / s:,.0f} keys/s walked (10 values each)")

    lnk = ls.sample_lnk()
    _r, s = timed(lambda: [shelllink.to_rows(shelllink.parse_lnk(lnk), source_path="x")
                           for _ in range(2000)])
    say(f"   shortcuts      {2000 / s:,.0f} files/s")

    pf_plain = ps.build_scca(30, files=[(f"\\VOLUME{{1}}\\F{i}.DLL", (i + 100, 1))
                                        for i in range(200)])
    pf_mam = ps.mam(pf_plain)
    _r, s1 = timed(lambda: [prefetch.parse_prefetch(pf_plain) for _ in range(300)])
    _r, s2 = timed(lambda: [prefetch.parse_prefetch(pf_mam) for _ in range(300)])
    say(f"   Prefetch       {300 / s1:,.0f} files/s plain, {300 / s2:,.0f} files/s "
        "Windows 10 compressed (pure-Python decompressor)")

    v = fs.FatImage("FAT32", sectors=140000)
    v.mkdir("", fs.sfn("BENCH"), "bench", clusters=400)
    for i in range(2000):
        v.add_file("bench", fs.sfn(f"F{i:06d}", "TXT"), b"x" * 100, f"file {i}.txt")
    vol = bytes(v.build())

    class R:
        size = len(vol)
        @staticmethod
        def read_at(o, n):
            return vol[o:o + n]
    _r, s = timed(lambda: list(fat.open_fat(R).entries()))
    say(f"   FAT32          {2000 / s:,.0f} directory entries/s (long names)")


def main() -> int:
    logdir = ROOT / "logs" / "bench"
    logdir.mkdir(parents=True, exist_ok=True)
    # a fresh folder per run: a file an earlier run could not delete (held
    # open by a scanner, say) never stops this one
    shutil.rmtree(ROOT / "bench_tmp", ignore_errors=True)
    scratch = ROOT / "bench_tmp" / time.strftime("%Y%m%d_%H%M%S")
    scratch.mkdir(parents=True)
    say(f"Digital Forensics Workshop {__version__} — speed on this machine")
    say(f"{platform.platform()} · Python {platform.python_version()} · "
        f"{os.cpu_count()} logical cores · {time.strftime('%Y-%m-%d %H:%M')}")
    say()
    try:
        bench_digests()
        say()
        bench_e01(scratch)
        say()
        bench_raw(scratch)
        say()
        bench_parsers()
    finally:
        shutil.rmtree(ROOT / "bench_tmp", ignore_errors=True)
    out = logdir / f"bench_{time.strftime('%Y%m%d_%H%M%S')}.txt"
    out.write_text("\n".join(LINES) + "\n", encoding="utf-8")
    say()
    say(f"Saved to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
