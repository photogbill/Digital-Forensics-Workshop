"""Build a synthetic evidence folder to point the workshop at.

    python samples\\build_samples.py              writes samples\\profile\\
    python samples\\build_samples.py D:\\scratch   writes D:\\scratch\\profile\\

Everything in it is invented: documents, a disguised ZIP named .jpg, a
duplicate photograph, random bytes, a hidden file, and Chrome and Firefox
databases — Chrome's with rows still sitting in its write-ahead log, which is
what a running browser leaves behind. Nothing here is, or came from, real
evidence, and `.gitignore` keeps whatever this writes out of the repository.

Then, for example:

    python -m forensics_workshop case new  D:\\cases\\DEMO --id DEMO-1 --examiner "Your Name"
    python -m forensics_workshop add       D:\\cases\\DEMO samples\\profile --examiner "Your Name"
    python -m forensics_workshop ingest    D:\\cases\\DEMO E001 --examiner "Your Name"
    python -m forensics_workshop browser   D:\\cases\\DEMO E001 --examiner "Your Name"
    python -m forensics_workshop artefacts D:\\cases\\DEMO E001 --examiner "Your Name"

Keep the case folder OUTSIDE the sample folder: the engine refuses a case
that sits inside its own evidence, and says why.

It also writes `disk\\laptop.001` … `.003`: a synthetic GPT disk, split in
three, holding an NTFS volume with a deleted spreadsheet, a file whose
timestamps were set by hand, an alternate data stream, text left in file
slack, a change journal, a PNG in unallocated clusters and a JPEG in the
unpartitioned space after the partition. Every one of those is invented too.

    python -m forensics_workshop add-image  D:\\cases\\DEMO samples\\disk\\laptop.001 --examiner "Your Name"
    python -m forensics_workshop image      D:\\cases\\DEMO E002 --examiner "Your Name"
    python -m forensics_workshop volumes    D:\\cases\\DEMO E002 --examiner "Your Name"
    python -m forensics_workshop ntfs       D:\\cases\\DEMO E002 --volume 2 --examiner "Your Name"
    python -m forensics_workshop entries    D:\\cases\\DEMO E002 --volume 2 --filter deleted --examiner "Your Name"
    python -m forensics_workshop carve      D:\\cases\\DEMO E002 --volume 2 --unallocated --examiner "Your Name"
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tests"))

import synth  # noqa: E402


def main(argv: list[str]) -> int:
    base = Path(argv[1]) if len(argv) > 1 else HERE
    target = base / "profile"
    if target.exists() or (base / "disk").exists():
        print(f"{target} or {base / 'disk'} already exists; remove it first "
              "or choose another folder. Nothing was changed.")
        return 1
    info = synth.build_corpus(target)
    print(f"wrote a synthetic profile to {target}")
    if not info["link_made"]:
        print("(no symlink: this account cannot create one — that part of "
              "the sample is skipped)")
    import test_disk_case  # noqa: E402  (the disk builder the suite uses)
    disk, _facts = test_disk_case.build_disk()
    folder = base / "disk"
    folder.mkdir()
    third = -(-len(disk) // 3)
    for i in range(3):
        (folder / f"laptop.{i + 1:03d}").write_bytes(disk[i * third:(i + 1) * third])
    print(f"wrote a synthetic split disk image to {folder} "
          f"({len(disk):,} bytes in 3 segments)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
