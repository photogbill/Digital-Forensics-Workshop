# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The honest capability table, as data — and the licence rule it obeys.

FORENSICS_PLAN.md §1 is the most useful page of the plan because it says,
for every capability, whether it is native Python against a documented
format or someone else's code with a licence attached — and which ones are
deliberately NOT offered. This module is that table, live: each row says
whether the capability is BUILT in this tree, and for a third-party one,
whether its package is present.

This is ATK's third unavailable state — "loaded, but a capability is
missing" — and it is a table rather than an error page because it is not a
failure. A workshop with no E01 reader is a working workshop that cannot
open E01 files yet, and it should say exactly that.

    available          built here and its module imports
    failed-to-load     built here, and importing it raised — the error is shown
    planned            not built yet; the phase it belongs to is named
    deferred           deliberately postponed, and said so rather than
                       half-supported
    out-of-scope       not offered in v1
    excluded           a third-party route that FAILS THE LICENCE RULE. It is
                       listed, with the licence that fails, so that nobody
                       adds it later without knowing

**THE LICENCE RULE — Bill, 2026-09-11: nothing that restricts commercial
use.** A third-party route is admissible only when its licence, and the
licence of everything it pulls in or bundles, passes `licence_permits`:
permissive licences only. That shuts out copyleft of every strength (GPL,
AGPL, LGPL, MPL, EPL, the IBM and Common Public Licences, the Volatility
Software License) and every non-commercial or source-available licence. It is
an ALLOWLIST, so a licence nobody has checked is refused rather than waved
through. FORENSICS_PLAN.md §1.1 says why LGPL is on the wrong side of it.

The engine imports nothing outside the standard library
(`tests/test_isolation.py`), so today the rule decides what is PLANNED: E01,
shadow copies and ESE are written natively because the libraries that read
them fail it. It also decides where code comes from — a format is implemented
from its documentation, never copied or translated from an excluded project.

For a third-party row the `package` column is probed with `find_spec` —
presence only, never an import, so a heavy or broken package cannot slow
or break this table. An excluded package that happens to be installed is
reported present, and is still never used.
"""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import asdict, dataclass

STATUSES = ("available", "failed-to-load", "planned", "deferred",
            "out-of-scope", "excluded")

#: SPDX identifiers that pass the licence rule. Permissive only; an addition
#: here is a decision, and FORENSICS_PLAN.md §1.1 is where it is recorded.
PERMISSIVE_LICENCES = frozenset({
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "HPND",
    "ISC", "MIT", "MIT-CMU", "PSF-2.0", "Python-2.0", "Unlicense", "Zlib",
})


def licence_permits(expression: str) -> bool:
    """True when an SPDX-style licence expression passes the licence rule.

    `A OR B` passes when either side does: a dual licence lets the user
    choose. `A AND B` passes only when both do: a package that bundles B
    carries B. Parentheses are not parsed, so an expression that uses them
    fails — as does anything unrecognised. Refusing by default is the point.
    """
    text = (expression or "").strip()
    if not text:
        return False
    for alternative in text.split(" OR "):
        if all(term.strip() in PERMISSIVE_LICENCES
               for term in alternative.split(" AND ")):
            return True
    return False


@dataclass(frozen=True)
class Capability:
    id: str
    label: str
    phase: int
    how: str                  # native | third-party | atk
    module: str               # the module that implements it, when built
    package: str              # third-party import name, when there is one
    licence: str
    status: str
    package_present: bool | None
    note: str

    def as_dict(self) -> dict:
        return asdict(self)


#: (id, label, phase, how, module-if-built, package, licence, planned-status, note)
_TABLE = (
    ("hashing", "Hashing (MD5, SHA-1, SHA-256)", 1, "native",
     "forensics_workshop.hashing", "", "", "planned",
     "One pass computes all three."),
    ("case", "Case store and custody log", 1, "native",
     "forensics_workshop.case", "", "", "planned",
     "Append-only, fsynced, hash-chained."),
    ("readonly", "Read-only evidence access and its ratchet", 1, "native",
     "forensics_workshop.blocker", "", "", "planned",
     "Structural: no write reaches evidence. NOT a hardware write blocker."),
    ("usb-policy", "USB WriteProtect policy, with verification", 1, "native",
     "forensics_workshop.blocker", "", "", "planned",
     "Windows only, needs elevation, USB mass storage only; verified by an "
     "attempted write to a test device."),
    ("logical", "Logical folder ingest", 1, "native",
     "forensics_workshop.ingest", "", "", "planned",
     "Measures last-access changes rather than promising none."),
    ("filetype", "File type by signature, extension mismatch", 1, "native",
     "forensics_workshop.filetype", "", "", "planned",
     "Bytes decide; the name is compared, never believed."),
    ("dedupe", "Duplicates by hash", 1, "native",
     "forensics_workshop.manifest", "", "", "planned", ""),
    ("browser", "Browser history, downloads, searches, cookies", 1, "native",
     "forensics_workshop.artefacts.browser", "", "", "planned",
     "Chromium family and Firefox. WAL-aware. Cookie values not decrypted."),
    ("raw", "RAW/DD image reading, single and split", 2, "native",
     "forensics_workshop.image", "", "", "planned",
     "Containers that are not raw (E01, VHDX, VMDK, dynamic VHD) are refused "
     "by signature, with the reason. Fixed VHD accepted, footer excluded."),
    ("partitions", "MBR/GPT partition tables", 2, "native",
     "forensics_workshop.partitions", "", "", "planned",
     "CRCs and the backup GPT checked; unpartitioned gaps reported."),
    ("ntfs", "NTFS $MFT, ADS, deleted entries", 2, "native",
     "forensics_workshop.ntfs", "", "", "planned",
     "Fixups checked; paths checked against parent sequence numbers; a "
     "deleted file's clusters measured against $Bitmap. Compressed and "
     "EFS-encrypted content refused, not returned."),
    ("timestomp", "Timestamp indicators ($STANDARD_INFORMATION vs $FILE_NAME)",
     2, "native", "forensics_workshop.ntfs", "", "", "planned",
     "Measurements with their benign explanations, never conclusions."),
    ("usnjrnl", "NTFS change journal ($UsnJrnl:$J)", 2, "native",
     "forensics_workshop.usn", "", "", "planned",
     "USN_RECORD V2/V3/V4. Checked against synthetic records only: no "
     "Windows-written journal has been parsed yet."),
    ("slack", "File slack and unallocated space", 2, "native",
     "forensics_workshop.diskimage", "", "", "planned",
     "Slack regions holding data are indexed; unallocated space is carved."),
    ("fat", "FAT/exFAT", 2, "native", "", "", "", "planned",
     "Volumes are identified and can be carved; their directories are not "
     "parsed yet."),
    ("carving", "Signature carving with preview", 2, "native",
     "forensics_workshop.carve", "", "", "planned",
     "Every candidate carries the basis of its length and previews before "
     "anything is written."),
    ("ewf", "E01/EWF images", 2, "native", "", "", "", "planned",
     "Refused today, with the reason. To be read natively from the format's "
     "documentation, decompressing with the standard library's zlib: pyewf "
     "fails the licence rule."),
    ("vdisk", "VHDX, VMDK and dynamic VHD images", 2, "native", "", "", "",
     "planned",
     "Refused today, with the reason; a fixed VHD is already read. Native from "
     "the published specifications: pyvhdi and pyvmdk fail the licence rule."),
    ("ext4", "ext4 inodes and orphan recovery", 2, "native", "", "", "",
     "planned", "Extent trees are the work."),
    ("domex", "Document metadata, EXIF, OCR, steganalysis", 3, "atk", "", "",
     "", "planned", "Extends ATK's existing forensics.py and ocr.py."),
    ("transcripts", "Audio and video through Whisper", 3, "atk", "", "", "",
     "planned", "Tagged by task, not detected language."),
    ("hunts", "Hunts across documents, images and transcripts", 3, "atk",
     "", "", "", "planned",
     "The shared hunt engine; findings confirmed by the analyst."),
    ("registry", "Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER)", 4,
     "native", "", "", "", "planned", ""),
    ("prefetch", "Prefetch (including Win10+ MAM compression)", 4, "native",
     "", "", "", "planned", "MAM via RtlDecompressBufferEx through ctypes."),
    ("lnk", "LNK and Jump Lists", 4, "native", "", "", "", "planned", ""),
    ("ese", "ESE databases (SRUM, Windows Search)", 4, "native", "", "", "",
     "planned", "Native, from the format's documentation: pyesedb fails the "
     "licence rule."),
    ("vss", "Volume Shadow Copies", 4, "native", "", "", "", "planned",
     "Offline, from an image, native: pyvshadow fails the licence rule."),
    ("timeline", "Super timeline and IOC export", 4, "native", "", "", "",
     "planned", "STIX only if a consumer for it exists."),
    ("memory", "Memory analysis", 5, "native", "", "", "", "deferred",
     "No route passes the licence rule — Volatility 3 and MemProcFS are both "
     "copyleft — so it waits for a native reader, and for Phases 1-4 to be "
     "solid."),
    ("fde-detect", "Encrypted volume detection (BitLocker, LUKS)", 2,
     "native", "forensics_workshop.partitions", "", "", "planned",
     "By signature at the start of each volume. VeraCrypt is designed to "
     "have none."),
    ("apfs", "APFS", 0, "native", "", "", "", "deferred",
     "Genuinely hard; deferred rather than half-supported. Native when it "
     "comes: pyfsapfs fails the licence rule."),
    ("fde-decrypt", "Encrypted volume decryption and key extraction", 0,
     "native", "", "", "", "out-of-scope", "Detection yes; decryption later."),
    ("mobile", "Mobile device acquisition", 0, "third-party", "", "", "",
     "out-of-scope", ""),

    # Routes that fail the licence rule. Each names the licence that fails
    # and what the capability does instead; none is ever built or imported.
    ("pyewf", "pyewf (libewf): E01 reading", 0, "third-party", "", "pyewf",
     "LGPL-3.0-or-later", "excluded", "Copyleft. E01 is planned natively."),
    ("pyvhdi", "pyvhdi and pyvmdk (libvhdi, libvmdk): VHDX and VMDK", 0,
     "third-party", "", "pyvhdi", "LGPL-3.0-or-later", "excluded",
     "Copyleft, both. Virtual disks are planned natively."),
    ("pytsk3", "pytsk3 (The Sleuth Kit): file system coverage", 0,
     "third-party", "", "pytsk3", "Apache-2.0 AND IPL-1.0 AND CPL-1.0",
     "excluded",
     "The bindings are Apache-2.0, but they build in The Sleuth Kit, whose "
     "IPL and CPL terms are copyleft. File systems are added natively."),
    ("pyvshadow", "pyvshadow (libvshadow): Volume Shadow Copies", 0,
     "third-party", "", "pyvshadow", "LGPL-3.0-or-later", "excluded",
     "Copyleft. Shadow copies are planned natively (Phase 4)."),
    ("pyesedb", "pyesedb (libesedb): ESE databases", 0, "third-party", "",
     "pyesedb", "LGPL-3.0-or-later", "excluded",
     "Copyleft. ESE is planned natively (Phase 4)."),
    ("pyfsapfs", "pyfsapfs (libfsapfs): APFS", 0, "third-party", "",
     "pyfsapfs", "LGPL-3.0-or-later", "excluded",
     "Copyleft. APFS stays deferred."),
    ("volatility3", "Volatility 3: memory analysis", 0, "third-party", "",
     "volatility3", "LicenseRef-Volatility-Software-License-1.0", "excluded",
     "Copyleft, under its own licence. Memory analysis is deferred."),
    ("memprocfs", "MemProcFS: memory analysis", 0, "third-party", "",
     "memprocfs", "AGPL-3.0", "excluded",
     "Network copyleft. Memory analysis is deferred."),
)


def capabilities() -> list[Capability]:
    out = []
    for cid, label, phase, how, module, package, licence, status, note in _TABLE:
        present = None
        if package:
            try:
                present = importlib.util.find_spec(package) is not None
            except (ImportError, ValueError):
                present = False
            if status != "excluded" and not licence_permits(licence):
                # A row added without checking is shown as what it is.
                status = "excluded"
                named = licence or "no licence recorded"
                note = f"Fails the licence rule ({named}). {note}".strip()
        if module:
            try:
                importlib.import_module(module)
                status = "available"
            except Exception as exc:                  # noqa: BLE001
                status = "failed-to-load"
                note = f"{type(exc).__name__}: {exc}"
        out.append(Capability(cid, label, phase, how, module, package,
                              licence, status, present, note))
    return out
