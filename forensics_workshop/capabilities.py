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
licence of everything it pulls in or bundles, passes `licence_permits`: it
must permit commercial use of a closed, all-rights-reserved product with at
most a notice-and-replaceability obligation. Two tiers pass:

    - permissive (MIT, BSD, Apache-2.0, ISC, PSF, zlib …) — keep the notice;
    - weak / file-level copyleft (LGPL, MPL, EPL, and the IBM/Common Public
      Licences that cover the Sleuth Kit core) — commercial use is fine, the
      cost is shipping the library's licence text, publishing any changes you
      make TO THAT LIBRARY (never your own code), and leaving it replaceable.
      For Python that replaceability is automatic: packages import
      dynamically and the user can swap in their own build.

Excluded: whole-program copyleft (GPL, AGPL, and the Volatility Software
License, which requires publishing the source of software built WITH it) and
every non-commercial or source-available licence (PolyForm-NC, CC-BY-NC,
BUSL, SSPL). FORENSICS_PLAN.md §1.1 is the account. It is an ALLOWLIST, so a
licence nobody has checked is refused rather than waved through.

**Passing the rule is not the same as being used.** The engineering default
is native and standard-library-only (`tests/test_isolation.py`) — it runs in
a bare interpreter, installs nothing, and bundles no third-party licence
texts. A permitted library is reached for only where a native parser would be
a poor use of time (APFS is the standing example, via pyfsapfs). So E01,
shadow copies, ESE and the virtual-disk containers are PLANNED NATIVE with a
permitted library named as the alternative, not because the library is
forbidden. A format is implemented from its documentation, never copied or
translated from a GPL/AGPL project whose terms would reach this code.

For a third-party row the `package` column is probed with `find_spec` —
presence only, never an import, so a heavy or broken package cannot slow
or break this table.
"""

from __future__ import annotations

import importlib
import importlib.util
from dataclasses import asdict, dataclass

STATUSES = ("available", "failed-to-load", "planned", "deferred",
            "out-of-scope", "excluded")

#: Tier 1 — permissive. Notice only; no effect on our own code.
PERMISSIVE_LICENCES = frozenset({
    "0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "CC0-1.0", "HPND",
    "ISC", "MIT", "MIT-CMU", "PSF-2.0", "Python-2.0", "Unlicense", "Zlib",
})

#: Tier 2 — weak / file-level copyleft. Commercial use of a closed product is
#: permitted; the cost is a bundled licence, published changes to the library
#: itself, and keeping it replaceable. These pass the rule but are still used
#: only where native is not worth it (FORENSICS_PLAN.md §1.1). GPL, AGPL and
#: the Volatility Software License are NOT here: they reach our own code.
RECIPROCAL_LICENCES = frozenset({
    "LGPL-2.0-only", "LGPL-2.0-or-later", "LGPL-2.1-only", "LGPL-2.1-or-later",
    "LGPL-3.0-only", "LGPL-3.0-or-later", "MPL-1.1", "MPL-2.0",
    "EPL-1.0", "EPL-2.0", "CPL-1.0", "IPL-1.0", "CDDL-1.0", "CDDL-1.1",
    "Ms-PL",
})

#: The full allowlist: what permits commercial use of a closed product.
PERMITTED_LICENCES = PERMISSIVE_LICENCES | RECIPROCAL_LICENCES


def licence_permits(expression: str) -> bool:
    """True when an SPDX-style licence expression passes the licence rule.

    `A OR B` passes when either side does: a dual licence lets the user
    choose. `A AND B` passes only when both do: a package that bundles B
    carries B (so pytsk3's `Apache-2.0 AND IPL-1.0 AND CPL-1.0` passes only
    because all three are permitted). Parentheses are not parsed, so an
    expression that uses them fails — as does anything unrecognised. Refusing
    by default is the point.
    """
    text = (expression or "").strip()
    if not text:
        return False
    for alternative in text.split(" OR "):
        if all(term.strip() in PERMITTED_LICENCES
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
     "Refused today, with the reason. Planned native — the chunks are zlib, "
     "which the stdlib decompresses. pyewf (libewf, LGPL) is licence-permitted "
     "as an alternative; native is the default for the offline property."),
    ("vdisk", "VHDX, VMDK and dynamic VHD images", 2, "native", "", "", "",
     "planned",
     "Refused today, with the reason; a fixed VHD is already read. Planned "
     "native from the published specs. pyvhdi/pyvmdk (libyal, LGPL) are "
     "licence-permitted alternatives."),
    ("ext4", "ext4 inodes and orphan recovery", 2, "native", "", "", "",
     "planned", "Extent trees are the work."),
    ("tsk", "Broad Sleuth Kit filesystem coverage", 2, "native", "", "", "",
     "planned",
     "Filesystems are added natively, one at a time (NTFS built; FAT, ext4, "
     "APFS to come). pytsk3 (Apache-2.0 over an IPL/CPL core) is "
     "licence-permitted as a breadth fallback."),
    ("domex", "Document metadata, EXIF, OCR, steganalysis", 3, "atk", "", "",
     "", "planned", "Extends ATK's existing forensics.py and ocr.py."),
    ("transcripts", "Audio and video through Whisper", 3, "atk", "", "", "",
     "planned", "Tagged by task, not detected language."),
    ("hunts", "Hunts across documents, images and transcripts", 3, "atk",
     "", "", "", "planned",
     "The shared hunt engine; findings confirmed by the analyst."),
    ("mobile-analysis",
     "Mobile image analysis — iOS backup (messages, calls, contacts, Safari)",
     3, "native", "forensics_workshop.artefacts.mobile", "", "", "planned",
     "Analysis of an already-extracted image, not acquisition. Built: iOS "
     "iTunes/Finder backups — device metadata, encryption detection, the "
     "domain→file map (fileID = SHA-1(domain-relativePath)), and the "
     "artefact parsers over it: messages (SMS/iMessage), call history "
     "(modern and legacy), contacts, and Safari history — WAL-aware, each "
     "timestamp kept raw beside its decoded value with the epoch named. In "
     "progress: more iOS artefacts (locations, notes) and Android dumps. "
     "Native from SQLite, plists and protobuf."),
    ("registry", "Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER)", 4,
     "native", "", "", "", "planned", ""),
    ("prefetch", "Prefetch (including Win10+ MAM compression)", 4, "native",
     "", "", "", "planned", "MAM via RtlDecompressBufferEx through ctypes."),
    ("lnk", "LNK and Jump Lists", 4, "native", "", "", "", "planned", ""),
    ("ese", "ESE databases (SRUM, Windows Search)", 4, "native", "", "", "",
     "planned", "Planned native from the format's documentation. pyesedb "
     "(libesedb, LGPL) is a licence-permitted alternative."),
    ("vss", "Volume Shadow Copies", 4, "native", "", "", "", "planned",
     "Offline, from an image; planned native. pyvshadow (libvshadow, LGPL) is "
     "a licence-permitted alternative."),
    ("timeline", "Super timeline and IOC export", 4, "native", "", "", "",
     "planned", "STIX only if a consumer for it exists."),
    ("memory", "Memory analysis", 5, "native", "", "", "", "deferred",
     "No licence-permitted route: Volatility 3 (its own copyleft licence) and "
     "MemProcFS (AGPL) both require publishing this engine's source. Deferred "
     "pending a native reader and Phases 1-4."),
    ("fde-detect", "Encrypted volume detection (BitLocker, LUKS)", 2,
     "native", "forensics_workshop.partitions", "", "", "planned",
     "By signature at the start of each volume. VeraCrypt is designed to "
     "have none."),
    ("apfs", "APFS", 0, "third-party", "", "pyfsapfs", "LGPL-3.0-or-later",
     "deferred",
     "Genuinely hard; deferred rather than half-supported. When built, this is "
     "the one capability where a permitted library is the plan rather than a "
     "native parser: pyfsapfs (libfsapfs, LGPL) reads it, and LGPL permits "
     "commercial use with a bundled notice and the library left replaceable."),
    ("fde-decrypt", "Encrypted volume decryption and key extraction", 0,
     "native", "", "", "", "out-of-scope",
     "Detection is available; decryption needs a symmetric cipher the stdlib "
     "does not provide, so it waits on a permitted crypto dependency "
     "(cryptography or pycryptodome, both permitted) — a separate decision."),
    ("mobile-acq", "Mobile device acquisition", 0, "third-party", "", "", "",
     "out-of-scope",
     "Physical-device protocols and exploits. Analysis of an already-extracted "
     "mobile image is a different thing and is planned — see mobile-analysis."),

    # Routes that FAIL the licence rule: whole-program copyleft that would
    # require publishing this engine's own source. Never built or imported.
    ("volatility3", "Volatility 3: memory analysis", 0, "third-party", "",
     "volatility3", "LicenseRef-Volatility-Software-License-1.0", "excluded",
     "Its licence requires publishing the source of software built with it. "
     "Memory analysis is deferred."),
    ("memprocfs", "MemProcFS: memory analysis", 0, "third-party", "",
     "memprocfs", "AGPL-3.0", "excluded",
     "Network copyleft — would reach this engine's source. Memory deferred."),
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
