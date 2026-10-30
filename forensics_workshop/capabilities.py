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
a poor use of time (APFS is the standing example, via pyfsapfs). So E01/EWF is
read natively (built — `ewf.py`), and shadow copies, ESE and the virtual-disk
containers are PLANNED NATIVE, each with a permitted library named as the
alternative, not because the library is forbidden. A format is implemented from its documentation, never copied or
translated from a GPL/AGPL project whose terms would reach this code.

**OWNER EXCEPTIONS — none today.** The mechanism admits ONE component under
ONE licence the rule refuses, as a named, dated decision of Bill's, bound to
one row id and one exact licence string. It held one: SAM Audio (Meta's SAM
License bans military, espionage and ITAR end uses), granted 2026-09-30 and
REMOVED with SAM on 2026-10-29. `OWNER_EXCEPTIONS` is empty; adding one is a
decision for Bill, made in FORENSICS_PLAN.md first.

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
    exception: str = ""        # an owner exception's sentence, when one applies

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class OwnerException:
    """A named, dated decision to admit ONE component under ONE licence that
    the rule refuses — with the reason and the trigger that removes it."""

    capability: str           # the one row id it covers
    licence: str              # the one licence string it admits, exactly
    granted_by: str
    granted_on: str
    reason: str
    removal_trigger: str
    sentence: str             # what the capability row shows

    def as_dict(self) -> dict:
        return asdict(self)


#: Every owner exception there is: NONE. SAM Audio held the only one and was
#: removed on 2026-10-29 (Bill). Adding one is a decision for Bill, made in
#: FORENSICS_PLAN.md first — never a line added here to make a row stop
#: showing as excluded.
OWNER_EXCEPTIONS: dict = {}


def owner_exception(row_id: str, licence: str) -> OwnerException | None:
    """The exception for exactly this row AND exactly this licence, or None.
    Nothing else can ride it: not another row with the same licence, and
    not this row with some other licence the rule refuses."""
    found = OWNER_EXCEPTIONS.get(row_id)
    if found is not None and found.capability == row_id and \
            found.licence == licence:
        return found
    return None


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
    ("acquisition", "Drive imaging — a physical drive or one volume to E01 "
     "or RAW (FTK Imager's job)", 1, "native", "forensics_workshop.acquire",
     "", "", "planned",
     "Built 2026-10-29: read once through the read-only door; MD5, SHA-1 and "
     "SHA-256 in that read; E01 (fast/best/none compression) or RAW, one file "
     "or split; unreadable sectors retried, zero-filled and listed (log, "
     "custody, E01 error2); the image read back and hashed again; custody "
     "and registration in the open case. Refuses a destination on the source "
     "drive, inside a case, or not empty. Windows needs Administrator. The "
     "E01s are checked against libewf (ewfverify) in the suite where it is "
     "installed. NOT a hardware write blocker; not yet run on a Windows drive."),
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
     "E01/EWF is read natively (see the ewf row); other containers that are "
     "not raw (Ex01, VHDX, VMDK, dynamic VHD) are refused by signature, with "
     "the reason. Fixed VHD accepted, footer excluded."),
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
    ("fat", "FAT12/16/32 and exFAT directories, deleted entries included", 2,
     "native", "forensics_workshop.fatcase", "", "", "planned",
     "Built 2026-10-29 (fat.py, from Microsoft's FAT and exFAT "
     "specifications): every folder walked, deleted entries and deleted "
     "folders included, entries hidden after an end-of-directory marker "
     "found, long names checked against their 8.3 checksums, chains "
     "followed with loop and cross-link detection, every FAT copy and the "
     "backup boot sector compared. A deleted FAT file is read on the "
     "contiguous ASSUMPTION (FAT zeroes its chain) and says how many of its "
     "clusters are now allocated. FAT times are local with no zone and are "
     "never shown as UTC. Checked against mtools, The Sleuth Kit, "
     "dissect.fat, pyfatfs and fsck.exfat on driver-written and corrupted "
     "images."),
    ("carving", "Signature carving with preview", 2, "native",
     "forensics_workshop.carve", "", "", "planned",
     "Every candidate carries the basis of its length and previews before "
     "anything is written."),
    ("ewf", "E01/EWF images", 2, "native", "forensics_workshop.ewf", "", "",
     "planned",
     "Read natively: EWF sections, volume/disk geometry, the base-offset table "
     "and zlib chunks decoded to one raw stream, verified against the geometry. "
     "pyewf (libewf, LGPL) is a licence-permitted alternative; native chosen "
     "for the offline property. Ex01 is not read (a different container)."),
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
    ("domex", "Document/image/email metadata over a disk image (EXIF/GPS)",
     3, "native", "forensics_workshop.domex", "", "", "planned",
     "Built native: over an NTFS volume it mines documents (OOXML and "
     "OpenDocument properties, a PDF /Info scan), images (JPEG/TIFF EXIF "
     "including the full GPS IFD — signed latitude/longitude and the UTC GPS "
     "timestamp) and email (EML and mbox headers, one row per message) into "
     "the artefacts index — the corpus the hunts and the geospatial view run "
     "over. Reads through the read-only door; writes nothing to disk, keeps "
     "the file-system time as each row's measured UTC. Still to come: OCR and "
     "steganalysis (extend ATK's forensics.py/ocr.py), legacy OLE2 "
     "SummaryInformation. (PST/OST: the 'pst' row.)"),
    ("auto-pipeline", "One-button end-to-end runbook over a disk image", 3,
     "native", "forensics_workshop.pipeline", "", "", "planned",
     "Built native: on a registered disk image it runs hash → partitions → "
     "NTFS → DOMEX → slack (carve optional) on every NTFS volume, resumable "
     "and unattended — one failing step is recorded and the run carries on. "
     "Deterministic; no model. Files a run-summary proposal into the review "
     "queue as the top of the morning's worklist."),
    ("review-queue", "Findings review queue — propose / confirm / reject", 3,
     "native", "forensics_workshop.review", "", "", "planned",
     "Built native: the man-in-the-middle of §6/§10. Engine proposals (and, "
     "later, a local model's) land in findings.jsonl; an examiner's confirm or "
     "reject lands in decisions.jsonl AND the custody log; only a confirmed "
     "finding is admitted to a report or the contact graph. Streaming + fsync. "
     "This is the queue the hunts and the graph file into."),
    ("transcripts", "Audio and video through Whisper", 3, "atk", "", "", "",
     "planned", "Tagged by task, not detected language."),
    ("hunts", "Hunts — deterministic over the parsed rows; the model's in ATK", 3,
     "native", "forensics_workshop.hunts", "", "", "planned",
     "Built native (the §10.2 backbone): selectors (email, IPv4, Bitcoin, "
     "Ethereum, Luhn-checked cards, heuristic phone), keyword and watchlist "
     "term search, a known-bad SHA-256 hashset over the file manifest, and a "
     "high-value triage (geotagged photos + document/email counts). Every hit "
     "is filed into the review queue as a PROPOSAL citing the exact rows; "
     "re-runs are idempotent and never resurrect a rejected lead. No model — "
     "reproducible. The model layer is BUILT in ATK (2026-10-29, "
     "atk/core/dfw_ai.py over corpus.py): pictures, 30 frames per video, "
     "text with verbatim quotes checked against the text, translation with "
     "its reasoning — every result a proposal in the same queue, "
     "attributed model:<file>. Still to come: triage ranking, playbooks, "
     "the contact graph."),
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
    ("registry", "Registry hives (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER, "
     "UsrClass, Amcache)", 4, "native", "forensics_workshop.registry", "", "",
     "planned",
     "Built 2026-10-29: every key and value, transaction logs (Windows 8.1+) "
     "replayed in memory, deleted keys and values recovered from free cells "
     "and flagged. Rows for USB devices (USBSTOR, USB, MountedDevices), "
     "ShimCache (Win7-10), services, autoruns, installed programs, network "
     "interfaces and profiles, time zone, computer name, user profiles, SAM "
     "accounts, Amcache files, UserAssist, RecentDocs, typed paths and URLs, "
     "RunMRU, WordWheelQuery, Open/Save and LastVisited MRUs, and shellbags. "
     "Checked key for key against hivex and plugin for plugin against regipy "
     "on 17 real hives. Not read: SAM password hashes, SECURITY's secrets, "
     "XP/Vista ShimCache, pre-8.1 logs."),
    ("prefetch", "Prefetch (including Win10+ MAM compression)", 4, "native",
     "forensics_workshop.prefetch", "", "", "planned",
     "Built 2026-10-29: versions 17-31, MAM (LZXPRESS Huffman) decompressed "
     "in pure Python from [MS-XCA], run times, run count, volumes and "
     "referenced files. 10,133 fields on 64 real files agree with libscca. "
     "The optional cross-check against Windows' own decompressor has not yet "
     "been run on Windows."),
    ("lnk", "LNK and Jump Lists", 4, "native",
     "forensics_workshop.jumplist", "", "", "planned",
     "Built 2026-10-29: shell links (shell items, LinkInfo, tracker and "
     "property stores; shelllink.py), automatic destinations (compound file, "
     "DestList, deleted streams recovered and flagged) and custom "
     "destinations. Checked on 1,036 real links against liblnk and "
     "LnkParse3, compound files against olefile, DestList against dtformats."),
    ("pst", "Outlook mailboxes (PST and OST)", 3, "native",
     "forensics_workshop.pst", "", "", "planned",
     "Built 2026-10-29 from [MS-PST]: ANSI, Unicode and 4 KB-page OST "
     "layouts; none, permute and cyclic encodings; compressed OST blocks. "
     "Folders, messages (sender, recipients, the four times raw, headers, "
     "message ID, body excerpt), attachments (streamed), embedded messages; "
     "contacts, appointments, tasks and notes as their own rows, not mail. "
     "1,250 messages and 656 attachments in 19 real files identical to "
     "libpff. Deleted-item recovery is not done; named-property names and "
     "search-folder contents are not read. No real ANSI file was available "
     "to test."),
    ("evtx", "Windows event logs (EVTX)", 4, "native",
     "forensics_workshop.evtx", "", "", "planned",
     "Built 2026-10-29: binary XML with templates, chunk by chunk, records "
     "recovered from chunk slack and flagged (a copy of a live record is "
     "folded into it), damaged logs read around and reported. Rows for "
     "logons and failures, privileges, process creation, services, "
     "scheduled tasks, account changes, log clearing, power, RDP, "
     "PowerShell script blocks, Defender, Sysmon. 37,364 records identical "
     "to pyevtx-rs. Message text (from the DLLs) and legacy .evt are not "
     "read."),
    ("ese", "ESE databases (SRUM, Windows Search)", 4, "native", "", "", "",
     "planned", "Planned native from the format's documentation. pyesedb "
     "(libesedb, LGPL) is a licence-permitted alternative."),
    ("vss", "Volume Shadow Copies", 4, "native", "", "", "", "planned",
     "Offline, from an image; planned native. pyvshadow (libvshadow, LGPL) is "
     "a licence-permitted alternative."),
    ("report", "Case report and IOC export (CSV/JSON)", 4, "native",
     "forensics_workshop.report", "", "", "planned",
     "Built 2026-10-29: one self-contained HTML report of CONFIRMED findings "
     "only (proposals awaiting review and rejected ones are counted, not "
     "reported), each finding marked as found by the engine or proposed by a "
     "named model, the model's words quoted; the case, evidence hashes, "
     "acquisitions, custody-chain verification and limits. The IOC export "
     "lists e-mail, IPv4, phone, crypto addresses and known-bad SHA-256s from "
     "confirmed findings, card numbers masked to the last four. Written "
     "inside the case, never overwriting, hashed and recorded in custody. "
     "STIX only if a consumer for it exists."),
    ("timeline", "Super timeline", 4, "native", "", "", "", "planned",
     "The artefacts index already carries every parsed row's time with its "
     "raw value and epoch; a merged, filterable super-timeline view is to "
     "come."),
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

    ("media", "Media recovery spine — five trust tiers, recipes, residuals "
     "(FORENSICS_PLAN §12.2–12.3)", 3, "native",
     "forensics_workshop.media.lab", "", "", "planned",
     "Every output carries its tier and a recipe sidecar; outputs live in the "
     "case with custody records; the original is read once through the "
     "read-only door. Video input needs an FFmpeg executable passed in (ATK "
     "passes its own), run as a separate process. SAM Audio (generative "
     "separation) was REMOVED on 2026-10-29; SAM runs left in an older case "
     "are not deleted and still read back as Invented."),
    ("restoration", "Audio restoration — analyse, recommend, run, compare, "
     "export (§13.3–13.4)", 3, "third-party",
     "forensics_workshop.media.restore", "", "Apache-2.0", "planned",
     "Measured analysis (noise, hum, rumble, DC, clipping, clicks, "
     "bandwidth, level) by media/restore_worker.py in its own process; "
     "ranked options built from FFmpeg filters (arm's length) and "
     "SpeechBrain's MetricGAN+, SepFormer-DNS4 and SepFormer-WHAMR! "
     "(Apache-2.0); every output with its residual, tier and recipe; run the "
     "best, chosen or all; export into the case. Faint sounds (§13.8): "
     "channels that hold one sound combined (maximal-ratio, Recovered); a salience "
     "map of what stands out of the recording's own noise over windows to "
     "16 s, a clip of each faint event; tonal lines; repeats averaged "
     "(Recovered) or a repeating background lifted off (Cleaned). Speech "
     "denoisers beside them: DeepFilterNet 3 (deep-filter.exe, MIT/Apache-2.0, "
     "its own process) and RNNoise (FFmpeg's arnndn, model not subject to "
     "copyright), each marked SPEECH ONLY. What the file really holds "
     "(§13.9: a codec's or telephone's cut, a lower rate, no anti-alias "
     "roll-off, energy below 20 Hz), a linear map above 12 kHz, and bands "
     "out of hearing moved into it (single-sideband shift, slowed or sped-up "
     "copies — Measured). Not yet run against the real models."),
    ("voiceprint", "Voice comparison — speaker embeddings, a probability only "
     "through a calibration (§13)", 3, "third-party",
     "forensics_workshop.media.voiceprint", "", "Apache-2.0", "planned",
     "SpeechBrain's ECAPA-TDNN (speechbrain/spkrec-ecapa-voxceleb, "
     "Apache-2.0 code and weights) run by media/vp_worker.py in its own "
     "process under the host's torch interpreter (ATK: get_speechbrain.bat). "
     "Case-scoped profiles; every comparison a review-queue LEAD; INVENTED "
     "audio refused. Not yet run against the real model."),

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
        exception = ""
        if package:
            try:
                present = importlib.util.find_spec(package) is not None
            except (ImportError, ValueError):
                present = False
        if (package or licence) and status != "excluded" and \
                not licence_permits(licence):
            granted = owner_exception(cid, licence)
            if granted is not None:
                exception = granted.sentence
                note = f"{granted.sentence}. {note}".strip()
            else:
                # A row added without checking is shown as what it is.
                status = "excluded"
                named = licence or "no licence recorded"
                note = f"Fails the licence rule ({named}). {note}".strip()
        if module and status != "excluded":
            try:
                loaded = importlib.import_module(module)
                status = "available"
                live = getattr(loaded, "capability_note", None)
                if callable(live):
                    note = f"{note} {live()}".strip()
            except Exception as exc:                  # noqa: BLE001
                status = "failed-to-load"
                note = f"{type(exc).__name__}: {exc}"
        out.append(Capability(cid, label, phase, how, module, package,
                              licence, status, present, note, exception))
    return out
