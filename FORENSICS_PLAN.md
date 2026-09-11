# Digital Forensics Workshop — build plan

Scoped 2026-09-10. Own repository, consumed by ATK as an **optional
submodule**, on the CyberWolf pattern.

## Status — Phases 1 and 2 built 2026-09-11

**Phase 1** — all six items of §8: the case store and custody log, hashing,
read-only enforcement and its AST ratchet, logical folder ingest with
signature type ID and dedupe, browser SQLite artefacts, and the ATK host page
through the airlock.

**Phase 2** — the file system layer (§5), the same day: RAW/DD and split
images; MBR (with the extended chain) and GPT, CRCs and the backup checked;
NTFS `$MFT` with fixups checked, attribute lists, sparse and fragmented runs
and ADS; deleted entries with their clusters measured against `$Bitmap` and
paths checked against parent sequence numbers; timestomp indicators
(`$STANDARD_INFORMATION` vs `$FILE_NAME`) as measurements with their benign
explanations; `$UsnJrnl:$J` (V2/V3/V4); file slack; signature carving of an
image, a volume, a gap or a volume's unallocated clusters, every result a
candidate with the basis of its length; preview that writes nothing and
recovery that records how the bytes were found. ATK gained **Disk Image** and
**Carving** pages. Engine 0.2.0; `python -m unittest discover -s tests`
(249 tests on a machine with ntfs-3g, sfdisk and sgdisk; the six real-tool
tests skip elsewhere).

`python -m forensics_workshop capabilities` lists what is built, what is not,
and which routes the licence rule excludes.

**Four decisions from Bill that change this plan as written:**

- **The package is `forensics_workshop`, not `forensics`** (§7). ATK already
  has `atk/core/forensics.py`, and the airlock decides "installed" by
  importing a name — a generic one can be answered by the wrong thing.
- **The licence is the same as ATK's: all rights reserved.** It is not
  Apache-2.0 like CyberWolf and the Writing Workshop. See `LICENSE`.
- **In ATK the workspace sits immediately after Image Analysis**, ninth in
  the rail.
- **Nothing that restricts commercial use** (§1.1, 2026-09-11, corrected the
  same day). Any third-party code — and everything it pulls in or bundles —
  must permit commercial use of this closed product: permissive, or weak /
  file-level copyleft (LGPL, MPL, EPL, and the IPL/CPL over the Sleuth Kit
  core). Whole-program copyleft (GPL, AGPL, the Volatility Software License)
  and non-commercial licences are excluded. So the libyal libraries and pytsk3
  all pass; the engineering default is still native for the offline property,
  so E01, virtual disks, shadow copies and ESE are planned native with the
  library named as the alternative, APFS is the one library route, and memory
  analysis is deferred (Volatility 3 and MemProcFS fail the rule).

**Built beyond the letter of the plan, because the spine needed it:** a
hash-chained custody log with an anchor kept outside the case (ATK's case
index), so a rewritten log is caught; WAL-aware browser parsing; before-and-
after timestamps on every read, so a last-access change is *measured*; cloud
placeholders recorded and not read; a command line, which is the engine's own
surface and the seed of its reachability guard; and — in Phase 2 — refusal of
container formats read as raw, naming of GPT entries altered in one copy of
the array, a digest of every run's rows in custody, and a cross-check of the
parsers against real ntfs-3g and util-linux output.

**Not yet proven:**

- **The ATK pages have not been built under real Qt.** No package index was
  reachable that day; the pages were driven through a stand-in for PySide6
  (87 checks, every handler of all eight pages), which proves the Python and
  not the Qt calls. Run `tests\test_dfw_pages_build.py` in ATK — it now also
  asks real Qt to draw a carved PNG thumbnail.
- **No volume written by Windows has been parsed.** The real-tool tests use
  NTFS written by ntfs-3g, which is real NTFS but not Windows' own; the first
  Windows image is the next test.
- **The change journal has only met synthetic records** laid out from the
  documented structures; ntfs-3g does not keep one.
- **Not built in Phase 2:** LZNT1 decompression (compressed streams are
  refused, not returned), FAT/exFAT directories (volumes are identified and
  can be carved), ext4, E01 and VHDX/VMDK (to be native, §1.1), Volume Shadow Copies (Phase 4),
  `$MFT`/`$J` files exported by collection tools such as KAPE, and a live
  physical-device reader.
- The USB `WriteProtect` policy and the write probe have not run on Windows.

---

## 0. The two decisions that shape everything else

### 0.1 It is a separate repo, and it goes through the airlock

ATK already has the pattern and has already been burned by getting it wrong:
CyberWolf reported *"not installed"* when it was installed, three times, because
a page constructor raised and the failure was rendered as a missing repo. The
rule that came out of it is absolute and this repo inherits it:

> **Past the line where the vendor package imported, no failure may be
> reported as a missing repo.**

So the ATK side is a thin host that (a) imports, (b) reports the *actual*
`Reported:` line on failure, and (c) calls `subsystem.forget()` on teardown. The
`_unavailable_page` says which of the three states it is in — not installed,
installed but failed to load, installed and loaded but a capability is missing —
because those need three different actions from the operator.

Consequence for this repo: **it must be usable and testable standing alone**,
with no ATK import anywhere in its core. ATK supplies the model, the panel and
the hunts; the forensics engine supplies evidence handling and knows nothing
about Qt.

### 0.2 Evidence does not live in the ATK folder

ATK's standing rule is that every result lives inside the ATK folder. **This
module is the deliberate exception**, and the reason should be written down
before someone "fixes" it: a case is the operator's, often on a different
volume, frequently larger than the application, and sometimes required to sit on
media that is handled under its own rules. A case folder is chosen per case and
remembered by path.

What ATK *does* keep is the **case index** — where cases are, when they were
opened, their hashes — so a case can be found again without the toolkit holding
the evidence.

---

## 1. The honest capability table

Bill's requirement is offline-first with no external APIs. That is achievable
for most of this list and **not** achievable for all of it without vendoring
third-party code, some of which carries licence terms ATK has already had to
refuse once (`pykakasi`, GPL-3.0, refused with `--no-deps`).

So before any build order, the honest breakdown. **Native** means ATK writes it
in Python against a documented format — the house style, and already proven
against the Midas BLUE layouts and the stdlib OSM PBF reader.

| capability | how | honesty note |
|---|---|---|
| Hashing MD5/SHA-1/SHA-256 | **native** (`hashlib`) | trivial, and the foundation |
| RAW/DD image reading | **native** | it is a byte stream |
| E01 / EWF reading | **native** (`zlib`) by default | documented, chunks are zlib-compressed. pyewf (libewf) is LGPL — licence-permitted as an alternative; native chosen for the offline property |
| AFF4 | **native**, low priority | rare in practice. pyaff4 is Apache-2.0 (permitted), but the engine avoids dependencies by default |
| VHD/VHDX/VMDK | **native** by default | a fixed VHD is read already; the rest follow published specifications. pyvhdi/pyvmdk (libyal, LGPL) are licence-permitted alternatives — the "Apache-2.0-ish" this row once said was wrong |
| Partition tables (MBR/GPT) | **native** | documented, small |
| NTFS: `$MFT`, `$USNJrnl`, ADS | **native** | the formats are published and stable; this is exactly the kind of parser this project writes well |
| FAT/exFAT | **native** | small |
| Ext4 inodes, orphan recovery | **native**, non-trivial | superblock + inode tables are documented; extent trees are the work |
| APFS | **pyfsapfs** (LGPL, permitted) when built; deferred for now | genuinely hard; the one place a permitted library is the plan rather than a native parser |
| Full TSK coverage | **native**, one filesystem at a time | pytsk3 (Apache-2.0 over an IPL/CPL core) is licence-permitted as a breadth fallback |
| File carving by signature | **native** | a signature table plus a scanner; ATK should own this |
| Volume Shadow Copies | **native** | offline, from an image. pyvshadow (LGPL) is a licence-permitted alternative |
| Registry hives | **native** | the hive format is well documented. `python-registry` is Apache-2.0 from 0.2.0 (GPL-3.0 before), but the engine takes no dependencies |
| Prefetch | **native** | Win10+ MAM compression needs `RtlDecompressBufferEx` — available on Windows through `ctypes`, no third party |
| LNK / Jump Lists | **native** | Shell Link + OLE compound file; documented |
| Amcache / Shimcache | **native** (they are registry/hive) | |
| Browser artefacts | **native** (`sqlite3` stdlib) | Chrome/Firefox/Edge are SQLite; this is the cheapest high-value win in the whole list |
| ESE databases (SRUM, Windows Search) | **native** | documented, and a real piece of work. pyesedb (LGPL) is a licence-permitted alternative |
| EXIF / document metadata | **native** (PIL + existing `forensics.py`) | already partly built |
| Steganalysis (LSB, chi-square, RS) | **native** | `forensics.py` already does ELA and noise fingerprinting; this is an extension of work that exists |
| OCR | **existing `ocr.py`** | already in ATK |
| Audio transcription | **existing Whisper path** | already in ATK |
| Memory (RAM) analysis | **deferred** | **no licence-permitted route**: Volatility 3 (its own copyleft licence) and MemProcFS (AGPL-3.0) both reach our source. Native, if it earns its place after Phase 4 — with its own symbol-table problem |
| Super timeline | **native** merge | the merge is easy; the parsers above are the work |
| Encrypted volume *detection* | **native** | signatures for BitLocker/LUKS/FileVault are identifiable |
| Encrypted volume *decryption* | **out of scope for v1** | key extraction from hibernation/memory is a real capability and a real rabbit hole; do not promise it in the same breath as detection |

**What this table is for**: so that a phase does not get planned around a
capability that turns out to need a package we cannot ship. Every "native" row
is a week of work and no licence risk. A third-party row is admissible only if
it passes §1.1 — and none of the ones this table first named does.

### 1.1 The licence rule — nothing that restricts commercial use

**Bill, 2026-09-11: nothing that will restrict commercial use.** Said at the
start, so nothing is built on a library that has to be torn out later.
Corrected the same day: an earlier draft of this section read the rule as
"permissive only" and put LGPL on the excluded side. **That was wrong — LGPL
does not restrict commercial use.** As the rule actually applies:

- **Two tiers pass**, for anything the engine would import, bundle or require,
  its dependencies included:
  - *permissive* (MIT, BSD, Apache-2.0, ISC, PSF, zlib, CC0 …) — keep the
    notice; no effect on our own code;
  - *weak / file-level copyleft* (LGPL-2.1/3.0, MPL-2.0, EPL, and the IPL/CPL
    that cover the Sleuth Kit core) — commercial use of a closed product is
    fine. The cost is shipping the library's licence text, publishing any
    change you make **to that library** (never your own code), and leaving it
    replaceable — automatic in Python, where imports are dynamic and the user
    can swap in their own build.

  The allowlist is `PERMISSIVE_LICENCES | RECIPROCAL_LICENCES` in
  `capabilities.py`; a licence nobody has checked is refused, not waved through.
- **Excluded: whole-program copyleft and non-commercial.** GPL, AGPL, and the
  Volatility Software License — which requires publishing the source of
  software built *with* it — would force this engine open. PolyForm-NC,
  CC BY-NC, BUSL and SSPL restrict commercial use outright.
- **The whole tree counts.** A permissive package that bundles a copyleft one
  carries it. pytsk3 is the case, and it passes only because the Sleuth Kit's
  IPL/CPL are themselves weak copyleft.
- **Passing the rule is not the same as being used.** The engineering default
  is native and standard-library-only: the engine runs in a bare interpreter,
  installs nothing and bundles no licence texts. A permitted library is reached
  for only where a native parser would be a poor use of time.
- **Formats are implemented from their documentation**, never by copying or
  translating code from a GPL/AGPL project whose terms would reach this code.
- **An examiner's own tools are not dependencies.** Converting an E01 to raw
  with FTK Imager or ewfexport before registering it is the examiner's step;
  nothing of those tools ships with the workshop or is needed by it.

Where each library the plan first named now stands:

| library | licence | rule | plan |
|---|---|---|---|
| pyewf (libewf) | LGPL-3.0-or-later | **permitted** | E01 native by default; library the alternative |
| pyvhdi, pyvmdk (libyal) | LGPL-3.0-or-later | **permitted** | VHDX/VMDK/dynamic VHD native by default |
| pytsk3 (Sleuth Kit) | Apache-2.0 AND IPL-1.0 AND CPL-1.0 | **permitted** | filesystems native, one at a time; library a breadth fallback |
| pyvshadow (libvshadow) | LGPL-3.0-or-later | **permitted** | Volume Shadow Copies native (Phase 4) |
| pyesedb (libesedb) | LGPL-3.0-or-later | **permitted** | ESE native (Phase 4) |
| pyfsapfs (libfsapfs) | LGPL-3.0-or-later | **permitted** | APFS — the one place the library IS the plan, when built |
| Volatility 3 | Volatility Software License 1.0 | **excluded** | memory deferred |
| MemProcFS; Fox-IT dissect.evidence | AGPL-3.0 | **excluded** | not used, and not a source to copy from |

Only the two excluded rows appear as **excluded** in the capability table,
each with the licence that fails; `tests/test_capabilities_packaging.py` holds
every third-party row to the allowlist and shows a failing row as excluded even
if someone adds it as planned.

**One thing the rule does not decide: FDE decryption.** Detecting an encrypted
volume is native and available. Decrypting one, given the key, needs a
symmetric cipher (AES-XTS) and a KDF the standard library does not provide. The
permissive crypto libraries — `cryptography` (Apache-2.0/BSD) and
`pycryptodome` (BSD/public-domain) — pass the rule, so this is not a licence
question; it is the separate decision of whether to take the engine's first
dependency and give up the bare-interpreter property.

**Beyond this repository.** Phase 3 leans on ATK's own components — OCR,
Whisper, Pillow — and ATK has dependencies under the same question: PySide6,
which draws every ATK page, is LGPL-3.0 (permitted, with the same
notice/replaceability cost); the bundled FFmpeg builds are GPL-3.0 (a binary
shipped, not a library linked — a real question). That review belongs to ATK.

---

## 2. The pipeline

```mermaid
flowchart TD
    A[Evidence source<br/>disk image · live volume · folder · single file] --> B[Write block + verify]
    B --> C[Hash on ingest<br/>MD5 · SHA-1 · SHA-256]
    C --> D[Case store<br/>manifest · custody log]
    D --> E{Container type}
    E -->|image| F[Partition + volume parse]
    E -->|logical| G[Directory walk]
    F --> H[File system layer<br/>MFT · USN · ADS · inodes]
    H --> I[Recovery<br/>deleted entries · carving · slack · VSS]
    G --> J[File triage<br/>type ID · hash · dedupe]
    I --> J
    J --> K{Content kind}
    K -->|document| L[Text extract + OCR fallback]
    K -->|image| M[EXIF · ELA · steganalysis]
    K -->|audio/video| N[Whisper transcript + language]
    K -->|system artefact| O[Registry · Prefetch · LNK · browser]
    L --> P[HUNTS]
    M --> P
    N --> P
    O --> Q[Timeline events]
    P --> R[Findings<br/>streamed · confirmed by analyst]
    Q --> S[Super timeline]
    R --> S
    S --> T[Report · IOC export · link graph]
```

Two things to notice about the shape.

**Everything converges on hunts.** A document, a photograph, a voice memo and a
registry key are four extractors feeding one question-answering layer. That is
why the hunt engine is being built shared (see ATK `FUTURE_PLANS.md` §H) — this
module is its third front door, and if it were built separately here there would
be three answers to "what is a finding".

**Preview before recovery.** Bill: *"With previews where possible before
recovery."* Every recovery path — a carved file, a deleted MFT entry, a shadow
copy — yields a **header, a size, a type guess and a thumbnail or first page**
before anything is written out. Carving a 40 GB unallocated region produces
thousands of candidates and most are fragments; recovering them all first and
looking after is how an analyst loses an afternoon.

---

## 3. Write blocking, and the part that must not be oversold

This is the capability where a toolkit can do real harm by being confident.

**A software write blocker on Windows is not a hardware write blocker.** What
can honestly be built:

1. **Read-only by construction.** Every handle this module opens on evidence is
   opened read-only, on every path, with no exceptions and an **AST ratchet
   asserting no `"w"`, `"a"`, `"r+"` or `os.O_WRONLY` reaches an evidence
   path.** This is the guarantee that is actually enforceable, and it is
   enforceable because it is structural rather than a promise.
2. **USB write protection via the documented registry policy**
   (`HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect`).
   Requires elevation; affects USB mass storage only; **does not cover
   Thunderbolt, internal buses, or anything already mounted.**
3. **Verification, which is the part that matters.** Set the policy, then
   *attempt a write and confirm it fails*, and report the result of the
   attempt. A setting that was applied is not the same claim as a device that
   refused a write. This module reports the second.
4. **Mount-state warnings.** If Windows has already mounted and journalled a
   volume, saying so plainly, because by then the evidence has already changed
   and no tool can undo it.

**What the UI must say, prominently and permanently**: for evidence that will be
presented anywhere it matters, use a hardware write blocker. This module's
protection is defence in depth, not a substitute. A forensics tool that implies
otherwise is worse than one with no write blocking at all, because it removes
the operator's reason to reach for the real thing.

---

## 4. Chain of custody

The case store is the spine, and the design rule is the one CyberWolf's actor
ledger arrived at: **the record is append-only and it never states a conclusion.**

```
<case>/
    case.json          identifier, examiner, opened, description
    custody.jsonl      append-only: every action, actor, timestamp, hashes
    evidence/          source images and their sidecars (read-only)
    extracted/         everything recovered, by source
    findings/          hunt findings + analyst decisions (the §H store)
    reports/
```

- **Hash on ingest, hash on export, and verify on demand.** The verify is a
  first-class button, not a setting — an examiner is asked *when* a hash was
  last confirmed, not whether hashing is enabled.
- **`custody.jsonl` is append-only and separately flushed and `fsync`ed.** Same
  reasoning as the GPS track: a log that only survives a clean shutdown does not
  survive the situations it exists for.
- **A recovered file records how it was recovered** — MFT entry, carved at
  offset, shadow copy N, slack space — because "recovered" spans claims of very
  different strength and a report that flattens them is misleading.
- **Nothing here says a file is a file.** A carved JPEG whose header parsed and
  whose tail is missing is a *candidate*, and it is labelled one all the way to
  the report.

---

## 5. Phases

### Phase 1 — the spine (build this before anything clever)

Ingestion, hashing, case store, custody log, read-only enforcement + its AST
ratchet, logical folder walk, file type identification by signature, dedupe by
hash, and the ATK host page through the airlock. **Plus browser SQLite
artefacts**, because they are stdlib, high value, and prove the whole spine
end to end on real data with no third-party dependency at all.

Deliverable: point it at a folder or a mounted volume, get a hashed, indexed,
custody-logged case with browser history in it.

### Phase 2 — the file system layer

RAW/DD and partition parsing, NTFS `$MFT` and `$USNJrnl`, ADS enumeration,
deleted-entry recovery, **signature carving with preview**, slack and
unallocated scraping, timestomp detection (`$FILE_NAME` vs
`$STANDARD_INFORMATION`). E01 and the virtual disk containers (VHDX, VMDK,
dynamic VHD) **natively by default** — the libraries that read them are
licence-permitted (§1.1) but native is the choice — and not built yet.

### Phase 3 — DOMEX and hunts

Text extraction + OCR fallback, EXIF and Office/PDF metadata, steganalysis
extending the existing `forensics.py`, Whisper on every audio and video file,
and the **hunt engine wired across all of them**. This is the phase Bill
described first and it is third on purpose: hunts over an unverified,
un-custodied corpus produce findings nobody can stand behind.

**Mobile image analysis** (Bill, 2026-09-11) also lands here: comprehensive
native analysis of an already-extracted image — **not acquisition**, which
needs physical-device protocols and stays out of scope. It is large enough to
have its own spec: **see §9**. Increments 1-2 (the iOS backup file map + the
messages/calls/contacts/Safari parsers) are built; §9 is the full plan and the
remaining increment order.

**Audio, per his note**: Whisper first, transcript into the hunt corpus, and
**the language tagged by task, not by detected language** — the subtitles path
already learned that one. A non-English source is noted on the finding, and the
transcript keeps both the original and the translation rather than replacing
one with the other.

### Phase 4 — system state and timeline

Registry hives, Prefetch, Amcache, Shimcache, LNK and Jump Lists, ESE
databases and Volume Shadow Copies (both native, §1.1), and the **super timeline** merging file system
timestamps, event logs, browser history and artefact events into one ordered
record. IOC export to CSV/JSON, and STIX **only if a consumer for it actually
exists** — an export format nobody reads is a week spent on nothing.

### Phase 5 — memory, and only if it earns its place

**Deferred: no route passes the licence rule** (§1.1). Volatility 3 and
MemProcFS are both copyleft, so process and thread extraction, injection
detection and network state reconstruction would be written natively — a large
body of work with its own symbol-table problem, and a different skill set.
Worth doing; not worth doing before phases 1–4 are solid.

**Explicitly out of scope for v1**: FDE key extraction and volume decryption,
APFS, and mobile device acquisition. Detection of all three, yes. Handling,
later, deliberately.

---

## 6. Where the LLM belongs — and where it does not

Bill: *"Consider comprehensively how visual analysis and document analysis using
LLMs can be leveraged."*

Comprehensively, and the boundary matters more than the list.

**Good uses — judgement over extracted facts:**

- **Hunts** across documents, images and transcripts. The core of it.
- **Triage ranking**: given 40,000 recovered files, which 200 should a human
  open first, and why — with the reason in the model's own sentences, which is
  already the rule the vision path enforces (`why` is the whole point; a bare
  label cannot be argued with).
- **Cross-artefact correlation proposals**: this LNK file, this browser
  download and this USB serial appear to describe one event. **Proposed**, then
  confirmed by the analyst, onto the link graph — the same man-in-the-middle
  design as the image hunts.
- **Timeline narration**: turning a 400,000-row super timeline into "here is
  what appears to have happened between 14:02 and 14:19", with every sentence
  citing the rows it came from.
- **Explaining an artefact** to an examiner who has not met it before. This is
  the Signals Analysis Assistant pattern, pointed at forensics.

**Where it must never go:**

- **It does not decide what a file is.** Type identification is signatures and
  magic numbers. A model's guess in that field would flow into the report as
  fact.
- **It does not touch hashes, timestamps or offsets.** Measured values, and the
  measured/authored boundary this project already enforces in the writing
  engine applies here with more force.
- **It does not write to `custody.jsonl`.** Ever.
- **Its output is always attributed and always dated with the model that
  produced it**, exactly as the online core stamps every remote answer.
- **A finding it produced is a finding, never a conclusion**, and the report
  says which of its sentences came from a model.

---

## 7. Repository shape

```
Digital-Forensics-Workshop/
    pyproject.toml
    README.md
    FORENSICS_PLAN.md          this file
    forensics_workshop/        (built as forensics_workshop — see Status)
        __init__.py            __version__, capability probe
        case.py                case store, custody log, manifest
        hashing.py
        blocker.py             read-only enforcement + USB policy + verify
        containers/            raw, ewf, vhd, partitions
        filesystems/           ntfs, fat, ext4
        recovery/              carve, slack, unallocated, vss
        artefacts/             registry, prefetch, lnk, browser, ese
        domex/                 metadata, stego, ocr bridge, transcript bridge
        timeline/              events, merge, export
        report/                markdown, docx, IOC export
    tests/                     runs standalone, no ATK, no Qt
    samples/                   synthetic images built by script, never real evidence
```

- **`samples/` are generated, never committed.** A build script writes a small
  NTFS image with known deleted files and known ADS. Committing real evidence to
  a repository is a mistake nobody undoes, and synthetic samples make the tests
  deterministic besides.
- **Tests import no ATK and construct no `QApplication`.** The suite must go
  green in a bare checkout, or the airlock cannot be tested at all.
- Public entry points enumerated and covered by a **reachability guard** — the
  same set-equality ratchet ATK uses, because a re-export is an offer, not a
  path, and this repo will accumulate engines faster than surfaces.

---

## 8. First session's work

1. `pyproject.toml`, package skeleton, version, capability probe.
2. `case.py` + `hashing.py` + `custody.jsonl` with `fsync`, and their tests.
3. `blocker.py` read-only enforcement and the AST ratchet — the guarantee that
   is actually enforceable, built before anything that could violate it.
4. Logical folder ingestion end to end: point it at a directory, get a hashed
   case with a custody log.
5. Browser SQLite artefacts, as the first real extractor.
6. The ATK host page through the airlock, reporting all three unavailable
   states correctly.

That is a standing, testable, honest tool with no third-party dependency and no
licence question — and every later phase plugs into it rather than reshaping it.

---

## 9. Mobile analysis — the comprehensive build plan

Analysis of an already-extracted mobile image. **Never acquisition** (physical-
device protocols and exploits — out of scope). Bill, 2026-09-11: "as
comprehensive and capable as possible," built native, in tested increments.

**The dimension the first cut missed: the EXTRACTION TYPE.** The same phone
yields very different data by how it was extracted, and the highest-value
artefacts are not in a backup at all. The engine identifies what it was handed
and routes accordingly.

### 9.1 Scope (Bill's decisions, 2026-09-11)

- **Input types: backups + full-filesystem file trees.** iOS iTunes/Finder
  backups (encrypted and not) and full-filesystem extractions delivered as a
  file tree (tar/zip of real paths); Android ADB backups and file-tree dumps.
  **Not** raw physical images (APFS/ext4/f2fs partitions) yet — those ride on
  the Phase-2 filesystem work and are a later addition.
- **Encrypted backups: detect now, decrypt with a PERMITTED crypto dependency.**
  `pycryptodome` (BSD/public-domain) or `cryptography` (Apache/BSD) — both pass
  the §1.1 licence rule. Design: an **optional** dependency, imported lazily
  only in the decryption path, declared as a `pyproject` extra. The engine still
  imports and runs standard-library-only in a bare interpreter; decryption
  reports "available" only when the library is present, degrading honestly when
  it is not. This is the engine's first third-party dependency, and it is
  optional by construction so the offline/bare-interpreter property survives
  everywhere except the one feature that needs a cipher. `test_isolation` gains
  a single named exception for the guarded optional import.
- **Third-party apps: a pluggable registry + a starter set.** Register a parser
  by path + schema signature; starter set WhatsApp, Signal, Telegram, Snapchat,
  Instagram, Facebook Messenger, Google Maps. Others are added as plugins
  without touching the core.

### 9.2 Cross-cutting plumbing (correctness depends on it)

- **NSKeyedArchiver / `attributedBody`.** On iOS 12+ a message's `text` column is
  often NULL and the real text is in `attributedBody` as an NSKeyedArchiver
  `NSAttributedString`. **The increment-2 SMS parser misses this — a correctness
  gap to close first.** A native NSKeyedArchiver decoder also unlocks the
  Manifest `file` blob, many plists, and Notes bodies.
- **SQLite deleted-record recovery** (free pages, WAL frames, journals) — "the
  deleted texts." A distinct, reusable capability that also serves the browser
  and disk parsers.
- **Protobuf** — Android `usagestats`, iOS Biome/SEGB, Google/app payloads. A
  small native reader; no dependency.
- **The epoch zoo + timezone** — Cocoa (s/ns), Unix (s/ms/µs), WebKit, FILETIME
  are handled; add **Google µs-since-1970**. Every timestamp keeps raw + decoded
  + epoch (house rule).
- **Encryption detection everywhere**, decryption where a key/password is given:
  encrypted iOS backups (keybag → per-file AES), Android FBE (detect; decrypt
  only with keys), WhatsApp `crypt15`, encrypted app DBs.

### 9.3 iOS artefact catalogue   (B = in a backup, F = full-filesystem only)

- **Comms:** Messages incl. attachments, group chats, reactions, edited/unsent
  (iOS 16+) (B); Call history + FaceTime (B); Voicemail + audio (B); Mail (F).
- **PIM:** Contacts (B, built), Calendar, Reminders, Notes (`NoteStore` /
  `notes.sqlite`, gzip'd protobuf bodies) (B).
- **Web:** Safari history (B, built) + bookmarks (`Bookmarks.db`), tabs
  (`BrowserState.db`), downloads; other browsers (F).
- **Location & pattern-of-life (mostly F):** `knowledgeC.db` (app usage, device
  lock/unlock, now-playing, notifications — the crown jewel), `CurrentPowerLog.
  PLSQL`, location caches (`Cache.sqlite`, `cache_encryptedB.db`), `routined`,
  `interactionC.db`.
- **Media:** `Photos.sqlite` (Camera Roll: GPS, faces, albums) + EXIF/GPS on files.
- **Device/network:** `preferences.plist`, `CellularUsage.db`, `DataUsage.sqlite`
  / `netusage.sqlite`, Wi-Fi (`com.apple.wifi.known-networks.plist`), Bluetooth
  (`…ledevices.paired.db`), `applicationState.db`, `TCC.db` (permissions),
  Screen Time, HomeKit.
- **Health** (encrypted backup / F): `healthdb_secure.sqlite`.
- **Keychain** (encrypted backup / F): passwords, tokens, Wi-Fi PSKs.

### 9.4 Android artefact catalogue

- SMS/MMS (`mmssms.db`; Messages-by-Google `bugle_db`), Calls + Contacts
  (`contacts2.db`), Accounts (`accounts_ce/de.db`).
- **Chrome reuses the existing browser parser**; plus Samsung Internet.
- Wi-Fi (`WifiConfigStore.xml`, PSKs), Bluetooth (`bt_config.conf`), Downloads,
  Calendar, MediaStore (`external.db` — paths/dates/GPS), app usage
  (`usagestats`, protobuf), Google location/Maps if present.
- Per-app `/data/data/<pkg>` databases + `shared_prefs`.
- Containers: ADB `.ab` (TAR, deflate, optional password), sparse `.img`, TWRP.

### 9.5 The ATK Mobile page

A new **Mobile** sub-tab in the Forensics workspace, under the DFW house rules
(evidence outside ATK; preview writes nothing; recovery needs a reason; the
"analysis of an extracted image, NOT acquisition" notice; locked/encrypted state
shown). Views: **device summary** (model, OS, serial, IMEI, number, last backup,
encryption state, extraction type, app count); a threaded **conversation** view;
a **call log**; a **contacts** list; a **map** for locations; a unified
**timeline**; filter by type, search, sort by time. Every row shows provenance
(db / wal / recovered) and its source DB + raw-and-decoded timestamp. Driven
through the fake-Qt harness + a real-Qt build test.

### 9.6 Validation

Hold the parsers to **real public reference images**, not only the synthetic
builder: Josh Hickman's images on Digital Corpora — **iOS 13-17** and
**Android 7-14** — are the standard corpus, and are how the `attributedBody`-
class surprises get caught.

### 9.7 Increment order

1. **Built:** iOS backup file map (spine); messages/calls/contacts/Safari parsers.
2. NSKeyedArchiver decoder + fix `attributedBody`; MMS/attachments; the rest of
   the core iOS *backup* artefacts (Notes, Calendar, Reminders, Voicemail,
   bookmarks, Wi-Fi/Bluetooth, `applicationState`/`TCC`, `DataUsage`).
3. Extraction-type detection + full-filesystem *file-tree* routing; the
   pattern-of-life goldmine (`knowledgeC`, powerlog, location caches,
   `Photos.sqlite`, `interactionC`) + protobuf/SEGB/Biome basics.
4. Encrypted iOS backup decryption (optional `pycryptodome`): keybag → per-file
   AES; then keychain and Health.
5. SQLite deleted-record recovery (shared capability).
6. Android: ADB backup + file-tree; `mmssms`/`contacts2`/accounts/Wi-Fi/
   Bluetooth/MediaStore/`usagestats`; Chrome via the existing parser.
7. Third-party registry + starter set (WhatsApp/Signal/Telegram/…).
8. The ATK Mobile page (can slot in once the core iOS artefacts are solid).

Validation against the public images runs throughout, not at the end.
