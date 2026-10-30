# Digital Forensics Workshop

The evidence-handling engine behind ATK's **Digital Forensics** workspace.
Offline, standard library only, and usable on its own from the command line.

- **Package:** `forensics_workshop` (what ATK probes)
- **Repository:** `github.com/photogbill/Digital-Forensics-Workshop`
- **Status:** Phases 1 and 2 of [`FORENSICS_PLAN.md`](FORENSICS_PLAN.md), built 2026-09-11;
  Phase 3 under way; **drive imaging** built 2026-10-29 (not yet run on a Windows
  drive); SAM Audio **removed** 2026-10-29. Where it stands against FTK, and the
  build order, is §14 of the plan.
- **Licence:** all rights reserved; see [`LICENSE`](LICENSE)
- **Dependencies:** none outside the Python standard library. Anything added
  must pass the licence rule — nothing that restricts commercial use
  ([`FORENSICS_PLAN.md`](FORENSICS_PLAN.md) §1.1)

> **This is not a hardware write blocker.** The engine guarantees it never
> opens evidence for writing. It cannot stop Windows, another program, or the
> act of mounting a volume from changing it. For evidence that will be
> presented anywhere it matters, use a hardware write blocker.

## What Phase 1 does

| | |
|---|---|
| **Case store** | A case folder you choose, *outside* ATK: `case.json` (written once, hash checked on every open), `index.db`, and `evidence/ extracted/ findings/ reports/`. |
| **Custody log** | `custody.jsonl`: append-only, fsynced per record, hash-chained. Only an examiner or the tool can act; a model cannot. A record never states a conclusion. A torn line is acknowledged, never repaired. |
| **Read-only evidence** | One door (`blocker.open_evidence`, `O_RDONLY`). An AST ratchet fails the build on any write outside a named writer, and each case writer must assert that its target is inside the case. |
| **Layout refusals** | A case inside its evidence, evidence inside its case, and overlapping evidence items are all refused, and the refusal says why. |
| **Logical ingest** | MD5, SHA-1 and SHA-256 in one read. Timestamps are measured before and after each read, so a last-access change is *observed* rather than promised away. Links are recorded and never followed. Cloud placeholders are not read. Ingest is resumable and streams its results as it goes. |
| **Type by signature** | About 100 signatures, container-aware for OOXML, ODF, OLE, RIFF and ISO BMFF. Every result says whether it came from a signature, the container, or a heuristic. A strong signature that disagrees with the file name is flagged; a weak one never is. |
| **Duplicates, verification, export** | Dedupe by SHA-256. *Verify now* re-hashes the evidence **and** checks the index against the digest held in custody. Every export is hashed from the same read that wrote the copy. |
| **Browser artefacts** | Chromium-family and Firefox history, downloads, searches, form entries and cookies. Working copies are read, never the evidence. Rows are labelled **db / wal / wal-updated / rolled-back**, because the most recent history lives in the write-ahead log. |
| **USB write protection** | Reads and applies the Windows `WriteProtect` policy (needs Administrator), then **verifies it by attempting a write to a test device**. A policy that was applied is not the same claim as a device that refused a write. |

## What Phase 2 does — the file system layer

| | |
|---|---|
| **Disk images** | RAW/DD as one file or a split set (`.001…`, `.aa…`), read through the same read-only door. A set that is incomplete, has a gap, or is opened part-way through is refused. **EnCase E01/EWF is read natively** — sections, geometry, the base-offset table and zlib chunks decoded to one raw stream so partitions/NTFS/carving are unaware it was compressed (verified on a real 20 GB image). Other containers that are not raw — Ex01, AFF, VHDX, VMDK, QCOW, a dynamic VHD — are refused by their signature, with the reason; reading one as raw would put every partition at the wrong offset while looking right. A fixed VHD is accepted with its footer excluded. The whole disk and each segment are hashed in one read; for E01 the disk hash is of the decompressed stream. |
| **Partition tables** | MBR with the extended chain (loop-protected) and GPT. Header and array CRCs and the backup GPT are checked; a tampered primary array is read from the intact copy and the altered entries are named. Overlaps, partitions past the end of the image, hybrid and missing protective MBRs are reported. Unpartitioned space is listed as regions, and a volume boot sector found in one is called out. |
| **NTFS** | Every MFT record: update sequence fixups *checked* (a torn record says so), attributes and data runs bounds-checked, attribute lists followed into extension records, sparse and fragmented streams read back, alternate data streams listed. Compressed and EFS-encrypted content is refused rather than returned as garbage. |
| **Deleted entries** | A deleted record's name, times, runs and — measured against `$Bitmap` — how many of its clusters are now allocated to something else. Paths are rebuilt from `$FILE_NAME` and checked against each parent's sequence number, so a file whose folder's record was reused is shown as orphaned, not inside a stranger. |
| **Timestamp indicators** | `$STANDARD_INFORMATION` vs `$FILE_NAME`, whole-second times, a changed time before creation — each a *measurement* stated with the ordinary operations that produce the same pattern. Never a conclusion. |
| **Change journal** | `$Extend\$UsnJrnl:$J`, USN_RECORD V2, V3 and V4, sparse holes skipped, every record's USN checked against its offset. |
| **Slack** | The tail of each file's last cluster; regions holding data are indexed with the text found in them. |
| **Carving** | JPEG, PNG, GIF, BMP, PDF, ZIP/OOXML, SQLite, RIFF, OLE2, PE, MP4/MOV/HEIF, gzip and 7-Zip, over a whole image, a volume, a gap, or **a volume's unallocated clusters only**. **Every result is a candidate** with the basis of its length (`structure`, `footer`, `capped`) and a status (`complete`, `truncated`, `capped`). |
| **Preview, then recover** | Previews read into memory and write nothing. Recovery needs a reason, hashes what it writes, and records in custody *how* the bytes were found. |

## What Phase 3 begins — DOMEX over a disk image

| | |
|---|---|
| **Documents** | OOXML (docx/xlsx/pptx) core and app properties, OpenDocument `meta.xml`, and a PDF `/Info` scan: author, title, the created and modified times, the producing application. Dates the format wrote with a zone are decoded to UTC; the raw string is kept beside them. Legacy OLE2 (`.doc`/`.xls`) is catalogued by type and named as not-yet-mined, never guessed. |
| **Images** | JPEG (APP1) and TIFF **EXIF, including the whole GPS IFD** — latitude and longitude as **signed degrees** (west and south negative), altitude, and the GPS timestamp, which the EXIF specification defines as UTC. Camera make and model too. This is what the forensic geospatial view reads. |
| **Email** | EML (one RFC 822 message) and mbox (many): from / to / cc / subject / date / message-id and attachment names, **one artefact row per message**, the Date header decoded to UTC. Outlook PST/OST is detected and named as not-yet-parsed. |

Every result lands in the case's `artefacts` index as a timeline-ready row — the corpus the hunt engine and the contact/geospatial views run over (you need parsed rows before you can hunt them). DOMEX reads a file's bytes straight out of the NTFS volume through the same read-only door as everything else, parses the metadata in memory, and **writes nothing to disk**. A row's `at_utc` is the file system's *measured* modified time; the times a document or camera wrote about itself are authored values, kept in `detail` with their epoch named and never quietly promoted into the UTC column. Run `ntfs` on a volume first, then `domex`.

### The runbook and the review queue

`auto` presses the buttons for you: on a registered disk image it runs hash → partitions → NTFS → DOMEX → slack (carving is off by default — it's the slow one — and turns on with `--carve`) on **every** NTFS volume, in order, with no model in the loop. It's built to run alone: one failing step is recorded and the run carries on to the next, it takes progress and cancel callbacks, and it never stops to ask a question. It's **resumable** — a step whose output is already in the index is skipped, so a re-run costs only what's new (`--force` redoes). Each run files one summary into the **review queue**.

### Hunts — turning parsed rows into leads

`hunt` runs the reproducible questions an investigation starts with over the parsed `artefacts` rows and the file manifest: **selectors** (email, IPv4, Bitcoin and Ethereum addresses, credit-card numbers checked by the Luhn digit, heuristic phone numbers), **keyword** and **watchlist** term search, a **known-bad SHA-256 hashset**, and a **high-value triage** (each geotagged photo as a place and a time, plus the document and email counts — the seed of a goal-directed playbook like a kidnapping). Every hit is filed into the review queue as a proposal **citing the exact rows it came from** — a lead to confirm, never a conclusion. There's no model here: this is the deterministic backbone, reproducible byte-for-byte, and the local-LLM layer (topic classification, triage ranking) proposes into the same queue on top of it. Re-runs are idempotent and never resurrect a rejected lead.

That queue is the line the whole tool draws, made concrete. A *measurement* (a hash, a time, a parsed row) is a fact; a *judgement* (this file matters, this thread is a threat) is a **proposal** that waits for you. The engine's runbook and, later, the local model file proposals into `findings.jsonl`; your `confirm`/`reject` lands in `decisions.jsonl` **and** the custody log, because admitting a finding is a custodial act; and only a confirmed finding is ever treated as admitted. So an overnight `auto` run can do all the deterministic work and park every proposal for you to confirm in the morning — ease of use, nobody present, without a finding no human stood behind.

`python -m forensics_workshop capabilities` prints the full table: what is
built, what is planned and in which phase, which third-party packages are
present and under what licence, what is deferred or out of scope, and which
third-party routes the licence rule excludes, with the licence that fails.

## Drive acquisition — built 2026-10-29

`acquire.py` images a physical drive (or one volume) the way FTK Imager does:
read once through the read-only door, **MD5, SHA-1 and SHA-256 in that same
read**, written as an **EnCase E01** set (`ewfwrite.py`, fast / best / no
compression) or **RAW/DD**, one file or split; then read back through the
engine's own readers and hashed again. An FTK-style log goes beside the image;
in a case, `acquisition.started` / `.completed` custody and the image is
registered as evidence.

| | |
|---|---|
| **Read-only, structurally** | The source goes through `blocker.open_evidence`. Drive listing on Windows uses read-only `DeviceIoControl` queries, and the one function that may send them (`_win_query`) refuses any access but none-or-read and any control code not on `READ_ONLY_IOCTLS` — a `device-query` writer in the ratchet, its guard checked. |
| **Writes only where the examiner said** | Three `acquisition` writers, each guarded by `assert_acquisition_path`. Refused: a destination on the drive being imaged, inside a case, overlapping evidence, or not empty. |
| **Unreadable sectors** | Retried sector by sector, then zero-filled, listed (as runs) in the log, custody and the E01 `error2` section; the hashes are of what was written. A drive that disappears mid-run, or more than 1 GB in a row that will not read, STOPS the run — an image of zeros is never marked verified. Stop is heard within half a second, even mid-retry. |
| **A volume is read through its disk** | `\\.\E:` stops where the file system says the volume ends (NTFS one sector early — its backup boot sector). A Windows volume is therefore read through `\\.\PhysicalDriveN` from the volume's first byte, for its whole length; a volume that spans disks, or sits in a virtual/encrypted container, is refused with the reason. |
| **Checked by a reader we did not write** | Every E01 the suite makes is read back by `ewf.py` and, where libewf is installed, by `ewfverify` — single and split sets, all three compressions, `error2`, and base-offset tables past 2 GiB. |
| **Not a write blocker** | Windows may have mounted and touched the drive before it was opened. Imaging the running system disk is warned: a smear, not a snapshot. Windows needs Administrator. |

## FAT/exFAT, Windows artefacts, mailboxes, reports — built 2026-10-29

Items 1-5 of FORENSICS_PLAN §14's FTK-parity build order. Every parser was
written from the format's published documentation (no GPL code), and checked
against independent readers on real files (the numbers are in each module's
docstring and in `capabilities.py`); those third-party samples are never
copied into `tests/` — set `DFW_SAMPLES` to a folder holding them to run the
optional comparisons.

| Module | What it reads | Checked against |
|---|---|---|
| `fat.py` + `fatcase.py` | FAT12/16/32 and exFAT: every folder, deleted entries and deleted folders, entries hidden after an end-of-directory marker, chains with loop and cross-link detection, every FAT copy and backup boot sector compared. FAT times are LOCAL with no zone and never shown as UTC. A deleted FAT file is read on the contiguous ASSUMPTION and says how many of its clusters are now allocated. | mtools, The Sleuth Kit, dissect.fat, pyfatfs, fsck.exfat |
| `registry.py` | Hives (and .LOG1/.LOG2 replayed in memory, deleted keys from free cells): USB, ShimCache, services, autoruns, programs, network, time zone, users, SAM, Amcache, UserAssist, RecentDocs, typed paths/URLs, RunMRU, WordWheelQuery, Open/Save and LastVisited MRUs, shellbags. | hivex (every key and value), regipy plugins — 17 real hives |
| `shelllink.py`, `jumplist.py` | Shortcuts; automatic (compound file + DestList, deleted streams recovered) and custom destinations. | liblnk, LnkParse3 (1,036 links), olefile, dtformats |
| `prefetch.py` | Versions 17-31, Windows 10 MAM compression decoded in pure Python. | libscca (64 files, 0 disagreements), dissect.util |
| `evtx.py` | Binary XML with templates, records recovered from chunk slack, damaged logs read around; rows for logons, processes, services, tasks, log clearing, RDP, PowerShell, Defender, Sysmon. | pyevtx-rs (37,364 records identical), python-evtx |
| `pst.py` | PST and OST (ANSI, Unicode, 4 KB pages; none/permute/cyclic; compressed OST): folders, messages, recipients, the four times, headers, attachments, embedded messages. Contacts, appointments, tasks and notes are `pst-item` rows, not mail. | libpff (1,250 messages, 656 attachments identical), readpst |
| `winartifacts.py` | Finds all of the above by name and place on a parsed NTFS/FAT volume, or in an ingested folder (a triage collection, an exported mailbox), and stores their rows in the artefacts index with the file they came from (hashed). Deleted shortcuts/Jump Lists/Prefetch are read and say so. | — |
| `parallel.py` | The parsing runs in isolated worker processes, one per spare core; reading stays in the engine process. Rows are stored in the same order either way. | rows identical with 0 and 2 workers |
| `report.py` | The case report (one HTML file): CONFIRMED findings only, each marked engine or model, the model's words quoted; evidence hashes, acquisitions, custody verification, limits. IOC export CSV/JSON (cards masked). | — |
| `artefacts/query.py` | One read-only view across every parser's rows (ATK's Artifacts page), with the rows that state a GPS position. | — |

"Run everything" (`pipeline.py`) now also reads FAT/exFAT volumes and the
Windows artefacts and mailboxes on every parsed volume.

**Speed** — `bench.bat` measures the digests, E01 reading and every parser on
this machine and saves the numbers in `logs\bench\`. On Bill's machine's
Linux VM (two cores): the three digests side by side 565 MB/s (one after
another 369); E01 inflate on threads 316 MB/s (one at a time 247); event
logs about 4,000 records/s per core — the slowest parser, and the reason the
parsing runs on every core. A single-file RAW image is now hashed once (it
was hashed twice). No C accelerator yet: the numbers do not call for one.

## What the model hunts read — `corpus.py`

ATK's model hunts (pictures, 30 frames across each video, text with verbatim
quotes, translation with its reasoning — in ATK's `atk/core/dfw_ai.py`) need
the bytes of files, not parsed rows. `corpus.py` lists an evidence item's
pictures, videos, documents, text and e-mail — from a folder's manifest (typed
by bytes) or a disk image's NTFS entries (by extension, re-typed when read) —
and reads one **into memory** through the read-only door. It writes nothing,
except `working_copy`: one hashed copy of a video inside `<case>/working/`
for FFmpeg to seek in, with custody. Every model result is a proposal in the
review queue, attributed `model:<file>`; the model never writes custody.

## Media recovery

**SAM Audio was removed on 2026-10-29** (its adapter, the separator interface,
the weights manifest, seed disagreement, and the `media-sam / -replay / -pin /
-weights / -negative-control` commands). Restoration and voice comparison
(§13) are unchanged; the child-process runner they used moved to
`media/proc.py`. A case made before then may still hold SAM runs under
`<case>/media/`: they are not deleted, and still read back as Invented.

## Command line

```
python -m forensics_workshop case new    D:\cases\OP-1 --id OP-1 --examiner "Name"
python -m forensics_workshop add         D:\cases\OP-1 E:\Users\subject --examiner "Name"
python -m forensics_workshop ingest      D:\cases\OP-1 E001 --examiner "Name"
python -m forensics_workshop verify      D:\cases\OP-1 E001 --examiner "Name"
python -m forensics_workshop files       D:\cases\OP-1 E001 --examiner "Name" --filter mismatch
python -m forensics_workshop dupes       D:\cases\OP-1 --examiner "Name"
python -m forensics_workshop extract     D:\cases\OP-1 E001 Documents\x.pdf --examiner "Name" --reason "..."
python -m forensics_workshop browser     D:\cases\OP-1 E001 --examiner "Name"
python -m forensics_workshop artefacts   D:\cases\OP-1 E001 --examiner "Name" --kind visit
python -m forensics_workshop custody     D:\cases\OP-1 --examiner "Name"
python -m forensics_workshop drives
python -m forensics_workshop acquire     \\.\PhysicalDrive2 E:\images\OP-1 --name OP-1_E003 --examiner "Name" --case D:\cases\OP-1 --write-blocker "Tableau T35u"
python -m forensics_workshop corpus      D:\cases\OP-1 E002 --examiner "Name" --families image,video
python -m forensics_workshop usb-policy  status
python -m forensics_workshop probe-write F:\ --i-confirm-this-is-not-evidence

python -m forensics_workshop add-image     D:\cases\OP-1 E:\images\laptop.001 --examiner "Name"
python -m forensics_workshop image         D:\cases\OP-1 E002 --examiner "Name"
python -m forensics_workshop volumes       D:\cases\OP-1 E002 --examiner "Name"
python -m forensics_workshop ntfs          D:\cases\OP-1 E002 --volume 2 --examiner "Name"
python -m forensics_workshop entries       D:\cases\OP-1 E002 --volume 2 --filter deleted --examiner "Name"
python -m forensics_workshop entry         D:\cases\OP-1 E002 --volume 2 --record 4711 --examiner "Name"
python -m forensics_workshop preview       D:\cases\OP-1 E002 --volume 2 --record 4711 --examiner "Name"
python -m forensics_workshop recover       D:\cases\OP-1 E002 --volume 2 --record 4711 --reason "..." --examiner "Name"
python -m forensics_workshop usn           D:\cases\OP-1 E002 --volume 2 --reason FILE_DELETE --examiner "Name"
python -m forensics_workshop carve         D:\cases\OP-1 E002 --volume 2 --unallocated --examiner "Name"
python -m forensics_workshop candidates    D:\cases\OP-1 E002 --status complete --examiner "Name"
python -m forensics_workshop carve-preview D:\cases\OP-1 E002 17 --examiner "Name"
python -m forensics_workshop carve-recover D:\cases\OP-1 E002 17 --reason "..." --examiner "Name"
python -m forensics_workshop slack         D:\cases\OP-1 E002 --volume 2 --examiner "Name"
python -m forensics_workshop domex          D:\cases\OP-1 E002 --volume 2 --examiner "Name" [--categories image,document,email] [--path Users] [--limit N]
python -m forensics_workshop domex-list     D:\cases\OP-1 E002 --examiner "Name" [--kind image] [--geo] [--search "..."]
python -m forensics_workshop auto           D:\cases\OP-1 E002 --examiner "Name" [--steps image,ntfs,domex,slack] [--carve] [--path Users] [--force]
python -m forensics_workshop hunt           D:\cases\OP-1 E002 --examiner "Name" [--terms ransom,pier] [--watchlist ...] [--selectors email,phone] [--hashset bad.txt]
python -m forensics_workshop findings       D:\cases\OP-1 --examiner "Name" [--status proposed] [--kind pipeline-run]
python -m forensics_workshop confirm        D:\cases\OP-1 FINDING_ID --examiner "Name" [--note "..."]
python -m forensics_workshop reject         D:\cases\OP-1 FINDING_ID --examiner "Name" [--note "..."]
python -m forensics_workshop report         D:\cases\OP-1 --examiner "Name" [--title "Op Pier"] [--no-iocs]
python -m forensics_workshop rows           D:\cases\OP-1 --examiner "Name" [--evidence E002] [--parser evtx] [--kind evtx_logon] [--geo] [--since 2026-07-01] [--parsers]
python -m forensics_workshop mail           D:\cases\OP-1 --examiner "Name" [--evidence E002]      (e-mail by source, total at the bottom)
python -m forensics_workshop fat            D:\cases\OP-1 E003 --volume 1 --examiner "Name"
python -m forensics_workshop windows        D:\cases\OP-1 E002 --volume 2 --examiner "Name" [--kinds registry,evtx] [--workers 0]
python -m forensics_workshop windows        D:\cases\OP-1 E004 --examiner "Name"        (an ingested folder: no --volume)

```

`entries`, `entry`, `preview` and `recover` serve FAT/exFAT volumes too
(`--record` is then the entry id `entries` shows).

`--examiner` is required wherever a case is opened, because opening a case is
itself a custody record.

To try it without real evidence, run `python samples\build_samples.py`, which
writes a synthetic profile to `samples\profile\` and a synthetic split disk
image to `samples\disk\`.

## Tests

**`run_tests.bat`** runs everything in one go: this engine's whole suite, then
ATK's Digital Forensics tests with ATK's own Python (`/all` adds the rest of
ATK's suite). One line per part and a TOTAL at the bottom; the full output
goes to `logs\tests\`. By hand:

```
python -m unittest discover -s tests
```

Standard library `unittest`, so the suite runs in a bare interpreter; pytest
collects it unchanged. It imports no ATK and builds no `QApplication`. It
includes three guards that matter more than any single test:

- **`test_ratchet.py`** runs the read-only ratchet over the package, asserts
  what it covered, and watches it fail on one small program per rule.
- **`test_isolation.py`** checks for no ATK, no Qt, no third-party imports,
  and an `__init__.py` that imports nothing. ATK's airlock depends on all four.
- **`test_reachability.py`** requires every public operation to be reachable
  from the command line, or listed with a reason.
- **`test_real_tools.py`** holds the NTFS and partition parsers to volumes and
  tables made by real tools — ntfs-3g, sfdisk, sgdisk, mkfs.vfat — including a
  deletion scored against `ntfsundelete`. A builder that shared a parser's
  misunderstanding would pass everything else. It skips, naming the missing
  tools, where they are not installed (Windows included).

## How ATK uses it

ATK finds the package in `vendor\Digital-Forensics-Workshop` (where
`get_engines.bat /forensics` clones it) or beside ATK as
`..\Digital Forensics Workshop`. It probes `import forensics_workshop` through
`atk/ui/subsystem.py`, and reports one of three states: **not installed**,
**installed but ATK's adapter failed**, or **loaded but the panel failed to
start**. A missing capability, such as no Ex01 reader yet, is not a failure;
the workspace's Capabilities page lists it.

ATK keeps only an index of where cases are, plus each case's custody head as
an anchor kept outside the case. It never keeps the evidence.
