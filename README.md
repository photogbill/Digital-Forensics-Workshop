# Digital Forensics Workshop

The evidence-handling engine behind ATK's **Digital Forensics** workspace.
Offline, standard library only, and usable on its own from the command line.

- **Package:** `forensics_workshop` (what ATK probes)
- **Repository:** `github.com/photogbill/Digital-Forensics-Workshop`
- **Status:** Phases 1 and 2 of [`FORENSICS_PLAN.md`](FORENSICS_PLAN.md), built 2026-09-11
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

`python -m forensics_workshop capabilities` prints the full table: what is
built, what is planned and in which phase, which third-party packages are
present and under what licence, what is deferred or out of scope, and which
third-party routes the licence rule excludes, with the licence that fails.

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
```

`--examiner` is required wherever a case is opened, because opening a case is
itself a custody record.

To try it without real evidence, run `python samples\build_samples.py`, which
writes a synthetic profile to `samples\profile\` and a synthetic split disk
image to `samples\disk\`.

## Tests

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
