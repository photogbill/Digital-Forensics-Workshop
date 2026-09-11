# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The command line — the engine's own surface, with no ATK and no Qt.

    python -m forensics_workshop capabilities
    python -m forensics_workshop case new    CASE --id ID --examiner NAME [--description TEXT]
    python -m forensics_workshop case show   CASE --examiner NAME
    python -m forensics_workshop add         CASE FOLDER --examiner NAME [--label TEXT]
    python -m forensics_workshop ingest      CASE E001 --examiner NAME
    python -m forensics_workshop verify      CASE E001 --examiner NAME
    python -m forensics_workshop files       CASE E001 --examiner NAME [--filter mismatch] [--search TEXT]
    python -m forensics_workshop dupes       CASE --examiner NAME [--evidence E001]
    python -m forensics_workshop extract     CASE E001 RELPATH --examiner NAME --reason TEXT
    python -m forensics_workshop browser     CASE E001 --examiner NAME [--all-sqlite]
    python -m forensics_workshop artefacts   CASE E001 --examiner NAME [--kind visit] [--search TEXT]
    python -m forensics_workshop custody     CASE --examiner NAME [--tail N]

  disk images (phase 2)
    python -m forensics_workshop add-image     CASE IMAGE --examiner NAME [--label TEXT]
    python -m forensics_workshop image         CASE E002 --examiner NAME
    python -m forensics_workshop volumes       CASE E002 --examiner NAME
    python -m forensics_workshop ntfs          CASE E002 --volume N --examiner NAME [--no-journal]
    python -m forensics_workshop entries       CASE E002 --volume N --examiner NAME [--filter deleted] [--search TEXT]
    python -m forensics_workshop entry         CASE E002 --volume N --record R --examiner NAME
    python -m forensics_workshop preview       CASE E002 --volume N --record R --examiner NAME [--stream S]
    python -m forensics_workshop recover       CASE E002 --volume N --record R --examiner NAME --reason TEXT [--stream S]
    python -m forensics_workshop usn           CASE E002 --volume N --examiner NAME [--reason FILE_DELETE] [--search TEXT]
    python -m forensics_workshop carve         CASE E002 --examiner NAME [--volume N [--unallocated]] [--types jpeg,png] [--every-byte]
    python -m forensics_workshop candidates    CASE E002 --examiner NAME [--type jpeg] [--status complete] [--run ID]
    python -m forensics_workshop carve-preview CASE E002 ID --examiner NAME
    python -m forensics_workshop carve-recover CASE E002 ID --examiner NAME --reason TEXT
    python -m forensics_workshop slack         CASE E002 --volume N --examiner NAME
    python -m forensics_workshop volume      PATH
    python -m forensics_workshop usb-policy  status | on | off
    python -m forensics_workshop probe-write FOLDER --i-confirm-this-is-not-evidence

Why it exists at all: the plan's first rule is that this engine is usable
and testable standing alone, and a library nobody can drive without ATK is
not standing alone. It is also the SEED of the reachability guard
(`tests/test_reachability.py`) — every public operation in the engine must be
reachable from here or be listed, with a reason, as reachable by design.

`--examiner` is required on every command that opens a case, because
opening a case is itself a custody record and a custody record says who.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, blocker, capabilities as caps
from . import carve as _carve
from . import diskimage as _disk
from . import manifest as _manifest
from . import verify as _verify
from .artefacts import browser as _browser
from .artefacts import mobile as _mobile
from .case import Case
from .errors import ForensicsError
from .extract import extract_file
from .ingest import ingest_folder


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def _progress(line: str) -> None:
    print(f"  {line}", file=sys.stderr)


def _open(args) -> Case:
    return Case.open(args.case, examiner=args.examiner)


def cmd_capabilities(args) -> int:
    for c in caps.capabilities():
        present = ("" if c.package_present is None else
                   f"  [{c.package}: {'present' if c.package_present else 'absent'}]")
        print(f"{c.status:15} phase {c.phase}  {c.label}{present}")
        if c.licence:
            print(f"{'':25}licence: {c.licence}")
        if c.note:
            print(f"{'':25}{c.note}")
    return 0


def cmd_case_new(args) -> int:
    case = Case.create(args.case, case_id=args.id, examiner=args.examiner,
                       description=args.description)
    _print(case.info.as_dict())
    return 0


def cmd_case_show(args) -> int:
    case = _open(args)
    evidence = []
    for item in case.evidence():
        last = _verify.last_verification(case, item.id)
        evidence.append(dict(item.as_dict(), last_verified=(
            None if last is None else
            {"at": last["at"], "all_matched": last["detail"]["all_matched"]})))
    _print({"info": case.info.as_dict(), "integrity": case.integrity(),
            "evidence": evidence, "chain": case.custody.verify().as_dict()})
    return 0 if not case.integrity() else 2


def cmd_add(args) -> int:
    case = _open(args)
    item = case.add_folder(args.folder, label=args.label)
    _print(item.as_dict())
    if item.volume.get("warning"):
        print(f"\nWARNING: {item.volume['warning']}", file=sys.stderr)
    print(f"\n{blocker.HARDWARE_NOTICE}", file=sys.stderr)
    return 0


def cmd_ingest(args) -> int:
    case = _open(args)
    summary = ingest_folder(case, args.evidence, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_verify(args) -> int:
    case = _open(args)
    summary = _verify.verify_evidence(case, args.evidence, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.all_matched else 1


def cmd_files(args) -> int:
    case = _open(args)
    rows, total = _manifest.list_files(case, args.evidence, filter=args.filter,
                                       search=args.search, limit=args.limit)
    for r in rows:
        flag = "!" if r.get("ext_mismatch") else " "
        print(f"{flag} {r.get('type_id') or '-':12} "
              f"{r.get('size') if r.get('size') is not None else '':>12}  "
              f"{r['relpath']}")
    print(f"\n{len(rows)} shown of {total}")
    return 0


def cmd_dupes(args) -> int:
    case = _open(args)
    _print([d.as_dict() for d in _manifest.duplicates(
        case, evidence_id=args.evidence or None)])
    return 0


def cmd_extract(args) -> int:
    case = _open(args)
    _print(extract_file(case, args.evidence, args.relpath,
                        reason=args.reason).as_dict())
    return 0


def cmd_browser(args) -> int:
    case = _open(args)
    summary = _browser.extract_browser_artefacts(
        case, args.evidence, all_sqlite=args.all_sqlite, progress=_progress)
    _print(summary.as_dict())
    return 0


def cmd_mobile(args) -> int:
    case = _open(args)
    summary = _mobile.analyse_evidence(case, args.evidence, progress=_progress)
    _print(summary.as_dict())
    return 0


def cmd_mobile_artefacts(args) -> int:
    case = _open(args)
    rows, total = _mobile.list_mobile(case, args.evidence, artefact=args.kind,
                                      search=args.search, limit=args.limit)
    for r in rows:
        print(f"{r['at_utc'] or '(no time)':28} {r['artefact']:10} "
              f"{r['provenance']:11} {r['browser']:16} "
              f"{r['url'] or r['title']} {r['value']}".rstrip())
    print(f"\n{len(rows)} shown of {total}")
    return 0


def cmd_artefacts(args) -> int:
    case = _open(args)
    rows, total = _browser.list_artefacts(case, args.evidence,
                                          artefact=args.kind,
                                          search=args.search, limit=args.limit)
    for r in rows:
        print(f"{r['at_utc'] or '(no time)':28} {r['artefact']:10} "
              f"{r['provenance']:11} {r['url'] or r['value']}")
    print(f"\n{len(rows)} shown of {total}")
    return 0


def cmd_custody(args) -> int:
    case = _open(args)
    for row in case.custody.rows()[-args.tail:]:
        print(f"{row['seq']:>6} {row['at']} {row['actor']['kind']:8} "
              f"{row['action']:32} {row['target']}")
    report = case.custody.verify()
    print(f"\nchain {'intact' if report.ok else 'BROKEN'} — {report.records} "
          "records")
    for problem in report.problems:
        print(f"  PROBLEM: {problem}")
    for note in report.notes:
        print(f"  note: {note}")
    return 0 if report.ok else 2


def cmd_add_image(args) -> int:
    case = _open(args)
    item = case.add_image(args.image, label=args.label)
    side = case.sidecar(item.id)
    _print(dict(item.as_dict(), image=side.get("image")))
    for note in (side.get("image") or {}).get("notes") or []:
        print(f"\nNOTE: {note}", file=sys.stderr)
    print(f"\n{blocker.HARDWARE_NOTICE}", file=sys.stderr)
    return 0


def cmd_image(args) -> int:
    case = _open(args)
    summary = _disk.ingest_image(case, args.evidence, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_volumes(args) -> int:
    case = _open(args)
    for v in _disk.list_volumes(case, args.evidence):
        fs = v["fs_label"] or v["fs_type"] or ""
        label = f" '{v['fs_volume_label']}'" if v["fs_volume_label"] else ""
        print(f"{v['volume']:>3} {v['entry']:8} {v['kind']:10} "
              f"offset {v['offset']:>15,}  {v['length']:>15,} bytes  "
              f"{v['type_label'] or '':28} {fs}{label}")
        for problem in v["problems"]:
            print(f"{'':4}PROBLEM: {problem}")
        if v["fs_note"]:
            print(f"{'':4}note: {v['fs_note']}")
    return 0


def cmd_ntfs(args) -> int:
    case = _open(args)
    summary = _disk.parse_ntfs(case, args.evidence, args.volume,
                               journal=not args.no_journal, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_entries(args) -> int:
    case = _open(args)
    rows, total = _disk.list_entries(case, args.evidence, args.volume,
                                     filter=args.filter, search=args.search,
                                     limit=args.limit)
    for r in rows:
        state = " " if r["in_use"] else "D"
        flags = ("T" if r["indicators"] else " ") + ("A" if r["ads_count"] else " ")
        size = "" if r["size"] is None else f"{r['size']:,}"
        print(f"{state}{flags} {r['record']:>8} {size:>14}  "
              f"{r['si_modified_utc'] or '':27} {r['path']}"
              + ("" if r["path_status"] == "ok" else f"   [{r['path_status']}]"))
    print(f"\n{len(rows)} shown of {total}   (D deleted · T timestamp "
          "indicators · A alternate data streams)")
    return 0


def cmd_entry(args) -> int:
    case = _open(args)
    _print(_disk.entry_detail(case, args.evidence, args.volume, args.record))
    return 0


def cmd_preview(args) -> int:
    case = _open(args)
    out = _disk.preview_entry(case, args.evidence, args.volume, args.record,
                              args.stream, limit=args.bytes)
    return _show_preview(out)


def _show_preview(out: dict) -> int:
    data = out.pop("data", b"")
    hexdump, text = out.pop("hex", ""), out.pop("text", "")
    _print(out)
    if out.get("refused"):
        print(f"\nREFUSED: {out['refused']}", file=sys.stderr)
        return 1
    print(f"\n{hexdump}")
    if text:
        print(f"\ntext:\n{text[:2000]}")
    print(f"\n(preview only: {len(data):,} bytes read into memory, nothing written)")
    return 0


def cmd_recover(args) -> int:
    case = _open(args)
    _print(_disk.recover_entry(case, args.evidence, args.volume, args.record,
                               args.stream, reason=args.reason).as_dict())
    return 0


def cmd_usn(args) -> int:
    case = _open(args)
    rows, total = _disk.list_journal(case, args.evidence, args.volume,
                                     search=args.search, reason=args.reason,
                                     limit=args.limit)
    for r in rows:
        print(f"{r['usn']:>12} {r['timestamp_utc'] or '':27} "
              f"{r['file_record']:>8}-{r['file_sequence']:<5} {r['name']:32} "
              f"{r['reason_names']}")
    print(f"\n{len(rows)} shown of {total}")
    return 0


def cmd_carve(args) -> int:
    case = _open(args)
    types = [t.strip() for t in args.types.split(",") if t.strip()] or None
    summary = _disk.carve_evidence(
        case, args.evidence, volume=args.volume, unallocated=args.unallocated,
        types=types, aligned=1 if args.every_byte else 512, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_candidates(args) -> int:
    case = _open(args)
    rows, total = _carve.list_candidates(case, args.evidence, run_id=args.run,
                                         type_id=args.type, status=args.status,
                                         limit=args.limit)
    for r in rows:
        nested = "  (inside another candidate)" if r["nested_in"] is not None else ""
        print(f"{r['id']:>7} {r['offset']:>15,} {r['length']:>13,}  "
              f"{r['type_id']:8} {r['basis']:9} {r['status']:9} "
              f"{r['note'][:60]}{nested}")
    print(f"\n{len(rows)} shown of {total} — every row is a CANDIDATE")
    return 0


def cmd_carve_preview(args) -> int:
    case = _open(args)
    return _show_preview(_disk.preview_candidate(case, args.evidence,
                                                 args.candidate, limit=args.bytes))


def cmd_carve_recover(args) -> int:
    case = _open(args)
    _print(_disk.recover_candidate(case, args.evidence, args.candidate,
                                   reason=args.reason).as_dict())
    return 0


def cmd_slack(args) -> int:
    case = _open(args)
    summary = _disk.scrape_slack(case, args.evidence, args.volume,
                                 progress=_progress)
    _print(summary.as_dict())
    rows, total = _disk.list_slack(case, args.evidence, args.volume, limit=20)
    for r in rows:
        print(f"{r['record']:>8} {r['nonzero']:>6}/{r['length']:<6} "
              f"{r['path'] or ''}  {(r['strings'] or '')[:60]!r}")
    if total:
        print(f"\n{len(rows)} shown of {total} slack regions holding data")
        first = rows[0]
        detail = _disk.slack_preview(case, args.evidence, args.volume,
                                     first["record"], first["stream"])
        print(f"\nlargest, record {first['record']}:\n{detail['hex'][:1200]}")
    return 0 if summary.state == "completed" else 1


def cmd_volume(args) -> int:
    _print(blocker.volume_state(args.path).as_dict())
    return 0


def cmd_usb_policy(args) -> int:
    if args.action == "status":
        _print(blocker.usb_policy_state().as_dict())
        return 0
    change = blocker.apply_usb_policy(args.action == "on")
    _print(change.as_dict())
    return 0 if change.applied else 1


def cmd_probe_write(args) -> int:
    result = blocker.verify_write_refused(
        args.folder, confirm_not_evidence=args.i_confirm_this_is_not_evidence)
    _print(result.as_dict())
    return 0 if result.refused else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m forensics_workshop",
                                description=f"Digital Forensics Workshop "
                                            f"engine {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def with_case(name, fn, helptext, evidence=False):
        sp = sub.add_parser(name, help=helptext)
        sp.add_argument("case")
        if evidence:
            sp.add_argument("evidence")
        sp.add_argument("--examiner", required=True)
        sp.set_defaults(fn=fn)
        return sp

    sub.add_parser("capabilities",
                   help="what is built, planned, deferred and excluded"
                   ).set_defaults(fn=cmd_capabilities)

    case = sub.add_parser("case", help="create or show a case")
    case_sub = case.add_subparsers(dest="case_command", required=True)
    new = case_sub.add_parser("new")
    new.add_argument("case")
    new.add_argument("--id", required=True)
    new.add_argument("--examiner", required=True)
    new.add_argument("--description", default="")
    new.set_defaults(fn=cmd_case_new)
    show = case_sub.add_parser("show")
    show.add_argument("case")
    show.add_argument("--examiner", required=True)
    show.set_defaults(fn=cmd_case_show)

    add = with_case("add", cmd_add, "register a folder as evidence")
    add.add_argument("folder")
    add.add_argument("--label", default="")
    with_case("ingest", cmd_ingest, "hash and index a folder", evidence=True)
    with_case("verify", cmd_verify, "re-hash and compare", evidence=True)
    files = with_case("files", cmd_files, "list the manifest", evidence=True)
    files.add_argument("--filter", default="all",
                       choices=sorted(_manifest.FILTERS))
    files.add_argument("--search", default="")
    files.add_argument("--limit", type=int, default=200)
    dupes = with_case("dupes", cmd_dupes, "files that exist more than once")
    dupes.add_argument("--evidence", default="")
    ext = with_case("extract", cmd_extract, "copy one file into the case",
                    evidence=True)
    ext.add_argument("relpath")
    ext.add_argument("--reason", required=True)
    br = with_case("browser", cmd_browser, "parse browser databases",
                   evidence=True)
    br.add_argument("--all-sqlite", action="store_true")
    with_case("mobile", cmd_mobile,
              "read an iOS backup: device, encryption, file map, artefacts",
              evidence=True)
    ma = with_case("mobile-artefacts", cmd_mobile_artefacts,
                   "list parsed mobile artefacts", evidence=True)
    ma.add_argument("--kind", default="", choices=["", *_mobile.ARTEFACT_KINDS])
    ma.add_argument("--search", default="")
    ma.add_argument("--limit", type=int, default=200)
    art = with_case("artefacts", cmd_artefacts, "list parsed artefacts",
                    evidence=True)
    art.add_argument("--kind", default="", choices=["", *_browser.ARTEFACT_KINDS])
    art.add_argument("--search", default="")
    art.add_argument("--limit", type=int, default=200)
    cus = with_case("custody", cmd_custody, "show and verify the custody log")
    cus.add_argument("--tail", type=int, default=40)

    ai = with_case("add-image", cmd_add_image,
                   "register a RAW/DD image (first segment of a split set)")
    ai.add_argument("image")
    ai.add_argument("--label", default="")
    with_case("image", cmd_image, "hash an image and read its partitions",
              evidence=True)
    with_case("volumes", cmd_volumes, "list an image's volumes and gaps",
              evidence=True)
    nt = with_case("ntfs", cmd_ntfs, "parse an NTFS volume's MFT and journal",
                   evidence=True)
    nt.add_argument("--volume", type=int, required=True)
    nt.add_argument("--no-journal", action="store_true")
    en = with_case("entries", cmd_entries, "list parsed MFT entries",
                   evidence=True)
    en.add_argument("--volume", type=int, required=True)
    en.add_argument("--filter", default="all", choices=_disk.ENTRY_FILTERS)
    en.add_argument("--search", default="")
    en.add_argument("--limit", type=int, default=200)
    ed = with_case("entry", cmd_entry, "everything one MFT record says",
                   evidence=True)
    ed.add_argument("--volume", type=int, required=True)
    ed.add_argument("--record", type=int, required=True)
    pv = with_case("preview", cmd_preview,
                   "an entry's first bytes, identified — nothing written",
                   evidence=True)
    pv.add_argument("--volume", type=int, required=True)
    pv.add_argument("--record", type=int, required=True)
    pv.add_argument("--stream", default="")
    pv.add_argument("--bytes", type=int, default=_disk.PREVIEW_BYTES)
    rc = with_case("recover", cmd_recover,
                   "copy an entry's stream into the case", evidence=True)
    rc.add_argument("--volume", type=int, required=True)
    rc.add_argument("--record", type=int, required=True)
    rc.add_argument("--stream", default="")
    rc.add_argument("--reason", required=True)
    us = with_case("usn", cmd_usn, "list the change journal", evidence=True)
    us.add_argument("--volume", type=int, required=True)
    us.add_argument("--search", default="")
    us.add_argument("--reason", default="")
    us.add_argument("--limit", type=int, default=200)
    cv = with_case("carve", cmd_carve, "carve for files by signature",
                   evidence=True)
    cv.add_argument("--volume", type=int, default=None)
    cv.add_argument("--unallocated", action="store_true")
    cv.add_argument("--types", default="",
                    help=f"comma-separated, from: {', '.join(_carve.TYPES)}")
    cv.add_argument("--every-byte", action="store_true")
    cd = with_case("candidates", cmd_candidates, "list carve candidates",
                   evidence=True)
    cd.add_argument("--type", default="")
    cd.add_argument("--status", default="",
                    choices=["", "complete", "truncated", "capped"])
    cd.add_argument("--run", default="")
    cd.add_argument("--limit", type=int, default=200)
    cp = with_case("carve-preview", cmd_carve_preview,
                   "a candidate's bytes — nothing written", evidence=True)
    cp.add_argument("candidate", type=int)
    cp.add_argument("--bytes", type=int, default=_disk.PREVIEW_BYTES)
    cr = with_case("carve-recover", cmd_carve_recover,
                   "copy a candidate into the case", evidence=True)
    cr.add_argument("candidate", type=int)
    cr.add_argument("--reason", required=True)
    sl = with_case("slack", cmd_slack, "scrape file slack on an NTFS volume",
                   evidence=True)
    sl.add_argument("--volume", type=int, required=True)

    vol = sub.add_parser("volume", help="is this volume read-only?")
    vol.add_argument("path")
    vol.set_defaults(fn=cmd_volume)
    usb = sub.add_parser("usb-policy", help="the USB WriteProtect policy")
    usb.add_argument("action", choices=["status", "on", "off"])
    usb.set_defaults(fn=cmd_usb_policy)
    probe = sub.add_parser("probe-write",
                           help="ATTEMPT a write to a TEST device")
    probe.add_argument("folder")
    probe.add_argument("--i-confirm-this-is-not-evidence", action="store_true")
    probe.set_defaults(fn=cmd_probe_write)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except ForensicsError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except ValueError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
