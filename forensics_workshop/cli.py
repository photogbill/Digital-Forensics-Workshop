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
    python -m forensics_workshop domex         CASE E002 --volume N --examiner NAME [--categories image,document,email] [--path Users] [--limit N]
    python -m forensics_workshop domex-list    CASE E002 --examiner NAME [--kind image] [--geo] [--search TEXT]
    python -m forensics_workshop auto          CASE E002 --examiner NAME [--steps image,ntfs,domex,slack] [--carve] [--path Users] [--force]
    python -m forensics_workshop hunt          CASE E002 --examiner NAME [--terms ransom,pier] [--watchlist +1555...] [--selectors email,phone] [--hashset bad.txt] [--no-high-value]
    python -m forensics_workshop findings      CASE --examiner NAME [--status proposed] [--kind pipeline-run] [--id ID]
    python -m forensics_workshop confirm       CASE FINDING_ID --examiner NAME [--note TEXT]
    python -m forensics_workshop reject        CASE FINDING_ID --examiner NAME [--note TEXT]
  voice comparison (FORENSICS_PLAN §13) — SpeechBrain ECAPA in its own process
    python -m forensics_workshop voice-enrol    CASE FILE... --examiner NAME --name "Caller A" [--profile ID] --model-dir DIR --python EXE --ffmpeg EXE [--device auto|cuda|cpu] [--evidence E001]
    python -m forensics_workshop voice-profiles CASE --examiner NAME
    python -m forensics_workshop voice-compare  CASE INPUT --examiner NAME --model-dir DIR --python EXE --ffmpeg EXE [--calibration NAME] [--prior 0.5] [--profile ID]... [--evidence E001] [--device auto]
    python -m forensics_workshop voice-runs     CASE --examiner NAME [--id RUN_ID]
    python -m forensics_workshop voice-calibrate REFERENCE_DIR --name NAME --out DIR --model-dir DIR --python EXE --ffmpeg EXE [--conditions TEXT] [--max-clips 8]
    python -m forensics_workshop voice-calibrations --model-dir DIR
  audio restoration (FORENSICS_PLAN §13.3-13.4) — analyse, recommend, run, export
    python -m forensics_workshop restore-analyse CASE INPUT --examiner NAME --ffmpeg EXE --python EXE --scratch DIR [--evidence E001] [--no-faint]
    python -m forensics_workshop restore-run     CASE RUN_ID --examiner NAME --ffmpeg EXE --python EXE --scratch DIR --models-root DIR [--option ID]... [--all] [--force] [--device auto] [--deepfilter EXE] [--rnnoise-model FILE]
    python -m forensics_workshop restore-list    CASE --examiner NAME [--id RUN_ID]
    python -m forensics_workshop restore-export  CASE RUN_ID FILE --examiner NAME
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
from . import domex as _domex
from . import hunts as _hunts
from . import pipeline as _pipeline
from . import review as _review
from . import manifest as _manifest
from . import verify as _verify
from .artefacts import browser as _browser
from .artefacts import mobile as _mobile
from .media import restore as _restore
from .media import voiceprint as _voice
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


def cmd_domex(args) -> int:
    case = _open(args)
    categories = [c.strip() for c in args.categories.split(",") if c.strip()] \
        or _domex.DEFAULT_CATEGORIES
    summary = _domex.analyse_volume(
        case, args.evidence, args.volume, categories=categories,
        path_prefix=args.path, limit=args.limit, max_file_mb=args.max_file_mb,
        progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_domex_list(args) -> int:
    case = _open(args)
    rows, total = _domex.list_domex(case, args.evidence, artefact=args.kind,
                                    geo_only=args.geo, search=args.search,
                                    limit=args.limit)
    for r in rows:
        print(f"{r['at_utc'] or '(no time)':28} {r['artefact']:9} "
              f"{r['title'][:40]:40} {r['value']}".rstrip())
    print(f"\n{len(rows)} shown of {total}")
    return 0


def cmd_auto(args) -> int:
    case = _open(args)
    steps = [s.strip() for s in args.steps.split(",") if s.strip()] \
        or _pipeline.DEFAULT_STEPS
    summary = _pipeline.run_pipeline(
        case, args.evidence, steps=steps, carve=args.carve, domex_path=args.path,
        domex_limit=args.limit, force=args.force, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


_MARK = {"proposed": "?", "confirmed": "✓", "rejected": "✗"}


def cmd_findings(args) -> int:
    case = _open(args)
    if args.id:
        f = _review.finding(case, args.id)
        if f is None:
            print(f"no finding {args.id}", file=sys.stderr)
            return 1
        _print(f.as_dict())
        return 0
    for f in _review.list_findings(case, status=args.status, kind=args.kind,
                                   evidence_id=args.evidence):
        print(f"{_MARK.get(f.status, '?')} {f.id} {f.source:14} {f.kind:13} "
              f"{f.title}")
    t = _review.counts(case)
    print(f"\nproposed {t['proposed']} · confirmed {t['confirmed']} · "
          f"rejected {t['rejected']}")
    return 0


def cmd_hunt(args) -> int:
    case = _open(args)
    terms = [t.strip() for t in args.terms.split(",") if t.strip()]
    watch = [t.strip() for t in args.watchlist.split(",") if t.strip()]
    kinds = [k.strip().lower() for k in args.selectors.split(",") if k.strip()] \
        or list(_hunts.SELECTOR_KINDS)
    hashset: list = []
    if args.hashset:
        with open(args.hashset, encoding="utf-8") as fh:
            hashset = fh.read().split()
    summary = _hunts.run_hunts(
        case, args.evidence, selectors=not args.no_selectors,
        selector_kinds=kinds, terms=terms, watchlist=watch, hashset=hashset,
        high_value=not args.no_high_value, progress=_progress)
    _print(summary.as_dict())
    return 0 if summary.state == "completed" else 1


def cmd_confirm(args) -> int:
    case = _open(args)
    _print(_review.decide(case, args.finding, "confirmed", note=args.note))
    return 0


def cmd_reject(args) -> int:
    case = _open(args)
    _print(_review.decide(case, args.finding, "rejected", note=args.note))
    return 0


def _voice_kw(args) -> dict:
    return {"model_dir": args.model_dir, "python": args.python or None,
            "ffmpeg": args.ffmpeg or None, "device": args.device,
            "scratch": args.scratch or None}


def cmd_voice_enrol(args) -> int:
    case = _open(args)
    profile = _voice.enrol(case, args.files, name=args.name,
                           profile_id=args.profile, evidence_id=args.evidence,
                           progress=_progress, **_voice_kw(args))
    shown = {k: v for k, v in profile.items() if k != "embedding"}
    shown["samples"] = [{k: v for k, v in sample.items()
                         if k not in ("embedding", "segments")}
                        for sample in profile.get("samples") or []]
    _print(shown)
    return 0


def cmd_voice_profiles(args) -> int:
    rows = _voice.list_profiles(_open(args))
    for r in rows:
        print(f"{r['id']:34} {r['name'] or '-':24} samples {r['samples']:>2} "
              f"speech {r['net_speech_s']:7.1f} s"
              + (f"  [{r['error']}]" if r.get("error") else ""))
    print(f"\n{len(rows)} voice profile(s)")
    return 0


def _print_voice(result: dict) -> None:
    shown = {k: v for k, v in result.items() if k != "embedding"}
    _print(shown)
    for m in result.get("matches") or []:
        what = m.get("shown") or f"raw {m['score']:.3f} (uncalibrated)"
        print(f"  {m['name']:24} {what:>28}  {m['band']}", file=sys.stderr)
    for f in result.get("flags") or []:
        print(f"  [{f['level']}] {f['text']}", file=sys.stderr)


def cmd_voice_compare(args) -> int:
    case = _open(args)
    _print_voice(_voice.compare(
        case, args.input, profiles=args.profile or None,
        calibration=args.calibration, prior=args.prior,
        evidence_id=args.evidence, progress=_progress, **_voice_kw(args)))
    return 0


def cmd_voice_runs(args) -> int:
    case = _open(args)
    if args.id:
        _print_voice(_voice.load_run(case, args.id))
        return 0
    rows = _voice.list_runs(case)
    for r in rows:
        print(f"{r['run_id']:34} {r['state']:10} {r['input'][:28]:28} "
              f"closest {r['closest'] or '-':20} {r['shown'] or ''}"
              + (f"  [{r['error']}]" if r.get("error") else ""))
    print(f"\n{len(rows)} voice comparison(s)")
    return 0


def cmd_voice_calibrate(args) -> int:
    _print(_voice.calibrate(args.reference, name=args.name, out_dir=args.out,
                            conditions=args.conditions,
                            max_clips=args.max_clips, progress=_progress,
                            **_voice_kw(args)))
    return 0


def cmd_voice_calibrations(args) -> int:
    _print(_voice.load_calibrations(args.model_dir))
    return 0


def _print_restore(report: dict) -> None:
    _print({k: v for k, v in report.items() if k not in ("options",)}
           | {"options": [{k: o[k] for k in ("id", "label", "tier", "score",
                                              "recommended")}
                          for o in report.get("options") or []]})
    for i in report.get("issues") or []:
        print(f"  [{i['severity']}] {i['label']}: {i['measured']}",
              file=sys.stderr)
    for o in report.get("options") or []:
        mark = "*" if o["recommended"] else " "
        print(f" {mark} {o['id']:16} {o['tier']:9} {o['label']}",
              file=sys.stderr)


def cmd_restore_analyse(args) -> int:
    case = _open(args)
    report = _restore.analyse(
        case, args.input, ffmpeg=args.ffmpeg, python=args.python or None,
        scratch=args.scratch, evidence_id=args.evidence,
        faint=not args.no_faint, progress=_progress)
    _print_restore(report)
    fa = (report.get("analysis") or {}).get("faint") or {}
    for e in fa.get("events") or []:
        print(f"  faint #{e['n']} {e['start_s']:.1f}-{e['end_s']:.1f} s "
              f"{e['f_lo']:.0f}-{e['f_hi']:.0f} Hz z {e['z']:.1f} "
              f"({e['broadband_snr_db']:+.0f} dB) {e.get('confidence', '')}",
              file=sys.stderr)
    return 0


def cmd_restore_run(args) -> int:
    case = _open(args)
    which = "all" if args.all else (args.option or "best")
    report = _restore.run(case, args.run_id, which, ffmpeg=args.ffmpeg,
                          python=args.python or None, scratch=args.scratch,
                          models_root=args.models_root, device=args.device,
                          force=args.force, deepfilter=args.deepfilter or None,
                          rnnoise_model=args.rnnoise_model or None,
                          progress=_progress)
    _print_restore(report)
    for r in report.get("results") or []:
        removed = (r.get("measured") or {}).get("removed") or {}
        print(f"  {r['option']:16} {r['tier']:9} "
              f"pauses {removed.get('during_pauses_db')} dB, speech "
              f"{removed.get('during_speech_db')} dB"
              + ("  SPEECH ONLY" if r.get("speech_only") else "")
              + (f"  ERROR {r['error']}" if r.get("error") else ""),
              file=sys.stderr)
    return 0


def cmd_restore_list(args) -> int:
    case = _open(args)
    if args.id:
        _print_restore(_restore.load_run(case, args.id))
        return 0
    rows = _restore.list_runs(case)
    for r in rows:
        print(f"{r['run_id']:34} {r['input'][:28]:28} issues {r['issues']:>2} "
              f"best {r['best'] or '-':16} ran {','.join(r['ran']) or '-'}"
              + (f"  [{r['error']}]" if r.get("error") else ""))
    print(f"\n{len(rows)} restoration run(s)")
    return 0


def cmd_restore_export(args) -> int:
    _print(_restore.export(_open(args), args.run_id, args.file))
    return 0


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
    dx = with_case("domex", cmd_domex,
                   "mine documents, images (EXIF/GPS) and email on a volume",
                   evidence=True)
    dx.add_argument("--volume", type=int, required=True)
    dx.add_argument("--categories", default=",".join(_domex.DEFAULT_CATEGORIES),
                    help=f"comma-separated, from: {', '.join(_domex.CATEGORIES)}")
    dx.add_argument("--path", default="", help="only files under this path")
    dx.add_argument("--limit", type=int, default=0, help="0 = no limit")
    dx.add_argument("--max-file-mb", type=int, default=512)
    dl = with_case("domex-list", cmd_domex_list, "list mined DOMEX artefacts",
                   evidence=True)
    dl.add_argument("--kind", default="", choices=["", *_domex.ARTEFACT_KINDS])
    dl.add_argument("--geo", action="store_true", help="only geotagged rows")
    dl.add_argument("--search", default="")
    dl.add_argument("--limit", type=int, default=200)

    au = with_case("auto", cmd_auto,
                   "run the whole deterministic pipeline on a disk image",
                   evidence=True)
    au.add_argument("--steps", default=",".join(_pipeline.DEFAULT_STEPS),
                    help=f"comma-separated, from: {', '.join(_pipeline.STEPS)}")
    au.add_argument("--carve", action="store_true",
                    help="also carve each volume's unallocated space (slow)")
    au.add_argument("--path", default="", help="scope DOMEX to files under this path")
    au.add_argument("--limit", type=int, default=0, help="cap DOMEX rows (0 = no cap)")
    au.add_argument("--force", action="store_true",
                    help="redo steps whose output is already in the index")
    ht = with_case("hunt", cmd_hunt,
                   "deterministic hunts over the parsed rows → the review queue",
                   evidence=True)
    ht.add_argument("--terms", default="", help="comma-separated keywords")
    ht.add_argument("--watchlist", default="",
                    help="comma-separated watchlist values")
    ht.add_argument("--selectors", default="",
                    help="selector kinds, blank for all: "
                         + ",".join(_hunts.SELECTOR_KINDS))
    ht.add_argument("--no-selectors", action="store_true")
    ht.add_argument("--hashset", default="",
                    help="path to a file of known-bad SHA-256 hashes")
    ht.add_argument("--no-high-value", action="store_true")
    fn = with_case("findings", cmd_findings,
                   "the review queue: proposals awaiting an examiner")
    fn.add_argument("--evidence", default="")
    fn.add_argument("--status", default="",
                    choices=["", "proposed", "confirmed", "rejected"])
    fn.add_argument("--kind", default="")
    fn.add_argument("--id", default="", help="show one finding in full")
    cf = with_case("confirm", cmd_confirm, "admit a finding (a custodial act)")
    cf.add_argument("finding")
    cf.add_argument("--note", default="")
    rj = with_case("reject", cmd_reject, "reject a finding (a custodial act)")
    rj.add_argument("finding")
    rj.add_argument("--note", default="")


    def voice_runtime(sp):
        sp.add_argument("--model-dir", required=True,
                        help="the spkrec-ecapa-voxceleb folder")
        sp.add_argument("--python", default="",
                        help="a Python with torch and SpeechBrain "
                             "(ATK: envs\\atk_audio\\Scripts\\python.exe)")
        sp.add_argument("--ffmpeg", default="", help="FFmpeg")
        sp.add_argument("--device", default="auto",
                        choices=["auto", "cuda", "cpu"])
        sp.add_argument("--scratch", default="",
                        help="the worker's temp and cache folder (default: "
                             "tmp beside the model folder)")
    ve = with_case("voice-enrol", cmd_voice_enrol,
                   "make a voice profile from known recordings, or add to one")
    ve.add_argument("files", nargs="+")
    ve.add_argument("--name", default="")
    ve.add_argument("--profile", default="", help="add to this profile")
    ve.add_argument("--evidence", default="")
    voice_runtime(ve)
    with_case("voice-profiles", cmd_voice_profiles, "the case's voice profiles")
    vc = with_case("voice-compare", cmd_voice_compare,
                   "score a recording against the case's voice profiles "
                   "(a LEAD, filed into the review queue)")
    vc.add_argument("input")
    vc.add_argument("--calibration", default="",
                    help="a calibration's name; without one, raw scores only")
    vc.add_argument("--prior", type=float, default=_voice.DEFAULT_PRIOR)
    vc.add_argument("--profile", action="append", default=[])
    vc.add_argument("--evidence", default="")
    voice_runtime(vc)
    vr = with_case("voice-runs", cmd_voice_runs, "the case's voice comparisons")
    vr.add_argument("--id", default="")
    vk = sub.add_parser("voice-calibrate",
                        help="fit a calibration on a reference set (one "
                             "subfolder per speaker) and keep it beside the "
                             "model")
    vk.add_argument("reference")
    vk.add_argument("--name", required=True)
    vk.add_argument("--out", required=True,
                    help="a folder outside every case for the working files")
    vk.add_argument("--conditions", default="")
    vk.add_argument("--max-clips", type=int,
                    default=_voice.MAX_CLIPS_PER_SPEAKER)
    voice_runtime(vk)
    vk.set_defaults(fn=cmd_voice_calibrate)
    vl = sub.add_parser("voice-calibrations",
                        help="the calibrations kept beside a voice model")
    vl.add_argument("--model-dir", required=True)
    vl.set_defaults(fn=cmd_voice_calibrations)

    def restore_runtime(sp):
        sp.add_argument("--ffmpeg", required=True)
        sp.add_argument("--python", default="",
                        help="a Python with torch and SpeechBrain")
        sp.add_argument("--scratch", required=True,
                        help="the worker's temp and cache folder, outside "
                             "every case")
    ra = with_case("restore-analyse", cmd_restore_analyse,
                   "measure a recording and rank what could restore it")
    ra.add_argument("input")
    ra.add_argument("--evidence", default="")
    ra.add_argument("--no-faint", action="store_true",
                    help="skip the faint-sound search (salience map, clips, "
                         "repeats)")
    restore_runtime(ra)
    rr = with_case("restore-run", cmd_restore_run,
                   "run the best option of an analysis, chosen ones, or all")
    rr.add_argument("run_id")
    rr.add_argument("--option", action="append", default=[])
    rr.add_argument("--all", action="store_true")
    rr.add_argument("--force", action="store_true")
    rr.add_argument("--models-root", required=True,
                    help="the folder holding the SpeechBrain model folders")
    rr.add_argument("--device", default="auto",
                    choices=["auto", "cuda", "cpu"])
    rr.add_argument("--deepfilter", default="",
                    help="DeepFilterNet's deep-filter.exe (option dfn)")
    rr.add_argument("--rnnoise-model", default="",
                    help="the RNNoise model file, sh.rnnn (option rnnoise)")
    restore_runtime(rr)
    rl = with_case("restore-list", cmd_restore_list,
                   "the case's restoration runs")
    rl.add_argument("--id", default="")
    rx = with_case("restore-export", cmd_restore_export,
                   "copy one restoration output into the case's exports")
    rx.add_argument("run_id")
    rx.add_argument("file")

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
