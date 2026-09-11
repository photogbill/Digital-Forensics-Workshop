"""The case store: created once, checked on every open, never overlapping evidence."""

from __future__ import annotations

import json
import os
import unittest

from _support import EXAMINER, TempDirCase

from forensics_workshop import case as case_mod
from forensics_workshop.case import Case
from forensics_workshop.caseindex import CaseIndex
from forensics_workshop.errors import (CaseError, CaseLayoutError,
                                       CustodyRefused, EvidenceError)


class CreateAndOpen(TempDirCase):
    def test_create_lays_out_the_case_and_records_it(self):
        case = Case.create(self.tmp / "c", case_id="OP-1", examiner=EXAMINER,
                           description="  a description  ")
        for sub in case_mod.LAYOUT:
            self.assertTrue((case.root / sub).is_dir(), sub)
        self.assertTrue((case.root / "index.db").is_file())
        info = json.loads((case.root / "case.json").read_text())
        self.assertEqual(info["case_id"], "OP-1")
        self.assertEqual(info["created_by"], EXAMINER)
        self.assertEqual(info["description"], "a description")
        first = case.custody.rows()[0]
        self.assertEqual(first["action"], "case.created")
        self.assertEqual(first["actor"], {"kind": "examiner", "name": EXAMINER})
        self.assertIn("case.json", first["hashes"])

    def test_an_examiner_is_required(self):
        with self.assertRaises(CustodyRefused):
            Case.create(self.tmp / "c", case_id="OP-1", examiner=" ")
        self.assertFalse((self.tmp / "c").exists(),
                         "a refused case leaves no folder behind")

    def test_bad_identifiers_are_refused(self):
        for bad in ("", "../escape", "a" * 65, "-leading"):
            with self.assertRaises(CaseError):
                Case.create(self.tmp / f"c{len(bad)}", case_id=bad,
                            examiner=EXAMINER)

    def test_a_non_empty_folder_is_refused(self):
        (self.tmp / "busy").mkdir()
        (self.tmp / "busy" / "something.txt").write_text("x")
        with self.assertRaises(CaseError):
            Case.create(self.tmp / "busy", case_id="OP-1", examiner=EXAMINER)

    def test_an_existing_case_is_not_recreated(self):
        Case.create(self.tmp / "c", case_id="OP-1", examiner=EXAMINER)
        with self.assertRaises(CaseError):
            Case.create(self.tmp / "c", case_id="OP-2", examiner=EXAMINER)

    def test_open_records_who_opened_it(self):
        Case.create(self.tmp / "c", case_id="OP-1", examiner=EXAMINER)
        case = Case.open(self.tmp / "c", examiner="Second Examiner")
        last = case.custody.rows()[-1]
        self.assertEqual(last["action"], "case.opened")
        self.assertEqual(last["actor"]["name"], "Second Examiner")
        self.assertTrue(last["detail"]["chain_ok"])
        self.assertEqual(case.integrity(), [])

    def test_an_edited_case_file_is_reported_on_open_not_refused(self):
        Case.create(self.tmp / "c", case_id="OP-1", examiner=EXAMINER)
        path = self.tmp / "c" / "case.json"
        data = json.loads(path.read_text())
        data["description"] = "quietly changed"
        path.write_text(json.dumps(data))
        case = Case.open(self.tmp / "c", examiner=EXAMINER)
        self.assertTrue(any("changed since" in p for p in case.integrity()))
        self.assertEqual(case.custody.rows()[-1]["detail"]["integrity_problems"],
                         case.integrity())

    def test_open_refuses_what_is_not_a_case(self):
        with self.assertRaises(CaseError):
            Case.open(self.tmp, examiner=EXAMINER)

    def test_path_refuses_to_leave_the_case(self):
        case = Case.create(self.tmp / "c", case_id="OP-1", examiner=EXAMINER)
        self.assertTrue(case.path("extracted", "x").is_relative_to(case.root)
                        if hasattr(case.root, "is_relative_to") else True)
        with self.assertRaises(CaseError):
            case.path("..", "outside")


class Evidence(TempDirCase):
    def setUp(self):
        super().setUp()
        self.src = self.tmp / "src"
        (self.src / "inner").mkdir(parents=True)
        (self.src / "a.txt").write_text("a")
        self.case = Case.create(self.tmp / "case", case_id="EV-1",
                                examiner=EXAMINER)

    def test_register_writes_a_sidecar_and_a_custody_record(self):
        item = self.case.add_folder(self.src, label="laptop")
        self.assertEqual(item.id, "E001")
        self.assertEqual(item.kind, "logical-folder")
        sidecar = json.loads((self.case.root / "evidence" / "E001.json").read_text())
        self.assertEqual(sidecar["source"], os.path.realpath(self.src))
        self.assertIn("read_only", sidecar["volume"])
        rec = self.case.custody.last("evidence.registered", "E001")
        self.assertIn("sidecar", rec["hashes"])
        self.assertEqual([e.id for e in self.case.evidence()], ["E001"])

    def test_ids_increase(self):
        other = self.tmp / "other"
        other.mkdir()
        self.case.add_folder(self.src)
        self.assertEqual(self.case.add_folder(other).id, "E002")

    def test_registration_reads_nothing_inside_the_source(self):
        before = {p: p.stat().st_mtime_ns for p in self.src.rglob("*")}
        self.case.add_folder(self.src)
        self.assertEqual(before, {p: p.stat().st_mtime_ns
                                  for p in self.src.rglob("*")})

    def test_a_case_inside_the_evidence_is_refused(self):
        inside = Case.create(self.src / "inner" / "case", case_id="BAD",
                             examiner=EXAMINER)
        with self.assertRaises(CaseLayoutError):
            inside.add_folder(self.src)

    def test_evidence_inside_the_case_is_refused(self):
        nested = self.case.root / "extracted" / "loot"
        nested.mkdir()
        with self.assertRaises(CaseLayoutError):
            self.case.add_folder(nested)

    def test_the_same_or_an_overlapping_source_is_refused(self):
        self.case.add_folder(self.src)
        with self.assertRaises(EvidenceError):
            self.case.add_folder(self.src)
        with self.assertRaises(EvidenceError):
            self.case.add_folder(self.src / "inner")

    def test_a_file_is_not_a_folder(self):
        with self.assertRaises(EvidenceError):
            self.case.add_folder(self.src / "a.txt")


class Index(TempDirCase):
    def test_remember_anchor_and_present(self):
        case = Case.create(self.tmp / "c", case_id="IX-1", examiner=EXAMINER)
        idx = CaseIndex(self.tmp / "atk" / "data" / "case_index.json")
        idx.remember(case)
        entries = idx.entries()
        self.assertEqual(len(entries), 1)
        self.assertTrue(entries[0]["present"])
        self.assertEqual(idx.anchor(case.root), case.custody.head())

        reopened = Case.open(case.root, examiner=EXAMINER,
                             anchor=idx.anchor(case.root))
        self.assertEqual(reopened.integrity(), [])

    def test_a_missing_case_is_listed_as_missing(self):
        idx = CaseIndex(self.tmp / "idx.json")
        case = Case.create(self.tmp / "c", case_id="IX-2", examiner=EXAMINER)
        idx.remember(case)
        os.rename(self.tmp / "c", self.tmp / "moved")
        self.assertFalse(idx.entries()[0]["present"])

    def test_the_anchor_catches_a_rewritten_log_on_open(self):
        idx = CaseIndex(self.tmp / "idx.json")
        case = Case.create(self.tmp / "c", case_id="IX-3", examiner=EXAMINER)
        idx.remember(case)
        case.custody.path.unlink()
        case.custody.record("case.created", actor=case.actor(),
                            target="IX-3", hashes={"case.json": "forged"})
        reopened = Case.open(case.root, examiner=EXAMINER,
                             anchor=idx.anchor(case.root))
        self.assertTrue(any("rewritten" in p or "no longer" in p
                            for p in reopened.integrity()),
                        reopened.integrity())

    def test_forget_touches_only_the_index(self):
        idx = CaseIndex(self.tmp / "idx.json")
        case = Case.create(self.tmp / "c", case_id="IX-4", examiner=EXAMINER)
        idx.remember(case)
        self.assertTrue(idx.forget(case.root))
        self.assertFalse(idx.forget(case.root))
        self.assertEqual(idx.entries(), [])
        self.assertTrue((case.root / "case.json").is_file())


if __name__ == "__main__":
    unittest.main()
