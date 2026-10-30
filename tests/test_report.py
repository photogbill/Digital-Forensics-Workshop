"""The case report and IOC export (report.py): confirmed findings only,
model-made findings marked, cards masked in the IOC export, every file new,
inside the case, hashed and recorded in custody."""

from __future__ import annotations

import csv
import json
import unittest
from pathlib import Path

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

from forensics_workshop import blocker, hashing, ingest, report, review
from forensics_workshop.case import Case
from forensics_workshop.errors import CasePathError


class ReportCase(TempDirCase):
    def setUp(self):
        super().setUp()
        self.case = Case.create(self.tmp / "case", case_id="REP-1",
                                examiner=EXAMINER, description="report test")
        folder = self.tmp / "ev"
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        self.eid = self.case.add_folder(folder, label="phone dump").id
        P = lambda **kw: review.propose(self.case, evidence_id=self.eid, **kw)
        self.email = P(source="engine", kind="selector:email",
                       title="E-mail: alice@example.com — 3 artefact(s)",
                       detail={"hunt": "selector:email", "value": "alice@example.com",
                               "count": 3, "first_at": "2026-07-01T10:00:00Z",
                               "last_at": "2026-07-04T13:22:10Z"})
        self.card = P(source="engine", kind="selector:card",
                      title="Card number: 4111111111111111 — 1 artefact(s)",
                      detail={"hunt": "selector:card", "value": "4111111111111111",
                              "count": 1})
        self.bad = P(source="engine", kind="hashset",
                     title="known-bad file: tools/x.exe",
                     detail={"hunt": "hashset", "sha256": "ab" * 32,
                             "relpath": "tools/x.exe", "size": 10})
        self.tr = P(source="model:qwen2.5-7b.gguf", kind="ai-translation",
                    title="Translation (Spanish → English): note.txt",
                    detail={"source_language": "Spanish",
                            "target_language": "English", "confidence": "high",
                            "original": "nos vemos en el muelle",
                            "translation": "see you at the pier",
                            "reasoning": [{"original": "muelle",
                                           "rendered_as": "pier",
                                           "why": "a harbour structure here"}],
                            "uncertain": [], "item": {"path": "note.txt",
                                                      "ref": "E001:note.txt"}})
        self.rejected = P(source="engine", kind="selector:ipv4",
                          title="IPv4: 10.9.8.7 — 1 artefact(s)",
                          detail={"hunt": "selector:ipv4", "value": "10.9.8.7"})
        self.pending = P(source="model:qwen2.5-7b.gguf", kind="ai-text",
                         title="Threats: chat.txt",
                         detail={"quote": "PENDING-QUOTE-XYZ", "why": "w"})
        for fid in (self.email, self.card, self.bad, self.tr):
            review.decide(self.case, fid, "confirmed", note="checked")
        review.decide(self.case, self.rejected, "rejected")


class TheReport(ReportCase):
    def test_only_confirmed_findings_appear(self):
        text, facts = report.build_html(self.case)
        self.assertIn("alice@example.com", text)
        self.assertIn("known-bad file: tools/x.exe", text)
        self.assertNotIn("10.9.8.7", text)            # rejected
        self.assertNotIn("PENDING-QUOTE-XYZ", text)   # still awaiting review
        self.assertEqual(facts["confirmed"], 4)
        self.assertEqual(facts["awaiting"], 1)
        self.assertEqual(facts["rejected"], 1)
        self.assertIn("1 still awaiting review and 1 rejected", text)

    def test_model_findings_are_marked_and_quoted(self):
        text, facts = report.build_html(self.case)
        self.assertEqual(facts["model_findings"], 1)
        self.assertIn("proposed by a model (qwen2.5-7b.gguf)", text)
        self.assertIn("found by the engine (deterministic)", text)
        self.assertIn("stated reasoning", text)
        self.assertIn("nos vemos en el muelle", text)

    def test_html_is_escaped_and_self_contained(self):
        review.decide(self.case, review.propose(
            self.case, source="engine", kind="keyword", evidence_id=self.eid,
            title="<script>alert(1)</script>"), "confirmed")
        text, _ = report.build_html(self.case)
        self.assertNotIn("<script>", text)
        self.assertNotIn("http://", text)
        self.assertNotIn("https://", text)

    def test_case_and_evidence_and_chain(self):
        text, facts = report.build_html(self.case)
        self.assertIn("REP-1", text)
        self.assertIn("phone dump", text)
        self.assertIn("<td>—</td>", text)     # not ingested yet: no hash claimed
        ingest.ingest_folder(self.case, self.eid)
        text, _ = report.build_html(self.case)
        self.assertIn("Manifest SHA-256", text)
        self.assertTrue(facts["chain_ok"])
        self.assertIn("Custody chain intact", text)


class TheFiles(ReportCase):
    def test_generate_writes_hashes_and_records_custody(self):
        out = report.generate(self.case, title="Op Pier")
        for key in ("html", "iocs_csv", "iocs_json"):
            path = Path(out["files"][key]["path"])
            self.assertTrue(path.is_file())
            self.assertTrue(blocker.is_inside(path, self.case.root))
            self.assertEqual(hashing.hash_bytes(path.read_bytes()).sha256,
                             out["files"][key]["sha256"])
        rec = self.case.custody.last("report.generated")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["hashes"]["sha256"], out["files"]["html"]["sha256"])
        self.assertTrue(self.case.custody.verify().ok)

    def test_the_command_line(self):
        import contextlib
        import io
        from forensics_workshop import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["report", str(self.case.root), "--examiner",
                             EXAMINER, "--title", "Op Pier"])
        self.assertEqual(code, 0)
        self.assertIsNotNone(self.case.custody.last("report.generated"))
        self.assertIn('"confirmed": 4', out.getvalue())

    def test_iocs_mask_cards_and_skip_unconfirmed(self):
        out = report.generate(self.case)
        with open(out["files"]["iocs_csv"]["path"], encoding="utf-8-sig") as fh:
            rows = list(csv.DictReader(fh))
        by_type = {r["type"]: r["value"] for r in rows}
        self.assertEqual(by_type["email"], "alice@example.com")
        self.assertEqual(by_type["sha256"], "ab" * 32)
        self.assertTrue(by_type["card"].endswith("1111"))
        self.assertNotIn("4111111111111111", by_type["card"])
        self.assertNotIn("ipv4", by_type)              # rejected
        data = json.loads(Path(out["files"]["iocs_json"]["path"]).read_text("utf-8"))
        self.assertEqual(len(data["iocs"]), 3)
        self.assertEqual(out["iocs"], 3)
        raw = Path(out["files"]["iocs_csv"]["path"]).read_text("utf-8-sig")
        self.assertNotIn("4111111111111111", raw)

    def test_the_writer_refuses_outside_the_case(self):
        with self.assertRaises(CasePathError):
            report._write_case_file(self.case, self.tmp / "outside.html", b"x")
        self.assertFalse((self.tmp / "outside.html").exists())

    def test_never_overwrites(self):
        target = self.case.root / "reports" / "same.html"
        report._write_case_file(self.case, target, b"one")
        with self.assertRaises(FileExistsError):
            report._write_case_file(self.case, target, b"two")
        self.assertEqual(target.read_bytes(), b"one")


class Masking(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(report.mask_card("4111 1111 1111 1234"),
                         "••••••••••••1234")


if __name__ == "__main__":
    unittest.main()
