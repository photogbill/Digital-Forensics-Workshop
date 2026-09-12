"""Hunts turn parsed rows into leads an examiner can confirm.

The selector regexes are held to spec-shaped strings (an octet over 255 is not
an IP, a thirteen-digit number is a card only if Luhn says so, an all-one-digit
run is not a phone). Then a synthetic `artefacts` corpus — the shape DOMEX and
the mobile parser produce — is hunted end to end: the values come back as
findings that cite the exact rows, a re-run adds nothing, and a hunt over a
corpus that was never parsed says so instead of returning a confident nothing."""

from __future__ import annotations

import json
import unittest

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

from forensics_workshop import hunts, index, review
from forensics_workshop.case import Case
from forensics_workshop.errors import EvidenceError


class Selectors(unittest.TestCase):
    def test_the_high_precision_selectors(self):
        s = hunts.find_selectors(
            "mail a@b.com, ip 8.8.8.8 not 300.1.1.1, eth "
            "0xABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD, card 4111111111111111 "
            "not 4111111111111112")
        self.assertEqual(s["email"], {"a@b.com"})
        self.assertEqual(s["ipv4"], {"8.8.8.8"})
        self.assertEqual(s["eth"], {"0xabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"})
        self.assertEqual(s["card"], {"4111111111111111"})   # Luhn-valid only

    def test_luhn_is_what_makes_a_card_a_card(self):
        self.assertTrue(hunts._luhn_ok("4111111111111111"))
        self.assertFalse(hunts._luhn_ok("4111111111111112"))

    def test_phone_normalises_and_rejects_nonsense(self):
        self.assertEqual(hunts._norm_phone("+1 (555) 123-4567"), "+15551234567")
        self.assertIsNone(hunts._norm_phone("0000000000"))     # all one digit
        self.assertIsNone(hunts._norm_phone("12345"))          # too short


ARTEFACT_COLS = ("run_id", "evidence_id", "source_relpath", "parser",
                 "artefact", "at_utc", "url", "title", "value", "detail_json",
                 "provenance", "row_ref")


class OverACorpus(TempDirCase):
    def setUp(self):
        super().setUp()
        self.case = Case.create(self.tmp / "case", case_id="HUNT-1",
                                examiner=EXAMINER)
        folder = self.tmp / "ev"
        folder.mkdir()
        (folder / "a.txt").write_text("x")
        self.eid = self.case.add_folder(folder).id

    def _add(self, rows):
        for r in rows:
            r.setdefault("run_id", "testrun")
            r.setdefault("source_relpath", r.get("row_ref", ""))
        with index.session(self.case.root) as conn:
            conn.executemany(
                "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
                "parser, artefact, at_utc, url, title, value, detail_json, "
                "provenance, row_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                [tuple(r.get(c) for c in ARTEFACT_COLS) for r in rows])

    def _corpus(self):
        self._add([
            {"evidence_id": self.eid, "parser": "domex", "artefact": "email",
             "at_utc": "2026-07-04T13:22:10Z", "title": "meet at the pier",
             "value": "From alice@example.com to bob@example.com",
             "detail_json": json.dumps({"email": {"from": "alice@example.com",
                                                  "to": "bob@example.com"}}),
             "provenance": "domex-native", "row_ref": "v4:mft100"},
            {"evidence_id": self.eid, "parser": "mobile", "artefact": "message",
             "at_utc": "2026-07-05T09:00:00Z", "title": "+1 (555) 123-4567",
             "value": "bring the ransom to the docks",
             "detail_json": "{}", "provenance": "wal", "row_ref": "message:7"},
            {"evidence_id": self.eid, "parser": "domex", "artefact": "document",
             "at_utc": "2026-07-01T00:00:00Z", "title": "plan.docx",
             "value": "Bob Jones", "detail_json": "{}",
             "provenance": "domex-native", "row_ref": "v4:mft200"},
            {"evidence_id": self.eid, "parser": "domex", "artefact": "image",
             "at_utc": "2026-07-02T00:00:00Z", "title": "beach.jpg",
             "value": "GPS 40.44620,-79.98220",
             "detail_json": json.dumps({"path": "Photos/beach.jpg",
                                        "geo": {"lat": 40.44620, "lon": -79.98220,
                                                "ts_utc": "2026-07-02T00:00:00Z"}}),
             "provenance": "domex-native", "row_ref": "v4:mft300"},
        ])

    def test_selectors_become_findings_that_cite_the_rows(self):
        self._corpus()
        summary = hunts.run_hunts(self.case, self.eid, high_value=False)
        self.assertEqual(summary.state, "completed")
        emails = review.list_findings(self.case, kind="selector:email")
        found = {f.detail["value"]: f for f in emails}
        self.assertIn("alice@example.com", found)
        self.assertIn("bob@example.com", found)
        self.assertEqual(found["alice@example.com"].detail["count"], 1)
        self.assertEqual(found["alice@example.com"].detail["row_refs"], ["v4:mft100"])
        phones = review.list_findings(self.case, kind="selector:phone")
        self.assertTrue(any("5551234567" in f.detail["value"] for f in phones))

    def test_a_keyword_hunt_cites_the_message(self):
        self._corpus()
        hunts.run_hunts(self.case, self.eid, selectors=False, high_value=False,
                        terms=["ransom", "unrelatedxyz"])
        hits = review.list_findings(self.case, kind="keyword")
        self.assertEqual([f.detail["term"] for f in hits], ["ransom"])
        self.assertEqual(hits[0].detail["row_refs"], ["message:7"])

    def test_high_value_surfaces_the_geotagged_photo_and_counts(self):
        self._corpus()
        hunts.run_hunts(self.case, self.eid, selectors=False)
        hv = review.list_findings(self.case, kind="high-value")
        titles = [f.title for f in hv]
        self.assertTrue(any("geotagged photo" in t for t in titles))
        self.assertTrue(any("document" in t for t in titles))
        geo = next(f for f in hv if "geotagged photo" in f.title)
        self.assertEqual(geo.detail["path"], "Photos/beach.jpg")
        self.assertAlmostEqual(geo.detail["lat"], 40.44620, places=4)

    def test_a_re_run_adds_nothing_new(self):
        self._corpus()
        first = hunts.run_hunts(self.case, self.eid)
        _rows, before = review.list_findings(self.case), None
        before = len(review.list_findings(self.case))
        second = hunts.run_hunts(self.case, self.eid)
        after = len(review.list_findings(self.case))
        self.assertEqual(before, after, "a second run duplicated findings")
        self.assertEqual(second.proposed, 0)
        self.assertGreater(second.skipped_existing, 0)
        self.assertGreater(first.proposed, 0)

    def test_a_rejected_lead_stays_rejected_across_a_re_run(self):
        self._corpus()
        hunts.run_hunts(self.case, self.eid)
        email = next(f for f in review.list_findings(self.case,
                                                     kind="selector:email"))
        review.decide(self.case, email.id, "rejected")
        hunts.run_hunts(self.case, self.eid)                 # re-run
        same = review.finding(self.case, email.id)
        self.assertEqual(same.status, "rejected")
        # and it was not re-proposed as a fresh proposed finding
        dupes = [f for f in review.list_findings(self.case, kind="selector:email")
                 if f.detail["value"] == email.detail["value"]]
        self.assertEqual(len(dupes), 1)

    def test_hunting_an_unparsed_evidence_says_so(self):
        with self.assertRaisesRegex(EvidenceError, "no parsed artefacts"):
            hunts.run_hunts(self.case, self.eid)             # corpus is empty

    def test_a_hashset_hunt_flags_a_known_bad_file(self):
        # a hashset hunt reads the file manifest, not artefacts
        bad = "a" * 64
        with index.session(self.case.root) as conn:
            conn.execute("INSERT INTO files (evidence_id, relpath, kind, sha256) "
                         "VALUES (?, 'Downloads/evil.exe', 'file', ?)",
                         (self.eid, bad))
        summary = hunts.run_hunts(self.case, self.eid, selectors=False,
                                  high_value=False, hashset=[bad.upper()])
        hits = review.list_findings(self.case, kind="hashset")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].detail["relpath"], "Downloads/evil.exe")
        self.assertEqual(summary.proposed, 1)


if __name__ == "__main__":
    unittest.main()
