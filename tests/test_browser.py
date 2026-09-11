"""Browser artefacts: found by signature, confirmed by schema, WAL-aware."""

from __future__ import annotations

import json
import sqlite3
import unittest

import synth
from _support import CorpusCase

from forensics_workshop import ingest
from forensics_workshop.artefacts import browser
from forensics_workshop.errors import EvidenceError

CHROME = "AppData/Local/Google/Chrome/User Data/Default/History"
FF = "AppData/Roaming/Mozilla/Firefox/Profiles/abcd.default-release"


class Extraction(CorpusCase):
    def setUp(self):
        super().setUp()
        ingest.ingest_folder(self.case, self.item.id)
        self.before = synth.snapshot(self.evidence)
        self.summary = browser.extract_browser_artefacts(self.case, self.item.id)
        self.sources = {s["relpath"]: s for s in self.summary.sources}

    def rows(self, **kw):
        return browser.list_artefacts(self.case, self.item.id, **kw)[0]

    def test_the_evidence_databases_are_not_touched(self):
        self.assertEqual(synth.snapshot(self.evidence), self.before,
                         "SQLite touched the evidence — WAL replay or a "
                         "journal was applied in place")

    def test_all_five_schemas_are_recognised(self):
        kinds = sorted(s["kind"] for s in self.summary.sources)
        self.assertEqual(kinds, ["chromium-cookies", "chromium-history",
                                 "firefox-cookies", "firefox-formhistory",
                                 "firefox-places"])
        for s in self.summary.sources:
            self.assertEqual(s["problems"], [], s)
            self.assertTrue(s["matches_manifest"], s)

    def test_browser_and_profile_come_from_the_path_and_say_so(self):
        chrome = self.sources[CHROME]
        self.assertEqual((chrome["browser"], chrome["browser_basis"],
                          chrome["profile"]), ("Google Chrome", "path", "Default"))
        cookies = self.sources[
            "AppData/Local/Google/Chrome/User Data/Default/Network/Cookies"]
        self.assertEqual(cookies["profile"], "Default",
                         "Chromium's Network/ subfolder is not the profile")
        self.assertEqual(self.sources[f"{FF}/places.sqlite"]["profile"],
                         "abcd.default-release")

    def test_rows_only_in_the_wal_are_labelled_wal(self):
        chrome = self.sources[CHROME]
        self.assertEqual(chrome["sidecars"], ["-wal", "-shm"])
        self.assertEqual(chrome["by_provenance"], {"db": 3, "wal": 1,
                                                   "wal-updated": 2})
        late = [r for r in self.rows(artefact="visit")
                if r["url"] == "https://late.example/"]
        self.assertEqual(len(late), 1)
        self.assertEqual(late[0]["provenance"], "wal")
        renamed = [r for r in self.rows(artefact="visit")
                   if r["url"] == "https://example.org/"]
        self.assertTrue(all(r["provenance"] == "wal-updated" for r in renamed))
        self.assertTrue(all(r["title"] == "Example (renamed)" for r in renamed))

    def test_visit_times_and_transitions(self):
        first = next(r for r in self.rows(artefact="visit")
                     if r["row_ref"] == "visits:1")
        self.assertEqual(first["at_utc"], "2026-03-01T12:00:00.000000Z")
        self.assertEqual(first["at_raw"], synth.WEBKIT_2026)
        self.assertEqual(first["at_epoch"], "webkit_us")
        transition = json.loads(first["detail_json"])["transition"]
        self.assertEqual(transition["core"], "typed")
        self.assertEqual(sorted(transition["qualifiers"]),
                         ["chain_end", "chain_start"])

    def test_chromium_download_keeps_its_chain_and_state(self):
        d = next(r for r in self.rows(artefact="download")
                 if r["browser"] == "Google Chrome")
        detail = json.loads(d["detail_json"])
        self.assertEqual(d["url"], "https://cdn.example.org/map.pdf")
        self.assertEqual(detail["url_chain"][0], "https://example.org/get?id=9")
        self.assertEqual(detail["state_label"], "complete")
        self.assertEqual(detail["end_time_utc"], "2026-03-01T12:03:21.000000Z")

    def test_a_search_term_says_what_its_time_means(self):
        s = next(r for r in self.rows(artefact="search")
                 if r["browser"] == "Google Chrome")
        self.assertEqual(s["value"], "boat ramp")
        self.assertIn("LAST VISIT", json.loads(s["detail_json"])["time_basis"])

    def test_firefox_visits_downloads_and_forms(self):
        visit = next(r for r in self.rows(artefact="visit")
                     if r["browser"] == "Mozilla Firefox")
        self.assertEqual(visit["at_utc"], "2026-03-01T12:00:00.000000Z")
        self.assertEqual(json.loads(visit["detail_json"])["visit_type"]["label"],
                         "typed")
        dl = next(r for r in self.rows(artefact="download")
                  if r["browser"] == "Mozilla Firefox")
        self.assertEqual(dl["title"], "tool.zip")
        self.assertEqual(json.loads(dl["detail_json"])["end_time_utc"],
                         "2026-03-01T12:00:06.000000Z")
        searches = [r["value"] for r in self.rows(artefact="search")
                    if r["browser"] == "Mozilla Firefox"]
        self.assertEqual(searches, ["tide tables"])
        forms = self.rows(artefact="form-entry")
        self.assertEqual([f["title"] for f in forms], ["email"])

    def test_cookies_encrypted_values_are_not_pretended_away(self):
        chrome = next(r for r in self.rows(artefact="cookie")
                      if r["browser"] == "Google Chrome")
        self.assertIn("encrypted", chrome["value"])
        self.assertIn("not decrypted", chrome["value"])
        ff = {r["title"]: json.loads(r["detail_json"])
              for r in self.rows(artefact="cookie")
              if r["browser"] == "Mozilla Firefox"}
        self.assertEqual(ff["pref"]["expiry_unit"], "unix_s")
        self.assertEqual(ff["ms"]["expiry_unit"], "unix_ms")
        self.assertEqual(ff["pref"]["expiry_utc"], ff["ms"]["expiry_utc"])
        self.assertEqual(ff["pref"]["expiry_unit_basis"],
                         "inferred from magnitude")

    def test_working_copies_live_in_the_case_with_recorded_hashes(self):
        chrome = self.sources[CHROME]
        work = self.case.root / "extracted" / "E001" / "browser"
        self.assertTrue(chrome["working_copy"].startswith(str(work)))
        rec = self.case.custody.last("artefacts.browser.source",
                                     f"E001:{CHROME}")
        self.assertIn(CHROME, rec["hashes"])
        self.assertIn(CHROME + "-wal", rec["hashes"])
        self.assertEqual(rec["hashes"][CHROME]["sha256"],
                         self.before[CHROME][2])

    def test_a_rerun_replaces_rather_than_duplicates(self):
        n = len(self.rows())
        browser.extract_browser_artefacts(self.case, self.item.id)
        self.assertEqual(len(self.rows()), n)

    def test_the_custody_chain_is_intact_afterwards(self):
        self.assertTrue(self.case.custody.verify().ok)


class Discovery(CorpusCase):
    wal = False

    def test_no_wal_means_no_second_view_and_all_rows_db(self):
        ingest.ingest_folder(self.case, self.item.id)
        summary = browser.extract_browser_artefacts(self.case, self.item.id)
        chrome = next(s for s in summary.sources if s["relpath"] == CHROME)
        self.assertEqual(chrome["sidecars"], [])
        self.assertEqual(set(chrome["by_provenance"]), {"db"})

    def test_a_renamed_database_is_found_only_when_asked(self):
        renamed = self.evidence / "Documents" / "hist.bak"
        (self.evidence / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
         / "Default" / "History").rename(renamed)
        ingest.ingest_folder(self.case, self.item.id)
        by_name = browser.discover(self.case, self.item.id)
        self.assertNotIn("Documents/hist.bak", [c.relpath for c in by_name])
        wide = browser.discover(self.case, self.item.id, all_sqlite=True)
        self.assertIn("Documents/hist.bak", [c.relpath for c in wide])
        summary = browser.extract_browser_artefacts(self.case, self.item.id,
                                                    all_sqlite=True)
        found = next(s for s in summary.sources
                     if s["relpath"] == "Documents/hist.bak")
        self.assertEqual(found["kind"], "chromium-history")
        self.assertIsNone(found["expected"])

    def test_an_unrelated_sqlite_is_reported_not_parsed(self):
        other = self.evidence / "Documents" / "History"
        conn = sqlite3.connect(other)
        conn.execute("CREATE TABLE shopping (item TEXT)")
        conn.commit()
        conn.close()
        ingest.ingest_folder(self.case, self.item.id)
        summary = browser.extract_browser_artefacts(self.case, self.item.id)
        odd = next(s for s in summary.sources
                   if s["relpath"] == "Documents/History")
        self.assertIsNone(odd["kind"])
        self.assertIn("not a schema", odd["problems"][0])

    def test_extraction_before_ingest_is_refused_with_the_reason(self):
        with self.assertRaises(EvidenceError):
            browser.extract_browser_artefacts(self.case, self.item.id)


class Pieces(unittest.TestCase):
    def test_transition_decoding(self):
        t = browser.decode_transition(-2147483647)          # signed storage
        self.assertEqual(t["core"], "typed")
        self.assertIn("server_redirect", t["qualifiers"])
        self.assertEqual(browser.decode_transition("x"), {"raw": "x"})

    def test_browser_from_path(self):
        self.assertEqual(browser.browser_from_path(
            "Users/a/AppData/Local/Microsoft/Edge/User Data/Profile 2/History"),
            ("Microsoft Edge", "path", "Profile 2"))
        self.assertEqual(browser.browser_from_path("x/History")[0:2],
                         ("unidentified", "none"))

    def test_provenance_labels_a_rolled_back_row(self):
        row = {"row_ref": "visits:9", "at_raw": 1, "url": "u", "title": "",
               "value": "", "detail": {}}
        merged = browser.label_provenance([], [row], ["-journal"])
        self.assertEqual(merged[0]["provenance"], "rolled-back")


if __name__ == "__main__":
    unittest.main()
