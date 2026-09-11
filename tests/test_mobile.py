"""iOS backup analysis: the file map is read, the artefacts are parsed off it,
and the evidence is never touched. Increment 1 (spine) + increment 2 (parsers)."""

from __future__ import annotations

import datetime as _dt
import hashlib
import plistlib
import sqlite3
import unittest
from pathlib import Path

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

from forensics_workshop import ingest, timeutil
from forensics_workshop.artefacts import mobile
from forensics_workshop.case import Case

BACKUP_ROOT = "MobileSync/Backup/DEVICEUDID0001"
WHEN = _dt.datetime(2026, 9, 1, 12, 0, 0, tzinfo=timeutil.UTC)
COCOA_S = int((WHEN - timeutil.COCOA_EPOCH).total_seconds())
COCOA_NS = int((WHEN - timeutil.COCOA_EPOCH).total_seconds() * 1_000_000_000)


def _fid(domain: str, rel: str) -> str:
    return hashlib.sha1(f"{domain}-{rel}".encode()).hexdigest()


# -- the databases the parsers read, each a builder writing a real SQLite -----

def _build_sms(path):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE handle (ROWID INTEGER PRIMARY KEY, id TEXT, "
              "service TEXT)")
    c.execute("CREATE TABLE message (ROWID INTEGER PRIMARY KEY, guid TEXT, "
              "text TEXT, handle_id INTEGER, service TEXT, date INTEGER, "
              "is_from_me INTEGER)")
    c.execute("INSERT INTO handle VALUES (1, '+15550100', 'iMessage')")
    c.executemany("INSERT INTO message VALUES (?,?,?,?,?,?,?)", [
        (1, "g1", "Hey there", 1, "iMessage", COCOA_NS, 0),
        (2, "g2", "On my way", 1, "iMessage", COCOA_NS, 1)])
    c.commit(); c.close()


def _build_calls(path):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE ZCALLRECORD (Z_PK INTEGER PRIMARY KEY, "
              "ZANSWERED INTEGER, ZCALLTYPE INTEGER, ZORIGINATED INTEGER, "
              "ZDURATION REAL, ZDATE REAL, ZADDRESS BLOB, "
              "ZSERVICE_PROVIDER TEXT)")
    c.executemany("INSERT INTO ZCALLRECORD VALUES (?,?,?,?,?,?,?,?)", [
        (1, 1, 1, 1, 42.0, float(COCOA_S), b"+15550111", "com.apple.Telephony"),
        (2, 0, 1, 0, 0.0, float(COCOA_S), b"+15550122", "com.apple.Telephony")])
    c.commit(); c.close()


def _build_contacts(path):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE ABPerson (ROWID INTEGER PRIMARY KEY, First TEXT, "
              "Last TEXT, Organization TEXT, Note TEXT, CreationDate REAL, "
              "ModificationDate REAL)")
    c.execute("CREATE TABLE ABMultiValue (UID INTEGER PRIMARY KEY, "
              "record_id INTEGER, property INTEGER, value TEXT)")
    c.execute("INSERT INTO ABPerson VALUES (1,'Jane','Doe','Acme','a note',?,?)",
              (float(COCOA_S), float(COCOA_S)))
    c.executemany("INSERT INTO ABMultiValue VALUES (?,?,?,?)", [
        (1, 1, 3, "+15550122"), (2, 1, 4, "jane@example.com")])
    c.commit(); c.close()


def _build_safari(path):
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT, "
              "visit_count INTEGER)")
    c.execute("CREATE TABLE history_visits (id INTEGER PRIMARY KEY, "
              "history_item INTEGER, visit_time REAL, title TEXT, "
              "load_successful INTEGER)")
    c.execute("INSERT INTO history_items VALUES (1, 'https://example.com/', 3)")
    c.execute("INSERT INTO history_visits VALUES (1, 1, ?, 'Example', 1)",
              (float(COCOA_S),))
    c.commit(); c.close()


def _build_blob(path):
    path.write_bytes(b"not a database, just bytes")


#: (domain, relativePath, builder | None-if-absent-on-disk)
FILES = [
    ("HomeDomain", "Library/SMS/sms.db", _build_sms),
    ("WirelessDomain", "Library/CallHistoryDB/CallHistory.storedata",
     _build_calls),
    ("HomeDomain", "Library/AddressBook/AddressBook.sqlitedb", _build_contacts),
    ("HomeDomain", "Library/Safari/History.db", _build_safari),
    ("CameraRollDomain", "Media/DCIM/100APPLE/IMG_0001.JPG", _build_blob),
    ("HomeDomain", "Library/Preferences/com.apple.springboard.plist", None),
]
PRESENT = sum(1 for _d, _r, b in FILES if b is not None)


def build_ios_backup(evidence: Path, *, encrypted: bool = False,
                     legacy: bool = False, bad_fileid: bool = False) -> Path:
    root = evidence / Path(BACKUP_ROOT)
    root.mkdir(parents=True)

    info = {
        "Device Name": "Test iPhone", "Product Type": "iPhone14,2",
        "Product Version": "17.5.1", "Serial Number": "F2LABC123DEF",
        "IMEI": "356789012345678", "Phone Number": "+1 555 0100",
        "Unique Identifier": "DEVICEUDID0001",
        "Last Backup Date": WHEN.replace(tzinfo=None),
        "Installed Applications": ["com.example.app", "com.apple.Maps"],
    }
    with open(root / "Info.plist", "wb") as fh:
        plistlib.dump(info, fh)

    if legacy:
        (root / "Manifest.mbdb").write_bytes(b"mbdb\x05\x00" + bytes(64))
        return root

    with open(root / "Manifest.plist", "wb") as fh:
        plistlib.dump({"IsEncrypted": encrypted, "Version": "10.0"}, fh)

    db = root / "Manifest.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, "
                 "relativePath TEXT, flags INTEGER, file BLOB)")
    rows = []
    for domain, rel, builder in FILES:
        fid = _fid(domain, rel)
        rows.append((fid, domain, rel, 1, b"bplist00\x00metadata"))
        if builder is not None:
            fan = root / fid[:2]
            fan.mkdir(exist_ok=True)
            builder(fan / fid)
    if bad_fileid:
        rows.append(("de" * 20, "HomeDomain", "Library/Wrong/name.db", 1, b""))
    conn.executemany("INSERT INTO Files VALUES (?,?,?,?,?)", rows)
    conn.commit()
    conn.close()

    if encrypted:
        db.write_bytes(b"\x00encrypted-blob\x00" + bytes(128))
    return root


class Backup(TempDirCase):
    encrypted = False
    legacy = False
    bad_fileid = False

    def setUp(self):
        super().setUp()
        self.evidence = self.tmp / "evidence"
        self.evidence.mkdir()
        build_ios_backup(self.evidence, encrypted=self.encrypted,
                         legacy=self.legacy, bad_fileid=self.bad_fileid)
        self.case = Case.create(self.tmp / "case", case_id="MOB-001",
                                examiner=EXAMINER, description="mobile")
        self.item = self.case.add_folder(self.evidence, label="phone")
        ingest.ingest_folder(self.case, self.item.id)

    def run_it(self):
        return mobile.analyse_evidence(self.case, self.item.id)

    def rows(self, kind=""):
        r, _ = mobile.list_mobile(self.case, self.item.id, artefact=kind)
        return r


class ReadsTheBackup(Backup):
    def test_the_backup_is_discovered(self):
        self.assertEqual(mobile.discover_backups(self.case, self.item.id),
                         [BACKUP_ROOT])

    def test_device_metadata_comes_from_info_plist(self):
        (b,) = self.run_it().backups
        self.assertEqual(b["manifest_kind"], "manifest-db")
        self.assertIs(b["encrypted"], False)
        self.assertEqual(b["device"]["Product Type"], "iPhone14,2")
        self.assertIn("com.example.app", b["apps"])

    def test_the_file_map_counts_presence_and_domains(self):
        (b,) = self.run_it().backups
        self.assertEqual(b["files_total"], len(FILES))
        self.assertEqual(b["files_present"], PRESENT)
        self.assertEqual(b["files_missing"], len(FILES) - PRESENT)
        self.assertEqual(b["domains"], {"HomeDomain": 4, "WirelessDomain": 1,
                                        "CameraRollDomain": 1})

    def test_evidence_is_never_written(self):
        before = {p: p.stat().st_mtime_ns for p in self.evidence.rglob("*")
                  if p.is_file()}
        self.run_it()
        self.assertEqual({p: p.stat().st_mtime_ns for p in
                          self.evidence.rglob("*") if p.is_file()}, before)


class ParsesArtefacts(Backup):
    def test_messages_are_parsed_with_the_right_epoch(self):
        (b,) = self.run_it().backups
        self.assertEqual(b["by_artefact"]["message"], 2)
        msgs = self.rows("message")
        first = msgs[0]
        self.assertEqual(first["at_epoch"], "cocoa_ns")
        self.assertEqual(first["at_utc"], timeutil.iso(WHEN))
        self.assertEqual(first["at_raw"], COCOA_NS)
        self.assertEqual(first["browser"], "iOS Messages")
        self.assertIn(first["value"], ("Hey there", "On my way"))
        self.assertEqual(first["title"], "+15550100")

    def test_calls_are_parsed_from_core_data(self):
        self.run_it()
        calls = self.rows("call")
        self.assertEqual(len(calls), 2)
        out = [c for c in calls if "outgoing" in c["title"]][0]
        self.assertEqual(out["at_epoch"], "cocoa_s")
        self.assertEqual(out["at_utc"], timeutil.iso(WHEN))
        self.assertEqual(out["value"], "+15550111")
        self.assertIn("42s", out["title"])

    def test_contacts_gather_their_phone_and_email(self):
        self.run_it()
        (contact,) = self.rows("contact")
        self.assertEqual(contact["value"], "Jane Doe")
        import json
        detail = json.loads(contact["detail_json"])
        self.assertEqual(detail["organization"], "Acme")
        self.assertIn("+15550122", detail["contact_points"])
        self.assertIn("jane@example.com", detail["contact_points"])

    def test_safari_visits_are_parsed(self):
        self.run_it()
        (visit,) = self.rows("web-visit")
        self.assertEqual(visit["url"], "https://example.com/")
        self.assertEqual(visit["title"], "Example")
        self.assertEqual(visit["at_epoch"], "cocoa_s")

    def test_every_row_keeps_its_raw_time_and_names_its_epoch(self):
        self.run_it()
        for r in self.rows():
            if r["at_utc"] is not None:
                self.assertIsNotNone(r["at_raw"])
                self.assertIn(r["at_epoch"], ("cocoa_s", "cocoa_ns", "unix_s"))
            self.assertEqual(r["provenance"], "db")   # no WAL in this backup

    def test_reparsing_replaces_rather_than_duplicates(self):
        self.run_it()
        self.run_it()
        self.assertEqual(len(self.rows("message")), 2)


class Encrypted(Backup):
    encrypted = True

    def test_encrypted_is_reported_and_nothing_is_parsed(self):
        (b,) = self.run_it().backups
        self.assertIs(b["encrypted"], True)
        self.assertEqual(b["files_total"], 0)
        self.assertEqual(b["artefact_rows"], 0)
        self.assertEqual(b["device"]["Product Type"], "iPhone14,2")
        self.assertTrue(any("ENCRYPTED" in p for p in b["problems"]))


class Legacy(Backup):
    legacy = True

    def test_a_legacy_mbdb_backup_is_named_and_deferred(self):
        (b,) = self.run_it().backups
        self.assertEqual(b["manifest_kind"], "manifest-mbdb")
        self.assertTrue(any("mbdb" in p.lower() for p in b["problems"]))
        self.assertEqual(b["artefact_rows"], 0)


class TamperedIDs(Backup):
    bad_fileid = True

    def test_a_fileid_that_is_not_the_hash_is_flagged(self):
        (b,) = self.run_it().backups
        self.assertTrue(any("do not match" in p for p in b["problems"]))
        self.assertEqual(b["files_total"], len(FILES) + 1)


class NotABackup(TempDirCase):
    def test_a_folder_with_no_backup_yields_nothing(self):
        evidence = self.tmp / "evidence"
        (evidence / "sub").mkdir(parents=True)
        (evidence / "sub" / "note.txt").write_text("hi", encoding="utf-8")
        case = Case.create(self.tmp / "case", case_id="MOB-002",
                           examiner=EXAMINER, description="none")
        item = case.add_folder(evidence, label="x")
        ingest.ingest_folder(case, item.id)
        self.assertEqual(mobile.discover_backups(case, item.id), [])
        self.assertEqual(mobile.analyse_evidence(case, item.id).backups, [])


if __name__ == "__main__":
    unittest.main()
