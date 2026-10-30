"""artefacts/query.py: one read-only view over every parser's rows."""

from __future__ import annotations

import json
import unittest

import _support  # noqa: F401
from _support import EXAMINER, TempDirCase

from forensics_workshop import index
from forensics_workshop.artefacts import query
from forensics_workshop.case import Case


def _row(eid, parser, artefact, at, title, value, detail=None, ref=""):
    return ("run", eid, f"x/{title}", parser, artefact, at, title, value,
            json.dumps(detail or {}), "test", ref or title)


class Query(TempDirCase):
    def setUp(self):
        super().setUp()
        self.case = Case.create(self.tmp / "case", case_id="Q-1",
                                examiner=EXAMINER)
        f = self.tmp / "ev"
        f.mkdir()
        (f / "a").write_text("a")
        self.eid = self.case.add_folder(f).id
        rows = [
            _row(self.eid, "domex", "image", "2026-07-04T10:00:00Z", "pier.jpg",
                 "GPS", {"geo": {"lat": 51.5, "lon": -0.1}}),
            _row(self.eid, "domex", "image", "2026-07-03T10:00:00Z", "zero.jpg",
                 "GPS", {"geo": {"lat": 0, "lon": 0}}),
            _row(self.eid, "domex", "document", None, "plan.docx", "Word"),
            _row(self.eid, "mobile", "message", "2026-07-05T08:00:00Z", "sms",
                 "meet at the pier"),
            _row("E999", "evtx", "logon", "2026-07-01T00:00:00Z", "4624", "x"),
        ]
        with index.session(self.case.root) as conn:
            conn.executemany(
                "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
                "parser, artefact, at_utc, title, value, detail_json, "
                "provenance, row_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def test_parsers_and_kinds(self):
        self.assertEqual(dict(query.parsers(self.case, self.eid)),
                         {"domex": 3, "mobile": 1})
        self.assertEqual(dict(query.parsers(self.case)),
                         {"domex": 3, "mobile": 1, "evtx": 1})
        self.assertEqual(dict(query.kinds(self.case, self.eid, "domex")),
                         {"image": 2, "document": 1})

    def test_list_filters_and_order(self):
        rows, total = query.list_rows(self.case, self.eid)
        self.assertEqual(total, 4)
        self.assertEqual([r["title"] for r in rows],
                         ["zero.jpg", "pier.jpg", "sms", "plan.docx"])
        rows, total = query.list_rows(self.case, self.eid, search="pier")
        self.assertEqual({r["title"] for r in rows}, {"pier.jpg", "sms"})
        rows, _ = query.list_rows(self.case, self.eid,
                                  time_from="2026-07-04T00:00:00Z",
                                  time_to="2026-07-04T23:59:59Z")
        self.assertEqual([r["title"] for r in rows], ["pier.jpg"])

    def test_geo(self):
        rows, total = query.list_rows(self.case, self.eid, geo_only=True)
        self.assertEqual(total, 2)
        placed = [r["title"] for r in rows if query.geo_of(r)]
        self.assertEqual(placed, ["pier.jpg"])      # 0,0 is an unset fix
        self.assertIsNone(query.geo_of({"detail_json": '{"geo": {"lat": 91, "lon": 0}}'}))
        self.assertIsNone(query.geo_of({"detail_json": "not json"}))

    def test_the_command_line(self):
        import contextlib
        import io
        from forensics_workshop import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = cli.main(["rows", str(self.case.root), "--examiner", EXAMINER,
                             "--evidence", self.eid, "--geo"])
        self.assertEqual(code, 0)
        self.assertIn("@51.50000,-0.10000", out.getvalue())
        self.assertIn("2 shown of 2", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["rows", str(self.case.root), "--examiner", EXAMINER,
                      "--parsers"])
        self.assertIn("evtx", out.getvalue())


if __name__ == "__main__":
    unittest.main()


class MailBySource(TempDirCase):
    """Bill, 2026-10-30: e-mail separated by source and counted, with a
    final count at the bottom. Contacts and calendar items are not mail."""

    def setUp(self):
        super().setUp()
        self.case = Case.create(self.tmp / "case", case_id="M-1",
                                examiner=EXAMINER)
        f = self.tmp / "ev"
        f.mkdir()
        (f / "a").write_text("a")
        self.eid = self.case.add_folder(f).id
        rows = []
        for i in range(5):
            rows.append(("r", self.eid, "Users/bill/bill.pst", "pst", "email",
                         None, f"m{i}", "x", "{}", "pst-native", f"p{i}"))
        for i, cls in enumerate(["IPM.Contact", "IPM.Contact", "IPM.Appointment"]):
            rows.append(("r", self.eid, "Users/bill/bill.pst", "pst", "pst-item",
                         None, f"c{i}", "x", json.dumps({"message_class": cls}),
                         "pst-native", f"q{i}"))
        for i in range(2):
            rows.append(("r", self.eid, "Users/old/old.ost", "pst", "email",
                         None, f"o{i}", "x", "{}", "deleted-file", f"o{i}"))
        for i in range(3):
            rows.append(("r", self.eid, f"Mail/saved/m{i}.eml", "domex", "email",
                         None, f"e{i}", "x", "{}", "domex-native", f"e{i}"))
        rows.append(("r", self.eid, "Mail/archive.mbox", "domex", "email",
                     None, "mb", "x", "{}", "domex-native", "mb"))
        rows.append(("r", self.eid, "Mail/broken.eml", "domex", "mail-file",
                     None, "bad", "x", "{}", "domex-native", "bad"))
        with index.session(self.case.root) as conn:
            conn.executemany(
                "INSERT INTO artefacts (run_id, evidence_id, source_relpath, "
                "parser, artefact, at_utc, title, value, detail_json, "
                "provenance, row_ref) VALUES (?,?,?,?,?,?,?,?,?,?,?)", rows)

    def test_counts_by_source_and_the_total(self):
        m = query.mail_by_source(self.case, self.eid)
        by = {g["source"]: g for g in m["sources"]}
        self.assertEqual(by["Users/bill/bill.pst"]["emails"], 5)
        self.assertEqual(by["Users/bill/bill.pst"]["kind"], "Outlook mailbox (PST)")
        self.assertEqual(by["Users/bill/bill.pst"]["other"],
                         {"contacts": 2, "calendar items": 1})
        self.assertEqual(by["Users/old/old.ost"]["emails"], 2)
        self.assertEqual(by["Users/old/old.ost"]["from_deleted_file"], 2)
        self.assertEqual(by["Mail/saved/*.eml"]["emails"], 3)      # one line
        self.assertEqual(by["Mail/archive.mbox"]["kind"], "mbox")
        self.assertEqual(m["total_emails"], 11)                   # not the 3 items
        self.assertEqual(m["total_other"], 3)
        self.assertEqual(m["total_sources"], 4)
        self.assertEqual(m["sources"][0]["source"], "Users/bill/bill.pst",
                         "the biggest source first")

    def test_the_command_line_ends_with_the_total(self):
        import contextlib
        import io
        from forensics_workshop import cli
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cli.main(["mail", str(self.case.root), "--examiner", EXAMINER])
        last = out.getvalue().strip().splitlines()[-1]
        self.assertTrue(last.startswith("TOTAL 11 e-mails from 4 source(s)"), last)
        self.assertIn("3 other Outlook items", last)
