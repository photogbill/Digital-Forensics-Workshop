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
