"""Shared scaffolding for the suite. Standard library only — `unittest`, so the
suite runs in a bare interpreter, and pytest collects it unchanged."""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PACKAGE = ROOT / "forensics_workshop"
for p in (str(ROOT), str(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

import synth  # noqa: E402
from forensics_workshop.case import Case  # noqa: E402

EXAMINER = "W. R. Duncan"


class TempDirCase(unittest.TestCase):
    """A fresh temporary folder per test, removed afterwards."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="dfw-test-"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class CorpusCase(TempDirCase):
    """A synthetic profile registered as E001 in a fresh case."""

    wal = True

    def setUp(self) -> None:
        super().setUp()
        self.evidence = self.tmp / "evidence"
        self.corpus = synth.build_corpus(self.evidence, wal=self.wal)
        self.case = Case.create(self.tmp / "case", case_id="TEST-001",
                                examiner=EXAMINER, description="suite")
        self.item = self.case.add_folder(self.evidence, label="profile")
