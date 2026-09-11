# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Artefact parsers. Phase 1 has one: browser SQLite (`browser.py`).

Every parser here follows the same three rules:

* **It never reads evidence directly.** It works on WORKING COPIES that
  `extract.py` placed in the case with their hashes recorded — because
  merely opening a SQLite database can write to it (a hot journal is rolled
  back, a WAL is checkpointed on close), and that must happen to a copy.
* **Every timestamp keeps its raw value and names its epoch** (`timeutil`).
* **Every row says where it came from**: the source path and hash, the
  table and row id, and — for a database with a write-ahead log — whether
  the row existed in the main file or only in the uncommitted log.
"""
