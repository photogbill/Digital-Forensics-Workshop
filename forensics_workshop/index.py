# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""The case's queryable index: `<case>/index.db`.

**THE INDEX IS DERIVED; THE CUSTODY LOG IS THE RECORD.** Everything in here
can be rebuilt from the evidence, and the custody log holds a digest of each
completed manifest so an index that was altered afterwards can be caught
(`verify.manifest_digest`). That is why this database is allowed to be an
ordinary, updatable SQLite file while `custody.jsonl` is not.

Rollback journal, not WAL. A case folder lives wherever the examiner puts
it — a USB disk, an external array, a network share — and WAL does not work
on network file systems. The price is that a reader waits for a writer's
commit, which `BUSY_TIMEOUT_S` absorbs.

Every timestamp column holds the RAW measured value (`*_ns`, `at_raw`); a
decoded string, where there is one, sits beside it with its epoch named.
"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path

from . import blocker

FILENAME = "index.db"
SCHEMA_VERSION = 2
BUSY_TIMEOUT_S = 30.0

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS evidence (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    source         TEXT NOT NULL,
    label          TEXT,
    added_at       TEXT NOT NULL,
    sidecar_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS files (
    evidence_id           TEXT NOT NULL,
    relpath               TEXT NOT NULL,
    kind                  TEXT NOT NULL,     -- file | dir | link | other
    size                  INTEGER,
    mtime_ns              INTEGER,
    atime_ns              INTEGER,
    ctime_ns              INTEGER,           -- see ctime_meaning
    ctime_meaning         TEXT,
    attributes            INTEGER,
    reparse_tag           INTEGER,
    hidden                INTEGER,
    system                INTEGER,
    link_target           TEXT,
    md5                   TEXT,
    sha1                  TEXT,
    sha256                TEXT,
    type_id               TEXT,
    type_label            TEXT,
    type_family           TEXT,
    type_basis            TEXT,
    type_confidence       TEXT,
    type_note             TEXT,
    declared_ext          TEXT,
    ext_mismatch          INTEGER,
    head_entropy          REAL,
    atime_change_observed INTEGER,
    changed_during_read   INTEGER,
    not_read_reason       TEXT,
    error                 TEXT,
    read_at               TEXT,
    PRIMARY KEY (evidence_id, relpath)
);
CREATE INDEX IF NOT EXISTS files_sha256 ON files (sha256);
CREATE INDEX IF NOT EXISTS files_type ON files (evidence_id, type_id);
CREATE TABLE IF NOT EXISTS ingest_runs (
    run_id          TEXT PRIMARY KEY,
    evidence_id     TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    state           TEXT NOT NULL,
    summary_json    TEXT
);
CREATE TABLE IF NOT EXISTS artefacts (
    id              INTEGER PRIMARY KEY,
    run_id          TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,
    source_relpath  TEXT NOT NULL,
    source_sha256   TEXT,
    parser          TEXT NOT NULL,
    artefact        TEXT NOT NULL,
    at_utc          TEXT,
    at_raw          INTEGER,
    at_epoch        TEXT,
    browser         TEXT,
    browser_basis   TEXT,
    profile         TEXT,
    url             TEXT,
    title           TEXT,
    value           TEXT,
    detail_json     TEXT,
    provenance      TEXT NOT NULL,
    row_ref         TEXT
);
CREATE INDEX IF NOT EXISTS artefacts_time ON artefacts (evidence_id, at_utc);
CREATE INDEX IF NOT EXISTS artefacts_source
    ON artefacts (evidence_id, source_relpath);

-- schema 2: disk images (phase 2) -------------------------------------------
CREATE TABLE IF NOT EXISTS runs (
    run_id          TEXT PRIMARY KEY,
    evidence_id     TEXT NOT NULL,
    kind            TEXT NOT NULL,     -- image | ntfs | usn | carve | slack
    volume          INTEGER,
    started_at      TEXT NOT NULL,
    finished_at     TEXT,
    state           TEXT NOT NULL,
    settings_json   TEXT,
    summary_json    TEXT
);
CREATE TABLE IF NOT EXISTS volumes (
    evidence_id     TEXT NOT NULL,
    volume          INTEGER NOT NULL,  -- 1-based, disk order; gaps included
    kind            TEXT NOT NULL,     -- partition | extended | protective | gap | whole
    entry           TEXT NOT NULL,     -- mbr:1 · ebr:5 · gpt:2 · gap · whole
    offset          INTEGER NOT NULL,  -- bytes from the start of the disk
    length          INTEGER NOT NULL,
    start_lba       INTEGER,
    sectors         INTEGER,
    sector_size     INTEGER,
    type_code       TEXT,
    type_label      TEXT,
    name            TEXT,
    guid            TEXT,
    flags           TEXT,              -- JSON list
    fs_type         TEXT,
    fs_label        TEXT,
    fs_volume_label TEXT,
    fs_note         TEXT,
    problems        TEXT,              -- JSON list
    PRIMARY KEY (evidence_id, volume)
);
CREATE TABLE IF NOT EXISTS ntfs_entries (
    evidence_id     TEXT NOT NULL,
    volume          INTEGER NOT NULL,
    record          INTEGER NOT NULL,
    sequence        INTEGER,
    in_use          INTEGER,
    is_dir          INTEGER,
    link_count      INTEGER,
    name            TEXT,
    namespace       TEXT,
    other_names     TEXT,              -- JSON: further $FILE_NAMEs (hard links, DOS)
    parent_record   INTEGER,
    parent_sequence INTEGER,
    path            TEXT,
    path_status     TEXT,
    si_created      INTEGER,           -- raw FILETIME (epoch: filetime)
    si_modified     INTEGER,
    si_changed      INTEGER,
    si_accessed     INTEGER,
    fn_created      INTEGER,
    fn_modified     INTEGER,
    fn_changed      INTEGER,
    fn_accessed     INTEGER,
    file_attributes INTEGER,
    size            INTEGER,
    allocated       INTEGER,
    resident        INTEGER,
    data_flags      INTEGER,
    ads_count       INTEGER,
    clusters        INTEGER,
    clusters_now_allocated INTEGER,    -- for a deleted entry: clusters $Bitmap
                                       -- now gives to something (maybe else)
    lsn             INTEGER,
    usn             INTEGER,
    fixup_ok        INTEGER,
    indicators      TEXT,              -- JSON list of ntfs.INDICATORS codes
    problems        TEXT,              -- JSON list
    run_id          TEXT,
    PRIMARY KEY (evidence_id, volume, record)
);
CREATE INDEX IF NOT EXISTS ntfs_entries_path ON ntfs_entries (evidence_id, volume, path);
CREATE TABLE IF NOT EXISTS ntfs_streams (
    evidence_id     TEXT NOT NULL,
    volume          INTEGER NOT NULL,
    record          INTEGER NOT NULL,
    name            TEXT NOT NULL,     -- '' is the unnamed (main) stream
    size            INTEGER,
    allocated       INTEGER,
    initialized     INTEGER,
    resident        INTEGER,
    flags           INTEGER,
    runs            TEXT,              -- JSON [[vcn, lcn or null, clusters], …]
    PRIMARY KEY (evidence_id, volume, record, name)
);
CREATE TABLE IF NOT EXISTS usn_records (
    evidence_id     TEXT NOT NULL,
    volume          INTEGER NOT NULL,
    offset          INTEGER NOT NULL,  -- byte offset in $J
    usn             INTEGER,
    version         INTEGER,
    file_record     INTEGER,
    file_sequence   INTEGER,
    parent_record   INTEGER,
    parent_sequence INTEGER,
    timestamp       INTEGER,           -- raw FILETIME
    reasons         INTEGER,
    reason_names    TEXT,
    source_info     INTEGER,
    attributes      INTEGER,
    name            TEXT,
    run_id          TEXT,
    PRIMARY KEY (evidence_id, volume, offset)
);
CREATE INDEX IF NOT EXISTS usn_file ON usn_records (evidence_id, volume, file_record);
CREATE TABLE IF NOT EXISTS carve_candidates (
    id              INTEGER PRIMARY KEY,
    run_id          TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,
    volume          INTEGER,
    scope           TEXT NOT NULL,     -- image | volume | gap | unallocated
    offset          INTEGER NOT NULL,  -- bytes from the start of the DISK
    length          INTEGER NOT NULL,
    type_id         TEXT,
    label           TEXT,
    ext             TEXT,
    basis           TEXT,              -- structure | footer | capped
    status          TEXT,              -- complete | truncated | capped
    note            TEXT,
    head_hex        TEXT,
    entropy         REAL,
    nested_in       INTEGER
);
CREATE INDEX IF NOT EXISTS carve_by_run ON carve_candidates (evidence_id, run_id, offset);
CREATE TABLE IF NOT EXISTS slack_regions (
    evidence_id     TEXT NOT NULL,
    volume          INTEGER NOT NULL,
    record          INTEGER NOT NULL,
    stream          TEXT NOT NULL,
    offset          INTEGER NOT NULL,  -- bytes from the start of the DISK
    length          INTEGER NOT NULL,
    nonzero         INTEGER,
    entropy         REAL,
    strings         TEXT,
    run_id          TEXT,
    PRIMARY KEY (evidence_id, volume, record, stream)
);
"""


def connect(case_root) -> sqlite3.Connection:
    """A new connection to one case's index. One per thread, always.

    sqlite3 connections refuse to cross threads, and ATK reads the index on
    the GUI thread while an ingest writes it on a worker — so nothing holds
    a connection longer than the job that opened it.
    """
    root = Path(case_root)
    db = blocker.assert_case_path(root, root / FILENAME)
    conn = sqlite3.connect(db, timeout=BUSY_TIMEOUT_S)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    # Additive: every table is CREATE IF NOT EXISTS, so opening a case made
    # by an older engine adds what it lacks. The version only ever rises.
    stored = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'"
                          ).fetchone()
    if stored is None or not str(stored[0]).isdigit() or \
            int(stored[0]) < SCHEMA_VERSION:
        conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                     ("schema_version", str(SCHEMA_VERSION)))
    conn.commit()
    return conn


@contextmanager
def session(case_root):
    """Commit on success, roll back on an exception, CLOSE either way.

    `with sqlite3.connect(...) as conn` commits but does not close — which
    leaves a handle on `index.db` for as long as the garbage collector
    pleases, and on Windows a handle is a lock.
    """
    conn = connect(case_root)
    try:
        yield conn
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
