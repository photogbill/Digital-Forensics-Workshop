"""Synthetic evidence, built by script — never real evidence, never committed.

FORENSICS_PLAN.md §7: *"samples/ are generated, never committed."* Committing
real evidence to a repository is a mistake nobody undoes, and synthetic
samples make the tests deterministic besides: every file here has a known
type, a known hash and a known story.

`samples/build_samples.py` calls these same builders to write a corpus you
can point the command line or ATK at.
"""

from __future__ import annotations

import io
import os
import shutil
import sqlite3
import struct
import zipfile
from pathlib import Path

JPEG = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + b"\x00" * 200 + b"\xff\xd9"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"\x00" * 300
PDF = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF\n"


def pe_bytes(dll: bool = False) -> bytes:
    head = bytearray(512)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x80)
    head[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", head, 0x80 + 22, 0x2000 if dll else 0x0102)
    return bytes(head)


def docx_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr("_rels/.rels", "<Relationships/>")
        zf.writestr("word/document.xml", "<w:document/>")
    return buf.getvalue()


def odt_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(zipfile.ZipInfo("mimetype"),
                    "application/vnd.oasis.opendocument.text",
                    compress_type=zipfile.ZIP_STORED)
        zf.writestr("content.xml", "<office:document-content/>")
    return buf.getvalue()


def plain_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("notes.txt", "hello")
    return buf.getvalue()


def ole_doc_bytes() -> bytes:
    body = bytearray(4096)
    body[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    name = "WordDocument".encode("utf-16-le")
    body[1024:1024 + len(name)] = name
    return bytes(body)


# -- WebKit / PRTime helpers -------------------------------------------------

#: 2026-03-01T12:00:00Z in each epoch.
UNIX_2026 = 1772366400
WEBKIT_2026 = (UNIX_2026 + 11644473600) * 1_000_000
PRTIME_2026 = UNIX_2026 * 1_000_000


def chromium_history(path: Path, *, wal_rows: bool = False) -> Path:
    """A Chromium `History` with three visits, one download, one search.

    With `wal_rows`, the database is put in WAL mode, the base rows are
    checkpointed into the main file, and one more visit plus a title change
    are committed to the WAL and LEFT THERE — the connection is held open
    while the files are copied, which is what a running browser looks like.
    Returns the folder holding the copied files.
    """
    work = path.parent / (path.name + ".build")
    work.mkdir(parents=True, exist_ok=True)
    db = work / "History"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE meta (key TEXT, value TEXT);
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER,
            visit_time INTEGER, from_visit INTEGER, transition INTEGER,
            visit_duration INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, guid TEXT,
            current_path TEXT, target_path TEXT, start_time INTEGER,
            end_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
            state INTEGER, danger_type INTEGER, interrupt_reason INTEGER,
            opened INTEGER, last_access_time INTEGER, referrer TEXT,
            tab_url TEXT, mime_type TEXT);
        CREATE TABLE downloads_url_chains (id INTEGER, chain_index INTEGER,
            url TEXT);
        CREATE TABLE keyword_search_terms (keyword_id INTEGER,
            url_id INTEGER, term TEXT, normalized_term TEXT);
    """)
    if wal_rows:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.executemany("INSERT INTO urls VALUES (?, ?, ?, ?, ?, ?)", [
        (1, "https://example.org/", "Example", 2, 1, WEBKIT_2026 + 60_000_000),
        (2, "https://search.example/?q=boat+ramp", "boat ramp - Search", 1, 0,
         WEBKIT_2026 + 120_000_000),
    ])
    conn.executemany("INSERT INTO visits VALUES (?, ?, ?, ?, ?, ?)", [
        (1, 1, WEBKIT_2026, 0, 0x30000001, 5_000_000),       # typed, chain
        (2, 2, WEBKIT_2026 + 120_000_000, 1, 0x00000000, 0),
        (3, 1, WEBKIT_2026 + 60_000_000, 0, 0x00000008, 0),  # reload
    ])
    target = r"C:\Users\x\Downloads\map.pdf"
    conn.execute("INSERT INTO downloads VALUES (1, 'g', ?, ?, ?, ?, 1024, "
                 "1024, 1, 0, 0, 1, 0, 'https://example.org/', "
                 "'https://example.org/maps', 'application/pdf')",
                 (target, target, WEBKIT_2026 + 200_000_000,
                  WEBKIT_2026 + 201_000_000))
    conn.executemany("INSERT INTO downloads_url_chains VALUES (?, ?, ?)", [
        (1, 0, "https://example.org/get?id=9"),
        (1, 1, "https://cdn.example.org/map.pdf")])
    conn.execute("INSERT INTO keyword_search_terms VALUES "
                 "(7, 2, 'boat ramp', 'boat ramp')")
    conn.commit()
    if wal_rows:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("INSERT INTO urls VALUES (3, 'https://late.example/', "
                     "'Visited last', 1, 0, ?)", (WEBKIT_2026 + 900_000_000,))
        conn.execute("INSERT INTO visits VALUES (4, 3, ?, 0, 1, 0)",
                     (WEBKIT_2026 + 900_000_000,))
        conn.execute("UPDATE urls SET title = 'Example (renamed)' WHERE id = 1")
        conn.commit()
    path.mkdir(parents=True, exist_ok=True)
    for name in os.listdir(work):
        shutil.copyfile(work / name, path / name)
    conn.close()
    shutil.rmtree(work)
    return path


def firefox_places(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "places.sqlite"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE moz_places (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
            visit_count INTEGER, last_visit_date INTEGER, frecency INTEGER);
        CREATE TABLE moz_historyvisits (id INTEGER PRIMARY KEY,
            from_visit INTEGER, place_id INTEGER, visit_date INTEGER,
            visit_type INTEGER, session INTEGER);
        CREATE TABLE moz_anno_attributes (id INTEGER PRIMARY KEY, name TEXT);
        CREATE TABLE moz_annos (id INTEGER PRIMARY KEY, place_id INTEGER,
            anno_attribute_id INTEGER, content TEXT, flags INTEGER,
            expiration INTEGER, type INTEGER, dateAdded INTEGER,
            lastModified INTEGER);
    """)
    conn.executemany("INSERT INTO moz_places VALUES (?, ?, ?, ?, ?, ?)", [
        (1, "https://mozilla.example/", "Moz", 1, PRTIME_2026, 100),
        (2, "https://files.example/tool.zip", "tool.zip", 0, None, 0)])
    conn.execute("INSERT INTO moz_historyvisits VALUES (1, 0, 1, ?, 2, 0)",
                 (PRTIME_2026,))
    conn.executemany("INSERT INTO moz_anno_attributes VALUES (?, ?)", [
        (1, "downloads/destinationFileURI"), (2, "downloads/metaData")])
    conn.executemany("INSERT INTO moz_annos VALUES (?, ?, ?, ?, 0, 4, 3, ?, ?)", [
        (1, 2, 1, "file:///C:/Users/x/Downloads/tool.zip",
         PRTIME_2026 + 5_000_000, PRTIME_2026 + 5_000_000),
        (2, 2, 2, '{"state":1,"endTime":%d,"fileSize":2048}'
         % ((UNIX_2026 + 6) * 1000), PRTIME_2026 + 6_000_000,
         PRTIME_2026 + 6_000_000)])
    conn.commit()
    conn.close()
    return db


def firefox_formhistory(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "formhistory.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE moz_formhistory (id INTEGER PRIMARY KEY, "
                 "fieldname TEXT, value TEXT, timesUsed INTEGER, "
                 "firstUsed INTEGER, lastUsed INTEGER, guid TEXT)")
    conn.executemany("INSERT INTO moz_formhistory VALUES (?, ?, ?, ?, ?, ?, ?)", [
        (1, "searchbar-history", "tide tables", 3, PRTIME_2026,
         PRTIME_2026 + 1_000_000, "a"),
        (2, "email", "someone@example.org", 1, PRTIME_2026, PRTIME_2026, "b")])
    conn.commit()
    conn.close()
    return db


def chromium_cookies(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "Cookies"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE meta (key TEXT, value TEXT)")
    conn.execute("CREATE TABLE cookies (creation_utc INTEGER, host_key TEXT, "
                 "name TEXT, value TEXT, encrypted_value BLOB, path TEXT, "
                 "expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, "
                 "last_access_utc INTEGER, has_expires INTEGER, "
                 "is_persistent INTEGER, samesite INTEGER)")
    conn.execute("INSERT INTO cookies VALUES (?, '.example.org', 'sid', '', "
                 "?, '/', ?, 1, 1, ?, 1, 1, 0)",
                 (WEBKIT_2026, b"v10" + b"\x01" * 29,
                  WEBKIT_2026 + 86_400_000_000, WEBKIT_2026 + 1_000_000))
    conn.commit()
    conn.close()
    return db


def firefox_cookies(folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    db = folder / "cookies.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, "
                 "originAttributes TEXT, name TEXT, value TEXT, host TEXT, "
                 "path TEXT, expiry INTEGER, lastAccessed INTEGER, "
                 "creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, "
                 "sameSite INTEGER)")
    conn.executemany("INSERT INTO moz_cookies VALUES "
                     "(?, '', ?, ?, ?, '/', ?, ?, ?, 0, 0, 0)", [
                         (1, "pref", "dark", ".mozilla.example",
                          UNIX_2026 + 86400, PRTIME_2026, PRTIME_2026),
                         (2, "ms", "1", ".ms.example",
                          (UNIX_2026 + 86400) * 1000, PRTIME_2026,
                          PRTIME_2026)])
    conn.commit()
    conn.close()
    return db


def build_corpus(root: Path, *, wal: bool = True) -> dict:
    """A small user profile: documents, a disguised file, duplicates, an
    empty file, a hidden file, a link, and browser databases for both
    families. Returns what the tests need to know about it."""
    root.mkdir(parents=True, exist_ok=True)
    docs = root / "Documents"
    pics = root / "Pictures"
    docs.mkdir()
    pics.mkdir()
    (docs / "report.pdf").write_bytes(PDF)
    (docs / "letter.docx").write_bytes(docx_bytes())
    (docs / "minutes.odt").write_bytes(odt_bytes())
    (docs / "old.doc").write_bytes(ole_doc_bytes())
    (docs / "notes.txt").write_text("meeting at the boat ramp\n",
                                    encoding="utf-8")
    (docs / "empty.txt").write_bytes(b"")
    (pics / "holiday.jpg").write_bytes(JPEG)
    (pics / "copy of holiday.jpg").write_bytes(JPEG)          # duplicate
    (pics / "diagram.png").write_bytes(PNG)
    (pics / "vacation.jpg").write_bytes(plain_zip_bytes())    # disguised
    (root / "setup.exe").write_bytes(pe_bytes())
    (root / ".hidden_config").write_text("key=value\n", encoding="utf-8")
    (root / "random.bin").write_bytes(os.urandom(4096))
    link_made = False
    try:
        os.symlink(docs, root / "docs-link", target_is_directory=True)
        link_made = True
    except (OSError, NotImplementedError):
        pass

    chrome = (root / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
              / "Default")
    chromium_history(chrome, wal_rows=wal)
    chromium_cookies(chrome / "Network")
    ff = (root / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
          / "abcd.default-release")
    firefox_places(ff)
    firefox_formhistory(ff)
    firefox_cookies(ff)
    return {"link_made": link_made, "chrome": chrome, "firefox": ff}


def snapshot(root: Path) -> dict:
    """relpath -> (size, mtime_ns, sha256) for every file under root, read
    with plain Python — the test's own independent view of the evidence."""
    import hashlib
    out = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                continue
            st = p.stat()
            out[p.relative_to(root).as_posix()] = (
                st.st_size, st.st_mtime_ns,
                hashlib.sha256(p.read_bytes()).hexdigest())
    return out
