# SPDX-License-Identifier: LicenseRef-All-Rights-Reserved
"""Where the cases are — the only thing a host application keeps.

ATK does not hold evidence and does not hold cases; it holds this: a small
JSON file naming each case folder, its identifier, when it was last opened,
and **the custody log's head at that moment**.

That last field is the reason this exists beyond convenience. A hash chain
detects an edit, a deletion or a reordering, but not someone rewriting the
whole log and every hash after the change. An anchor kept OUTSIDE the case
does: `Case.open(..., anchor=entry["custody_head"])` checks that the log
still contains the record it had when the examiner last closed it.
"""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path

from .case import CASE_FILE
from .timeutil import utc_now


class CaseIndex:
    def __init__(self, path) -> None:
        self.path = Path(path)

    def _load(self) -> list[dict]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [e for e in data.get("cases", []) if isinstance(e, dict)]

    def _save(self, entries: list[dict]) -> None:
        """Atomic, like every other file this engine writes."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(f".{self.path.name}.{uuid.uuid4().hex}.tmp")
        payload = json.dumps({"cases": entries}, indent=2, ensure_ascii=False)
        with open(temp, "x", encoding="utf-8") as fh:
            fh.write(payload + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temp, self.path)

    def entries(self) -> list[dict]:
        """Every remembered case, most recently opened first, each marked
        `present` — a case on a detached drive is still a case, and the
        examiner needs to see that it is missing rather than not see it."""
        out = []
        for entry in self._load():
            root = entry.get("root", "")
            out.append(dict(entry, present=bool(root) and
                            (Path(root) / CASE_FILE).is_file()))
        out.sort(key=lambda e: e.get("last_opened", ""), reverse=True)
        return out

    def anchor(self, root) -> tuple[int, str] | None:
        key = os.path.normcase(os.path.abspath(os.fspath(root)))
        for entry in self._load():
            if os.path.normcase(entry.get("root", "")) == key:
                head = entry.get("custody_head") or {}
                if isinstance(head.get("seq"), int) and head.get("sha256"):
                    return head["seq"], head["sha256"]
        return None

    def remember(self, case) -> dict:
        seq, head = case.custody.head()
        root = os.path.abspath(os.fspath(case.root))
        entry = {"root": root, "case_id": case.info.case_id,
                 "created_at": case.info.created_at,
                 "last_opened": utc_now(), "last_examiner": case.examiner,
                 "custody_head": {"seq": seq, "sha256": head}}
        key = os.path.normcase(root)
        kept = [e for e in self._load()
                if os.path.normcase(e.get("root", "")) != key]
        self._save([entry, *kept])
        return entry

    def forget(self, root) -> bool:
        """Remove a case from the index. The case itself is not touched."""
        key = os.path.normcase(os.path.abspath(os.fspath(root)))
        entries = self._load()
        kept = [e for e in entries if os.path.normcase(e.get("root", "")) != key]
        if len(kept) == len(entries):
            return False
        self._save(kept)
        return True
