"""Every public operation is reachable from a surface — or says why not.

The shape ATK's `test_siga_reachable.py` arrived at: a re-export is an offer,
not a path, and an engine grows capabilities faster than surfaces. So the
command line is the seed, calls are followed through the package (including
through module-level tables such as `PARSERS`), and the set of public
functions nothing reaches must EQUAL the set listed below with a reason.
Set-equality both ways: a new unreachable function fails, and so does a
listed one that has since become reachable or been deleted — the list may
not go stale.

Name-based and deliberately over-approximate: a call to `.record(` reaches
every `record` in the package. That can only hide an unreachable function,
never invent one, which is the safe direction for a ratchet.
"""

from __future__ import annotations

import ast
import unittest

from _support import PACKAGE

#: public function -> why no surface in THIS repository reaches it
BY_DESIGN = {
    "caseindex:CaseIndex.remember":
        "ATK's case list; the command line keeps no index of cases",
    "caseindex:CaseIndex.forget":
        "ATK's case list; the command line keeps no index of cases",
    "ratchet:scan_package": "a build-time guard, run by the test suites",
    "ratchet:scan_source": "a build-time guard, run by the test suites",
    "timeutil:from_ns": "for a host rendering stat nanoseconds (ATK's pages)",
    "image:RegionFile.readable":
        "the file-object protocol; called by zipfile inside the stdlib",
    "image:RegionFile.seekable":
        "the file-object protocol; called by zipfile inside the stdlib",
    "image:RegionFile.tell":
        "the file-object protocol; called by zipfile inside the stdlib",
}


def _package():
    """({qualname: node}, {module-level name: value node}) for the package."""
    funcs, tables = {}, {}
    for path in sorted(PACKAGE.rglob("*.py")):
        rel = path.relative_to(PACKAGE).with_suffix("")
        module = ".".join(p for p in rel.parts if p != "__init__") or "__init__"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef):
                funcs[f"{module}:{node.name}"] = node
            elif isinstance(node, ast.ClassDef):
                # Naming a class reaches its body: `NtfsVolume(reader)` runs
                # `__init__`, whose name no call site ever spells.
                tables[f"{module}:{node.name}"] = node
                for item in node.body:
                    if isinstance(item, ast.FunctionDef):
                        funcs[f"{module}:{node.name}.{item.name}"] = item
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tables[f"{module}:{target.id}"] = node.value
    return funcs, tables


def _names(node) -> set:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
    return out


def _is_public(qual: str) -> bool:
    parts = qual.rsplit(":", 1)[1].split(".")
    return not any(p.startswith("_") for p in parts)


def reachability():
    funcs, tables = _package()
    nodes = {**funcs, **tables}
    by_name: dict = {}
    for qual in nodes:
        by_name.setdefault(qual.rsplit(":", 1)[1].split(".")[-1], []).append(qual)
    seeds = [q for q in funcs if q.startswith("cli:")]
    reached, frontier = set(seeds), list(seeds)
    while frontier:
        qual = frontier.pop()
        for name in _names(nodes[qual]):
            for target in by_name.get(name, ()):
                if target not in reached:
                    reached.add(target)
                    frontier.append(target)
    public = {q for q in funcs if _is_public(q)
              and not q.startswith(("cli:", "__main__:"))}
    return public, reached


class Reachability(unittest.TestCase):
    def test_unreachable_public_functions_are_exactly_the_listed_ones(self):
        public, reached = reachability()
        unreachable = public - reached
        self.assertEqual(sorted(unreachable - set(BY_DESIGN)), [],
                         "public functions no surface reaches — wire them "
                         "into cli.py or list them in BY_DESIGN with a reason")
        self.assertEqual(sorted(set(BY_DESIGN) - unreachable), [],
                         "listed as unreachable but now reached (or gone) — "
                         "remove from BY_DESIGN")

    def test_the_walk_actually_reaches_the_engine(self):
        """Coverage, not just a green light: a seed that reached nothing
        would make every function 'unreachable' and the test above would
        fail loudly — but a walk that reached EVERYTHING by accident would
        pass silently. So name what must be reached, including a parser
        that is only reachable through the PARSERS table."""
        public, reached = reachability()
        self.assertGreater(len(public), 40)
        for must in ("ingest:ingest_folder", "verify:verify_evidence",
                     "verify:last_verification",
                     "artefacts.browser:extract_browser_artefacts",
                     "artefacts.browser:parse_firefox_cookies",
                     "blocker:verify_write_refused",
                     "custody:CustodyLog.verify",
                     "diskimage:parse_journal", "diskimage:recover_entry",
                     "diskimage:scrape_slack", "carve:carve_regions",
                     "ntfs:build_paths", "ntfs:parse_attribute_list",
                     "partitions:detect_filesystem", "usn:scan",
                     "verify:verify_image", "image:hash_image"):
            self.assertIn(must, reached)


if __name__ == "__main__":
    unittest.main()
