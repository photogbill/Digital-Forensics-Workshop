"""The engine stands alone: no ATK, no Qt, no third-party code — and it knows it.

These are the properties the airlock depends on. If the engine imported ATK,
it could not be tested without ATK; if it imported Qt, it could not be tested
without a display; if `__init__` imported a module that can fail, ATK's probe
would report a broken engine as a missing one.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest

from _support import PACKAGE, ROOT

FORBIDDEN_ROOTS = {"atk", "PySide6", "PySide2", "PyQt5", "PyQt6", "shiboken6",
                   "shiboken2", "numpy", "PIL"}


def _sources():
    return sorted(PACKAGE.rglob("*.py"))


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield node.lineno, a.name.split(".")[0], 0
        elif isinstance(node, ast.ImportFrom):
            yield node.lineno, (node.module or "").split(".")[0], node.level


class Isolation(unittest.TestCase):
    def test_the_net_covers_the_package(self):
        names = {p.relative_to(PACKAGE).as_posix() for p in _sources()}
        for must in ("__init__.py", "case.py", "custody.py", "blocker.py",
                     "ingest.py", "artefacts/browser.py", "cli.py", "image.py",
                     "partitions.py", "ntfs.py", "usn.py", "carve.py",
                     "diskimage.py"):
            self.assertIn(must, names)

    def test_no_atk_no_qt_and_nothing_outside_the_standard_library(self):
        stdlib = set(sys.stdlib_module_names)
        for path in _sources():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for lineno, root, level in _imports(tree):
                where = f"{path.relative_to(ROOT)}:{lineno}"
                if level:                           # relative: inside the package
                    continue
                self.assertNotIn(root, FORBIDDEN_ROOTS, where)
                self.assertTrue(root in stdlib or root == "forensics_workshop",
                                f"{where} imports {root!r}, which is not in "
                                "the standard library — phase 1 has no "
                                "third-party dependency, by design")

    def test_init_imports_nothing(self):
        """The airlock's probe is `import forensics_workshop`. If this file
        imported `case`, a defect in `case.py` would read as a missing engine."""
        tree = ast.parse((PACKAGE / "__init__.py").read_text(encoding="utf-8"))
        imports = [n for n in ast.walk(tree)
                   if isinstance(n, (ast.Import, ast.ImportFrom))]
        self.assertEqual(imports, [])

    def test_importing_everything_loads_no_gui_toolkit(self):
        modules = []
        for path in _sources():
            rel = path.relative_to(PACKAGE).with_suffix("")
            if rel.name == "__main__":
                continue
            parts = [p for p in rel.parts if p != "__init__"]
            modules.append(".".join(["forensics_workshop", *parts]))
        code = ("import sys\n"
                + "".join(f"import {m}\n" for m in modules)
                + "bad = sorted(m for m in sys.modules if m.split('.')[0] in "
                  f"{sorted(FORBIDDEN_ROOTS)!r})\n"
                  "print(','.join(bad))\n")
        result = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_every_module_carries_the_licence_tag(self):
        for path in _sources():
            first = path.read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(first, "# SPDX-License-Identifier: "
                                    "LicenseRef-All-Rights-Reserved",
                             path.name)


if __name__ == "__main__":
    unittest.main()
