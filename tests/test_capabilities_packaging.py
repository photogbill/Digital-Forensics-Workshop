"""The capability table tells the truth, and the repository is shaped to ship."""

from __future__ import annotations

import ast
import re
import sys
import unittest
from unittest import mock

from _support import PACKAGE, ROOT

import forensics_workshop
from forensics_workshop import capabilities


class Capabilities(unittest.TestCase):
    def setUp(self):
        self.rows = {c.id: c for c in capabilities.capabilities()}

    def test_every_phase_one_capability_is_built_and_loads(self):
        phase1 = [c for c in self.rows.values() if c.phase == 1]
        self.assertGreaterEqual(len(phase1), 8)
        for c in phase1:
            self.assertEqual(c.status, "available", c)

    def test_the_phase_two_file_system_layer_is_built_and_loads(self):
        for cid in ("raw", "partitions", "ntfs", "timestomp", "usnjrnl",
                    "slack", "carving", "fde-detect"):
            self.assertEqual(self.rows[cid].status, "available", self.rows[cid])
        for cid in ("fat", "ewf", "vdisk", "ext4"):
            self.assertEqual(self.rows[cid].status, "planned", self.rows[cid])
        self.assertIn("synthetic", self.rows["usnjrnl"].note,
                      "the journal has not met a Windows-written $J yet, and says so")

    def test_nothing_unbuilt_claims_to_be_available(self):
        for c in self.rows.values():
            if not c.module:
                self.assertNotEqual(c.status, "available", c)
            self.assertIn(c.status, capabilities.STATUSES)

    def test_third_party_rows_carry_a_licence_and_a_presence_probe(self):
        for c in self.rows.values():
            if c.how == "third-party" and c.package:
                self.assertTrue(c.licence, c)
                self.assertIn(c.package_present, (True, False), c)
        self.assertEqual(self.rows["apfs"].licence, "LGPL-3.0-or-later")
        self.assertEqual(self.rows["volatility3"].licence,
                         "LicenseRef-Volatility-Software-License-1.0")

    def test_deferred_and_out_of_scope_are_said_out_loud(self):
        self.assertEqual(self.rows["apfs"].status, "deferred")
        self.assertEqual(self.rows["memory"].status, "deferred")
        self.assertEqual(self.rows["fde-decrypt"].status, "out-of-scope")

    def test_a_module_that_fails_to_import_is_reported_not_hidden(self):
        real = capabilities.importlib.import_module

        def broken(name, *a, **k):
            if name == "forensics_workshop.ingest":
                raise SyntaxError("simulated defect in ingest.py")
            return real(name, *a, **k)

        with mock.patch.object(capabilities.importlib, "import_module", broken):
            rows = {c.id: c for c in capabilities.capabilities()}
        self.assertEqual(rows["logical"].status, "failed-to-load")
        self.assertIn("simulated defect", rows["logical"].note)
        self.assertEqual(rows["hashing"].status, "available")

    def test_presence_is_probed_without_importing(self):
        tree = ast.parse((PACKAGE / "capabilities.py").read_text(encoding="utf-8"))
        imported = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                    and getattr(n.func, "attr", "") == "import_module"]
        self.assertEqual(len(imported), 1)
        self.assertEqual(ast.unparse(imported[0].args[0]), "module",
                         "only BUILT modules are imported; packages use find_spec")


class LicenceRule(unittest.TestCase):
    """Bill, 2026-09-11: nothing that restricts commercial use.

    Corrected the same day: LGPL and other weak/file-level copyleft PERMIT
    commercial use of a closed product (the cost is a bundled notice and
    leaving the library replaceable), so they pass. Only whole-program
    copyleft (GPL, AGPL, the Volatility Software License) and non-commercial
    licences are excluded. FORENSICS_PLAN.md §1.1 is the account; this holds
    the table to it."""

    def setUp(self):
        self.rows = {c.id: c for c in capabilities.capabilities()}

    def test_the_rule_permits_commercial_use_including_weak_copyleft(self):
        permits = capabilities.licence_permits
        for ok in ("MIT", "Apache-2.0", "BSD-3-Clause", "PSF-2.0", "Zlib",
                   "LGPL-3.0-or-later", "LGPL-2.1-only", "MPL-2.0", "EPL-2.0",
                   "IPL-1.0", "CPL-1.0", "Apache-2.0 AND IPL-1.0 AND CPL-1.0",
                   "MIT OR Apache-2.0", "GPL-3.0-only OR MIT"):
            self.assertTrue(permits(ok), ok)
        for bad in ("", "GPL-3.0-only", "GPL-2.0-or-later", "AGPL-3.0",
                    "LicenseRef-Volatility-Software-License-1.0", "SSPL-1.0",
                    "LicenseRef-PolyForm-Noncommercial-1.0.0", "CC-BY-NC-4.0",
                    "Apache-2.0 AND GPL-3.0-only", "(MIT)", "a licence nobody read"):
            self.assertFalse(permits(bad), bad)
        # weak copyleft is on the allowlist; whole-program copyleft is not
        self.assertLessEqual({"LGPL-3.0-or-later", "MPL-2.0", "IPL-1.0"},
                             capabilities.PERMITTED_LICENCES)
        for forbidden in ("GPL-3.0-only", "AGPL-3.0", "SSPL-1.0",
                          "LicenseRef-Volatility-Software-License-1.0"):
            self.assertNotIn(forbidden, capabilities.PERMITTED_LICENCES)

    def test_no_row_as_written_offers_a_route_that_fails_the_rule(self):
        # The written table, not the computed one: capabilities() also
        # downgrades a failing row at run time, which would hide the mistake.
        for cid, _label, _phase, how, module, package, licence, status, _note \
                in capabilities._TABLE:
            if package and status != "excluded":
                self.assertTrue(capabilities.licence_permits(licence),
                                f"{cid}: {licence!r} restricts commercial use")
            if status == "excluded":
                self.assertEqual((how, module), ("third-party", ""), cid)
                self.assertTrue(package, cid)
                self.assertFalse(capabilities.licence_permits(licence), cid)

    def test_a_route_added_without_checking_is_shown_as_excluded(self):
        row = ("careless", "Something useful", 2, "third-party", "", "json",
               "GPL-3.0-or-later", "planned", "Would be handy.")
        with mock.patch.object(capabilities, "_TABLE", (row,)):
            (c,) = capabilities.capabilities()
        self.assertEqual(c.status, "excluded")
        self.assertIn("GPL-3.0-or-later", c.note)

    def test_only_whole_program_copyleft_is_excluded(self):
        excluded = {c.id: c for c in self.rows.values()
                    if c.status == "excluded"}
        self.assertEqual(set(excluded), {"volatility3", "memprocfs"},
                         "only strong copyleft is excluded now")
        # the weak-copyleft libraries the plan first named all PASS the rule
        for licence in ("LGPL-3.0-or-later", "Apache-2.0 AND IPL-1.0 AND CPL-1.0"):
            self.assertTrue(capabilities.licence_permits(licence), licence)

    def test_what_they_would_have_read_is_native_by_default(self):
        # native default; a permitted library named in the note, not used
        for cid in ("ewf", "vdisk", "vss", "ese"):
            self.assertEqual((self.rows[cid].how, self.rows[cid].status),
                             ("native", "planned"), cid)
        self.assertEqual((self.rows["memory"].how, self.rows["memory"].status),
                         ("native", "deferred"))
        # APFS is the one place a permitted library IS the plan
        apfs = self.rows["apfs"]
        self.assertEqual((apfs.how, apfs.status, apfs.package),
                         ("third-party", "deferred", "pyfsapfs"))
        self.assertTrue(capabilities.licence_permits(apfs.licence))

    def test_the_e01_refusal_names_the_native_plan_not_a_licence_question(self):
        from forensics_workshop import image
        for key in ("ewf", "ewf2"):
            self.assertIn("native", image.CONTAINERS[key])
            self.assertNotIn("question", image.CONTAINERS[key])

    def test_the_plan_records_the_rule(self):
        text = (ROOT / "FORENSICS_PLAN.md").read_text(encoding="utf-8")
        self.assertIn("### 1.1 The licence rule", text)
        self.assertIn("restrict commercial use", text)
        self.assertNotIn("once the licence question is", text)


class Packaging(unittest.TestCase):
    def test_pyproject_version_matches_the_package(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        match = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), forensics_workshop.__version__)
        self.assertIn('name = "forensics_workshop"', text)
        self.assertIn("dependencies = []", text)

    def test_requires_python_admits_the_interpreters_it_is_tested_on(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        floor = re.search(r'requires-python\s*=\s*">=\s*3\.(\d+)"', text)
        self.assertIsNotNone(floor)
        self.assertLessEqual(int(floor.group(1)), sys.version_info.minor)

    def test_licence_and_readme_exist_and_say_what_matters(self):
        licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("All rights reserved", licence)
        self.assertIn("hardware write blocker", licence)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("forensics_workshop", readme)
        self.assertIn("python -m unittest discover -s tests", readme)

    def test_samples_are_never_committed(self):
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        self.assertIn("/samples/*", ignore)
        self.assertIn("!/samples/build_samples.py", ignore)

    def test_the_package_key_is_the_package_not_the_repository(self):
        self.assertEqual(forensics_workshop.PACKAGE, "forensics_workshop")
        self.assertTrue(forensics_workshop.PACKAGE.isidentifier())
        self.assertIn("Digital-Forensics-Workshop", forensics_workshop.REPOSITORY)


if __name__ == "__main__":
    unittest.main()
