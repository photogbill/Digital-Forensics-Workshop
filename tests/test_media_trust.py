"""What may run, and who said so: pinned weights, the negative control, the
owner exception, and the writers the ratchet allows (FORENSICS_PLAN §1.1,
§12.9, §12.12). Every guard here is also watched failing."""

from __future__ import annotations

import ast
import os
import unittest
from pathlib import Path
from unittest import mock

from _support import EXAMINER, PACKAGE, TempDirCase

import mediasynth as M
from forensics_workshop import blocker, capabilities, ratchet
from forensics_workshop.case import Case
from forensics_workshop.errors import CaseLayoutError, CasePathError, MediaError
from forensics_workshop.media import lab as L
from forensics_workshop.media import weights as WT


class PinnedWeights(TempDirCase):
    def setUp(self):
        super().setUp()
        self.model = M.fake_model(self.tmp / "models")

    def test_no_pin_is_allowed_and_says_unverified(self):
        status = WT.check_weights(self.model)
        self.assertEqual(status["state"], "unverified")
        self.assertEqual(status["sentence"],
                         "weights: unverified (parity not run)")

    def test_a_pinned_file_passes_and_a_changed_one_is_refused(self):
        pin = WT.pin_model(self.model, by="Bill", note="parity 2026-10-06")
        self.assertEqual(Path(pin["manifest"]).name, "model_manifest.json")
        self.assertEqual(Path(pin["manifest"]).parent, self.model.parent)
        self.assertEqual(WT.check_weights(self.model)["state"], "pinned")
        self.model.write_bytes(b"GGUF" + b"\x01" * 60)        # other bytes
        with self.assertRaisesRegex(MediaError, "not a file that was pinned"):
            WT.check_weights(self.model)

    def test_a_refused_model_writes_nothing_into_the_case(self):
        WT.pin_model(self.model, by="Bill")
        self.model.write_bytes(b"GGUF" + b"\x02" * 60)
        cli, _ff = M.install_fakes(self.tmp / "bin")
        clip = M.write_wav(self.tmp / "ev" / "c.wav", M.tone(0.5))
        case = Case.create(self.tmp / "case", case_id="T", examiner=EXAMINER)
        with self.assertRaisesRegex(MediaError, "not a file that was pinned"):
            L.run_sam(case, clip, text="x", model=self.model, audiocpp=cli)
        self.assertFalse((case.root / "media").exists())
        self.assertFalse([r for r in case.custody.rows()
                          if r["action"].startswith("media.")])

    def test_once_anything_is_pinned_only_pinned_bytes_run(self):
        WT.pin_model(self.model, by="Bill")
        bf16 = M.fake_model(self.tmp / "models", "sam-audio-large-bf16.gguf",
                            b"GGUF" + b"\x05" * 60)
        with self.assertRaisesRegex(MediaError, "only pinned weights run"):
            WT.check_weights(bf16)
        renamed = self.tmp / "models" / "my-copy.gguf"
        renamed.write_bytes(self.model.read_bytes())
        status = WT.check_weights(renamed)
        self.assertEqual(status["state"], "pinned")
        self.assertIn("pinned as sam-audio-large-q8_0.gguf", status["sentence"])
        WT.pin_model(bf16, by="Bill")
        self.assertEqual(WT.check_weights(bf16)["state"], "pinned")

    def test_the_hash_is_cached_by_size_mtime_and_file_id(self):
        first, cached = WT.model_sha256(self.model)
        self.assertFalse(cached)
        again, cached = WT.model_sha256(self.model)
        self.assertEqual((again, cached), (first, True))
        st = self.model.stat()
        os.utime(self.model, ns=(st.st_atime_ns, st.st_mtime_ns + 10 ** 9))
        self.assertFalse(WT.model_sha256(self.model)[1], "mtime moved: rehash")
        self.assertFalse(WT.model_sha256(self.model, fresh=True)[1])

    def test_re_pinning_other_bytes_is_a_decision(self):
        WT.pin_model(self.model, by="Bill")
        self.model.write_bytes(b"GGUF" + b"\x03" * 60)
        with self.assertRaisesRegex(MediaError, "already pinned"):
            WT.pin_model(self.model, by="Bill")
        out = WT.pin_model(self.model, by="Bill", replace=True)
        self.assertIsNotNone(out["pin"]["replaced"])
        with self.assertRaisesRegex(MediaError, "who ran the parity"):
            WT.pin_model(self.model, by=" ")

    def test_an_unreadable_manifest_never_unpins_a_model(self):
        WT.pin_model(self.model, by="Bill")
        WT.manifest_path(self.model).write_text("{not json")
        with self.assertRaisesRegex(MediaError, "cannot be read"):
            WT.check_weights(self.model)

    def test_the_manifest_writer_writes_exactly_one_file(self):
        with self.assertRaisesRegex(MediaError, "only ever"):
            WT.assert_manifest_path(self.model, self.tmp / "other.json")
        case = Case.create(self.tmp / "c2", case_id="T2", examiner=EXAMINER)
        inside = M.fake_model(case.root / "reports")
        with self.assertRaisesRegex(MediaError, "inside the case"):
            WT.assert_manifest_path(inside, WT.manifest_path(inside))


class NegativeControl(TempDirCase):
    def setUp(self):
        super().setUp()
        self.cli, _ff = M.install_fakes(self.tmp / "bin")
        self.model = M.fake_model(self.tmp / "models")
        self.noise = M.write_wav(self.tmp / "noise.wav",
                                 M.tone(2.0, freq=3000, amp=0.2))

    def test_until_it_runs_every_surface_says_not_tested(self):
        sha = WT.model_sha256(self.model)[0]
        self.assertEqual(WT.negative_control_status(self.model, sha)["sentence"],
                         "not yet negative-control tested")

    def test_quiet_on_noise_is_recorded_against_the_hash(self):
        result = L.negative_control(self.noise, out_dir=self.tmp / "harness",
                                    model=self.model, audiocpp=self.cli,
                                    text="quiet please", seeds=2)
        self.assertFalse(result["speaks_on_noise"])
        self.assertIn("energy only", result["method"])
        sha = WT.model_sha256(self.model)[0]
        status = WT.negative_control_status(self.model, sha)
        self.assertEqual(status["state"], "quiet-on-noise")
        self.assertTrue((Path(result["folder"]) /
                         "seed1.target.invented.wav").is_file())

    def test_speaks_on_noise_is_flagged_and_bound_to_these_bytes(self):
        result = L.negative_control(self.noise, out_dir=self.tmp / "harness",
                                    model=self.model, audiocpp=self.cli,
                                    seeds=1)
        self.assertTrue(result["speaks_on_noise"])
        self.assertEqual(result["per_seed"][0]["first_flagged_s"], 0.0)
        sha = WT.model_sha256(self.model)[0]
        self.assertEqual(WT.negative_control_status(self.model, sha)["state"],
                         "speaks-on-noise")
        self.model.write_bytes(b"GGUF" + b"\x09" * 60)
        other = WT.model_sha256(self.model)[0]
        self.assertEqual(WT.negative_control_status(self.model, other)["state"],
                         "not-run", "a result for other bytes does not count")

    def test_a_broken_output_records_no_result(self):
        for text in ("NAN noise", "EMPTY noise"):
            with self.assertRaisesRegex(MediaError, "No result was recorded"):
                L.negative_control(self.noise, out_dir=self.tmp / "harness",
                                   model=self.model, audiocpp=self.cli,
                                   text=text, seeds=1)
        self.assertEqual(WT.load_manifest(self.model)["negative_control"], {})

    def test_a_harness_inside_a_case_is_refused(self):
        case = Case.create(self.tmp / "case", case_id="T", examiner=EXAMINER)
        with self.assertRaises(CaseLayoutError):
            L.negative_control(self.noise, out_dir=case.root / "reports",
                               model=self.model, audiocpp=self.cli, seeds=1)
        with self.assertRaises(CasePathError):
            blocker.assert_harness_path(self.tmp / "h", self.tmp / "else")


class OwnerException(unittest.TestCase):
    """Bill, 2026-09-30: SAM Audio in, as a named exception — not a looser rule."""

    SAM = "LicenseRef-SAM-License"

    def rows(self):
        return {c.id: c for c in capabilities.capabilities()}

    def test_the_row_shows_the_exception_in_words(self):
        row = self.rows()["sam-audio"]
        self.assertEqual(row.status, "available")
        self.assertEqual(row.licence, self.SAM)
        sentence = ("owner exception — SAM License (military, warfare, "
                    "espionage and ITAR end uses banned); replace or remove "
                    "if ATK goes to defense-related work")
        self.assertEqual(row.exception, sentence)
        self.assertTrue(row.note.startswith(sentence))
        self.assertEqual(self.rows()["audiocpp"].licence, "Apache-2.0")
        self.assertEqual(self.rows()["audiocpp"].exception, "")

    def test_the_rule_itself_is_not_loosened(self):
        self.assertFalse(capabilities.licence_permits(self.SAM))
        self.assertNotIn(self.SAM, capabilities.PERMITTED_LICENCES)

    def test_there_is_one_exception_and_it_is_bound(self):
        self.assertEqual(list(capabilities.OWNER_EXCEPTIONS), ["sam-audio"])
        only = capabilities.OWNER_EXCEPTIONS["sam-audio"]
        self.assertEqual((only.capability, only.licence),
                         ("sam-audio", self.SAM))
        self.assertIn("defense", only.removal_trigger)
        self.assertEqual(only.granted_on, "2026-09-30")

    def test_no_other_component_can_ride_it(self):
        rider = ("other-model", "Another model", 3, "third-party", "", "", self.SAM,
                 "planned", "Same licence, different component.")
        swapped = ("sam-audio", "SAM under another licence", 3, "third-party",
                   "", "", "GPL-3.0-only", "planned", "")
        with mock.patch.object(capabilities, "_TABLE", (rider, swapped)):
            got = {c.id: c for c in capabilities.capabilities()}
        self.assertEqual(got["other-model"].status, "excluded")
        self.assertEqual(got["sam-audio"].status, "excluded")
        self.assertIn("Fails the licence rule", got["other-model"].note)

    def test_without_the_exception_sam_is_excluded(self):
        with mock.patch.object(capabilities, "OWNER_EXCEPTIONS", {}):
            row = self.rows()["sam-audio"]
        self.assertEqual(row.status, "excluded")
        self.assertEqual(row.exception, "")

    def test_the_written_table_admits_only_permitted_or_excepted_licences(self):
        for cid, _l, _p, _h, _m, package, licence, status, _n in \
                capabilities._TABLE:
            if (package or licence) and status != "excluded":
                self.assertTrue(capabilities.licence_permits(licence) or
                                capabilities.owner_exception(cid, licence),
                                cid)


class WritersAndIsolation(unittest.TestCase):
    MEDIA_WRITERS = {"media.lab:_case_log": "case",
                     "media.lab:_case_settle": "case",
                     "media.lab:_harness_dirs": "harness",
                     "media.lab:_harness_log": "harness",
                     "media.lab:_harness_settle": "harness",
                     "media.lab:_harness_json": "harness",
                     "media.weights:_write_manifest": "model-manifest",
                     "media.sam_audio:run_process": "spawn",
                     "media.sam_audio:probe_version": "spawn",
                     "media.sam_audio:make_scratch": "runtime-scratch"}

    def test_the_media_writers_are_listed_and_the_package_is_clean(self):
        for name, kind in self.MEDIA_WRITERS.items():
            self.assertEqual(blocker.WRITERS.get(name), kind, name)
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        self.assertEqual(report.violations, [])
        for module in ("media.lab", "media.weights", "media.sam_audio",
                       "media.wav", "media.recipe", "media.disagreement",
                       "media.separator"):
            self.assertIn(module, report.files)
        self.assertTrue(set(self.MEDIA_WRITERS) <= report.writers_seen)

    def test_unlisting_a_media_writer_turns_the_ratchet_red(self):
        writers = {k: v for k, v in blocker.WRITERS.items()
                   if k != "media.lab:_case_log"}
        report = ratchet.scan_package(PACKAGE, writers)
        self.assertTrue(any("media.lab:_case_log" in v
                            for v in report.violations))

    def test_starting_a_child_process_is_a_write_site(self):
        for call in ("subprocess.run(['x'])", "subprocess.Popen(['x'])",
                     "os.system('x')"):
            report = ratchet.scan_source(
                f"import os, subprocess\ndef f():\n    {call}\n", "m")
            self.assertTrue(report.violations, call)
        report = ratchet.scan_package(PACKAGE, blocker.WRITERS)
        spawns = [s for s in report.sites if s.what.startswith("subprocess.")]
        self.assertTrue(spawns and all(s.allowed for s in spawns))
        self.assertEqual({s.qualname for s in spawns},
                         {"media.sam_audio:run_process",
                          "media.sam_audio:probe_version"})

    def test_a_child_with_targets_needs_a_guard(self):
        with self.assertRaises(CasePathError):
            blocker.assert_child_writes(None, ["x"])
        self.assertEqual(blocker.assert_child_writes(None, ()), [])

    def test_harness_and_manifest_writers_must_call_their_guards(self):
        for kind, guard in (("harness", "assert_harness_path"),
                            ("model-manifest", "assert_manifest_path"),
                            ("spawn", "assert_child_writes")):
            report = ratchet.scan_source("def w(p):\n    open(p, 'xb')\n",
                                         "m", {"m:w": kind})
            self.assertTrue(any(guard in v for v in report.violations), kind)
            ok = ratchet.scan_source(
                f"def w(r, p):\n    {guard}(r, p)\n    open(p, 'xb')\n",
                "m", {"m:w": kind})
            self.assertEqual(ok.violations, [], kind)

    def test_numpy_is_reached_in_one_place_and_never_imported(self):
        hits = []
        for path in (PACKAGE / "media").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names] + [
                        getattr(node, "module", "") or ""]
                    self.assertFalse(any(n.split(".")[0] == "numpy"
                                         for n in names), path.name)
                if isinstance(node, ast.Call) and getattr(
                        node.func, "attr", "") == "import_module":
                    hits.append((path.name, ast.unparse(node.args[0])))
        self.assertEqual(hits, [("disagreement.py", "'numpy'")])

    def test_the_media_init_imports_nothing(self):
        tree = ast.parse((PACKAGE / "media" / "__init__.py").read_text(
            encoding="utf-8"))
        self.assertFalse([n for n in ast.walk(tree)
                          if isinstance(n, (ast.Import, ast.ImportFrom))])

    def test_the_capability_note_says_which_measure_without_numpy(self):
        with mock.patch("importlib.util.find_spec", return_value=None):
            self.assertIn("RMS-envelope", L.capability_note())

    def test_the_notices_name_every_licence(self):
        text = (PACKAGE / "media" / "NOTICES.md").read_text(encoding="utf-8")
        for needle in ("SAM License", "military", "T5", "Apache License 2.0",
                       "ShugoAI", "v0.9.0"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
