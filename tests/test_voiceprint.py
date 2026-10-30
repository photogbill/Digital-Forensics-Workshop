"""Voice comparison (FORENSICS_PLAN §13) through a FAKE worker and a fake
FFmpeg, both run by the real subprocess path.

The fake worker turns a segment's pitch into a "voice", so a tone at 300 Hz
is one speaker and a tone at 900 Hz another. What is held here is the
engine's part: the energy gate and segments, the calibration maths, profiles
and comparisons in the case with custody and a review-queue lead, Invented
audio refused, nothing on the worker's side outside the scratch folder, and
the calibration kept beside the model — never in a case.
"""

from __future__ import annotations

import io
import json
import os
import random
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from _support import EXAMINER, TempDirCase

import mediasynth as M
from forensics_workshop import blocker, cli, ratchet, review
from forensics_workshop.case import Case
from forensics_workshop.errors import ForensicsError, MediaError
from forensics_workshop.media import voiceprint as V

ALICE, BOB, CAROL = 300.0, 900.0, 1500.0


class TheNumbers(unittest.TestCase):
    def test_the_gate_finds_speech_between_silences(self):
        levels = [-120.0] * 4 + [-12.0] * 8 + [-120.0] * 4
        mask, gate = V.speech_mask(levels)
        self.assertEqual(sum(mask), 8)
        self.assertEqual(gate["note"], "")
        segs = V.segments(mask, len(levels) * V.WINDOW_S)
        # 4 s in 3 s stretches: the first carries the speech, the 1 s tail
        # is silent and dropped
        self.assertEqual(segs, [{"start": 0.0, "end": 3.0, "speech_s": 2.0}])

    def test_a_flat_recording_counts_what_is_above_the_floor_and_says_so(self):
        mask, gate = V.speech_mask([-20.0] * 12)
        self.assertTrue(all(mask))
        self.assertIn("flat level", gate["note"])

    def test_a_short_clip_is_one_segment(self):
        segs = V.segments([True] * 3, 0.75)
        self.assertEqual(segs, [{"start": 0.0, "end": 0.75, "speech_s": 0.75}])

    def test_cosine_and_the_mean_voice(self):
        self.assertAlmostEqual(V.cosine([1, 0], [2, 0]), 1.0)
        self.assertAlmostEqual(V.cosine([1, 0], [0, 3]), 0.0)
        voice = V.mean_embedding([[1, 0], [0, 1]], [3, 1])
        self.assertAlmostEqual(sum(v * v for v in voice), 1.0, places=6)
        self.assertGreater(voice[0], voice[1])
        with self.assertRaisesRegex(MediaError, "different sizes"):
            V.cosine([1, 0], [1, 0, 0])
        with self.assertRaisesRegex(MediaError, "no length"):
            V.cosine([0, 0], [1, 0])

    def test_the_calibration_turns_scores_into_probabilities(self):
        rnd = random.Random(7)
        same = [rnd.gauss(0.62, 0.08) for _ in range(150)]
        diff = [rnd.gauss(0.08, 0.08) for _ in range(3000)]
        cal = V.fit_calibration(same, diff)
        self.assertGreater(cal["a"], 0)
        self.assertLess(0.2, cal["score_at_50"])
        self.assertLess(cal["score_at_50"], 0.5)
        self.assertLess(cal["eer"], 0.05)
        self.assertGreater(V.probability(0.62, cal), 0.95)
        self.assertLess(V.probability(0.08, cal), 0.05)
        self.assertAlmostEqual(V.probability(cal["score_at_50"], cal), 0.5,
                               places=3)
        # the prior moves it, and is shown — never hidden
        self.assertLess(V.probability(0.35, cal, prior=0.1),
                        V.probability(0.35, cal, prior=0.5))
        self.assertIsNone(V.probability(0.9, None))
        for bad in (0.0, 1.0, 1.5):
            with self.assertRaisesRegex(MediaError, "prior"):
                V.probability(0.3, cal, prior=bad)

    def test_a_reference_set_that_separates_perfectly_stays_finite(self):
        cal = V.fit_calibration([0.8, 0.85, 0.9], [0.0, 0.05, 0.1])
        self.assertTrue(all(map(lambda v: abs(v) < 1e6, (cal["a"], cal["b"]))))
        self.assertEqual(cal["eer"], 0.0)

    def test_the_equal_error_rate_sweep(self):
        eer, t = V.equal_error_rate([0.6, 0.7, 0.2], [0.1, 0.3, 0.05])
        self.assertAlmostEqual(eer, 1 / 3, places=4)
        self.assertTrue(0.05 <= t <= 0.6)

    def test_bands_and_how_a_probability_is_written(self):
        self.assertEqual(V.band(0.4, None), "above-threshold")
        self.assertEqual(V.band(0.1, None), "below-threshold")
        self.assertEqual([V.band(0, p) for p in (0.95, 0.8, 0.5, 0.1)],
                         ["strong", "likely", "inconclusive", "unlikely"])
        self.assertEqual(V.shown(None), "")
        self.assertEqual(V.shown(0.873), "87%")
        self.assertEqual(V.shown(0.9995), ">99.9%")
        self.assertEqual(V.shown(0.0004), "<0.1%")
        self.assertEqual(V.shown(0.995), "99.5%")

    def test_pairs_are_scored_the_way_the_page_uses_the_model(self):
        voices = {"a": [[1, 0.0], [1, 0.1], [1, 0.05], [1, 0.02]],
                  "b": [[0.0, 1], [0.1, 1], [0.05, 1], [0.02, 1]]}
        same, diff = V.pair_scores(voices)
        self.assertEqual((len(same), len(diff)), (4, 4))
        self.assertGreater(min(same), max(diff))


class _Fixture(TempDirCase):
    def setUp(self):
        super().setUp()
        self.ffmpeg = M.install_ffmpeg(self.tmp / "bin")
        self.worker = M.install_vp_worker(self.tmp / "bin")
        self.model = M.fake_voice_model(self.tmp / "models" / "voiceprint"
                                        / "spkrec-ecapa-voxceleb")
        self.scratch = self.tmp / "atk-data" / "tmp" / "voiceprint"
        self.evidence = self.tmp / "evidence"
        self.alice = [M.voice_clip(self.evidence / "known" / f"alice{i}.wav",
                                   ALICE + 4 * i) for i in range(2)]
        self.bob = [M.voice_clip(self.evidence / "known" / "bob0.wav", BOB,
                                 rate=48000, fmt="float32")]
        self.case = Case.create(self.tmp / "case", case_id="VOICE-1",
                                examiner=EXAMINER)
        self.item = self.case.add_folder(self.evidence, label="phone")

    def kw(self, **extra):
        kw = {"model_dir": self.model, "ffmpeg": self.ffmpeg,
              "worker": self.worker, "scratch": self.scratch}
        kw.update(extra)
        return kw

    def actions(self, prefix="voiceprint."):
        return [r["action"] for r in self.case.custody.rows()
                if r["action"].startswith(prefix)]

    def two_profiles(self):
        a = V.enrol(self.case, self.alice, name="Alice", **self.kw())
        b = V.enrol(self.case, self.bob, name="Bob", **self.kw())
        return a, b


class Profiles(_Fixture):
    def test_a_profile_lives_in_the_case_with_custody(self):
        lines = []
        a = V.enrol(self.case, self.alice, name="Alice", progress=lines.append,
                    **self.kw())
        folder = Path(a["folder"])
        self.assertTrue(blocker.is_inside(folder, self.case.root))
        saved = json.loads((folder / "profile.json").read_text("utf-8"))
        self.assertEqual(saved["name"], "Alice")
        self.assertEqual(len(saved["samples"]), 2)
        self.assertEqual(saved["model"]["id"], V.MODEL_ID)
        self.assertEqual(len(saved["model"]["fingerprint"]), 64)
        for s in saved["samples"]:
            self.assertEqual(s["original"]["evidence_id"], self.item.id)
            self.assertEqual(s["tier"], "measured")
            self.assertGreater(s["net_speech_s"], 3.0)
            self.assertTrue((folder / s["folder"] / s["wav"]).is_file())
        self.assertEqual(self.actions(), ["voiceprint.enrolled"])
        self.assertTrue(self.case.custody.verify().ok)
        rows = V.list_profiles(self.case)
        self.assertEqual([(r["name"], r["samples"]) for r in rows],
                         [("Alice", 2)])
        self.assertTrue(any("Voice model" in l for l in lines))

    def test_samples_can_be_added_to_a_profile(self):
        a = V.enrol(self.case, self.alice[:1], name="Alice", **self.kw())
        more = V.enrol(self.case, self.alice[1:], profile_id=a["id"],
                       **self.kw())
        self.assertEqual(more["id"], a["id"])
        self.assertEqual(len(more["samples"]), 2)
        self.assertEqual([s["n"] for s in more["samples"]], [1, 2])

    def test_refusals_before_anything_is_written(self):
        for kwargs, needle in (
                ({"name": ""}, "name"),
                ({"name": "A", "model_dir": self.tmp / "nomodel"},
                 "missing"),
                ({"name": "A", "worker": None}, "No Python"),
                ({"name": "A", "ffmpeg": None}, "FFmpeg")):
            with self.assertRaisesRegex(MediaError, needle, msg=kwargs):
                V.enrol(self.case, self.alice, **self.kw(**kwargs))
        with self.assertRaisesRegex(MediaError, "at least one"):
            V.enrol(self.case, [], name="A", **self.kw())
        self.assertFalse((self.case.root / V.VP_DIR).exists())
        self.assertEqual(self.actions(), [])

    def test_invented_audio_is_never_a_voice_sample(self):
        stem = M.voice_clip(self.evidence / "seed1.target.invented.wav", ALICE)
        with self.assertRaisesRegex(MediaError, "INVENTED"):
            V.enrol(self.case, [stem], name="A", **self.kw())
        self.assertFalse((self.case.root / V.VP_DIR).exists())

    def test_a_recording_with_no_speech_is_refused_by_name(self):
        quiet = M.write_wav(self.evidence / "silence.wav", [0.0] * 44100)
        with self.assertRaisesRegex(MediaError, "no stretch of speech"):
            V.enrol(self.case, [quiet], name="A", **self.kw())
        self.assertEqual(self.actions(), ["voiceprint.failed"])

    def test_the_worker_runs_offline_with_temp_and_caches_in_scratch(self):
        a = V.enrol(self.case, self.alice[:1], name="Alice", **self.kw())
        folder = Path(a["folder"]) / a["samples"][0]["folder"]
        env = json.loads((folder / "response.json").read_text("utf-8"))["env"]
        self.assertEqual(Path(env["TEMP"]), self.scratch.resolve())
        self.assertEqual(env["TEMP"], env["TMP"])
        self.assertEqual(env["HF_HUB_OFFLINE"], "1")
        for key in ("HF_HOME", "TORCH_HOME", "CUDA_CACHE_PATH"):
            self.assertTrue(blocker.is_inside(env[key], self.scratch), key)
        log = (folder / "voiceprint.log").read_text("utf-8")
        self.assertIn("fake vp worker", log)
        self.assertTrue(log.rstrip().splitlines()[-1].startswith(
            "[forensics_workshop]"))

    def test_a_worker_crash_is_a_sentence_and_a_custody_record(self):
        crashing = M.fake_voice_model(self.tmp / "models" / "CRASH-model")
        with self.assertRaises(MediaError) as caught:
            V.enrol(self.case, self.alice, name="A",
                    **self.kw(model_dir=crashing))
        self.assertIn("out of memory", str(caught.exception))
        self.assertIn("full log", str(caught.exception))
        self.assertEqual(self.actions(), ["voiceprint.failed"])


class Comparing(_Fixture):
    def test_the_closest_voice_wins_and_is_filed_as_a_lead(self):
        self.two_profiles()
        q = M.voice_clip(self.evidence / "calls" / "q.wav", ALICE + 2)
        result = V.compare(self.case, q, **self.kw())
        self.assertEqual(result["state"], "completed")
        names = [m["name"] for m in result["matches"]]
        self.assertEqual(names[0], "Alice")
        top, other = result["matches"]
        self.assertGreater(top["score"], 0.9)
        self.assertLess(other["score"], 0.3)
        # uncalibrated: a raw score, no probability, and said so
        self.assertIsNone(top["probability"])
        self.assertEqual(top["shown"], "")
        self.assertEqual(top["band"], "above-threshold")
        self.assertTrue(any("UNCALIBRATED" in f["text"]
                            for f in result["flags"]))
        # a lead in the review queue, not a conclusion
        found = review.list_findings(self.case)
        self.assertEqual([f.kind for f in found], [V.FINDING_KIND])
        self.assertEqual(found[0].source, V.SOURCE)
        self.assertEqual(found[0].status, "proposed")
        self.assertIn("Alice", found[0].title)
        self.assertEqual(found[0].evidence_id, self.item.id)
        self.assertEqual(self.actions()[-1], "voiceprint.compared")
        record = self.case.custody.rows()[-1]
        self.assertEqual(record["hashes"]["result.json"],
                         __import__("hashlib").sha256(
                             (Path(result["folder"]) / "result.json")
                             .read_bytes()).hexdigest())
        self.assertNotIn("matches", record["detail"])
        back = V.load_run(self.case, result["run_id"])
        self.assertEqual(back["matches"][0]["name"], "Alice")
        runs = V.list_runs(self.case)
        self.assertEqual((runs[0]["closest"], runs[0]["state"]),
                         ("Alice", "completed"))

    def test_two_voices_in_one_recording_show_on_the_timeline(self):
        self.two_profiles()
        mixed = M.write_wav(
            self.evidence / "calls" / "mixed.wav",
            [a + b for a, b in zip(
                M.tone(6.0, ALICE, 0.4, rate=44100, start=0.0, total=12.0),
                M.tone(6.0, BOB, 0.4, rate=44100, start=6.0, total=12.0))],
            rate=44100)
        result = V.compare(self.case, mixed, **self.kw())
        bests = {s["best"] for s in result["segments"]}
        self.assertEqual(len(bests), 2)
        self.assertTrue(any("more than one known voice" in f["text"]
                            for f in result["flags"]))

    def test_short_speech_and_processed_input_are_flagged(self):
        self.two_profiles()
        short = M.voice_clip(self.evidence / "calls" / "short.wav", BOB,
                             seconds=2.0)
        result = V.compare(self.case, short, **self.kw())
        levels = {f["level"] for f in result["flags"]
                  if "Questioned" in f["text"]}
        self.assertEqual(levels, {"red"})
        cleaned = M.voice_clip(self.evidence / "calls" / "q.wav", BOB)
        with mock.patch.object(V._lab, "upstream_of_input",
                               return_value=("sam-x", "cleaned", "sidecar")):
            result = V.compare(self.case, cleaned, **self.kw())
        self.assertEqual(result["tier"], "cleaned")
        self.assertTrue(any("CLEANED audio" in f["text"]
                            for f in result["flags"]))

    def test_invented_audio_is_refused_before_anything_is_written(self):
        self.two_profiles()
        stem = M.voice_clip(self.evidence / "seed2.target.invented.wav", BOB)
        with self.assertRaisesRegex(MediaError, "never voice-compared"):
            V.compare(self.case, stem, **self.kw())
        self.assertFalse(V.runs_root(self.case).exists())

    def test_nothing_to_compare_against_is_refused(self):
        q = M.voice_clip(self.evidence / "calls" / "q.wav", ALICE)
        with self.assertRaisesRegex(MediaError, "no voice profiles"):
            V.compare(self.case, q, **self.kw())


class Calibrating(_Fixture):
    def _reference(self):
        root = self.tmp / "reference"
        for k, base in enumerate((ALICE, BOB, CAROL, 2100.0)):
            for j in range(4):
                M.voice_clip(root / f"spk{k}" / "ch1" / f"{j}.wav",
                             base * (1 + 0.01 * j), seconds=3.0)
        (root / "lonely").mkdir(exist_ok=True)
        M.voice_clip(root / "lonely" / "only.wav", 700.0)
        return root

    def test_a_calibration_lives_beside_the_model_never_in_a_case(self):
        harness = self.tmp / "atk-data" / "media" / "harness"
        cal = V.calibrate(self._reference(), name="tones", out_dir=harness,
                          conditions="test tones", **self.kw())
        self.assertEqual(cal["speakers"], 4)
        self.assertEqual((cal["same_pairs"], cal["diff_pairs"]), (8, 24))
        self.assertGreater(cal["same_mean"], cal["diff_mean"])
        kept = V.load_calibrations(self.model)
        self.assertEqual([c["name"] for c in kept], ["tones"])
        self.assertTrue(V.calibration_path(self.model).is_file())
        self.assertTrue(blocker.is_inside(cal["folder"], harness))
        self.assertFalse((self.case.root / V.VP_DIR).exists())
        # a same-named calibration is replaced, not duplicated
        V.calibrate(self._reference(), name="tones", out_dir=harness,
                    **self.kw())
        self.assertEqual(len(V.load_calibrations(self.model)), 1)

    def test_a_calibrated_comparison_gives_a_probability(self):
        harness = self.tmp / "harness"
        V.calibrate(self._reference(), name="tones", out_dir=harness,
                    **self.kw())
        self.two_profiles()
        q = M.voice_clip(self.evidence / "calls" / "q.wav", ALICE + 3)
        result = V.compare(self.case, q, calibration="tones", **self.kw())
        top, other = result["matches"]
        self.assertGreater(top["probability"], 0.9)
        self.assertLess(other["probability"], 0.1)
        self.assertTrue(top["shown"].endswith("%"))
        self.assertIn(top["band"], ("strong", "likely"))
        self.assertEqual(result["calibration"]["name"], "tones")
        low = V.compare(self.case, q, calibration="tones", prior=0.01,
                        **self.kw())
        self.assertLess(low["matches"][0]["probability"], top["probability"])

    def test_calibration_refusals(self):
        with self.assertRaisesRegex(MediaError, "Name the calibration"):
            V.calibrate(self._reference(), name="", out_dir=self.tmp / "h",
                        **self.kw())
        thin = self.tmp / "thin"
        M.voice_clip(thin / "a" / "1.wav", ALICE)
        M.voice_clip(thin / "a" / "2.wav", ALICE)
        with self.assertRaisesRegex(MediaError, "at least 2 speaker"):
            V.calibrate(thin, name="x", out_dir=self.tmp / "h", **self.kw())
        with self.assertRaisesRegex(MediaError, "No calibration named"):
            V.calibration_by_name(self.model, "nope")
        with self.assertRaisesRegex(ForensicsError, "inside the case"):
            V.calibrate(self._reference(), name="x",
                        out_dir=self.case.root / "harness", **self.kw())

    def test_the_calibration_writer_takes_exactly_one_file(self):
        with self.assertRaisesRegex(MediaError, "only ever"):
            V.assert_calibration_path(self.model, self.model / "other.json")
        inside = self.case.root / "models"
        inside.mkdir()
        with self.assertRaisesRegex(MediaError, "inside the case"):
            V.assert_calibration_path(inside, inside / V.CALIBRATION_FILE)
        with self.assertRaisesRegex(MediaError, "only ever"):
            V.assert_runtime_scratch(self.scratch, self.tmp / "elsewhere")


class WritersAndCommandLine(_Fixture):
    def test_the_new_writers_are_listed_and_the_package_is_clean(self):
        for name, kind in (("media.voiceprint:make_scratch",
                            "runtime-scratch"),
                           ("media.voiceprint:_write_calibration",
                            "calibration"),
                           ("media.vp_worker:_write", "worker-output")):
            self.assertEqual(blocker.WRITERS.get(name), kind, name)
        report = ratchet.scan_package(Path(V.__file__).parents[1],
                                      blocker.WRITERS)
        self.assertEqual(report.violations, [])
        self.assertIn("media.voiceprint", report.files)
        self.assertIn("media.vp_worker", report.files)

    def _cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_enrol_compare_and_list_from_the_command_line(self):
        common = ["--model-dir", str(self.model), "--ffmpeg", "FFMPEG",
                  "--python", "PY", "--scratch", str(self.scratch)]
        real_ffmpeg = list(self.ffmpeg)
        worker = list(self.worker)
        orig_runtime = V._proc.runtime_argv
        orig_worker = V.worker_argv

        def runtime(a):
            return real_ffmpeg if a == "FFMPEG" else orig_runtime(a)

        def worker_argv(python=None, w=None):
            return worker if python == "PY" else orig_worker(python, w)

        V._proc.runtime_argv = runtime
        V.worker_argv = worker_argv
        try:
            code, out, err = self._cli(
                "voice-enrol", str(self.case.root), str(self.alice[0]),
                "--examiner", EXAMINER, "--name", "Alice", *common)
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)["name"], "Alice")
            code, out, _ = self._cli("voice-profiles", str(self.case.root),
                                     "--examiner", EXAMINER)
            self.assertIn("Alice", out)
            q = M.voice_clip(self.evidence / "calls" / "q.wav", ALICE)
            code, out, err = self._cli(
                "voice-compare", str(self.case.root), str(q), "--examiner",
                EXAMINER, *common)
            self.assertEqual(code, 0, err)
            self.assertIn("uncalibrated", err)
            run = json.loads(out)["run_id"]
            code, out, _ = self._cli("voice-runs", str(self.case.root),
                                     "--examiner", EXAMINER)
            self.assertIn(run, out)
            code, _out, err = self._cli(
                "voice-compare", str(self.case.root), str(q), "--examiner",
                EXAMINER, "--calibration", "none-yet", *common)
            self.assertEqual(code, 3)
            self.assertIn("No calibration named", err)
            code, out, _ = self._cli("voice-calibrations", "--model-dir",
                                     str(self.model))
            self.assertEqual(json.loads(out), [])
        finally:
            V._proc.runtime_argv = orig_runtime
            V.worker_argv = orig_worker


if __name__ == "__main__":
    unittest.main()
