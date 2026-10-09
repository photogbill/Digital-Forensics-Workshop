"""Audio restoration (FORENSICS_PLAN §13.3–13.4) — analyse, recommend, run,
compare, export — through a fake worker and a fake FFmpeg run by the real
subprocess path.

The decision rules are held with planted measurements: what counts as a
problem, which recipe is least invasive for it, that two-voice separation is
offered and never the default, and that a clean recording recommends
nothing. The run is held to the forensic door: everything in the case, a
residual and a sidecar beside every output, tiers that never drop, a failing
option recorded while the others still run, and export with custody.
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from _support import EXAMINER, TempDirCase

import mediasynth as M
from forensics_workshop import blocker, cli, ratchet
from forensics_workshop.case import Case
from forensics_workshop.errors import MediaError
from forensics_workshop.media import lab as L
from forensics_workshop.media import recipe as R
from forensics_workshop.media import restore as RS
from forensics_workshop.media import voiceprint as V

BASE = {"duration_s": 3.0, "rate": 16000, "peak_dbfs": -6.0,
        "rms_dbfs": -24.0, "dc_offset": 0.0, "clipped_fraction": 0.0,
        "clipped_runs": 0, "clicks_per_s": 0.0, "floor_db": -60.0,
        "speech_peak_db": -12.0, "gate_db": -40.0, "speech_fraction": 0.5,
        "speech_db": -18.0, "noise_db": -60.0, "snr_db": 42.0,
        "noise_steadiness_db": 1.0,
        "hum": {"hz": 0, "prominence_db": 0.0, "harmonics": 0,
                "per_harmonic": []},
        "rumble_db": -20.0, "bandwidth_hz": 8000.0}


def m(**over):
    out = json.loads(json.dumps(BASE))
    out.update(over)
    return out


class Findings(unittest.TestCase):
    def test_each_problem_is_found_with_the_number_behind_it(self):
        a = m(snr_db=8.0, noise_db=-30.0,
              hum={"hz": 60, "prominence_db": 20.0, "harmonics": 5,
                   "per_harmonic": []},
              clipped_fraction=0.002, clipped_runs=40, clicks_per_s=3.0,
              dc_offset=0.02, rumble_db=0.0, bandwidth_hz=3500.0,
              speech_db=-40.0)
        found = {i["id"]: i for i in RS.issues(a)}
        self.assertEqual({k: v["severity"] for k, v in found.items()},
                         {"noise": "high", "hum": "high", "rumble": "medium",
                          "dc": "medium", "clipping": "high", "clicks": "high",
                          "band": "info", "quiet": "medium"})
        self.assertIn("60 Hz", found["hum"]["label"])
        self.assertEqual(found["hum"]["hz"], 60)
        self.assertIn("8 dB", found["noise"]["measured"])
        self.assertIn("invention", found["band"]["fix"])

    def test_a_clean_recording_has_nothing_to_fix(self):
        self.assertEqual(RS.issues(m()), [])
        opts = RS.options(m())
        self.assertEqual([o["id"] for o in opts], ["separate"])
        self.assertEqual(RS.best_option(opts), "")

    def test_weak_hum_or_two_harmonics_is_not_hum(self):
        for hum in ({"hz": 60, "prominence_db": 6.7, "harmonics": 2},
                    {"hz": 50, "prominence_db": 14.0, "harmonics": 2}):
            self.assertEqual(RS.issues(m(hum=dict(hum, per_harmonic=[]))), [])


class Recommending(unittest.TestCase):
    def ids(self, a):
        return [o["id"] for o in RS.options(a)]

    def test_moderate_steady_noise_prefers_the_least_invasive(self):
        opts = RS.options(m(snr_db=15.0, noise_db=-33.0))
        self.assertEqual(opts[0]["id"], "filters")
        self.assertTrue(opts[0]["recommended"])
        self.assertEqual(opts[0]["tier"], "cleaned")
        self.assertEqual(opts[-1]["id"], "separate")
        self.assertFalse(opts[-1]["recommended"])
        tiers = {o["id"]: o["tier"] for o in opts}
        self.assertEqual(tiers["metricgan"], "inferred")
        self.assertEqual(tiers["sepformer-dns4"], "inferred")

    def test_heavy_changing_noise_reaches_for_the_strongest_model(self):
        opts = RS.options(m(snr_db=5.0, noise_db=-23.0,
                            noise_steadiness_db=6.0))
        self.assertEqual(opts[0]["id"], "sepformer-dns4")
        self.assertTrue(opts[0]["recommended"])

    def test_shared_fixes_lead_every_option_and_a_baseline_is_offered(self):
        a = m(snr_db=15.0, noise_db=-33.0, rumble_db=0.0,
              hum={"hz": 50, "prominence_db": 18.0, "harmonics": 4,
                   "per_harmonic": []})
        opts = {o["id"]: o for o in RS.options(a)}
        self.assertIn("fixes-only", opts)
        for o in opts.values():
            kinds = [s["kind"] for s in o["steps"]]
            self.assertEqual(kinds[:2], ["highpass", "notch"], o["id"])
        notch = opts["filters"]["steps"][1]
        self.assertEqual(notch["filters"][0],
                         "bandreject=f=50:width_type=q:w=30")
        self.assertTrue(all("f=" in f for f in notch["filters"]))
        self.assertLessEqual(len(notch["filters"]), 20)

    def test_declipping_makes_even_the_filter_recipe_inferred(self):
        opts = {o["id"]: o for o in RS.options(
            m(snr_db=15.0, noise_db=-33.0, clipped_fraction=0.01,
              clipped_runs=9))}
        self.assertEqual(opts["filters"]["tier"], "inferred")
        self.assertEqual(opts["fixes-only"]["tier"], "inferred")

    def test_level_is_raised_without_pushing_peaks_over(self):
        self.assertEqual(RS._gain_db(m(speech_db=-40.0, peak_dbfs=-20.0)),
                         19.0)
        self.assertEqual(RS._gain_db(m(speech_db=-40.0, peak_dbfs=-30.0)),
                         20.0)
        quiet = RS.options(m(snr_db=15.0, noise_db=-55.0, speech_db=-40.0,
                             peak_dbfs=-25.0))
        self.assertEqual(quiet[0]["steps"][-1]["kind"], "gain")

    def test_energy_a_model_adds_counts_against_it(self):
        a = {"snr_db": 20.0}
        clean = {"option": "metricgan", "measured": {
            "removed": {"during_pauses_db": -1.0, "during_speech_db": -20.0},
            "added": {"speech_db": -40.0, "pauses_db": -40.0}}}
        maker = {"option": "sepformer-dns4", "measured": {
            "removed": {"during_pauses_db": -1.0, "during_speech_db": -20.0},
            "added": {"speech_db": -3.0, "pauses_db": -6.0}}}
        self.assertGreater(RS.measured_score(clean, a),
                           RS.measured_score(maker, a))

    def test_measured_best_rewards_taking_noise_not_speech(self):
        a = {"snr_db": 20.0}
        gentle = {"option": "filters", "measured": {"removed": {
            "during_pauses_db": -3.0, "during_speech_db": -20.0}}}
        greedy = {"option": "sepformer-dns4", "measured": {"removed": {
            "during_pauses_db": -0.5, "during_speech_db": -2.0}}}
        sep = {"option": "separate", "measured": {"removed": {
            "during_pauses_db": 0.0, "during_speech_db": -30.0}}}
        self.assertGreater(RS.measured_score(gentle, a),
                           RS.measured_score(greedy, a))
        self.assertEqual(RS.measured_best([gentle, greedy, sep], a),
                         "filters")
        self.assertAlmostEqual(RS.share(-3.0), 0.501, places=3)
        self.assertIsNone(RS.share(None))


class _Fixture(TempDirCase):
    def setUp(self):
        super().setUp()
        _cli, self.ffmpeg = M.install_fakes(self.tmp / "bin")
        self.worker = M.install_restore_worker(
            self.tmp / "bin", m(snr_db=13.0, noise_db=-31.0, rate=44100,
                                bandwidth_hz=22050.0))
        self.models = M.fake_restore_models(self.tmp / "models" / "speechbrain")
        self.scratch = self.tmp / "atk-data" / "tmp" / "speechbrain"
        self.evidence = self.tmp / "evidence"
        self.clip = M.write_wav(self.evidence / "calls" / "radio.wav",
                                M.tone(1.0, 400.0, 0.3, rate=16000, start=0.5,
                                       total=2.0), rate=16000)
        self.case = Case.create(self.tmp / "case", case_id="RESTORE-1",
                                examiner=EXAMINER)
        self.item = self.case.add_folder(self.evidence, label="radio")

    def kw(self, **extra):
        kw = {"ffmpeg": self.ffmpeg, "worker": self.worker,
              "scratch": self.scratch}
        kw.update(extra)
        return kw

    def run_kw(self, **extra):
        return self.kw(models_root=self.models, **extra)

    def actions(self):
        return [r["action"] for r in self.case.custody.rows()
                if r["action"].startswith("media.restore")]


class Analysing(_Fixture):
    def test_the_analysis_lives_in_the_case_with_its_recipe(self):
        lines = []
        report = RS.analyse(self.case, self.clip, progress=lines.append,
                            **self.kw())
        folder = Path(report["folder"])
        self.assertTrue(blocker.is_inside(folder, self.case.root))
        for name in ("analysis.json", "recipe.json", "analysis.wav",
                     "source/radio.wav", "analyse.log"):
            self.assertTrue((folder / name).is_file(), name)
        self.assertEqual(report["original"]["evidence_id"], self.item.id)
        self.assertEqual(report["best"], "filters")
        self.assertEqual([i["id"] for i in report["issues"]], ["noise"])
        R.load_recipe(folder)
        self.assertEqual(self.actions(), ["media.restore.started",
                                          "media.restore.analysed"])
        self.assertTrue(any("Found:" in l for l in lines))
        self.assertEqual(RS.list_runs(self.case)[0]["best"], "filters")


class Running(_Fixture):
    def test_the_best_option_runs_with_its_residual_and_sidecars(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        done = RS.run(self.case, report["run_id"], "best", **self.run_kw())
        (result,) = done["results"]
        self.assertEqual((result["option"], result["tier"], result["error"]),
                         ("filters", "cleaned", ""))
        out = Path(result["outputs"][0]["path"])
        res = Path(result["residual"]["path"])
        self.assertEqual(out.name, "output.wav")
        self.assertTrue(out.is_file() and res.is_file())
        for path in (out, res):
            side = json.loads(R.sidecar_path(path).read_text("utf-8"))
            self.assertEqual(side["tier"], "cleaned")
            self.assertEqual(side["recipe_id"], report["run_id"])
            self.assertEqual(R.upstream_of(path)[1], "cleaned")
        recipe = R.load_recipe(Path(done["folder"]))
        self.assertEqual(recipe["tier"], "cleaned")
        tools = [recipe["steps"][i]["tool"]
                 for i in recipe["outputs"][0]["chain"]]
        self.assertEqual(tools[0], RS.DOOR_TOOL)
        self.assertIn("removed", result["measured"])
        self.assertEqual(result["measured"]["lags"], [0])
        align = [recipe["steps"][i] for i in recipe["outputs"][0]["chain"]
                 if recipe["steps"][i]["tool"] == RS.ALIGN_TOOL]
        self.assertEqual(len(align), 1)
        self.assertEqual(align[0]["params"]["lag_samples"], 0)
        self.assertEqual(done["measured_best"], "filters")
        self.assertEqual(self.actions()[-1], "media.restore.derived")
        self.assertTrue(self.case.custody.verify().ok)

    def test_run_all_gives_every_option_to_listen_to(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        done = RS.run(self.case, report["run_id"], "all", **self.run_kw())
        got = {r["option"]: r for r in done["results"]}
        self.assertEqual(set(got), {o["id"] for o in report["options"]})
        self.assertTrue(all(not r["error"] for r in got.values()))
        self.assertEqual([o["stem"] for o in got["separate"]["outputs"]],
                         ["voice1", "voice2"])
        self.assertEqual(got["metricgan"]["tier"], "inferred")
        self.assertNotEqual(done["measured_best"], "separate")
        # the model steps are named in the recipe, never below Inferred
        recipe = R.load_recipe(Path(done["folder"]))
        model_steps = [s for s in recipe["steps"]
                       if s["tool"].startswith("speechbrain")]
        self.assertEqual(len(model_steps), 3)
        self.assertTrue(all(s["tier"] == "inferred" for s in model_steps))

    def test_a_run_option_is_kept_and_force_runs_it_again(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        RS.run(self.case, report["run_id"], ["filters"], **self.run_kw())
        lines = []
        again = RS.run(self.case, report["run_id"], ["filters"],
                       progress=lines.append, **self.run_kw())
        self.assertTrue(any("already run" in l for l in lines))
        self.assertEqual(len(again["results"]), 1)
        forced = RS.run(self.case, report["run_id"], ["filters"], force=True,
                        **self.run_kw())
        self.assertNotEqual(forced["results"][0]["outputs"][0]["file"],
                            again["results"][0]["outputs"][0]["file"])

    def test_a_failing_option_is_recorded_and_the_others_still_run(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        crashing = self.tmp / "models" / "CRASH"
        M.fake_restore_models(crashing)
        done = RS.run(self.case, report["run_id"], ["filters", "metricgan"],
                      **self.kw(models_root=crashing))
        got = {r["option"]: r for r in done["results"]}
        self.assertEqual(got["filters"]["error"], "")
        self.assertIn("out of memory", got["metricgan"]["error"])
        self.assertIn("media.restore.failed", self.actions())

    def test_refusals(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        with self.assertRaisesRegex(MediaError, "not all installed"):
            RS.run(self.case, report["run_id"], ["metricgan"],
                   ffmpeg=self.ffmpeg, python=sys.executable,
                   scratch=self.scratch, models_root=self.tmp / "nomodels")
        with self.assertRaisesRegex(MediaError, "not one of"):
            RS.run(self.case, report["run_id"], ["nope"], **self.run_kw())
        clean_worker = M.install_restore_worker(self.tmp / "bin", m())
        clean = RS.analyse(self.case, self.clip,
                           **self.kw(worker=clean_worker))
        with self.assertRaisesRegex(MediaError, "Nothing the analysis"):
            RS.run(self.case, clean["run_id"], "best",
                   **self.run_kw(worker=clean_worker))
        self.assertEqual(RS.models_missing(self.tmp / "nomodels").keys(),
                         RS.MODELS.keys())

    def test_an_invented_input_stays_invented_and_says_so_in_its_name(self):
        stem = M.write_wav(self.evidence / "seed1.target.invented.wav",
                           M.tone(1.0, 300.0, 0.3, rate=16000, total=2.0),
                           rate=16000)
        report = RS.analyse(self.case, stem, **self.kw())
        done = RS.run(self.case, report["run_id"], "best", **self.run_kw())
        (result,) = done["results"]
        self.assertEqual(result["tier"], "invented")
        self.assertTrue(result["outputs"][0]["file"].endswith(
            ".invented.wav"))
        with self.assertRaisesRegex(MediaError, "INVENTED"):
            V.compare(self.case, result["outputs"][0]["path"],
                      model_dir=M.fake_voice_model(self.tmp / "vm"),
                      ffmpeg=self.ffmpeg,
                      worker=M.install_vp_worker(self.tmp / "bin"),
                      scratch=self.scratch)

    def test_a_renamed_restored_file_is_still_known_by_its_hash(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        done = RS.run(self.case, report["run_id"], ["metricgan"],
                      **self.run_kw())
        out = Path(done["results"][0]["outputs"][0]["path"])
        loose = self.tmp / "somewhere" / "renamed.wav"
        loose.parent.mkdir()
        loose.write_bytes(out.read_bytes())
        rid, tier, basis = L.upstream_of_input(self.case, loose)
        self.assertEqual((rid, tier, basis),
                         (report["run_id"], "inferred", "hash"))


class Exporting(_Fixture):
    def test_export_copies_into_the_case_with_custody(self):
        report = RS.analyse(self.case, self.clip, **self.kw())
        done = RS.run(self.case, report["run_id"], "best", **self.run_kw())
        out = done["results"][0]["outputs"][0]
        first = RS.export(self.case, report["run_id"], out["file"])
        dest = Path(first["path"])
        self.assertTrue(blocker.is_inside(dest, self.case.root))
        self.assertEqual(dest.parent.name, report["run_id"])
        self.assertTrue(R.sidecar_path(dest).is_file())
        self.assertEqual(first["sha256"], out["sha256"])
        self.assertEqual(self.actions()[-1], "media.restore.exported")
        again = RS.export(self.case, report["run_id"], out["file"])
        self.assertTrue(again["already"])
        for bad in ("../recipe.json", "analysis.wav", "/etc/passwd"):
            with self.assertRaises(MediaError, msg=bad):
                RS.export(self.case, report["run_id"], bad)


# ------------------------------------------------------- faint sounds (§13.8)
FAINT = {
    "events": [
        {"n": 1, "start_s": 0.6, "end_s": 1.1, "peak_s": 0.8, "f_lo": 600.0,
         "f_hi": 900.0, "z": 9.1, "band_snr_db": -2.0,
         "broadband_snr_db": -18.0, "faint": True, "confidence": "detected"},
        {"n": 2, "start_s": 1.4, "end_s": 1.7, "peak_s": 1.5, "f_lo": 2000.0,
         "f_hi": 2600.0, "z": 6.4, "band_snr_db": -4.0,
         "broadband_snr_db": -24.0, "faint": True, "confidence": "possible"},
        {"n": 3, "start_s": 0.5, "end_s": 1.5, "peak_s": 1.0, "f_lo": 300.0,
         "f_hi": 500.0, "z": 30.0, "band_snr_db": 12.0,
         "broadband_snr_db": 4.0, "faint": False, "confidence": "detected"}],
    "lines": [{"hz": 3141.5, "prominence_db": 6.0, "z": 30.0, "series": "",
               "mains": False},
              {"hz": 60.0, "prominence_db": 9.0, "z": 50.0, "series": "",
               "mains": True}],
    "clips": [{"n": 1, "file": "", "gain_db": 31.0, "start_s": 0.1,
               "end_s": 1.6, "f_lo": 600.0, "f_hi": 900.0, "z": 9.1},
              {"n": 2, "file": "", "gain_db": 36.0, "start_s": 0.9,
               "end_s": 2.0, "f_lo": 2000.0, "f_hi": 2600.0, "z": 6.4}],
    "map": {"width": 1, "height": 1},
    "thresholds": {"possible": 6.0, "detected": 7.5}}
REPEATS = {"found": True, "period_s": 0.25, "count": 8, "strength": 0.6,
           "prominence": 20.0, "waveform": True, "waveform_r": 0.4,
           "used": 8, "expected_gain_db": 9.0}
CHANNELS = {"count": 2, "kind": "coherent", "reference": 0,
            "pairs": [{"channel": 1, "lag_samples": 12, "lag_ms": 0.75,
                       "r": 0.5, "significance": 40.0}],
            "used": True, "combination": {"gain_db": 2.8},
            "why": "combining measured +2.8 dB"}


class FaintFindings(unittest.TestCase):
    """What the faint-sound measurements turn into (§13.8): findings that
    quote their numbers, options with honest tiers, the main content still
    first when there is a main problem."""

    def test_each_finding_quotes_its_measurement(self):
        a = m(faint=FAINT, repeats=REPEATS, channels=CHANNELS)
        found = {i["id"]: i for i in RS.issues(a)}
        self.assertEqual(found["faint"]["severity"], "medium")
        self.assertIn("2 found (1 certain)", found["faint"]["measured"])
        self.assertIn("600–900 Hz, 18 dB under the noise",
                      found["faint"]["measured"])
        self.assertIn("3142 Hz", found["lines"]["measured"])
        self.assertNotIn("60 Hz", found["lines"]["measured"], "mains is hum's")
        self.assertIn("every 0.250 s, 8 times", found["repeats"]["measured"])
        self.assertIn("+2.8 dB", found["channels"]["measured"])
        self.assertIn("channel 2 +0.8 ms", found["channels"]["measured"])
        self.assertEqual(found["channels"]["severity"], "info")

    def test_only_possible_events_are_a_low_finding(self):
        possible = json.loads(json.dumps(FAINT))
        possible["events"] = [possible["events"][1]]
        possible["lines"] = []
        self.assertEqual({i["id"]: i["severity"] for i in RS.issues(
            m(faint=possible))}, {"faint": "low"})
        self.assertEqual(RS.issues(m(faint={"events": [FAINT["events"][2]]})),
                         [], "a loud event is not a faint one")

    def test_the_channel_kinds_say_what_to_do(self):
        for kind, needle, sev in (("unrelated", "different sound", "medium"),
                                  ("copies", "identical", "info"),
                                  ("faint", "not used", "info")):
            ch = dict(CHANNELS, kind=kind, used=False, why="measured only "
                      "+0.2 dB")
            (issue,) = RS.issues(m(channels=ch))
            self.assertIn(needle, issue["label"])
            self.assertEqual(issue["severity"], sev)

    def test_faint_options_are_offered_with_their_tiers(self):
        a = m(faint=FAINT, repeats=REPEATS)
        opts = {o["id"]: o for o in RS.options(a)}
        self.assertEqual(opts["faint-band"]["tier"], "measured")
        self.assertEqual(opts["faint-mask"]["tier"], "cleaned")
        self.assertEqual(opts["average-repeats"]["tier"], "recovered")
        self.assertEqual(opts["repeating-apart"]["tier"], "cleaned")
        band = opts["faint-band"]["steps"][0]
        self.assertEqual(band["filters"][0], "highpass=f=480:poles=2")
        self.assertEqual(band["filters"][-1], "lowpass=f=1125:poles=2")
        self.assertEqual(opts["faint-band"]["steps"][-1]["filters"], [RS.LIFT])
        mask = opts["faint-mask"]["steps"][0]
        self.assertEqual((mask["kind"], mask["tool"]),
                         ("dsp:mask", RS.DSP_TOOLS["mask"]))
        # nothing else is wrong: the faint sounds are the work, and the
        # repeats' averaging (Recovered) leads
        ids = [o["id"] for o in RS.options(a)]
        self.assertEqual(ids[0], "average-repeats")
        self.assertTrue(RS.options(a)[0]["recommended"])
        self.assertEqual(ids[-1], "separate")

    def test_a_main_problem_keeps_the_main_options_first(self):
        a = m(snr_db=8.0, noise_db=-30.0, faint=FAINT, repeats=REPEATS)
        opts = RS.options(a)
        self.assertEqual(opts[0]["id"], "sepformer-dns4")
        faint_at = [i for i, o in enumerate(opts) if o["purpose"] == "faint"]
        main_at = [i for i, o in enumerate(opts) if o["purpose"] == "main"
                   and o["id"] != "separate"]
        self.assertLess(max(main_at), min(faint_at))

    def test_combined_channels_raise_every_option_to_recovered(self):
        a = m(snr_db=15.0, noise_db=-33.0, channels=CHANNELS)
        opts = {o["id"]: o for o in RS.options(a)}
        self.assertEqual(opts["combine"]["tier"], "recovered")
        self.assertEqual(opts["combine"]["reference"], "best_channel")
        self.assertEqual(opts["fixes-only"]["tier"] if "fixes-only" in opts
                         else "recovered", "recovered")
        self.assertEqual(opts["filters"]["tier"], "cleaned")

    def test_measured_best_never_ranks_the_faint_or_combining_outputs(self):
        def r(option, pauses):
            return {"option": option, "measured": {
                "removed": {"during_pauses_db": pauses,
                            "during_speech_db": -30.0},
                "added": {"speech_db": -60.0, "pauses_db": -60.0}}}
        results = [r("filters", -6.0), r("faint-mask", -0.1),
                   r("combine", -0.2), r("average-repeats", -0.1)]
        self.assertEqual(RS.measured_best(results, m()), "filters")


class FaintRuns(_Fixture):
    """The faint-sound paths through the fake worker and the fake FFmpeg:
    every channel kept, the combination as the working copy, the map and
    the clips recorded with their tiers, each option's own step."""

    def setUp(self):
        super().setUp()
        self.worker = M.install_restore_worker(
            self.tmp / "bin", m(rate=16000, faint=FAINT, repeats=REPEATS,
                                channels=CHANNELS))
        left = M.tone(1.0, 400.0, 0.3, rate=16000, start=0.5, total=2.0)
        frames = [v for pair in zip(left, [0.8 * x for x in left])
                  for v in pair]
        self.stereo = M.write_wav(self.evidence / "calls" / "two-mics.wav",
                                  frames, rate=16000, channels=2)

    def test_two_channels_combined_are_the_working_copy(self):
        report = RS.analyse(self.case, self.stereo, **self.kw())
        folder = Path(report["folder"])
        self.assertEqual(report["channels"], 2)
        self.assertEqual(report["working"], "combined.wav")
        for name in ("probe.wav", "channels.wav", "combined.wav",
                     "bestch.wav", "analysis.wav", "salience.png"):
            self.assertTrue((folder / name).is_file(), name)
        recipe = R.load_recipe(folder)
        steps = [recipe["steps"][i] for i in report["working_chain"]]
        self.assertEqual([s["tool"] for s in steps],
                         [RS.DOOR_TOOL, "ffmpeg", RS.COMBINE_TOOL])
        self.assertEqual(steps[-1]["tier"], "recovered")
        self.assertEqual(steps[1]["params"]["args"][3], "2", "-ac 2: kept")
        self.assertIn("combine", {o["id"] for o in report["options"]})

    def test_the_map_and_the_clips_are_recorded_with_sidecars(self):
        report = RS.analyse(self.case, self.stereo, **self.kw())
        folder = Path(report["folder"])
        fa = report["analysis"]["faint"]
        self.assertEqual([c["file"] for c in fa["clips"]],
                         ["faint/faint01.wav", "faint/faint02.wav"])
        recipe = R.load_recipe(folder)
        for clip in fa["clips"]:
            path = Path(clip["path"])
            self.assertTrue(path.is_file())
            self.assertEqual(clip["tier"], "cleaned")
            self.assertEqual(R.upstream_of(path)[1], "cleaned")
            out = next(o for o in recipe["outputs"] if o["file"] == clip["file"])
            tools = [recipe["steps"][i]["tool"] for i in out["chain"]]
            self.assertEqual(tools[-1], RS.DSP_TOOLS["mask"])
            self.assertIn(RS.COMBINE_TOOL, tools)
        self.assertTrue(Path(fa["map"]["path"]).is_file())
        analysed = self.case.custody.last("media.restore.analysed")
        for name in ("salience.png", "faint/faint01.wav", "combined.wav"):
            self.assertIn(name, analysed["hashes"])
        # a clip copied out and renamed is still known by its bytes
        loose = self.tmp / "elsewhere" / "listen.wav"
        loose.parent.mkdir()
        loose.write_bytes(Path(fa["clips"][0]["path"]).read_bytes())
        self.assertEqual(L.upstream_of_input(self.case, loose)[1:],
                         ("cleaned", "hash"))
        # clips and the map export like any output
        got = RS.export(self.case, report["run_id"], "faint/faint01.wav")
        self.assertTrue(R.sidecar_path(Path(got["path"])).is_file())
        self.assertTrue(Path(RS.export(self.case, report["run_id"],
                                       "salience.png")["path"]).is_file())

    def test_each_faint_option_runs_its_own_step(self):
        report = RS.analyse(self.case, self.stereo, **self.kw())
        done = RS.run(self.case, report["run_id"],
                      ["faint-mask", "faint-band", "average-repeats",
                       "repeating-apart", "combine"], **self.run_kw())
        got = {r["option"]: r for r in done["results"]}
        self.assertTrue(all(not r["error"] for r in got.values()),
                        {k: r["error"] for k, r in got.items()})
        self.assertEqual({k: r["tier"] for k, r in got.items()},
                         {"faint-mask": "cleaned", "faint-band": "recovered",
                          "average-repeats": "recovered",
                          "repeating-apart": "cleaned",
                          "combine": "recovered"})
        recipe = R.load_recipe(Path(done["folder"]))
        tools = {s["tool"] for s in recipe["steps"]}
        for kind in ("mask", "average", "repet"):
            self.assertIn(RS.DSP_TOOLS[kind], tools)
        lifted = [s for s in recipe["steps"] if s["tool"] == "ffmpeg"
                  and s["params"].get("filters") == [RS.LIFT]]
        self.assertEqual(len(lifted), 2, "the two faint options are lifted")
        # combining alone is measured against the best channel
        res = got["combine"]["residual"]["file"]
        out = next(o for o in recipe["outputs"] if o["file"] == res)
        self.assertIn("bestch.wav", {k for i in out["chain"]
                                     for k in recipe["steps"][i]["inputs"]})
        self.assertNotIn(done["measured_best"], ("combine",) + RS.FAINT_OPTIONS)

    def test_a_mono_recording_works_from_its_mono_copy(self):
        self.worker = M.install_restore_worker(
            self.tmp / "bin", m(rate=16000, faint=FAINT))
        report = RS.analyse(self.case, self.clip, **self.kw())
        folder = Path(report["folder"])
        self.assertEqual((report["channels"], report["working"]),
                         (1, "analysis.wav"))
        self.assertFalse((folder / "channels.wav").exists())
        recipe = R.load_recipe(folder)
        self.assertEqual([recipe["steps"][i]["tool"]
                          for i in report["working_chain"]],
                         [RS.DOOR_TOOL, "ffmpeg"])
        self.assertEqual(recipe["steps"][report["working_chain"][1]]
                         ["outputs"], {"analysis.wav": recipe["steps"][
                             report["working_chain"][1]]["outputs"]
                             ["analysis.wav"]})

    def test_the_faint_search_can_be_left_out(self):
        report = RS.analyse(self.case, self.clip, faint=False, **self.kw())
        self.assertNotIn("faint", report["analysis"])
        self.assertNotIn("repeats", report["analysis"])
        self.assertFalse((Path(report["folder"]) / "salience.png").exists())


class WritersAndCommandLine(_Fixture):
    def test_the_worker_writer_is_listed_and_the_package_is_clean(self):
        self.assertEqual(blocker.WRITERS.get(
            "media.restore_worker:_write_bytes"), "worker-output")
        report = ratchet.scan_package(Path(RS.__file__).parents[1],
                                      blocker.WRITERS)
        self.assertEqual(report.violations, [])
        self.assertIn("media.restore", report.files)
        self.assertIn("media.restore_worker", report.files)
        for key, spec in RS.MODELS.items():
            self.assertEqual(R.tool_floor(spec["tool"]), "inferred", key)

    def _cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_analyse_run_list_and_export_from_the_command_line(self):
        orig_runtime, orig_worker = RS._sam.runtime_argv, RS._worker_argv
        ff, wk = list(self.ffmpeg), list(self.worker)
        RS._sam.runtime_argv = lambda a: ff if a == "FF" else orig_runtime(a)
        RS._worker_argv = lambda p, w: wk if p == "PY" else orig_worker(p, w)
        common = ["--ffmpeg", "FF", "--python", "PY", "--scratch",
                  str(self.scratch)]
        try:
            code, out, err = self._cli("restore-analyse", str(self.case.root),
                                       str(self.clip), "--examiner", EXAMINER,
                                       *common)
            self.assertEqual(code, 0, err)
            run_id = json.loads(out)["run_id"]
            self.assertIn("* filters", err)
            code, out, err = self._cli(
                "restore-run", str(self.case.root), run_id, "--examiner",
                EXAMINER, "--option", "filters", "--option", "fixes-only"
                if False else "metricgan", "--models-root", str(self.models),
                *common)
            self.assertEqual(code, 0, err)
            files = [o["file"] for r in json.loads(out)["results"]
                     for o in r["outputs"]]
            self.assertEqual(len(files), 2)
            code, out, _ = self._cli("restore-list", str(self.case.root),
                                     "--examiner", EXAMINER)
            self.assertIn(run_id, out)
            code, out, err = self._cli("restore-export", str(self.case.root),
                                       run_id, files[0], "--examiner",
                                       EXAMINER)
            self.assertEqual(code, 0, err)
            self.assertTrue(os.path.isfile(json.loads(out)["path"]))
        finally:
            RS._sam.runtime_argv, RS._worker_argv = orig_runtime, orig_worker


if __name__ == "__main__":
    unittest.main()
