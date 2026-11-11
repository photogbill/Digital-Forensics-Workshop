"""HARK (FORENSICS_PLAN §15, HARK_PLAN.md) — the pitch-track hunter, the
file's own CEP and the audit.

Two halves. The ENGINE through a fake worker by the real subprocess path:
everything in the case, three stages each saved before the next, resume
that keeps finished stages, the map's step in the run's recipe as
Measured, custody, the audit's targets taken from the run's restorations,
and the sentences the examiner reads. Then the SCIENCE with the real
worker, when torch is installed: a voice-like sound well under the noise
is found and noise alone — white, level-swinging — gives nothing; the
surrogate null is faithful to the file's own noise; the audit catches a
chain that removed voice and one that made it; ESTOI agrees with the
reference implementation.
"""

from __future__ import annotations

import importlib.util
import json
import math
import os
import struct
import unittest
from pathlib import Path

from _support import EXAMINER, PACKAGE, TempDirCase

import mediasynth as M
from forensics_workshop.case import Case
from forensics_workshop.errors import MediaError
from forensics_workshop.media import hark as H
from forensics_workshop.media import recipe as R
from forensics_workshop.media import restore as RS

HAS_TORCH = importlib.util.find_spec("torch") is not None
HAS_PYSTOI = importlib.util.find_spec("pystoi") is not None
#: how much of a machine the census leaves (dB against the machine), measured
#: on the engine in test_a_machine_is_cancelled_along_its_own_track
MACHINE_LEFT_DB = -8.0     # measured -11.3 dB

PLAN = M.HARK_PLAN
SEG = M.HARK_SEG
install_hark_worker = M.install_hark_worker
calls = M.hark_calls


class _Fixture(TempDirCase):
    def setUp(self):
        super().setUp()
        self.bin = self.tmp / "bin"
        self.ffmpeg = M.install_ffmpeg(self.bin)
        self.rworker = M.install_restore_worker(self.bin)
        self.hworker = install_hark_worker(self.bin)
        self.models = M.fake_restore_models(self.tmp / "models")
        self.dfn = M.install_deepfilter(self.bin)
        self.rnnoise = M.fake_rnnoise_model(self.tmp / "rn")
        self.sbin = self.tmp / "sbin"
        self.sworker = M.install_selftrain_worker(self.sbin)
        self.gtcrn = M.fake_gtcrn_weights(self.tmp / "gtcrn")
        self.scratch = self.tmp / "atk-data" / "tmp" / "speechbrain"
        self.evidence = self.tmp / "evidence"
        self.clip = M.write_wav(self.evidence / "radio.wav",
                                M.tone(1.0, 400.0, 0.3, rate=16000, start=0.5,
                                       total=3.0), rate=16000)
        self.case = Case.create(self.tmp / "case", case_id="HARK-1",
                                examiner=EXAMINER)
        self.case.add_folder(self.evidence, label="radio")
        self.report = RS.analyse(self.case, self.clip, ffmpeg=self.ffmpeg,
                                 worker=self.rworker, scratch=self.scratch,
                                 faint=False)
        self.run_id = self.report["run_id"]

    def hark(self, **kw):
        kw.setdefault("worker", self.hworker)
        kw.setdefault("scratch", self.scratch)
        kw.setdefault("restore_worker", self.rworker)
        kw.setdefault("ffmpeg", self.ffmpeg)
        kw.setdefault("models_root", self.models)
        kw.setdefault("deepfilter", self.dfn)
        kw.setdefault("rnnoise_model", self.rnnoise)
        kw.setdefault("gtcrn_weights", self.gtcrn)
        kw.setdefault("selftrain_worker", self.sworker)
        return H.run(self.case, self.run_id, **kw)

    def long_noise(self):
        """A hunt that leaves 17 s of the recording's noise to learn from."""
        plan = json.loads(json.dumps(PLAN))
        plan["hunt"]["duration_s"] = 20.0
        install_hark_worker(self.bin, plan)
        return plan

    def phrases(self):
        refs = self.tmp / "LibriSpeech" / "test-clean"
        for spk in ("1089", "121"):
            for k in range(3):
                M.write_wav(refs / spk / "134686" / f"{spk}-{k}.wav",
                            M.tone(1.0, 200.0 + 30 * k, 0.3, rate=16000),
                            rate=16000)
        return refs

    def run_all(self):
        RS.run(self.case, self.run_id, "all", ffmpeg=self.ffmpeg,
               worker=self.rworker, scratch=self.scratch,
               models_root=self.models, deepfilter=self.dfn,
               rnnoise_model=self.rnnoise)

    def actions(self, prefix="media.hark"):
        return [r["action"] for r in self.case.custody.rows()
                if r["action"].startswith(prefix)]


class Engine(_Fixture):
    def test_every_stage_in_the_case_with_custody_and_a_measured_map(self):
        lines = []
        res = self.hark(progress=lines.append)
        folder = Path(res["folder"])
        self.assertTrue(str(folder).startswith(str(self.case.root)))
        self.assertEqual(folder.parent.name, H.HARK_DIR)
        for name in ("hark.json", "hark.png", "hunt.request.json",
                     "hunt.response.json", "calibrate.response.json",
                     "extract.response.json"):
            self.assertTrue((folder / name).is_file(), name)
        self.assertEqual(sorted(res["stages"]), sorted(H.STAGES))
        # no clean speech: nothing to hide in the noise, nothing scored
        self.assertTrue(res["stages"]["score"]["skipped"])
        # Move 2's own outputs are a restoration of the run, so audited
        # the speaker loop (one round: a hunt in the voice's range, two
        # calibrations on the same test voices) found nothing more here
        self.assertEqual(calls(self.bin), ["hunt", "calibrate", "hunt",
                                           "calibrate", "calibrate",
                                           "extract", "census", "audit"])
        self.assertEqual({t["id"] for t in res["audit"]["targets"]},
                         {"hark:voice", "hark:lift"})
        self.assertEqual(self.actions(), ["media.hark.started",
                                          "media.hark.derived",
                                          "media.hark.done"])
        recipe = R.load_recipe(Path(self.report["folder"]))
        step = recipe["steps"][-1]
        self.assertEqual(step["tool"], H.HUNT_TOOL)
        self.assertEqual(step["tier"], "measured")
        self.assertIn(f"hark/{res['hark_id']}/hark.png", step["outputs"])
        self.assertEqual(res["tier"], "measured")
        text = " ".join(res["verdict"])
        self.assertIn("1.4 s DETECTED", text)
        self.assertIn("pitch around 132 Hz", text)
        self.assertIn("nine times in ten down to -2.0 dB", text)
        self.assertIn("ESTOI 0.5", text)
        self.assertIn("Move 2 pulled 1.3 s of DETECTED voice", text)
        self.assertIn("Restorations not scored: no clean speech", text)
        self.assertNotIn("(Move 2)", text.split("Not yet")[-1])
        self.assertTrue(any("DETECTED" in l for l in lines))

    def test_move_2_lands_in_the_results_as_a_cleaned_restoration(self):
        res = self.hark()
        report = RS.load_run(self.case, self.run_id)
        hark = [r for r in report["results"] if r["option"] == H.RESULT_OPTION]
        self.assertEqual(len(hark), 1)
        r = hark[0]
        self.assertEqual(r["tier"], "cleaned")
        self.assertTrue(r["speech_only"])
        self.assertEqual(r["hark_id"], res["hark_id"])
        self.assertEqual([o["stem"] for o in r["outputs"]], ["voice", "lift"])
        sub = f"hark/{res['hark_id']}/extract-{res['hark_id']}/"
        for o in r["outputs"]:
            self.assertTrue(o["file"].startswith(sub), o["file"])
            self.assertTrue(Path(o["path"]).is_file())
            side = R.check_sidecar(json.loads(R.sidecar_path(o["path"])
                                              .read_text("utf-8")),
                                   Path(o["path"]).name)
            self.assertEqual(side["tier"], "cleaned")
            self.assertIn(H.EXTRACT_TOOL, [st["tool"] for st in
                                           side["chain"]])
        self.assertTrue(Path(r["residual"]["path"]).is_file())
        self.assertIsNotNone(r["measured"]["removed"]["during_pauses_db"])
        # the recipe still passes its own checks, Move 2's step Cleaned
        recipe = R.load_recipe(Path(report["folder"]))
        ex = [st for st in recipe["steps"] if st["tool"] == H.EXTRACT_TOOL]
        self.assertEqual(len(ex), 1)
        self.assertEqual(ex[0]["tier"], "cleaned")
        # it exports like any restoration output, with custody
        out = RS.export(self.case, self.run_id, r["outputs"][0]["file"])
        self.assertTrue(Path(out["path"]).is_file())
        self.assertEqual(self.actions("media.restore")[-1],
                         "media.restore.exported")
        # a newer HARK run's extraction replaces it in the table
        again = self.hark()
        report = RS.load_run(self.case, self.run_id)
        hark = [r for r in report["results"] if r["option"] == H.RESULT_OPTION]
        self.assertEqual(len(hark), 1)
        self.assertEqual(hark[0]["hark_id"], again["hark_id"])
        self.assertTrue(Path(r["outputs"][0]["path"]).is_file(),
                        "the earlier run's files stay")

    def test_no_detected_voice_means_nothing_is_extracted(self):
        plan = json.loads(json.dumps(PLAN))
        plan["hunt"]["segments"][0]["status"] = "possible"
        install_hark_worker(self.bin, plan)
        res = self.hark()
        self.assertTrue(res["stages"]["extract"]["skipped"])
        self.assertNotIn("extract", calls(self.bin))
        report = RS.load_run(self.case, self.run_id)
        self.assertEqual([r for r in report["results"]
                          if r["option"] == H.RESULT_OPTION], [])
        self.assertIn("Move 2: no DETECTED voice", " ".join(res["verdict"]))

    def test_restorations_are_scored_on_the_files_own_noise(self):
        res = self.hark(phrases=self.phrases())
        self.assertEqual(calls(self.bin), ["hunt", "calibrate", "hunt",
                                           "calibrate", "calibrate",
                                           "extract", "census", "probe",
                                           "extract", "score", "audit"])
        folder = Path(res["folder"])
        probe = folder / H.PROBE_DIR
        for name in ("probe.wav", "clean.wav", "recipe.json",
                     "hark-lift.wav", "hark-voice.wav"):
            self.assertTrue((probe / name).is_file(), name)
        req = json.loads((folder / "probe-extract.request.json")
                         .read_text("utf-8"))
        self.assertTrue(req["rehunt"])
        st = res["stages"]["score"]
        # Quick: the chains already run — none yet, so the recommended one
        best = self.report["best"]
        self.assertEqual(sorted(st["candidates"]),
                         sorted([best, H.RESULT_OPTION]))
        self.assertEqual(st["failed"], {})
        self.assertTrue(any(p.name.startswith(f"opt-{best}")
                            for p in probe.iterdir()))
        # the chain ran on the probe as Restore Audio runs it — no custody
        # of its own (HARK records the scoring), the run's results untouched
        self.assertEqual(self.actions("media.restore.derived"), [])
        self.assertIn("media.hark.scored", self.actions())
        report = RS.load_run(self.case, self.run_id)
        self.assertEqual([r["option"] for r in report["results"]],
                         [H.RESULT_OPTION])
        ch = res["choice"]
        # judged at the DETECTED voice's corrected level, -6 dB
        self.assertEqual(ch["target_db"], -6.0)
        self.assertAlmostEqual(ch["raw_estoi"], 0.25, places=3)
        self.assertEqual(ch["best"], H.RESULT_OPTION)
        self.assertEqual(ch["rows"][0]["id"], H.RESULT_OPTION)
        self.assertAlmostEqual(ch["rows"][0]["estoi"], 0.332, places=3)
        self.assertIn("Best restoration for this file", ch["sentence"])
        self.assertIn("ESTOI 0.33 against 0.25", ch["sentence"])
        self.assertIn(ch["sentence"], res["verdict"])

    def test_every_chain_is_scored_on_a_longer_budget(self):
        res = self.hark(phrases=self.phrases(), budget_name="thorough")
        st = res["stages"]["score"]
        want = {o["id"] for o in self.report["options"]
                if not RS.is_faint_option(o["id"]) and not o.get("shift")}
        self.assertEqual(set(st["candidates"]) - {H.RESULT_OPTION}, want)
        self.assertEqual(st["failed"], {})
        self.assertEqual({r["id"] for r in res["choice"]["rows"]},
                         want | {H.RESULT_OPTION})

    def test_a_chain_that_cannot_run_here_is_named_not_scored(self):
        res = self.hark(phrases=self.phrases(), budget_name="thorough",
                        models_root=None, deepfilter=None)
        failed = res["stages"]["score"]["failed"]
        model_opts = {o["id"] for o in self.report["options"]
                      if any(s.get("model") for s in o["steps"])}
        self.assertTrue(model_opts)
        for oid in model_opts:
            self.assertIn("SpeechBrain models folder", failed[oid])
        self.assertIn("Not scored:", res["choice"]["sentence"])

    def test_no_chain_beating_unprocessed_is_said_plainly(self):
        plan = json.loads(json.dumps(PLAN))
        plan["scores"]["hark"] = plan["scores"]["unprocessed"]
        plan["default_score"] = plan["scores"]["unprocessed"]
        install_hark_worker(self.bin, plan)
        res = self.hark(phrases=self.phrases())
        self.assertEqual(res["choice"]["best"], "")
        self.assertIn("None of the 2 restoration(s) scored beats leaving",
                      res["choice"]["sentence"])

    def test_move_3_trains_on_the_files_own_noise(self):
        self.long_noise()
        res = self.hark()
        st = res["stages"]["selftrain"]
        self.assertNotIn("skipped", st)
        self.assertEqual(M.selftrain_calls(self.sbin), ["selftrain:finetune"])
        # the noise: everything outside the voice (1.2-2.6 s, 0.3 s either
        # side), dealt into a half to train on and a half for the probe
        self.assertEqual(st["noise_s"], 17.1)
        req = json.loads((Path(res["folder"]) / "selftrain-finetune.request"
                          ".json").read_text("utf-8"))
        self.assertEqual(req["free"], [[2.9, 11.45]])
        self.assertEqual(req["voiced"], [[1.2, 2.6]])
        self.assertTrue(req["wav"].endswith("input16k.wav"))
        report = RS.load_run(self.case, self.run_id)
        r = next(x for x in report["results"]
                 if x["option"] == "hark-selftrained")
        self.assertEqual(r["tier"], "inferred")
        # the published model on this file sits beside it, the yardstick
        base = next(x for x in report["results"]
                    if x["option"] == "hark-gtcrn")
        self.assertEqual(base["tier"], "inferred")
        self.assertIsNone(req["teacher"])
        self.assertTrue(req["outputs"]["base"].endswith("base.raw.wav"))
        self.assertEqual([o["stem"] for o in r["outputs"]], ["output"])
        self.assertTrue(Path(r["residual"]["path"]).is_file())
        recipe = R.load_recipe(Path(report["folder"]))
        step = next(x for x in recipe["steps"]
                    if x["tool"] == H.SELFTRAIN_TOOL)
        self.assertEqual(step["tier"], "inferred")
        self.assertIn("RemixIT", step["params"]["method"])
        self.assertEqual(next(x for x in recipe["steps"]
                              if x["tool"] == H.GTCRN_TOOL)["tier"],
                         "inferred")
        self.assertEqual(step["model"]["repo"], H.GTCRN_REPO)
        self.assertFalse(step["model"]["pinned"])   # the stand-in weights
        self.assertEqual(step["params"]["check_best"], 7.25)
        side = R.check_sidecar(json.loads(R.sidecar_path(
            r["outputs"][0]["path"]).read_text("utf-8")),
            Path(r["outputs"][0]["path"]).name)
        self.assertEqual(side["tier"], "inferred")
        text = " ".join(res["verdict"])
        self.assertIn("Move 3 trained GTCRN on this recording's own noise",
                      text)
        self.assertIn("fell from 9.5 to 7.25", text)
        self.assertIn("GTCRN as published is beside it", text)
        self.assertNotIn("Move 3", text.split("Not yet")[-1])
        # its output is audited like every restoration
        self.assertIn("hark-selftrained", {t["id"] for t in
                                           res["audit"]["targets"]})

    def test_the_trained_denoiser_is_scored_on_noise_it_never_saw(self):
        self.long_noise()
        res = self.hark(phrases=self.phrases())
        self.assertEqual(M.selftrain_calls(self.sbin),
                         ["selftrain:finetune", "apply:scratch",
                          "apply:scratch"])
        folder = Path(res["folder"])
        probe = json.loads((folder / "probe.request.json").read_text("utf-8"))
        self.assertEqual(probe["free"], [[11.45, 20.0]])
        st = res["stages"]["score"]
        self.assertIn("hark-selftrained", st["candidates"])
        self.assertEqual(st["candidates"]["hark-selftrained"]["tier"],
                         "inferred")
        self.assertIn("hark-selftrained", {r["id"] for r in
                                           res["choice"]["rows"]})
        self.assertIn("hark-gtcrn", st["candidates"])
        req = json.loads((folder / "probe-base.request.json")
                         .read_text("utf-8"))
        self.assertEqual(req["model"], os.fspath(self.gtcrn))

    def test_a_long_budget_also_trains_one_from_nothing(self):
        self.long_noise()
        res = self.hark(budget_name="overnight")
        self.assertEqual(M.selftrain_calls(self.sbin),
                         ["selftrain:finetune", "selftrain:scratch"])
        report = RS.load_run(self.case, self.run_id)
        opts = {r["option"] for r in report["results"]}
        self.assertTrue({"hark-selftrained", "hark-fileonly",
                         "hark-gtcrn"} <= opts)
        reqs = [json.loads((Path(res["folder"]) / f"selftrain-{m}.request"
                            ".json").read_text("utf-8"))
                for m in ("finetune", "scratch")]
        # the budget's time is shared, the one from nothing runs longer
        self.assertEqual(reqs[0]["params"]["minutes"],
                         H.BUDGETS["overnight"]["selftrain_minutes"] / 2)
        self.assertEqual(reqs[1]["params"]["max_steps"],
                         3 * H.BUDGETS["overnight"]["selftrain_steps"])
        self.assertIsNone(reqs[1]["weights"])
        # what it learns speech from: Move 2's LIFT, at 16 kHz
        self.assertTrue(reqs[1]["teacher"].endswith("teacher16k.wav"))
        recipe = R.load_recipe(Path(report["folder"]))
        step = [x for x in recipe["steps"] if x["tool"] == H.SELFTRAIN_TOOL
                and x["params"]["mode"] == "scratch"][0]
        self.assertEqual(step["params"]["teacher"],
                         "Move 2's LIFT on this file")
        self.assertTrue(any(k.endswith("lift.wav") for k in step["inputs"]))

    def test_without_weights_or_noise_move_3_says_why(self):
        self.long_noise()
        res = self.hark(gtcrn_weights=None)
        self.assertTrue(res["stages"]["selftrain"]["skipped"])
        self.assertIn("weights are not installed",
                      res["stages"]["selftrain"]["note"])
        self.assertEqual(M.selftrain_calls(self.sbin), [])
        # Overnight trains one from nothing even so
        res = self.hark(gtcrn_weights=None, budget_name="overnight")
        self.assertEqual(M.selftrain_calls(self.sbin), ["selftrain:scratch"])
        # the default hunt leaves under a second of noise
        install_hark_worker(self.bin)
        res = self.hark()
        self.assertIn("free of voice to learn its noise from",
                      res["stages"]["selftrain"]["note"])
        self.assertIn("Move 3 (a denoiser trained on this file): only",
                      " ".join(res["verdict"]))

    def test_a_failed_training_costs_move_3_only(self):
        self.long_noise()
        M.install_selftrain_worker(self.sbin, fail=("selftrain",))
        res = self.hark()
        st = res["stages"]["selftrain"]
        self.assertIn("planted failure", st["failed"]["finetune"])
        self.assertEqual(st["models"], {})
        self.assertIn("audit", res["stages"])
        self.assertTrue(H.selftrain_sentence(st).startswith(
            "Move 3 could not train: HARK — denoiser trained on this file"))

    def test_the_noise_is_what_holds_no_voice(self):
        hunt = {"duration_s": 30.0, "segments": [
            {"start_s": 2.0, "end_s": 4.0, "status": "detected",
             "f0_hz": [120.0 + i for i in range(200)]},
            {"start_s": 4.5, "end_s": 5.0, "status": "possible",
             "f0_hz": [200.0] * 50},
            # a steady 12 s track: an engine, part of the noise
            {"start_s": 10.0, "end_s": 22.0, "status": "detected",
             "f0_hz": [93.0 + (i % 3) * 0.5 for i in range(1200)]},
            {"start_s": 25.0, "end_s": 25.2, "status": "below",
             "f0_hz": [150.0] * 20}]}
        self.assertEqual(H.machine_flags(hunt["segments"]),
                         [False, False, True, False])
        self.assertEqual(H.noise_stretches(hunt),
                         [[0.0, 1.7], [5.3, 30.0]])
        train, probe = H.split_noise([[0.0, 4.0], [10.0, 12.0],
                                      [20.0, 23.0]])
        self.assertEqual(train, [[0.0, 4.0]])
        self.assertEqual(probe, [[10.0, 12.0], [20.0, 23.0]])
        self.assertEqual(H.split_noise([[0.0, 10.0]]),
                         ([[0.0, 5.0]], [[5.0, 10.0]]))
        self.assertEqual(H.split_noise([]), ([], []))

    def loop_plan(self, narrow_pd50=-12.0):
        """A 20 s recording: the hunt DETECTED 1.4 s of a voice at 132 Hz;
        hunting only that voice's range finds 1.5 s more of it, and the
        planted calibrations test the narrowed search at `narrow_pd50`
        against -10 dB for the whole range."""
        plan = self.long_noise()
        more = dict(SEG, start_s=8.0, end_s=9.5, frames=150)
        plan["hunt_narrow"] = dict(plan["hunt"], segments=[SEG, more])
        plan["calibrate_narrow"] = dict(plan["calibrate"],
                                        pd50_db=narrow_pd50, pd90_db=-4.0)
        plan["calibrate_broad"] = dict(plan["calibrate"], pd50_db=-10.0,
                                       pd90_db=-2.0)
        install_hark_worker(self.bin, plan)
        return plan

    def test_the_speaker_loop_hunts_the_voices_own_range(self):
        self.loop_plan()
        res = self.hark()
        folder = Path(res["folder"])
        st = res["stages"]["loop"]
        self.assertEqual(st["adopted"], 1)
        r = st["rounds"][0]
        self.assertEqual((r["track"], r["seed_s"]), (1, 1.4))
        # one pitch (132 Hz) widened to half an octave around it
        self.assertAlmostEqual(r["lo_hz"], 111.0, delta=0.2)
        self.assertAlmostEqual(r["hi_hz"], 157.0, delta=0.2)
        self.assertEqual((r["gain_db"], r["new_s"]), (2.0, 1.5))
        self.assertTrue(r["kept"] and r["settled"])
        req = json.loads((folder / "loop1-hunt.request.json")
                         .read_text("utf-8"))
        self.assertEqual(req["params"]["tracks"], 1)
        self.assertAlmostEqual(req["params"]["f0_min_hz"], 111.0, delta=0.2)
        # both searches tested on the same voices in the same stretches
        a = json.loads((folder / "loop1-cal-narrow.request.json")
                       .read_text("utf-8"))
        b = json.loads((folder / "loop1-cal-broad.request.json")
                       .read_text("utf-8"))
        for k in ("free", "phrases"):
            self.assertEqual(a[k], b[k], k)
        self.assertEqual(a["params"], b["params"])
        self.assertEqual(a["phrases"], [])
        lo, hi = a["params"]["probe_f0_hz"]
        self.assertTrue(r["lo_hz"] < lo < hi < r["hi_hz"], (lo, hi))
        self.assertGreater(a["hunt"]["grid"]["f0_min_hz"], 100.0)
        self.assertNotIn("f0_min_hz", b["hunt"]["grid"])
        # the voice's stages use the narrowed search: Move 2 pulls both
        merged = json.loads((folder / H.LOOP_HUNT).read_text("utf-8"))
        self.assertEqual([g["start_s"] for g in merged["segments"]],
                         [1.2, 8.0])
        self.assertTrue(all(g["loop"] for g in merged["segments"]))
        ex = json.loads((folder / "extract.request.json").read_text("utf-8"))
        self.assertEqual(len(ex["hunt"]["segments"]), 2)
        aud = json.loads((folder / "audit.request.json").read_text("utf-8"))
        self.assertEqual(len(aud["hunt"]["segments"]), 2)
        # the page's tracks are the narrowed search's, marked
        rows = H.segment_rows(H.load(self.case, self.run_id, res["hark_id"]))
        self.assertEqual([r["kind"] for r in rows], ["speaker loop"] * 2)
        # the census still hears the whole range
        cen = json.loads((folder / "census.request.json").read_text("utf-8"))
        self.assertEqual(len(cen["hunt"]["segments"]), 1)
        text = " ".join(res["verdict"])
        self.assertIn("Speaker loop (Move 7): the voice on track 1 (1.4 s "
                      "DETECTED, pitch 132–132 Hz)", text)
        self.assertIn("2.0 dB quieter half the time than by the whole-range "
                      "search, and 1.5 s more of this voice is DETECTED",
                      text)
        self.assertIn("the range settled", text)
        self.assertIn("needs ClearerVoice", text)
        self.assertNotIn("Move 7", text.split("Not yet")[-1])

    def test_a_loop_round_that_tests_worse_is_rolled_back(self):
        self.loop_plan(narrow_pd50=-8.0)
        res = self.hark()
        folder = Path(res["folder"])
        st = res["stages"]["loop"]
        self.assertIsNone(st["adopted"])
        self.assertFalse(st["rounds"][0]["kept"])
        self.assertEqual(st["rounds"][0]["gain_db"], -2.0)
        self.assertFalse((folder / H.LOOP_HUNT).exists())
        ex = json.loads((folder / "extract.request.json").read_text("utf-8"))
        self.assertEqual(len(ex["hunt"]["segments"]), 1)
        self.assertIn("so it was rolled back: the rest of HARK uses the "
                      "whole-range hunt", " ".join(res["verdict"]))

    def test_the_loop_needs_a_voice_to_learn_from(self):
        plan = json.loads(json.dumps(PLAN))
        plan["hunt"]["segments"][0]["status"] = "possible"
        install_hark_worker(self.bin, plan)
        res = self.hark()
        self.assertTrue(res["stages"]["loop"]["skipped"])
        self.assertEqual(calls(self.bin).count("hunt"), 1)
        self.assertIn("Speaker loop (Move 7) skipped: no voice track holds "
                      "1 s of DETECTED voice", " ".join(res["verdict"]))
        # a machine is no speaker
        hum = dict(SEG, track=2, start_s=0.0, end_s=9.0, f0_hz=[60.0] * 900)
        self.assertIsNone(H.speaker_range({"segments": [hum]}))
        voice = dict(SEG, f0_hz=[100.0 + i for i in range(140)])
        rng = H.speaker_range({"segments": [voice, hum]})
        self.assertEqual(rng["track"], 1)
        self.assertAlmostEqual(rng["lo_hz"], 107.0 / 1.12, delta=0.2)
        self.assertAlmostEqual(rng["hi_hz"], 233.0 * 1.12, delta=0.2)
        self.assertEqual(H.F0_MIN_HZ, 60.0)

    def machine_plan(self, voice=True):
        """A 20 s hunt with a steady 9 s track at 60 Hz (an engine) beside
        the voice — or instead of it."""
        plan = self.long_noise()
        hum = dict(SEG, track=2, start_s=6.0, end_s=15.0, frames=900,
                   voiced_frames=900, f0_median_hz=60.0, f0_min_hz=59.5,
                   f0_max_hz=60.5, f0_hz=[60.0 + (i % 2) * 0.3
                                          for i in range(900)])
        plan["hunt"]["segments"] = ([SEG] if voice else []) + [hum]
        install_hark_worker(self.bin, plan)
        return plan

    def test_the_census_names_what_pulses(self):
        res = self.hark()
        text = " ".join(res["verdict"])
        self.assertIn("Census of other sounds (Move 8)", text)
        self.assertIn("loudness pulsing 7.5 times a second at 0–3 s "
                      "(DETECTED; seen at 2 multiples)", text)
        self.assertIn("What hums: no pitch track steady enough", text)
        self.assertIn("HARK names the rate, not the source", text)
        self.assertNotIn("Move 8", text.split("Not yet")[-1])
        self.assertEqual(res["stages"]["census"]["pulsing"], 1)
        self.assertEqual(res["stages"]["census"]["machines"], [])
        req = json.loads((Path(res["folder"]) / "census.request.json")
                         .read_text("utf-8"))
        self.assertEqual(req["machines"], [])
        self.assertEqual(req["outputs"], {})
        self.assertEqual(req["params"]["census_surrogates"], 3)
        # no machine, nothing taken out
        report = RS.load_run(self.case, self.run_id)
        self.assertEqual([r for r in report["results"]
                          if r["option"] == H.MACHINE_OPTION], [])
        self.assertEqual(H.budget("overnight")["census_surrogates"], 12)

    def test_a_steady_machine_is_taken_out_as_a_cleaned_restoration(self):
        self.machine_plan()
        res = self.hark()
        text = " ".join(res["verdict"])
        self.assertIn("9.0 s of it is steady", text)
        self.assertIn("What hums: 1 machine(s) — track 2 around 60 Hz at "
                      "6–15 s — taken out", text)
        req = json.loads((Path(res["folder"]) / "census.request.json")
                         .read_text("utf-8"))
        self.assertEqual([m["track"] for m in req["machines"]], [2])
        self.assertEqual(sorted(req["outputs"]), ["machine", "without"])
        # Move 2 pulls only the voice: the machine is left to the census
        self.assertEqual(res["stages"]["extract"].get("skipped"), None)
        report = RS.load_run(self.case, self.run_id)
        mach = [r for r in report["results"]
                if r["option"] == H.MACHINE_OPTION]
        self.assertEqual(len(mach), 1)
        r = mach[0]
        self.assertEqual(r["tier"], "cleaned")
        self.assertFalse(r["speech_only"])
        self.assertEqual([o["stem"] for o in r["outputs"]],
                         ["without", "machine"])
        for o in r["outputs"]:
            self.assertTrue(o["file"].startswith(
                f"hark/{res['hark_id']}/census-{res['hark_id']}/"), o["file"])
            side = R.check_sidecar(json.loads(R.sidecar_path(o["path"])
                                              .read_text("utf-8")),
                                   Path(o["path"]).name)
            self.assertIn(H.MACHINE_TOOL, [st["tool"] for st in
                                           side["chain"]])
        self.assertTrue(Path(r["residual"]["path"]).is_file())
        recipe = R.load_recipe(Path(report["folder"]))
        st = [x for x in recipe["steps"] if x["tool"] == H.MACHINE_TOOL]
        self.assertEqual(len(st), 1)
        self.assertEqual(st[0]["tier"], "cleaned")
        self.assertAlmostEqual(
            st[0]["params"]["machines"][0]["f0_median_hz"], 60.0, delta=0.5)
        self.assertEqual(res["stages"]["census"]["machines"][0]["track"], 2)
        # the audit checks the machine's removal took no voice with it
        tg = {t["id"]: t for t in res["audit"]["targets"]}
        self.assertTrue(tg[f"{H.MACHINE_OPTION}:without"]["had_residual"])
        self.assertIn(f"{H.MACHINE_OPTION}:machine", tg)

    def test_a_machine_alone_is_not_pulled_out_as_a_voice(self):
        self.machine_plan(voice=False)
        res = self.hark()
        self.assertTrue(res["stages"]["extract"]["skipped"])
        self.assertIn("machine", res["stages"]["extract"]["note"])
        self.assertNotIn("extract", calls(self.bin))
        self.assertIn("census", calls(self.bin))
        report = RS.load_run(self.case, self.run_id)
        self.assertEqual([r for r in report["results"]
                          if r["option"] == H.RESULT_OPTION], [])
        self.assertEqual(len([r for r in report["results"]
                              if r["option"] == H.MACHINE_OPTION]), 1)

    def test_a_failed_census_is_recorded_and_resumes(self):
        plan = json.loads(json.dumps(PLAN))
        plan["fail"] = ["census"]
        install_hark_worker(self.bin, plan)
        with self.assertRaises(MediaError) as cm:
            self.hark()
        self.assertIn("census did not finish", str(cm.exception))
        hid = H.list_harks(self.case, self.run_id)[0]["hark_id"]
        install_hark_worker(self.bin)
        done = self.hark(resume=hid)
        self.assertEqual(calls(self.bin)[0], "census")
        self.assertEqual(sorted(done["stages"]), sorted(H.STAGES))

    def test_a_track_is_placed_on_the_files_own_curve(self):
        res = self.hark()
        row = H.segment_rows(res)[0]
        # estimate -7.0, the calibration says the estimator reads 1 dB low
        self.assertEqual(row["level_db"], -6.0)
        self.assertIn("below the level where real speech stays intelligible",
                      row["placement"])
        self.assertEqual(row["f0_range"], "118–151")

    def test_the_audit_takes_every_restoration_output_and_its_residual(self):
        self.run_all()
        report = RS.load_run(self.case, self.run_id)
        ran = [r for r in report["results"] if not r.get("error")]
        targets = H._targets(report)
        self.assertEqual(len(targets),
                         sum(len(r["outputs"]) for r in ran))
        plan = json.loads(json.dumps(PLAN))
        first = ran[0]["option"]
        plan["audit_flags"] = {first: {
            "made": [{"start_s": 2.0, "end_s": 2.4, "f0_median_hz": 210.0,
                      "input_support": 0.2}],
            "removed": [{"start_s": 1.2, "end_s": 1.9, "f0_median_hz": 131.0,
                         "status": "detected", "input_track": 1,
                         "input_status": "detected"}],
            "revealed": [{"start_s": 0.4, "end_s": 0.9, "f0_median_hz": 140.0,
                          "input_track": 2}]}}
        install_hark_worker(self.bin, plan)
        res = self.hark()
        aud = res["audit"]["targets"]
        # every option's outputs, and Move 2's two
        self.assertEqual({t["id"] for t in aud},
                         {t["id"] for t in targets} | {"hark:voice",
                                                       "hark:lift"})
        report = RS.load_run(self.case, self.run_id)
        targets = H._targets(report)
        # one residual per option: on its first output only
        for t in aud:
            want = next(x for x in targets if x["id"] == t["id"])
            self.assertEqual(t["had_residual"], bool(want["residual"]))
        kinds = [f["kind"] for f in res["flags"]]
        self.assertEqual(kinds, ["made", "removed", "revealed"])
        self.assertIn("MADE voice-like sound at 2.0–2.4 s", res["flags"][0]
                      ["text"])
        self.assertIn("REMOVED voice", res["flags"][1]["text"])
        self.assertIn("REVEALED", res["flags"][2]["text"])
        self.assertIn("1 made voice the input lacks", " ".join(res["verdict"]))
        # a restoration run after HARK keeps Move 2's result in the table
        self.run_all()
        report = RS.load_run(self.case, self.run_id)
        self.assertIn(H.RESULT_OPTION, [r["option"] for r in
                                        report["results"]])

    def test_the_map_exports_once_with_custody(self):
        res = self.hark()
        out = H.export_map(self.case, self.run_id, res["hark_id"])
        self.assertTrue(Path(out["path"]).read_bytes().startswith(b"\x89PNG"))
        self.assertFalse(out["already"])
        self.assertEqual(self.actions()[-1], "media.hark.exported")
        again = H.export_map(self.case, self.run_id, res["hark_id"])
        self.assertTrue(again["already"])
        with self.assertRaises(MediaError):
            H.export_map(self.case, self.run_id, "hk-nothere")

    def test_resume_keeps_finished_stages(self):
        first = self.hark(stages=("hunt",))
        self.assertEqual(sorted(first["stages"]), ["hunt"])
        self.assertEqual(calls(self.bin), ["hunt"])
        again = self.hark(resume=first["hark_id"])
        self.assertEqual(again["hark_id"], first["hark_id"])
        # the speaker loop (one round: a hunt in the voice's range, two
        # calibrations on the same test voices) found nothing more here
        self.assertEqual(calls(self.bin), ["hunt", "calibrate", "hunt",
                                           "calibrate", "calibrate",
                                           "extract", "census", "audit"])
        self.assertEqual(sorted(again["stages"]), sorted(H.STAGES))
        listed = H.list_harks(self.case, self.run_id)
        self.assertEqual([r["hark_id"] for r in listed], [first["hark_id"]])
        self.assertTrue(listed[0]["finished"])

    def test_a_failed_stage_is_recorded_and_the_earlier_one_kept(self):
        for stage, before in (("calibrate", ["hunt"]),
                              ("extract", ["calibrate", "hunt", "loop"])):
            plan = json.loads(json.dumps(PLAN))
            plan["fail"] = [stage]
            install_hark_worker(self.bin, plan)
            with self.assertRaises(MediaError) as cm:
                self.hark()
            self.assertIn(f"{stage} did not finish", str(cm.exception))
            self.assertIn("planted failure", str(cm.exception))
            self.assertEqual(self.actions()[-1], "media.hark.failed")
            hid = H.list_harks(self.case, self.run_id)[0]["hark_id"]
            state = H._load_state(H.hark_root(self.case, self.run_id) / hid)
            self.assertEqual(sorted(state["stages"]), before)
            install_hark_worker(self.bin)
            done = self.hark(resume=hid)
            self.assertEqual(calls(self.bin)[0], stage)
            self.assertEqual(sorted(done["stages"]), sorted(H.STAGES))

    def test_clean_phrases_are_copied_in_as_calibration_probes(self):
        refs = self.phrases()
        found = H.list_phrases(refs)
        self.assertEqual(len(found), 6)
        self.assertEqual(found, sorted(found, key=lambda p: p.as_posix()
                                       .lower()))
        res = self.hark(phrases=refs)
        # one per level of the quick budget, as many as there are
        want = min(6, len(H.BUDGETS["quick"]["levels"]))
        self.assertEqual(len(res["phrases"]), want)
        for p in res["phrases"]:
            path = Path(res["folder"]) / p["file"]
            self.assertTrue(path.is_file())
            self.assertTrue(str(path).startswith(str(self.case.root)))
            self.assertTrue(p["source"].startswith(("1089/", "121/")))
        self.assertEqual(res["calibrate"]["phrases_seen"], want)
        req = json.loads((Path(res["folder"]) / "probe.request.json")
                         .read_text("utf-8"))
        self.assertEqual(len(req["phrases"]), want)

    def test_budgets_and_ids_are_checked(self):
        with self.assertRaises(MediaError):
            H.budget("forever")
        with self.assertRaises(MediaError):
            self.hark(resume="../escape")
        for name, b in H.BUDGETS.items():
            self.assertIn("label", b)
            self.assertGreaterEqual(b["surrogates"], 2, name)
            self.assertTrue(b["levels"] == sorted(b["levels"], reverse=True))
            self.assertIn(b["score_chains"], H.CHAINS_ASSUMED)
            self.assertGreaterEqual(b["probe_per_level"], 1)
        self.assertGreater(len(H.BUDGETS["day"]["levels"])
                           * H.BUDGETS["day"]["probes_per_level"], 1000)
        times = [H.estimate_minutes(k, 60.0) for k in H.BUDGETS]
        self.assertEqual(times, sorted(times))

    def test_no_python_says_how_to_get_one(self):
        with self.assertRaises(MediaError) as cm:
            H.run(self.case, self.run_id, python=None, worker=None,
                  scratch=self.scratch)
        self.assertIn("get_speechbrain.bat", str(cm.exception))

    def test_the_tools_hold_their_tiers(self):
        self.assertEqual(R.tool_floor(H.SELFTRAIN_TOOL), "inferred")
        self.assertEqual(R.tool_floor(H.MACHINE_TOOL), "cleaned")
        self.assertEqual(R.tool_floor(H.HUNT_TOOL), "measured")
        self.assertEqual(R.tool_floor(H.PROBE_TOOL), "measured")
        self.assertEqual(R.tool_floor(H.EXTRACT_TOOL), "cleaned")
        with self.assertRaises(MediaError):
            R.step(H.EXTRACT_TOOL, tier="measured")


# ---------------------------------------------------------------------------
# the science, with the real worker
# ---------------------------------------------------------------------------

def _load_worker():
    spec = importlib.util.spec_from_file_location(
        "hark_worker_under_test", PACKAGE / "media" / "hark_worker.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _wav(path, x, rate):
    pcm = x.float().numpy().tobytes()
    fmt = struct.pack("<HHIIHHH", 3, 1, rate, rate * 4, 4, 32, 0)
    body = (b"WAVE" + b"fmt " + struct.pack("<I", 18) + fmt + b"fact"
            + struct.pack("<II", 4, x.numel()) + b"data"
            + struct.pack("<I", len(pcm)) + pcm)
    Path(path).write_bytes(b"RIFF" + struct.pack("<I", len(body)) + body)


@unittest.skipUnless(HAS_TORCH, "torch is not installed here (the worker's "
                                "interpreter in ATK has it)")
class Science(TempDirCase):
    RATE = 16000
    QUICK = {"surrogates": 3, "slopes": [0.0, 0.25, -0.25], "tracks": 1,
             "seed": 5, "audit_surrogates": 2}

    @classmethod
    def setUpClass(cls):
        import torch
        cls.torch = torch
        cls.W = _load_worker()

    def noise(self, n, seed, kind="pink"):
        torch = self.torch
        g = torch.Generator().manual_seed(seed)
        w = torch.randn(n, generator=g)
        if kind != "white":
            X = torch.fft.rfft(w)
            f = torch.arange(X.numel()).float().clamp(min=1)
            w = torch.fft.irfft(X / f.sqrt(), n=n)
        if kind == "swinging":
            env = torch.randn(n // 1600 + 2, generator=g) * 4.0
            env = torch.nn.functional.interpolate(env[None, None], size=n,
                                                  mode="linear")[0, 0]
            w = w * 10 ** (env / 20)
        return w / w.std() * 0.05

    def with_voices(self, x, placements):
        """x plus voice-like probes: [(start_s, level_db, pitch_hz)] at a
        level against the noise in the hunter's band."""
        torch, W = self.torch, self.W
        grid = W.Grid(self.RATE, 36)
        logN = W.noise_log_mean(W.log_power(x, grid, "cpu"))

        class Ctx:
            pass
        ctx = Ctx()
        ctx.grid, ctx.logN = grid, logN
        noise_band = float(torch.exp(logN)[int(W.F0_MIN / grid.df):].sum())
        y = x.clone()
        for i, (t, lvl, f0) in enumerate(placements):
            pr, _f, on = W.voiced_probe(self.RATE, 2.5, f0, 60 + i)
            gain = math.sqrt(10 ** (lvl / 10) * noise_band
                             / W._band_power(pr, ctx, "cpu", on))
            k = int(t * self.RATE)
            y[k:k + pr.numel()] += gain * pr
        return y

    def hunt(self, y, **extra):
        path = self.tmp / "in.wav"
        _wav(path, y, self.RATE)
        params = dict(self.QUICK, **extra)
        return self.W.hunt_op({"wav": os.fspath(path), "params": params,
                               "png": os.fspath(self.tmp / "map.png")}), path

    def test_a_voice_under_the_noise_is_found_and_noise_alone_is_not(self):
        x = self.noise(30 * self.RATE, 1)
        y = self.with_voices(x, [(6.0, -5.0, 140.0), (18.0, 0.0, 190.0)])
        res, _ = self.hunt(y)
        det = [s for s in res["segments"] if s["status"] == "detected"]
        for t0, f0 in ((6.0, 140.0), (18.0, 190.0)):
            hits = [s for s in det if s["end_s"] > t0 and s["start_s"]
                    < t0 + 2.5]
            self.assertTrue(hits, f"the voice at {t0} s was not detected")
            self.assertTrue(any(self.W.same_voice(s["f0_median_hz"], f0 * k)
                                for s in hits for k in (0.9, 1.0, 1.1)),
                            [s["f0_median_hz"] for s in hits])
        off = [s for s in det if not any(s["end_s"] > a and s["start_s"]
                                         < a + 2.5 for a in (6.0, 18.0))]
        self.assertEqual(off, [])
        self.assertTrue((self.tmp / "map.png").read_bytes().startswith(
            b"\x89PNG"))
        # the page labels the map's frequency axis from these
        self.assertEqual(res["map"]["height"], self.W.MAP_H)
        self.assertAlmostEqual(res["map"]["top_hz"], self.W.MAP_TOP_HZ,
                               delta=2 * self.W.BIN_HZ)
        quiet, _ = self.hunt(self.noise(30 * self.RATE, 2))
        self.assertEqual([s for s in quiet["segments"]
                          if s["status"] == "detected"], [])

    def test_noise_that_swings_in_level_does_not_look_like_a_voice(self):
        res, _ = self.hunt(self.noise(30 * self.RATE, 3, "swinging"))
        self.assertEqual([s for s in res["segments"]
                          if s["status"] == "detected"], [])

    def test_a_drifting_whistle_is_not_a_voice(self):
        """One line — a heterodyne drifting 1050-1350 Hz — would otherwise
        pass as the third harmonic of a 400 Hz voice: no harmonic may count
        above the next strongest."""
        torch = self.torch
        n = 30 * self.RATE
        t = torch.arange(n) / self.RATE
        f = 1200 + 150 * torch.sin(2 * math.pi * 0.05 * t)
        whistle = torch.sin(2 * math.pi * torch.cumsum(f, 0) / self.RATE)
        x = self.noise(n, 12) + 0.02 * whistle
        res, _ = self.hunt(x)
        self.assertEqual([s for s in res["segments"]
                          if s["status"] == "detected"], [])

    def test_the_census_hears_what_pulses_and_not_noise_that_swings(self):
        """DEMON: broadband noise whose loudness pulses 8 times a second
        (10% deep) is found at 8 Hz; noise whose level swings at random by
        +/-4 dB, and steady noise, pulse at no rate."""
        torch, W = self.torch, self.W
        n = 40 * self.RATE
        t = torch.arange(n) / self.RATE
        pulsing = self.noise(n, 31) * (1 + 0.10 * torch.sin(2 * math.pi
                                                             * 8.0 * t))
        res = W.census_modulated(pulsing, self.RATE, 3, 4321)
        det = [i for i in res["items"] if i["status"] == "detected"]
        self.assertTrue(det, res["items"])
        self.assertAlmostEqual(det[0]["rate_hz"], 8.0, delta=0.15)
        for kind in ("swinging", "pink", "white"):
            res = W.census_modulated(self.noise(n, 32, kind), self.RATE, 3,
                                     4321)
            self.assertEqual([i for i in res["items"]
                              if i["status"] == "detected"], [],
                             (kind, res["items"]))

    def test_footsteps_are_one_source_at_their_own_rate(self):
        """A pulse train shows at its rate and every multiple: steps every
        0.55 s are ONE source at 1.82 Hz, seen at several multiples."""
        torch, W = self.torch, self.W
        n = 40 * self.RATE
        g = torch.Generator().manual_seed(33)
        x = self.noise(n, 34)
        step = int(0.03 * self.RATE)
        for k in range(int(3 * self.RATE), int(37 * self.RATE),
                       int(0.55 * self.RATE)):
            x[k:k + step] += torch.randn(step, generator=g) * 0.08 * \
                torch.hann_window(step)
        res = W.census_modulated(x, self.RATE, 3, 4321)
        det = [i for i in res["items"] if i["status"] == "detected"]
        self.assertEqual(len(det), 1, res["items"])
        self.assertAlmostEqual(det[0]["rate_hz"], 1 / 0.55, delta=0.05)
        self.assertGreater(len(det[0]["multiples"]), 1)

    def test_a_machine_is_cancelled_along_its_own_track(self):
        """An engine under load (110 Hz, +/-4% wobble, 11 harmonics) under
        pink noise for 16 s of 24: the hunt loses it now and then; the
        census joins its run, bridges the gaps and takes it out."""
        torch, W = self.torch, self.W
        n = 24 * self.RATE
        t = torch.arange(n) / self.RATE
        noise = self.noise(n, 5)
        f0 = 110.0 * (1 + 0.04 * torch.sin(2 * math.pi * 0.15 * t))
        ph = 2 * math.pi * torch.cumsum(f0, 0) / self.RATE
        hum = sum((0.8 ** k) * torch.sin(k * ph + k) for k in range(1, 12))
        hum = hum / hum.std() * 0.03
        on = torch.zeros(n)
        on[4 * self.RATE:20 * self.RATE] = 1
        y = noise + hum * on
        hunt, path = self.hunt(y, tracks=2)
        segs = hunt["segments"]
        flags = W.machine_flags(segs)
        self.assertEqual(flags, H.machine_flags(segs))
        self.assertTrue(any(flags), segs)
        mach = H.machines(hunt)
        out = {"without": os.fspath(self.tmp / "without.wav"),
               "machine": os.fspath(self.tmp / "machine.wav")}
        res = W.census_op({"wav": os.fspath(path), "hunt": hunt,
                           "machines": mach, "outputs": out,
                           "params": {"census_surrogates": 2}})
        self.assertEqual(len(res["machines"]), 1, res["machines"])
        self.assertAlmostEqual(res["machines"][0]["f0_median_hz"], 110.0,
                               delta=4.0)
        without, _ = W.read_wav(out["without"])
        machine, _ = W.read_wav(out["machine"])
        self.assertTrue(torch.allclose(without + machine, y, atol=1e-5))
        a, b = 6 * self.RATE, 18 * self.RATE

        def db(v):
            return 10 * math.log10(float((v ** 2).mean()) + 1e-20)
        left = db(without[a:b] - noise[a:b]) - db(hum[a:b])
        # measured 2026-11-11: MACHINE_LEFT_DB below
        self.assertLess(left, MACHINE_LEFT_DB, left)
        self.assertLess(abs(db(without[a:b]) - db(noise[a:b])), 1.0)
        # before it starts, nothing is taken
        self.assertEqual(float(machine[:3 * self.RATE].abs().max()), 0.0)

    def test_a_speakers_range_lowers_the_line(self):
        """Move 7: hunting one speaker's range (95-145 Hz, 22 pitches of
        111) lowers the detection line at the same false-alarm rate — both
        lines measured on surrogates of this file's noise. Measured
        2026-11-11 on 60 s of pink noise: 53.0 down to 33.0, and test voices
        in the range found half the time 1.25 dB quieter."""
        W = self.W
        self.assertEqual(W.Grid(self.RATE, 36, None, 95.0,
                                145.0).f0.numel(), 22)
        x = self.noise(20 * self.RATE, 41)
        broad, _path = self.hunt(x)
        narrow, _path = self.hunt(x, f0_min_hz=95.0, f0_max_hz=145.0)
        self.assertEqual(narrow["grid"]["f0_min_hz"], 95.0)
        self.assertEqual(broad["grid"]["f0_min_hz"], H.F0_MIN_HZ)
        self.assertEqual(broad["grid"]["f0_max_hz"], H.F0_MAX_HZ)
        self.assertLess(narrow["thresholds"]["detect_score"],
                        0.85 * broad["thresholds"]["detect_score"])
        self.assertEqual(W.Context(narrow, self.RATE).grid.f0.numel(), 22)

    def test_the_machine_rule_is_one_rule(self):
        W = self.W
        for k in ("MACHINE_MIN_S", "MACHINE_SPREAD", "MACHINE_GAP_S",
                  "MACHINE_COVER"):
            self.assertEqual(getattr(W, k), getattr(H, k), k)
        seg = {"track": 1, "status": "detected", "start_s": 0.0,
               "end_s": 3.0, "f0_hz": [100.0] * 300}
        later = dict(seg, start_s=4.5, end_s=7.0, f0_hz=[103.0] * 250)
        far = dict(seg, start_s=12.0, end_s=14.0, f0_hz=[101.0] * 200)
        voice = dict(seg, track=2, start_s=1.0, end_s=7.0,
                     f0_hz=[100.0 + (i % 60) for i in range(600)])
        segs = [seg, later, far, voice]
        self.assertEqual(H.machine_flags(segs), [True, True, False, False])
        self.assertEqual(W.machine_flags(segs), H.machine_flags(segs))
        runs = W.machine_runs(segs)
        self.assertEqual(len(runs), 1)
        times, f0, track = runs[0]
        self.assertEqual(track, 1)
        self.assertAlmostEqual(float(times[0]), 0.0)
        self.assertAlmostEqual(float(times[-1]), 7.0 - W.HOP_S, places=6)
        # the gap is bridged between the two pitches
        mid = int(round(3.75 / W.HOP_S))
        self.assertTrue(100.0 < float(f0[mid]) < 103.0)

    def test_the_surrogate_null_is_faithful_to_the_files_own_noise(self):
        W = self.W
        x = self.noise(30 * self.RATE, 4, "white")
        grid = W.Grid(self.RATE, 36)
        lp = W.log_power(x, grid, "cpu")
        logN = W.noise_log_mean(lp)
        g = W.whiten(lp, logN, grid)
        null = W.build_null(x, logN, grid, "cpu", [0.0], 2, 9,
                            say=lambda _l: None)
        z, _Z = W.evidence_z(g, grid, "cpu", null, [0.0])
        self.assertLess(abs(float(z.mean())), 0.1)
        self.assertLess(abs(float(z.std()) - 1.0), 0.1)

    def test_the_audit_catches_voice_removed_and_voice_made(self):
        torch, W = self.torch, self.W
        n = 30 * self.RATE
        x = self.noise(n, 5)
        y = self.with_voices(x, [(4.0, -3.0, 130.0), (16.0, -3.0, 170.0)])
        voice = y - x
        hunt, path = self.hunt(y)
        # A: keeps everything but the second voice, which is its residual
        v2 = torch.zeros(n)
        v2[16 * self.RATE:int(18.5 * self.RATE)] = \
            voice[16 * self.RATE:int(18.5 * self.RATE)]
        # B: honest — the voices kept, the noise down 10 dB
        # C: a voice where the input has none, at 25 s
        pr, _f, _on = W.voiced_probe(self.RATE, 2.5, 210.0, 91)
        fake = torch.zeros(n)
        fake[25 * self.RATE:25 * self.RATE + pr.numel()] = 0.05 * pr / pr.std()
        # D: a filter that only turns the phase (60 degrees, every
        # frequency): its residual holds as much voice as the input, its
        # output has lost none (a high-pass near the pitch does this)
        Y = torch.fft.rfft(y)
        turned = torch.fft.irfft(Y * complex(math.cos(math.pi / 3),
                                             math.sin(math.pi / 3)), n=n)
        files = {"A": (y - v2, v2), "B": (voice + 0.3 * x, 0.7 * x),
                 "C": (0.3 * y + fake, 0.7 * y - fake),
                 "D": (turned, y - turned)}
        targets = []
        for k, (out, res) in files.items():
            _wav(self.tmp / f"{k}_out.wav", out, self.RATE)
            _wav(self.tmp / f"{k}_res.wav", res, self.RATE)
            targets.append({"id": k, "output": os.fspath(self.tmp /
                                                          f"{k}_out.wav"),
                            "residual": os.fspath(self.tmp / f"{k}_res.wav")})
        aud = {t["id"]: t for t in W.audit_op({
            "wav": os.fspath(path), "hunt": hunt, "params": self.QUICK,
            "targets": targets})["targets"]}
        self.assertTrue(any(r["start_s"] < 18.5 and r["end_s"] > 16.0
                            for r in aud["A"]["removed"]), aud["A"])
        self.assertEqual(aud["A"]["made"], [])
        self.assertEqual(aud["B"]["removed"], [])
        self.assertEqual(aud["B"]["made"], [])
        self.assertTrue(any(m["start_s"] < 27.5 and m["end_s"] > 25.0
                            for m in aud["C"]["made"]), aud["C"])
        self.assertTrue(all(r["share_basis"] == "output"
                            for r in aud["A"]["removed"]))
        self.assertEqual(aud["D"]["removed"], [], aud["D"])
        self.assertGreaterEqual(aud["D"]["kept"], 1, aud["D"])

    def test_calibration_finds_loud_probes_and_not_buried_ones(self):
        x = self.noise(40 * self.RATE, 6, "white")
        hunt, path = self.hunt(x)
        cal = self.W.calibrate_op({
            "wav": os.fspath(path), "hunt": hunt,
            "params": {"levels": [5.0, -25.0], "probes_per_level": 3,
                       "seed": 2}})
        by = {r["level_db"]: r for r in cal["levels"]}
        self.assertEqual(by[5.0]["pd"], 1.0)
        self.assertEqual(by[-25.0]["pd"], 0.0)
        self.assertIsNotNone(cal["pd50_db"])
        self.assertLess(-25.0, cal["pd50_db"])
        self.assertLessEqual(cal["pd50_db"], 5.0)

    @unittest.skipUnless(HAS_PYSTOI, "pystoi is not installed here")
    def test_estoi_agrees_with_the_reference_implementation(self):
        import numpy as np
        from pystoi import stoi
        W = self.W
        pr, _f, _on = W.voiced_probe(self.RATE, 3.0, 150.0, 3)
        for snr in (5.0, -5.0):
            n = self.noise(pr.numel(), 8)
            n = n / n.std() * pr.std() * 10 ** (-snr / 20)
            y = pr + n
            ours = W.estoi(pr, y, self.RATE)
            ref = stoi(pr.numpy().astype(np.float64),
                       y.numpy().astype(np.float64), self.RATE,
                       extended=True)
            self.assertAlmostEqual(ours, ref, places=3)


    # -- Move 2 -------------------------------------------------------------
    def _si_snr(self, ref, est):
        return self.W._si_snr(ref, est, self.RATE)

    def test_move_2_pulls_a_voice_out_of_the_noise(self):
        W = self.W
        x = self.noise(24 * self.RATE, 21, "white")
        y = self.with_voices(x, [(5.0, -5.0, 140.0), (15.0, -5.0, 200.0)])
        clean = y - x
        hunt, path = self.hunt(y)
        out = {"voice": os.fspath(self.tmp / "voice.wav"),
               "lift": os.fspath(self.tmp / "lift.wav")}
        res = W.extract_op({"wav": os.fspath(path), "hunt": hunt,
                            "outputs": out})
        self.assertGreater(res["voiced_s"], 2.0)
        voice, rate = W.read_wav(out["voice"])
        lift, _ = W.read_wav(out["lift"])
        self.assertEqual(rate, self.RATE)
        self.assertEqual(voice.numel(), y.numel())
        self.assertEqual(lift.numel(), y.numel())
        for t0 in (5.0, 15.0):
            a, b = int(t0 * self.RATE), int((t0 + 2.5) * self.RATE)
            before = self._si_snr(clean[a:b], y[a:b])
            after = self._si_snr(clean[a:b], voice[a:b])
            # measured 2026-11-10: about +12 dB on these probes at -5 dB
            self.assertGreater(after - before, 6.0, (t0, before, after))
            self.assertGreater(self._si_snr(clean[a:b], lift[a:b]), before)
        # where no track is, VOICE is silent: it cannot add a voice
        quiet = slice(int(10 * self.RATE), int(14 * self.RATE))
        self.assertEqual(float(voice[quiet].abs().max()), 0.0)
        # every run's pitch was refined (the hunt's grid is 2% coarse)
        self.assertTrue(all(r["refined_pct"] > 0 for r in res["runs"]))

    def test_refinement_finds_the_true_pitch(self):
        torch, W = self.torch, self.W
        pr, f0_true, on = W.voiced_probe(self.RATE, 2.5, 150.0, 9)
        x = pr + self.noise(pr.numel(), 4, "white") * 0.5
        frames = [i for i in range(len(on)) if bool(on[i])][5:120]
        # the probe's pitch is given at its frames' centres
        times = torch.tensor([i * W.HOP_S + W.WIN_S / 2 for i in frames],
                             dtype=torch.float64)
        truth = torch.tensor([float(f0_true[i]) for i in frames],
                             dtype=torch.float64)
        noise_at = lambda f: torch.ones_like(f)          # noqa: E731
        got = W.refine_pitch(x, self.RATE, times, truth * 1.02, noise_at,
                             4000.0)
        err = float((got / truth - 1).abs().median())
        self.assertLess(err, 0.002, err)   # measured: about 0.03%

    def test_the_rest_filter_takes_noise_down(self):
        W = self.W
        x = self.noise(8 * self.RATE, 5, "white")
        y = W.rest_wiener(x, self.RATE)
        drop = 10 * math.log10(float((y ** 2).sum()) / float((x ** 2).sum()))
        self.assertLess(drop, -10.0)
        self.assertEqual(y.numel(), x.numel())

    # -- increment 2b ---------------------------------------------------------
    def test_the_probe_is_the_files_noise_with_phrases_at_their_levels(self):
        torch, W = self.torch, self.W
        x = self.noise(30 * self.RATE, 31)
        y = self.with_voices(x, [(4.0, 0.0, 150.0)])
        hunt, path = self.hunt(y)
        phrases = []
        for i in range(3):
            pr, _f, _on = W.voiced_probe(self.RATE, 2.0, 120.0 + 40 * i,
                                         80 + i)
            p = self.tmp / f"ph{i}.wav"
            _wav(p, pr * 0.3, self.RATE)
            phrases.append(os.fspath(p))
        out = {"probe": os.fspath(self.tmp / "probe.wav"),
               "clean": os.fspath(self.tmp / "clean.wav")}
        params = {"levels": [0.0, -10.0], "probe_per_level": 2, "seed": 3}
        res = W.probe_op({"wav": os.fspath(path), "hunt": hunt,
                          "phrases": phrases, "params": params,
                          "outputs": out})
        self.assertEqual(len(res["phrases"]), 4)
        self.assertEqual(sorted(r["level_db"] for r in res["phrases"]),
                         [-10.0, -10.0, 0.0, 0.0])
        probe, rate = W.read_wav(out["probe"])
        clean, _ = W.read_wav(out["clean"])
        self.assertEqual(probe.numel(), clean.numel())
        self.assertAlmostEqual(res["duration_s"], probe.numel() / rate,
                               places=2)
        # the phrases do not overlap, and each sits at its level against
        # the file's noise, measured as the calibration measures it
        ctx = W.Context(hunt, rate)
        band = float(torch.exp(ctx.logN.float())[int(W.F0_MIN /
                                                     ctx.grid.df):].sum())
        ends = 0.0
        for r in sorted(res["phrases"], key=lambda r: r["start_s"]):
            self.assertGreaterEqual(r["start_s"], ends + W.PROBE_GAP_S - 0.01)
            ends = r["end_s"]
            a, b = int(r["start_s"] * rate), int(r["end_s"] * rate)
            lvl = 10 * math.log10(W._band_power(clean[a:b], ctx, "cpu")
                                  / band)
            self.assertAlmostEqual(lvl, r["level_db"], delta=0.6)
        # the bed is noise: no voice of the file's own in it
        bed = probe - clean
        self.assertGreater(res["noise_from_file_s"], 5.0)
        self.assertLess(10 * math.log10(float(bed.std()) / float(x.std())
                                        + 1e-12) ** 2, 4.0)

    def test_scoring_ranks_a_clean_output_first(self):
        W = self.W
        x = self.noise(20 * self.RATE, 41)
        hunt, path = self.hunt(x)
        p = self.tmp / "ph.wav"
        pr, _f, _on = W.voiced_probe(self.RATE, 2.5, 150.0, 5)
        _wav(p, pr * 0.3, self.RATE)
        out = {"probe": os.fspath(self.tmp / "probe.wav"),
               "clean": os.fspath(self.tmp / "clean.wav")}
        res = W.probe_op({"wav": os.fspath(path), "hunt": hunt,
                          "phrases": [os.fspath(p)],
                          "params": {"levels": [0.0, -10.0],
                                     "probe_per_level": 1},
                          "outputs": out})
        sc = W.score_op({"clean": out["clean"], "probe": out["probe"],
                         "phrases": res["phrases"],
                         "outputs": [{"id": "perfect",
                                      "paths": [out["clean"]]}]})
        s = sc["scores"]
        for raw, best in zip(s["unprocessed"]["by_level"],
                             s["perfect"]["by_level"]):
            self.assertGreater(best["estoi"], 0.99)
            self.assertLess(raw["estoi"], best["estoi"])
            self.assertGreater(best["si_snr_db"], raw["si_snr_db"] + 10)
        self.assertLess(s["perfect"]["noise_left_db"], -40.0)
        self.assertEqual(s["unprocessed"]["noise_left_db"], 0.0)



def _load_selftrain():
    spec = importlib.util.spec_from_file_location(
        "selftrain_worker_under_test",
        PACKAGE / "media" / "selftrain_worker.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod._say = lambda _t: None
    return mod


@unittest.skipUnless(HAS_TORCH, "torch is not installed here (the worker's "
                                "interpreter in ATK has it)")
class SelfTrain(TempDirCase):
    """Move 3's worker with real torch: the port is GTCRN's network, the
    training runs and keeps its best weights, too little noise is refused."""
    RATE = 16000
    #: sha256 of the sorted (name, shape) list of the port's parameters —
    #: computed from the port after it loaded GTCRN's published DNS3
    #: weights strictly (2026-11-10), so a change that would stop those
    #: weights loading fails here even where they are not installed
    SIGNATURE = ("651cbbe217f85c0c73f8ed5affcb0bd72caa0ef800a523459435cbaa24"
                 "055e30")

    @classmethod
    def setUpClass(cls):
        import torch
        cls.torch = torch
        cls.S = _load_selftrain()

    def recording(self):
        """12 s: 3 s of noise, a voice, 3 s of noise, a voice, noise."""
        torch = self.torch
        W = _load_worker()
        g = torch.Generator().manual_seed(3)
        n = 12 * self.RATE
        x = torch.randn(n, generator=g) * 0.02
        for t0, f0 in ((3.0, 140.0), (8.0, 190.0)):
            pr, _f, _on = W.voiced_probe(self.RATE, 1.5, f0, int(f0))
            k = int(t0 * self.RATE)
            x[k:k + pr.numel()] += pr * 0.2
        path = self.tmp / "rec16k.wav"
        _wav(path, x, self.RATE)
        return path, x

    def test_the_port_is_gtcrns_network(self):
        import hashlib
        m = self.S._build_gtcrn()
        sd = m.state_dict()
        sig = json.dumps(sorted((k, list(v.shape)) for k, v in sd.items()))
        self.assertEqual(hashlib.sha256(sig.encode()).hexdigest(),
                         self.SIGNATURE)
        self.assertEqual(sum(v.numel() for v in sd.values()), 48847)
        weights = os.environ.get("HARK_GTCRN_WEIGHTS", "")
        if weights and Path(weights).is_file():
            torch = self.torch
            ck = torch.load(weights, map_location="cpu", weights_only=True)
            m.load_state_dict(ck["model"], strict=True)
            # the ERB filters the port computes are the ones stored
            self.assertTrue(torch.allclose(self.S._build_gtcrn().erb.erb_fc
                                           .weight, ck["model"]
                                           ["erb.erb_fc.weight"]))

    def test_training_on_one_file_keeps_its_best_weights(self):
        path, x = self.recording()
        out = {"model": os.fspath(self.tmp / "model.pt"),
               "output": os.fspath(self.tmp / "out.wav")}
        also = self.tmp / "also.wav"
        _wav(also, x[:4 * self.RATE], self.RATE)
        self.S.CHECK_EVERY = 3
        self.addCleanup(setattr, self.S, "CHECK_EVERY", 25)
        res = self.S.selftrain_op({
            "wav": os.fspath(path), "free": [[0.0, 3.0], [4.6, 8.0]],
            "voiced": [[3.0, 4.5], [8.0, 9.5]], "weights": None,
            "params": {"minutes": 30.0, "max_steps": 6, "seed": 1},
            "outputs": out,
            "also": [{"wav": os.fspath(also),
                      "output": os.fspath(self.tmp / "also.out.wav")}]})
        self.assertEqual(res["mode"], "scratch")
        self.assertEqual(res["steps"], 6)
        self.assertEqual([c[0] for c in res["curve"]], [0, 3, 6])
        self.assertLessEqual(res["check_best"], res["check_first"])
        self.assertAlmostEqual(res["noise_s"], 6.0, places=1)  # 2.8 + 3.2
        y, rate = self.S.read_wav(out["output"])
        self.assertEqual((rate, y.numel()), (self.RATE, x.numel()))
        self.assertTrue(bool(self.torch.isfinite(y).all()))
        z, _ = self.S.read_wav(os.fspath(self.tmp / "also.out.wav"))
        self.assertEqual(z.numel(), 4 * self.RATE)
        # the saved weights run again through "apply"
        again = self.tmp / "again.wav"
        self.S.apply_op({"model": out["model"], "wav": os.fspath(path),
                         "output": os.fspath(again)})
        w, _ = self.S.read_wav(os.fspath(again))
        self.assertLess(float((w - y).abs().max()), 1e-3)

    def test_too_little_noise_is_refused(self):
        path, _x = self.recording()
        with self.assertRaises(ValueError) as cm:
            self.S.selftrain_op({
                "wav": os.fspath(path), "free": [[0.0, 2.0]], "voiced": [],
                "params": {"max_steps": 5},
                "outputs": {"model": os.fspath(self.tmp / "m.pt"),
                            "output": os.fspath(self.tmp / "o.wav")}})
        self.assertIn("at least 4 s", str(cm.exception))
        # the engine's floor is the worker's
        self.assertEqual(self.S.MIN_NOISE_S, H.SELFTRAIN_MIN_NOISE_S)


if __name__ == "__main__":
    unittest.main()
