"""SAM Audio through a FAKE audiocpp_cli, run by the real subprocess path.

The command lines are held to audio.cpp v0.9.0's own documentation
(docs/models/sam_audio.md, docs/usage.md); the run is held to the forensic
door of FORENSICS_PLAN §12.3: into the case, through the read-only door,
custody for every stage, `.invented` on every generative file, the residual
kept, a recipe that reads back and replays.
"""

from __future__ import annotations

import functools
import io
import json
import os
import shutil
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from _support import EXAMINER, TempDirCase

import mediasynth as M
from forensics_workshop import blocker, cli
from forensics_workshop.case import Case
from forensics_workshop.errors import Cancelled, CasePathError, MediaError
from forensics_workshop.media import lab as L
from forensics_workshop.media import sam_audio as SA


class CommandLines(unittest.TestCase):
    """Every flag, against the pinned documentation."""

    def test_text_prompt(self):
        argv = SA.build_command("audiocpp_cli.exe", model="m.gguf",
                                input_wav="in.wav", out_dir="out",
                                text=" man speaking ", seed=2)
        self.assertEqual(argv, [
            "audiocpp_cli.exe", "--task", "s2s", "--family", "sam_audio",
            "--model", "m.gguf", "--backend", "cuda", "--audio", "in.wav",
            "--text", "man speaking", "--seed", "2", "--out-dir", "out",
            "--out-format", "float32", "--log", "--metrics"])

    def test_anchors_are_one_json_request_option(self):
        argv = SA.build_command(["py", "fake.py"], model="m", input_wav="i",
                                out_dir="o", text="woman", seed=1,
                                anchors=["+0.5:2.0", ("-", 3, 4)])
        self.assertEqual(argv[:2], ["py", "fake.py"])
        i = argv.index("--request-option")
        self.assertEqual(argv[i + 1], 'anchors=[["+",0.5,2.0],["-",3.0,4.0]]')

    def test_memory_bounded_needs_the_spec_override(self):
        argv = SA.build_command("cli", model="m", input_wav="i", out_dir="o",
                                text="x", seed=1, memory_bounded=True,
                                spec="bin/model_specs/sam_audio.json",
                                steps=8)
        self.assertEqual(argv[-4:], [
            "--model-spec-override", "bin/model_specs/sam_audio.json",
            "--session-option", "sam_audio.memory_bounded=true"])
        self.assertIn("num_inference_steps=8", argv)
        with self.assertRaisesRegex(MediaError, "model_specs"):
            SA.build_command("cli", model="m", input_wav="i", out_dir="o",
                             text="x", seed=1, memory_bounded=True)

    def test_text_is_required_even_with_anchors(self):
        with self.assertRaisesRegex(MediaError, "requires --text"):
            SA.build_command("cli", model="m", input_wav="i", out_dir="o",
                             text="  ", seed=1, anchors=["+0:1"])

    def test_bounded_mode_is_automatic_above_thirty_seconds(self):
        self.assertFalse(SA.memory_bounded_for(30.0)[0])
        self.assertTrue(SA.memory_bounded_for(30.5)[0])
        self.assertEqual(SA.memory_bounded_for(300, False),
                         (False, "set by the examiner"))
        self.assertGreater(SA.timeout_for(180), SA.timeout_for(10))


class ExitCodes(unittest.TestCase):
    def test_windows_crash_codes_become_sentences_with_the_raw_code(self):
        for code, needle in ((0xC0000135, "DLL it needs was not found"),
                             (3221225477, "access violation"),
                             (0xC0000409, "fail-fast"),
                             (0x40000015, "abort()"),
                             (0xC000001D, "AVX"),
                             (-1073741515, "DLL it needs was not found"),
                             (3, "abort()")):
            text = SA.exit_sentence(code)
            self.assertIn(needle, text, code)
            self.assertIn(f"0x{code & 0xFFFFFFFF:08X}", text)
        self.assertEqual(SA.exit_sentence(7), "exited with code 7 (0x00000007)")
        self.assertEqual(SA.exit_sentence(None), "did not start")


class AnsiPaths(unittest.TestCase):
    """audio.cpp v0.9.0 opens files through the ANSI code page on Windows."""

    def test_ascii_passes_and_a_short_name_is_used_when_there_is_one(self):
        with mock.patch.object(SA, "_windows", return_value=True):
            self.assertEqual(SA.ansi_path("D:/Cases/OP-1"), "D:/Cases/OP-1")
            with mock.patch.object(SA, "_short_path",
                                   return_value="D:\\CASES\\CAFE~1"):
                self.assertEqual(SA.ansi_path("D:/Cases/Café"),
                                 "D:\\CASES\\CAFE~1")
            with mock.patch.object(SA, "_short_path", return_value=None):
                with self.assertRaisesRegex(MediaError, "outside plain ASCII"):
                    SA.ansi_path("D:/Cases/Café")
        with mock.patch.object(SA, "_windows", return_value=False):
            self.assertEqual(SA.ansi_path("/cases/Café"), "/cases/Café")


class _Fixture(TempDirCase):
    def setUp(self):
        super().setUp()
        self.cli, self.ffmpeg = M.install_fakes(self.tmp / "bin")
        M.install_spec(self.tmp / "bin")
        self.model = M.fake_model(self.tmp / "models" / "sam-audio")
        self.evidence = self.tmp / "evidence"
        self.clip = M.write_wav(self.evidence / "calls" / "clip.wav",
                                M.tone(1.0, total=3.0), fmt="pcm16")
        self.case = Case.create(self.tmp / "case", case_id="MEDIA-1",
                                examiner=EXAMINER)
        self.item = self.case.add_folder(self.evidence, label="phone")

    def run_sam(self, source=None, **kw):
        kw.setdefault("text", "man speaking")
        kw.setdefault("model", self.model)
        kw.setdefault("audiocpp", self.cli)
        kw.setdefault("ffmpeg", self.ffmpeg)
        return L.run_sam(self.case, source or self.clip, **kw)

    def actions(self):
        return [r["action"] for r in self.case.custody.rows()
                if r["action"].startswith("media.")]


class TheRun(_Fixture):
    def test_outputs_land_in_the_case_labelled_with_their_residuals(self):
        result = self.run_sam(anchors=["+0.2:0.8"])
        folder = Path(result["folder"])
        self.assertTrue(blocker.is_inside(folder, self.case.root / "media"))
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["tier"], "invented")
        names = sorted(o["file"] for o in result["outputs"])
        self.assertEqual(names, ["input.wav"] + sorted(
            f"seed{s}.{stem}.invented.wav" for s in (1, 2, 3)
            for stem in ("target", "residual")))
        for out in result["outputs"]:
            self.assertTrue(Path(out["path"]).is_file(), out["file"])
            self.assertTrue((folder / out["sidecar"]).is_file(), out["file"])
            if out["stem"] in ("target", "residual"):
                self.assertIn(".invented", out["file"])
                self.assertEqual(out["tier"], "invented")
                self.assertTrue((folder / out["log"]).is_file())
            else:
                self.assertEqual(out["tier"], "measured")
        self.assertFalse(list(folder.glob("work-seed*")),
                         "the runtime's work folders are emptied and removed")
        self.assertEqual(result["weights"]["sentence"],
                         "weights: unverified (parity not run)")
        self.assertEqual(result["negative_control"]["sentence"],
                         "not yet negative-control tested")

    def test_the_command_reached_the_runtime_as_built(self):
        result = self.run_sam(anchors=["+0.2:0.8", "-2:2.5"], seeds=[7])
        log = (Path(result["folder"]) / "seed7.audiocpp.log").read_text()
        line = next(l for l in log.splitlines() if l.startswith("FAKE-ARGV "))
        argv = json.loads(line[len("FAKE-ARGV "):])
        self.assertEqual(argv[argv.index("--seed") + 1], "7")
        self.assertEqual(argv[argv.index("--out-format") + 1], "float32")
        self.assertIn('anchors=[["+",0.2,0.8],["-",2.0,2.5]]', argv)
        self.assertNotIn("--session-option", argv, "3 s is not bounded")

    def test_custody_names_recipe_tier_input_and_outputs(self):
        result = self.run_sam(seeds=2)
        self.assertEqual(self.actions(), ["media.started", "media.derived",
                                          "media.derived", "media.derived"])
        rows = [r for r in self.case.custody.rows()
                if r["action"].startswith("media.")]
        started, first, seed1 = rows[0], rows[1], rows[2]
        self.assertEqual(started["target"], result["recipe_id"])
        self.assertEqual(started["detail"]["tier"], "invented")
        self.assertEqual(started["detail"]["input"]["evidence_id"], "E001")
        self.assertEqual(first["detail"]["tier"], "measured")
        self.assertEqual(seed1["detail"]["tier"], "invented")
        self.assertEqual(seed1["detail"]["input_sha256"],
                         result["input_sha256"])
        self.assertEqual(set(seed1["hashes"]),
                         {"seed1.target.invented.wav",
                          "seed1.residual.invented.wav"})
        self.assertTrue(self.case.custody.verify().ok)

    def test_the_original_is_read_only_through_the_door_and_untouched(self):
        """Every byte of the original that reaches the case came through
        `open_evidence` — counted, not assumed: a copy made with a plain
        open() would leave the door's count at the header's few bytes."""
        before = (self.clip.read_bytes(), self.clip.stat().st_mtime_ns)
        real = blocker.open_evidence
        through = {"bytes": 0}
        clip = os.path.normcase(os.fspath(self.clip))

        class Counted:
            def __init__(self, fh):
                self.fh = fh

            def read(self, *a):
                data = self.fh.read(*a)
                through["bytes"] += len(data)
                return data

            def __getattr__(self, name):
                return getattr(self.fh, name)

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                self.fh.close()

        def door(path):
            fh = real(path)
            if os.path.normcase(os.fspath(path)) == clip:
                return Counted(fh)
            return fh

        with mock.patch.object(blocker, "open_evidence", side_effect=door):
            result = self.run_sam(seeds=1)
        self.assertGreaterEqual(through["bytes"], len(before[0]))
        copy = Path(result["folder"]) / "input.wav"
        self.assertEqual(copy.read_bytes(), before[0])
        self.assertEqual((self.clip.read_bytes(), self.clip.stat().st_mtime_ns),
                         before)

    def test_without_the_door_nothing_runs(self):
        with mock.patch.object(blocker, "open_evidence",
                               side_effect=PermissionError("door shut")):
            with self.assertRaises(PermissionError):
                self.run_sam(seeds=1)

    def test_the_recipe_reads_back_and_lists(self):
        result = self.run_sam()
        again = L.load_run(self.case, result["recipe_id"])
        self.assertEqual(again["outputs"], result["outputs"])
        self.assertEqual(again["input_sha256"], result["input_sha256"])
        side = json.loads(Path(result["folder"]).joinpath(
            "seed2.target.invented.wav.recipe.json").read_text())
        self.assertEqual(side["tier"], "invented")
        self.assertEqual([s["tier"] for s in side["chain"]],
                         ["measured", "invented"])
        self.assertEqual(side["chain"][-1]["seed"], 2)
        rows = L.list_runs(self.case)
        self.assertEqual(rows[0]["recipe_id"], result["recipe_id"])
        self.assertEqual(rows[0]["input"], "E001:calls/clip.wav")

    def test_seeds_that_disagree_are_shown_where(self):
        result = self.run_sam(seeds=3)
        spans = result["disagreement"]["spans"]
        self.assertEqual(len(spans), 1)
        self.assertEqual((spans[0]["start_s"], spans[0]["end_s"]), (1.5, 2.0))
        self.assertEqual(spans[0]["loud"], [2])
        steady = self.run_sam(text="steady voice", seeds=3)
        self.assertEqual(steady["disagreement"]["spans"], [])

    def test_a_video_goes_through_ffmpeg_as_a_measured_step(self):
        video = self.evidence / "calls" / "clip.mp4"
        video.write_bytes(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 200)
        result = self.run_sam(video, seeds=1)
        tools = [s["tool"] for s in result["steps"]]
        self.assertEqual(tools[1], "ffmpeg")
        self.assertEqual([s["tier"] for s in result["steps"][:2]],
                         ["measured", "measured"])
        self.assertTrue((Path(result["folder"]) / "source" / "clip.mp4"
                         ).is_file())
        self.assertEqual(result["input"]["wav"]["channels"], 2)
        self.assertIn("fake-0", result["steps"][1]["version"])

    def test_a_video_without_ffmpeg_is_refused_with_the_fix(self):
        video = self.evidence / "v.mov"
        video.write_bytes(b"\x00" * 64)
        with self.assertRaisesRegex(MediaError, "get_tools.bat|no FFmpeg"):
            self.run_sam(video, ffmpeg=None)
        self.assertIn("media.failed", self.actions())

    def test_a_failing_seed_is_recorded_and_its_words_reach_the_examiner(self):
        with self.assertRaisesRegex(MediaError, "out of memory"):
            self.run_sam(text="FAIL")
        failed = [r for r in self.case.custody.rows()
                  if r["action"] == "media.failed"][-1]
        self.assertEqual(failed["detail"]["stage"], "seed 1")
        rid = failed["target"]
        recipe = json.loads((self.case.root / "media" / rid / "recipe.json"
                             ).read_text())
        self.assertEqual(recipe["state"], "failed")
        self.assertIn("exited with code 3", recipe["failure"])
        self.assertIn("abort()", recipe["failure"])

    def test_broken_stems_fail_the_seed_never_pass_as_sound(self):
        for text, needle in (("NAN voice", "non-finite"),
                             ("EMPTY voice", "0 frames")):
            with self.assertRaisesRegex(MediaError, needle, msg=text):
                self.run_sam(text=text, seeds=1)
            failed = [r for r in self.case.custody.rows()
                      if r["action"] == "media.failed"][-1]
            self.assertEqual(failed["detail"]["stage"], "seed 1")

    def test_a_truncated_wav_goes_through_ffmpeg_as_a_measured_step(self):
        raw = self.clip.read_bytes()
        cut = self.evidence / "calls" / "cut.wav"
        cut.write_bytes(raw[:len(raw) // 2])
        result = self.run_sam(cut, seeds=1)
        self.assertEqual([s["tool"] for s in result["steps"][:2]],
                         ["forensics_workshop read-only door (hashed copy)",
                          "ffmpeg"])
        self.assertIn("header did not match", result["steps"][1]["note"])
        self.assertTrue((Path(result["folder"]) / "source" / "cut.wav"
                         ).is_file())
        with self.assertRaisesRegex(MediaError, "header does not match"):
            self.run_sam(cut, seeds=1, ffmpeg=None)

    def test_a_non_ascii_case_path_is_refused_before_anything_is_written(self):
        case = Case.create(self.tmp / "Café case", case_id="MEDIA-2",
                           examiner=EXAMINER)
        with mock.patch.object(SA, "_windows", return_value=True), \
                mock.patch.object(SA, "_short_path", return_value=None):
            with self.assertRaisesRegex(MediaError, "outside plain ASCII"):
                L.run_sam(case, self.clip, text="x", model=self.model,
                          audiocpp=self.cli)
        self.assertFalse((case.root / "media").exists())
        self.assertFalse([r for r in case.custody.rows()
                          if r["action"].startswith("media.")])

    def test_a_child_is_never_started_toward_a_path_outside_the_case(self):
        log = io.BytesIO()
        with self.assertRaises(CasePathError):
            SA.run_process(list(self.cli) + ["--text", "x"], log=log,
                           timeout_s=5, writes=[self.tmp / "outside"],
                           guard=functools.partial(blocker.assert_case_path,
                                                   self.case.root))
        self.assertEqual(log.getvalue(), b"", "refused before it started")
        with self.assertRaises(CasePathError):
            SA.run_process(list(self.cli), log=log, timeout_s=5,
                           writes=[self.case.root / "x"], guard=None)

    def test_an_invented_stem_fed_back_without_its_sidecar_stays_invented(self):
        first = self.run_sam(seeds=1)
        target = next(Path(o["path"]) for o in first["outputs"]
                      if o["stem"] == "target")
        away = self.tmp / "loose"
        away.mkdir()
        kept_name = away / target.name                 # name, no sidecar
        shutil.copyfile(target, kept_name)
        again = self.run_sam(kept_name, seeds=1)
        self.assertEqual((again["upstream"]["tier"],
                          again["upstream"]["basis"]),
                         ("invented", "filename"))
        renamed = away / "radio_clean.wav"              # renamed, no sidecar
        shutil.copyfile(target, renamed)
        third = self.run_sam(renamed, seeds=1)
        self.assertEqual((third["upstream"]["tier"], third["upstream"]["basis"]),
                         ("invented", "hash"))
        # the same bytes are recorded in the first run (its target) and the
        # second (its input copy); either is a true answer
        self.assertIn(third["upstream"]["recipe_id"],
                      {first["recipe_id"], again["recipe_id"]})
        self.assertEqual(third["input"]["file"], "input.invented.wav")
        self.assertTrue(all(o["tier"] == "invented"
                            for o in third["outputs"]))
        plain = self.run_sam(seeds=1)
        self.assertEqual(plain["upstream"]["tier"], "")

    def test_the_first_hash_of_the_weights_honours_cancel(self):
        with self.assertRaises(Cancelled):
            self.run_sam(seeds=1, should_cancel=lambda: True)
        self.assertEqual(self.actions(), [])

    def test_a_bad_recipe_is_listed_as_unreadable_never_raised(self):
        good = self.run_sam(seeds=1)
        for name, body in (("sam-bad-json", "{not json"),
                           ("sam-bad-shape", json.dumps(
                               {"schema": 1,
                                "kind": "forensics_workshop.media.recipe",
                                "recipe_id": "x", "input_sha256": "",
                                "original": {}, "steps": "garbage",
                                "outputs": "garbage"})),
                           ("sam-bad-type", "[1, 2, 3]"),
                           ("sam-bad-prompt", json.dumps(
                               {"schema": 1,
                                "kind": "forensics_workshop.media.recipe",
                                "recipe_id": "y", "input_sha256": "",
                                "original": {}, "steps": [], "outputs": [],
                                "prompt": "a string where a dict goes"}))):
            folder = self.case.root / "media" / name
            folder.mkdir()
            (folder / "recipe.json").write_text(body)
        rows = {r["recipe_id"]: r for r in L.list_runs(self.case)}
        self.assertEqual(rows[good["recipe_id"]]["state"], "completed")
        for name in ("sam-bad-json", "sam-bad-shape", "sam-bad-type",
                     "sam-bad-prompt"):
            self.assertEqual(rows[name]["state"], "unreadable", name)
            self.assertTrue(rows[name]["error"])

    def test_a_runtime_that_writes_nothing_is_a_failure(self):
        with self.assertRaisesRegex(MediaError, "wrote no target.wav"):
            self.run_sam(text="NOTHING", seeds=1)

    def test_cancel_kills_the_child_and_says_so(self):
        flag = threading.Event()
        threading.Timer(1.0, flag.set).start()
        started = time.monotonic()
        with self.assertRaises(Cancelled):
            self.run_sam(text="SLEEP", seeds=1, should_cancel=flag.is_set)
        self.assertLess(time.monotonic() - started, 15)
        self.assertEqual(self.actions()[-1], "media.failed")

    def test_a_hung_child_is_stopped_at_its_timeout(self):
        with self.assertRaisesRegex(MediaError, "ran past"):
            self.run_sam(text="SLEEP", seeds=1, timeout_s=1.0)

    def test_refusals_before_anything_is_written(self):
        for kwargs, needle in (({"text": ""}, "requires --text"),
                               ({"seeds": 9}, "1 to 5"),
                               ({"seeds": [1, 1]}, "distinct"),
                               ({"anchors": ["+2:1"]}, "not a span"),
                               ({"audiocpp": str(self.tmp / "nope.exe")},
                                "get_sam.bat")):
            with self.assertRaisesRegex(MediaError, needle, msg=kwargs):
                self.run_sam(**kwargs)
        self.assertEqual(self.actions(), [])
        self.assertFalse((self.case.root / "media").exists())

    def test_a_file_inside_a_disk_image_is_recovered_first(self):
        disk = self.tmp / "disk.dd"
        disk.write_bytes(b"\x00" * 1024 * 1024)
        item = self.case.add_image(disk)
        with self.assertRaisesRegex(MediaError, "Recover the file"):
            self.run_sam("Users/a.wav", evidence_id=item.id)

    def test_an_examiner_chosen_file_is_named_as_such(self):
        loose = M.write_wav(self.tmp / "elsewhere" / "radio.wav",
                            M.tone(0.5, total=1.0))
        result = self.run_sam(loose, seeds=1)
        self.assertEqual(result["original"]["kind"], "examiner-chosen")
        self.assertTrue(blocker.is_inside(result["folder"], self.case.root))

    def test_separating_an_invented_file_keeps_it_invented(self):
        first = self.run_sam(seeds=1)
        target = next(o["path"] for o in first["outputs"]
                      if o["stem"] == "target")
        second = self.run_sam(target, seeds=1)
        self.assertEqual(second["upstream"]["tier"], "invented")
        self.assertEqual(second["input"]["file"], "input.invented.wav")
        self.assertTrue(all(o["tier"] == "invented"
                            for o in second["outputs"]))

    def test_replay_from_the_untouched_original(self):
        first = self.run_sam(seeds=2)
        report = L.replay(self.case, first["recipe_id"], audiocpp=self.cli,
                          ffmpeg=self.ffmpeg)
        self.assertTrue(report["reproduced"])
        self.assertEqual({r["result"] for r in report["outputs"]},
                         {"bit-exact"})
        self.assertEqual(report["tolerance"]["generative_db"],
                         L.REPLAY_TOLERANCE_DB)
        replayed = L.load_run(self.case, report["replay"])
        self.assertEqual(replayed["replay_of"], first["recipe_id"])
        self.assertTrue((Path(report["folder"]) / "replay.json").is_file())

    def test_replay_is_refused_when_the_original_changed(self):
        first = self.run_sam(seeds=1)
        self.clip.write_bytes(M.wav_bytes(M.tone(2.0)))
        with self.assertRaisesRegex(MediaError, "has changed"):
            L.replay(self.case, first["recipe_id"], audiocpp=self.cli)

    def test_compare_stems_states_its_tolerance(self):
        a = M.write_wav(self.tmp / "a.wav", M.tone(1.0, amp=0.5), fmt="float32")
        b = M.write_wav(self.tmp / "b.wav", M.tone(1.0, amp=0.52), fmt="float32")
        c = M.write_wav(self.tmp / "c.wav", M.tone(1.0, amp=0.25), fmt="float32")
        self.assertEqual(L.compare_stems(a, a)["result"], "bit-exact")
        self.assertEqual(L.compare_stems(a, b)["result"], "within tolerance")
        self.assertEqual(L.compare_stems(a, c)["result"], "differs")


class LongRecordings(_Fixture):
    """SAM Audio takes at most 400 s at once (10,000 frames of 40 ms) — a
    99 min 55 s video failed on it, 2026-10-09. Longer recordings run as
    overlapping windows, joined with a crossfade; here with windows of
    a second so the suite stays fast."""

    SMALL = {"window_s": 1.0, "overlap_s": 0.4, "once_limit_s": 1.2}

    def test_the_limit_is_the_models_own(self):
        self.assertEqual(SA.MAX_AUDIO_S, 400.0)
        self.assertLess(L.ONCE_LIMIT_S, SA.MAX_AUDIO_S)
        self.assertLessEqual(L.WINDOW_S, L.ONCE_LIMIT_S)

    def test_the_plan_covers_the_recording_in_full_windows(self):
        self.assertEqual(L.plan_windows(390.0), [(0.0, 390.0)])
        spans = L.plan_windows(5995.04)          # Bill's 99 min 55 s video
        self.assertEqual(len(spans), 18)
        self.assertEqual(spans[0], (0.0, 360.0))
        self.assertEqual(spans[-1][1], 5995.04)
        for (a, b), (c, d) in zip(spans, spans[1:]):
            self.assertAlmostEqual(b - a, L.WINDOW_S)
            self.assertGreaterEqual(b - c, L.OVERLAP_S - 1e-6, "overlap")
        self.assertAlmostEqual(spans[-1][1] - spans[-1][0], L.WINDOW_S)
        fades = L.crossfades(spans)
        self.assertEqual(len(fades), 17)
        self.assertEqual(fades[0], (349.0, 351.0))
        for (f0, f1), (_a, b), (c, _d) in zip(fades, spans, spans[1:]):
            self.assertTrue(c <= f0 < f1 <= b)
        with self.assertRaises(MediaError):
            L.plan_windows(500, window_s=360, overlap_s=360)

    def test_anchors_move_into_each_windows_time(self):
        from forensics_workshop.media import separator as SEP
        anchors = SEP.check_anchors(["+1.5:2.5", "-0.1:0.3"])
        self.assertEqual([a.as_list() for a in
                          L.window_anchors(anchors, 1.2, 2.2)],
                         [["+", 0.3, 1.0]])
        self.assertEqual([a.as_list() for a in
                          L.window_anchors(anchors, 0.0, 1.0)],
                         [["-", 0.1, 0.3]])
        self.assertEqual(L.window_anchors(anchors, 2.6, 3.0), ())

    def test_windows_are_joined_with_a_crossfade(self):
        """Three windows of constant value: each one's own stretch exactly,
        a straight-line ramp where two meet."""
        rate = 1000
        folder = self.case.root / "media" / "join-test"
        folder.mkdir(parents=True)
        parts = []
        for k, value in enumerate((1.0, 2.0, 4.0)):
            parts.append(M.write_wav(folder / f"w{k}.wav", [value] * 1000,
                                     rate=rate, fmt="float32"))
        spans = [(0.0, 1.0), (0.6, 1.6), (1.2, 2.2)]
        fades = L.crossfades(spans, crossfade_s=0.2)
        self.assertEqual(fades, [(0.7, 0.9), (1.3, 1.5)])
        join = L._Join(self.case, folder / "joined.wav", rate, 2200)
        for k, path in enumerate(parts):
            fade = fades[k] if k < len(fades) else None
            join.add(path, int(spans[k][0] * rate),
                     (int(fade[0] * rate), int(fade[1] * rate)) if fade
                     else None)
        join.close()
        from forensics_workshop.media import wav as W
        info = W.read_info(folder / "joined.wav")
        self.assertEqual((info.frames, info.rate, info.kind), (2200, 1000,
                                                               "float"))
        x = [v for block in W.iter_mono(folder / "joined.wav") for v in block]
        self.assertEqual(x[:700], [1.0] * 700)
        self.assertEqual(x[900:1300], [2.0] * 400)
        self.assertEqual(x[1500:], [4.0] * 700)
        self.assertAlmostEqual(x[700], 1.0 + 0.5 / 200, places=5)
        self.assertAlmostEqual(x[799], 1.5, places=2)
        self.assertAlmostEqual(x[1399], 2.0 + 2.0 * 99.5 / 200, places=5)
        ramp = x[700:900]
        self.assertTrue(all(b > a for a, b in zip(ramp, ramp[1:])))

    def test_a_long_recording_runs_window_by_window(self):
        result = self.run_sam(anchors=["+1.5:2.5"], seeds=[1, 2], **self.SMALL)
        self.assertEqual(result["state"], "completed")
        folder = Path(result["folder"])
        self.assertFalse((folder / "windows").exists(), "window copies gone")
        self.assertFalse(list(folder.glob("work-seed*")))
        steps = result["steps"]
        (cut,) = [s for s in steps if s["tool"] == L.WINDOW_TOOL]
        self.assertEqual(cut["params"]["windows"],
                         [[0.0, 1.0], [0.6, 1.6], [1.2, 2.2], [1.8, 2.8],
                          [2.0, 3.0]])
        self.assertEqual(cut["tier"], "measured")
        self.assertEqual(len(cut["outputs"]), 5)
        joins = [s for s in steps if s["tool"] == L.JOIN_TOOL]
        self.assertEqual(len(joins), 2, "one join per seed")
        sams = [s for s in steps if s["tool"] == "audiocpp_cli sam_audio"]
        self.assertEqual(len(sams[0]["params"]["windows"]), 5)
        self.assertEqual(len(sams[0]["outputs"]), 10)
        self.assertEqual(sams[0]["params"]["windows"][2]["anchors"],
                         [["+", 0.3, 1.0]])
        from forensics_workshop.media import wav as W
        for out in result["outputs"]:
            if out["stem"] in ("target", "residual"):
                info = W.read_info(out["path"])
                self.assertEqual(info.frames, 3 * 48000, out["file"])
                self.assertEqual(out["tier"], "invented")
                tools = [steps[i]["tool"] for i in out["chain"]]
                self.assertEqual(tools[-3:], [L.WINDOW_TOOL,
                                              "audiocpp_cli sam_audio",
                                              L.JOIN_TOOL])
                side = json.loads((folder / out["sidecar"]).read_text())
                self.assertEqual(side["tier"], "invented")
        log = (folder / "seed1.audiocpp.log").read_text()
        self.assertEqual(log.count("FAKE-ARGV "), 5)
        self.assertIn('anchors=[[\\"+\\",0.3,1.0]]', log)
        self.assertTrue(self.case.custody.verify().ok)
        derived = [r for r in self.case.custody.rows()
                   if r["action"] == "media.derived"]
        self.assertEqual(derived[-1]["detail"]["windows"], 5)
        self.assertTrue(any("window copies were discarded" in n
                            for n in result["notes"]))

    def test_a_windowed_run_replays_with_the_same_windows(self):
        first = self.run_sam(seeds=1, **self.SMALL)
        report = L.replay(self.case, first["recipe_id"], audiocpp=self.cli,
                          ffmpeg=self.ffmpeg)
        self.assertTrue(report["reproduced"], report["outputs"])
        again = L.load_run(self.case, report["replay"])
        (cut,) = [s for s in again["steps"] if s["tool"] == L.WINDOW_TOOL]
        self.assertEqual(cut["params"]["window_s"], 1.0)
        self.assertEqual(len(cut["params"]["windows"]), 5)

    def test_a_short_recording_is_one_pass_as_before(self):
        result = self.run_sam(seeds=1)
        self.assertFalse([s for s in result["steps"]
                          if s["tool"] in (L.WINDOW_TOOL, L.JOIN_TOOL)])


class TheGpuAndTheLog(_Fixture):
    """2026-10-09: ATK ran SAM for hours on a CPU build get_sam.bat had
    fallen back to, with nothing on screen and a log that just stopped, and
    audio.cpp unpacking into %TEMP% in the Windows profile."""

    def _build_file(self, **fields):
        lines = [f"{k}={v}" for k, v in fields.items()]
        (self.tmp / "bin" / SA.BUILD_FILE).write_text("\n".join(lines) + "\n",
                                                      encoding="utf-8")

    def test_a_cpu_build_is_refused_before_anything_is_written(self):
        self._build_file(tag="v0.9.0", backend="cpu",
                         gpu_build="cuda failed - see logs\\get_sam-build.log")
        with self.assertRaisesRegex(MediaError, "refuses to run on the CPU") \
                as caught:
            self.run_sam(seeds=1)
        self.assertIn("cuda failed", str(caught.exception))
        self.assertIn("get_sam.bat /rebuild", str(caught.exception))
        self.assertEqual(self.actions(), [])
        self.assertFalse((self.case.root / "media").exists())

    def test_the_cpu_runs_only_when_asked_for(self):
        self._build_file(tag="v0.9.0", backend="cpu")
        lines = []
        result = self.run_sam(seeds=1, allow_cpu=True, progress=lines.append)
        self.assertEqual(result["state"], "completed")
        self.assertIn("--backend cpu", " ".join(result["steps"][-1]["params"]
                                                ["argv"]))
        self.assertTrue(any("CPU — no GPU" in l for l in lines), lines)
        self.assertFalse(any("on the GPU" in l for l in lines), lines)

    def test_the_negative_control_refuses_a_cpu_build_too(self):
        self._build_file(backend="cpu")
        noise = M.write_wav(self.tmp / "noise.wav", M.tone(1.0, amp=0.01))
        with self.assertRaisesRegex(MediaError, "refuses to run on the CPU"):
            L.negative_control(noise, out_dir=self.tmp / "harness",
                               model=self.model, audiocpp=self.cli, seeds=1)
        self.assertFalse((self.tmp / "harness").exists())

    def test_the_child_temp_is_beside_the_runtime_never_the_profile(self):
        result = self.run_sam(seeds=1)
        log = (Path(result["folder"]) / "seed1.audiocpp.log").read_text(
            encoding="utf-8")
        line = next(l for l in log.splitlines() if l.startswith("FAKE-TEMP "))
        scratch = SA.scratch_path(self.cli)
        self.assertEqual(Path(line[len("FAKE-TEMP "):]), scratch)
        self.assertTrue(scratch.is_dir())
        self.assertEqual(scratch.parent, (self.tmp / "bin").resolve())
        self.assertEqual(result["separator"]["scratch"], os.fspath(scratch))

    def test_the_scratch_guard_takes_exactly_one_folder(self):
        with self.assertRaisesRegex(MediaError, "only ever"):
            SA.assert_runtime_scratch(self.cli, self.tmp / "elsewhere")
        inside = self.case.root / "bin"
        inside.mkdir()
        fake = [self.cli[0], os.fspath(inside / "audiocpp_cli.exe")]
        with self.assertRaisesRegex(MediaError, "inside the case"):
            SA.assert_runtime_scratch(fake, inside / "tmp")

    def test_every_log_ends_saying_how_the_child_ended(self):
        result = self.run_sam(seeds=1)
        log = (Path(result["folder"]) / "seed1.audiocpp.log").read_text(
            encoding="utf-8").splitlines()
        self.assertTrue(log[-1].startswith(SA.OWN_LINE), log[-1])
        self.assertIn("exited 0", log[-1])
        with self.assertRaises(MediaError) as caught:
            self.run_sam(text="FAIL", seeds=1)
        # The examiner hears audio.cpp's words, never our own footer.
        self.assertIn("out of memory", str(caught.exception))
        self.assertNotIn(SA.OWN_LINE, str(caught.exception))
        failed = sorted((self.case.root / "media").glob(
            "*/seed1.audiocpp.log"))
        tails = [p.read_text(encoding="utf-8").splitlines()[-1]
                 for p in failed]
        self.assertTrue(any("exited with code 3" in t for t in tails), tails)

    def test_a_killed_child_says_it_was_killed(self):
        with self.assertRaises(MediaError):
            self.run_sam(text="SLEEP", seeds=1, timeout_s=1.0)
        log = next((self.case.root / "media").glob("*/seed1.audiocpp.log"))
        last = log.read_text(encoding="utf-8").splitlines()[-1]
        self.assertIn("KILLED", last)
        self.assertIn("ran past the 1 s limit", last)

    def test_a_long_run_beats_a_heartbeat_with_the_last_thing_it_said(self):
        beats, stages = [], []
        with mock.patch.object(SA, "HEARTBEAT_S", 0.3):
            with self.assertRaises(MediaError):
                self.run_sam(text="SLEEP", seeds=1, timeout_s=2.0,
                             progress=stages.append, heartbeat=beats.append)
        self.assertTrue(beats, "no heartbeat while the child ran")
        self.assertIn("SAM Audio seed 1 (1 of 1) on CUDA (GPU) — running",
                      beats[-1])
        self.assertIn("audio.cpp: FAKE-TEMP", beats[-1])
        # Heartbeats go only where they were sent: a host that logs the
        # stage lines is not flooded with them.
        self.assertFalse(any("running" in s for s in stages), stages)

    def test_last_line_drops_the_stamp_and_our_own_lines(self):
        path = self.tmp / "x.log"
        path.write_text("$ cli --x\n[TIMING ts=20261009-153949] sam_audio."
                        "codec.encoder.graph_buffer_mb 650.15\n"
                        f"{SA.OWN_LINE} the child exited 0\n", encoding="utf-8")
        self.assertEqual(SA.last_line(path),
                         "sam_audio.codec.encoder.graph_buffer_mb 650.15")
        path.write_text("$ cli --x\n", encoding="utf-8")
        self.assertEqual(SA.last_line(path), "")

    def test_labels_and_the_build_sentence(self):
        self.assertEqual(SA.backend_label("cuda"), "CUDA (GPU)")
        self.assertEqual(SA.backend_label("cpu"), "CPU — no GPU")
        self.assertIn("unknown", SA.build_sentence(self.cli))
        self._build_file(tag="v0.9.0", backend="vulkan", built="Fri 10/09",
                         gpu_build="cuda: toolkit not found")
        self.assertEqual(SA.build_sentence(self.cli),
                         "built for vulkan, v0.9.0, on Fri 10/09 — GPU build: "
                         "cuda: toolkit not found")
        self.assertEqual(SA.clock(48), "48 s")
        self.assertEqual(SA.clock(245), "4 min 05 s")
        self.assertEqual(SA.clock(3720), "1 h 02 min")


class CommandLine(_Fixture):
    def _cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_media_sam_list_and_weights(self):
        # The command line takes an executable path; here "FAKE" stands for
        # the fake's argv prefix, which then runs through the same Popen.
        with mock.patch.object(SA, "runtime_argv",
                               side_effect=lambda a: list(self.cli)
                               if a == "FAKE" else [os.fspath(a)]):
            code, out, err = self._cli(
                "media-sam", str(self.case.root), "calls/clip.wav",
                "--evidence", "E001", "--examiner", EXAMINER,
                "--text", "man speaking", "--anchor", "+0.1:0.9",
                "--anchor=-2:2.5", "--seeds", "2", "--model", str(self.model),
                "--audiocpp", "FAKE")
        self.assertEqual(code, 0, err)
        self.assertIn("INVENTED TIER", err)
        result = json.loads(out)
        self.assertEqual(result["prompt"]["anchors"],
                         [["+", 0.1, 0.9], ["-", 2.0, 2.5]])
        self.assertNotIn("series", result["disagreement"])
        code, out, _err = self._cli("media-list", str(self.case.root),
                                    "--examiner", EXAMINER)
        self.assertEqual(code, 0)
        self.assertIn(result["recipe_id"], out)
        code, out, _err = self._cli("media-weights", str(self.model))
        self.assertEqual(json.loads(out)["weights"]["state"], "unverified")

    def test_a_refusal_is_a_sentence_and_exit_three(self):
        code, _out, err = self._cli(
            "media-sam", str(self.case.root), str(self.clip), "--examiner",
            EXAMINER, "--text", "x", "--model", str(self.model),
            "--audiocpp", str(self.tmp / "missing.exe"))
        self.assertEqual(code, 3)
        self.assertIn("refused: audiocpp_cli is not at", err)

    def test_a_cpu_build_needs_allow_cpu_on_the_command_line(self):
        (self.tmp / "bin" / SA.BUILD_FILE).write_text("backend=cpu\n",
                                                      encoding="utf-8")
        args = ("media-sam", str(self.case.root), str(self.clip),
                "--examiner", EXAMINER, "--text", "man speaking", "--seeds",
                "1", "--model", str(self.model), "--audiocpp", "FAKE")
        with mock.patch.object(SA, "runtime_argv",
                               side_effect=lambda a: list(self.cli)
                               if a == "FAKE" else [os.fspath(a)]):
            code, _out, err = self._cli(*args)
            self.assertEqual(code, 3)
            self.assertIn("refuses to run on the CPU", err)
            code, out, err = self._cli(*args, "--allow-cpu")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["state"], "completed")


if __name__ == "__main__":
    unittest.main()
