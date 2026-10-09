"""Media recovery's pure parts: the WAV reader, the tiers, anchors, and seed
disagreement (FORENSICS_PLAN §12.2, §12.9). No subprocess, no GPU."""

from __future__ import annotations

import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from _support import TempDirCase

import mediasynth as M
from forensics_workshop import blocker
from forensics_workshop.errors import MediaError
from forensics_workshop.media import disagreement as D
from forensics_workshop.media import recipe as R
from forensics_workshop.media import separator as S
from forensics_workshop.media import wav as W


def _has_numpy() -> bool:
    return D._numpy() is not None


COPY = "forensics_workshop read-only door (hashed copy)"
SAM = "audiocpp_cli sam_audio"


class WavReader(TempDirCase):
    """PCM16 and IEEE float32 — audio.cpp writes both — and the rest."""

    def test_pcm16_mono_header_and_level(self):
        p = M.write_wav(self.tmp / "a.wav", M.tone(1.0), fmt="pcm16")
        info = W.read_info(p)
        self.assertEqual((info.kind, info.bits, info.channels, info.rate,
                          info.frames), ("pcm", 16, 1, 48000, 48000))
        _info, levels = W.window_levels(p, 0.25)
        self.assertEqual(len(levels), 4)
        for level in levels:         # a 0.5-amplitude sine: -9.03 dBFS
            self.assertAlmostEqual(level, 20 * math.log10(0.5 / math.sqrt(2)),
                                   delta=0.05)

    def test_float32_as_audiocpp_writes_it_with_a_fact_chunk(self):
        loud = [1.5 * s for s in M.tone(0.5, amp=1.0)]     # above full scale
        p = M.write_wav(self.tmp / "f.wav", loud, fmt="float32")
        raw = p.read_bytes()
        self.assertEqual(raw[20:22], b"\x03\x00", "format tag 3 (IEEE float)")
        self.assertIn(b"fact", raw[:64])
        info = W.read_info(p)
        self.assertEqual((info.kind, info.bits), ("float", 32))
        peak = max(max(abs(v) for v in block) for block in W.iter_mono(p))
        self.assertAlmostEqual(peak, 1.5, places=4,
                               msg="float is read as stored, never clipped")

    def test_extensible_float_pcm24_pcm32_and_u8(self):
        for fmt in ("float32x", "pcm24", "pcm32", "u8"):
            p = M.write_wav(self.tmp / f"{fmt}.wav", M.tone(0.5), fmt=fmt)
            info, levels = W.window_levels(p, 0.25)
            self.assertEqual(len(levels), 2, fmt)
            self.assertAlmostEqual(levels[0], -9.03, delta=0.3 if fmt == "u8"
                                   else 0.05, msg=fmt)

    def test_stereo_is_mixed_to_mono(self):
        left = M.tone(0.25, amp=0.5)
        frames = [v for s in left for v in (s, -s)]          # cancels
        p = M.write_wav(self.tmp / "st.wav", frames, channels=2)
        _info, levels = W.window_levels(p, 0.25)
        self.assertLess(levels[0], -80)

    def test_a_cut_off_recording_is_read_as_far_as_it_goes(self):
        p = M.write_wav(self.tmp / "cut.wav", M.tone(1.0))
        data = p.read_bytes()
        p.write_bytes(data[:len(data) // 2])
        info = W.read_info(p)
        self.assertTrue(info.notes and "cut off" in info.notes[0])
        self.assertLess(info.frames, 48000)

    def test_a_length_never_filled_in_is_noted(self):
        for placeholder in (0, 0xFFFFFFFF):
            raw = bytearray(M.wav_bytes(M.tone(0.5)))
            at = raw.index(b"data") + 4
            raw[at:at + 4] = placeholder.to_bytes(4, "little")
            p = self.tmp / f"ph{placeholder}.wav"
            p.write_bytes(bytes(raw))
            info = W.read_info(p)
            self.assertTrue(info.notes and "never filled in" in info.notes[0])
            self.assertEqual(info.frames, 24000, "read to the end of the file")

    def test_empty_and_non_finite_stems_are_broken_not_silent(self):
        empty = M.write_wav(self.tmp / "empty.wav", [], fmt="float32")
        with self.assertRaisesRegex(MediaError, "0 frames"):
            W.check_stem(empty)
        nan = M.write_wav(self.tmp / "nan.wav", [float("nan")] * 4800,
                          fmt="float32")
        with self.assertRaisesRegex(MediaError, "non-finite"):
            W.check_stem(nan)
        with self.assertRaisesRegex(MediaError, "non-finite"):
            W.window_levels(nan)
        if _has_numpy():
            with self.assertRaisesRegex(MediaError, "non-finite"):
                W.read_array(nan, D._numpy())
        good = M.write_wav(self.tmp / "ok.wav", M.tone(0.2), fmt="float32")
        self.assertEqual(W.check_stem(good).frames, 9600)

    def test_refusals_are_sentences(self):
        (self.tmp / "x.wav").write_bytes(b"ID3\x04" + b"\x00" * 60)
        with self.assertRaisesRegex(MediaError, "not a WAV"):
            W.read_info(self.tmp / "x.wav")
        adpcm = bytearray(M.wav_bytes(M.tone(0.1)))
        adpcm[20:22] = b"\x02\x00"
        (self.tmp / "adpcm.wav").write_bytes(bytes(adpcm))
        with self.assertRaisesRegex(MediaError, "format tag 2"):
            W.read_info(self.tmp / "adpcm.wav")

    def test_it_reads_through_the_read_only_door(self):
        p = M.write_wav(self.tmp / "door.wav", M.tone(0.25))
        real = blocker.open_evidence
        with mock.patch.object(blocker, "open_evidence",
                               side_effect=real) as door:
            W.window_levels(p)
        self.assertGreaterEqual(door.call_count, 2)

    @unittest.skipUnless(_has_numpy(), "numpy is not installed here")
    def test_the_numpy_reader_agrees_with_the_stdlib_one(self):
        np = D._numpy()
        for fmt in ("pcm16", "float32", "pcm24"):
            p = M.write_wav(self.tmp / f"n{fmt}.wav", M.tone(0.3), fmt=fmt)
            _i, arr = W.read_array(p, np)
            flat = [v for block in W.iter_mono(p) for v in block]
            self.assertEqual(len(arr), len(flat))
            self.assertLess(float(np.max(np.abs(arr - np.array(flat)))), 1e-6)


class Tiers(unittest.TestCase):
    def test_an_output_carries_the_highest_tier_of_its_chain(self):
        self.assertEqual(R.TIERS, ("measured", "recovered", "cleaned",
                                   "inferred", "invented"))
        chain = [R.step(COPY, tier="measured"),
                 R.step(SAM, tier="invented"),
                 R.step("ffmpeg", tier="measured")]
        self.assertEqual(R.output_tier(chain), "invented",
                         "a later faithful step cannot launder a tier down")
        self.assertEqual(R.output_tier(chain[:1]), "measured")
        self.assertEqual(R.output_tier(chain[:1], "invented"), "invented",
                         "an input that was itself invented stays invented")
        with self.assertRaises(MediaError):
            R.highest_tier(["measured", "made-up"])

    def test_invented_is_in_the_filename_and_only_there(self):
        self.assertEqual(R.invented_name("target", 2),
                         "seed2.target.invented.wav")
        self.assertEqual(R.output_name("residual", "invented", 3),
                         "seed3.residual.invented.wav")
        self.assertEqual(R.output_name("input", "invented"),
                         "input.invented.wav")
        for tier in ("measured", "recovered", "cleaned", "inferred"):
            self.assertNotIn("invented", R.output_name("input", tier))
        self.assertEqual(R.sidecar_path("x/seed1.target.invented.wav").name,
                         "seed1.target.invented.wav.recipe.json")

    def test_a_recipe_whose_tier_was_lowered_is_refused(self):
        steps = [R.step(COPY, tier="measured"),
                 R.step(SAM, tier="invented")]
        good = {"schema": 1, "kind": "forensics_workshop.media.recipe",
                "recipe_id": "sam-x", "input_sha256": "a" * 64,
                "original": {}, "steps": steps, "upstream_tier": "",
                "outputs": [{"file": "seed1.target.invented.wav",
                             "tier": "invented", "chain": [0, 1]}]}
        self.assertIs(R.check_recipe(good), good)
        edited = json.loads(json.dumps(good))
        edited["outputs"][0]["tier"] = "measured"
        with self.assertRaisesRegex(MediaError, "never lowered"):
            R.check_recipe(edited)

    def test_a_tool_sets_the_floor_of_its_step(self):
        with self.assertRaisesRegex(MediaError, "never below 'invented'"):
            R.step(SAM, tier="measured")
        with self.assertRaisesRegex(MediaError, "not a registered media tool"):
            R.step("some new denoiser", tier="measured")
        self.assertEqual(R.tool_floor("audiocpp_cli sam_audio v2"), "invented")

    def _recipe(self):
        steps = [R.step(COPY, tier="measured"), R.step(SAM, tier="invented")]
        return {"schema": 1, "kind": "forensics_workshop.media.recipe",
                "recipe_id": "sam-x", "input_sha256": "a" * 64,
                "original": {}, "steps": steps, "upstream_tier": "",
                "tier": "invented",
                "outputs": [{"file": "input.wav", "tier": "measured",
                             "chain": [0]},
                            {"file": "seed1.target.invented.wav",
                             "tier": "invented", "chain": [0, 1]}]}

    def test_an_edit_that_lowers_the_tool_and_the_output_is_refused(self):
        R.check_recipe(self._recipe())
        edited = self._recipe()
        edited["steps"][1]["tier"] = "measured"            # the SAM step
        edited["outputs"][1]["tier"] = "measured"
        edited["tier"] = "measured"
        with self.assertRaisesRegex(MediaError, "never below"):
            R.check_recipe(edited)

    def test_an_invented_name_is_invented_whatever_the_chain_says(self):
        edited = self._recipe()
        edited["outputs"][1].update(tier="measured", chain=[0])
        edited["tier"] = "measured"
        with self.assertRaisesRegex(MediaError, "never lowered"):
            R.check_recipe(edited)

    def test_the_recipe_tier_must_be_its_outputs_tier(self):
        edited = self._recipe()
        edited["tier"] = "measured"
        with self.assertRaisesRegex(MediaError, "its outputs make it"):
            R.check_recipe(edited)
        edited = self._recipe()
        edited["outputs"][1]["chain"] = [0, 7]
        with self.assertRaisesRegex(MediaError, "not in the recipe"):
            R.check_recipe(edited)

    def test_a_stem_that_lost_its_sidecar_is_invented_by_its_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            stem = M.write_wav(Path(tmp) / "seed2.target.invented.wav",
                               M.tone(0.1))
            self.assertEqual(R.upstream_of(stem), ("", "invented"))
            plain = M.write_wav(Path(tmp) / "clip.wav", M.tone(0.1))
            self.assertEqual(R.upstream_of(plain), ("", ""))
            # a sidecar edited to say "measured" is refused, not believed
            side = R.sidecar(recipe_id="sam-x", file=plain.name, sha256="b",
                             stem="target", seed=1, input_sha256="a",
                             original={},
                             chain=[R.step(COPY, tier="measured"),
                                    R.step(SAM, tier="invented")])
            side["tier"] = "measured"
            R.sidecar_path(plain).write_text(json.dumps(side))
            with self.assertRaisesRegex(MediaError, "never lowered"):
                R.upstream_of(plain)

    def test_a_sidecar_says_what_the_tier_means(self):
        side = R.sidecar(recipe_id="sam-x", file="seed1.target.invented.wav",
                         sha256="b" * 64, stem="target",
                         chain=[R.step(SAM, tier="invented")],
                         input_sha256="a" * 64, original={"kind": "evidence"},
                         seed=1)
        self.assertEqual(side["tier"], "invented")
        self.assertIn("never a reading", side["tier_note"])


class Anchors(unittest.TestCase):
    def test_spellings_and_the_rule(self):
        self.assertEqual(S.parse_anchor("+0.5:2.0").as_list(), ["+", 0.5, 2.0])
        self.assertEqual(S.parse_anchor("-3 4").as_list(), ["-", 3.0, 4.0])
        self.assertEqual(S.parse_anchor("+1.25-2").as_list(), ["+", 1.25, 2.0])
        self.assertEqual(S.make_anchor("exclude", "3", 4).sign, "-")
        for bad in ("0.5:2", "+2:1", "+1:1", "*1:2", "+a:b"):
            with self.assertRaises(MediaError, msg=bad):
                S.parse_anchor(bad)
        with self.assertRaisesRegex(MediaError, "after the recording ends"):
            S.check_anchors(["+5:6"], duration_s=4.0)
        self.assertEqual(len(S.check_anchors([("+", 0, 1), "-2:3"], 4.0)), 2)


class Disagreement(TempDirCase):
    def _targets(self, steady: bool) -> dict:
        out = {}
        for seed in (1, 2, 3):
            samples = M.tone(1.0, total=3.0)
            if not steady and seed == 2:
                extra = M.tone(0.5, freq=880, start=1.5, total=3.0)
                samples = [a + b for a, b in zip(samples, extra)]
            out[seed] = M.write_wav(self.tmp / f"s{seed}{steady}.wav",
                                    samples, fmt="float32")
        return out

    def test_identical_seeds_disagree_nowhere(self):
        for method in ("envelope", "bands") if _has_numpy() else ("envelope",):
            result = D.compare(self._targets(True), method=method)
            self.assertEqual(result["spans"], [], method)
            self.assertEqual(max(r["spread_db"] for r in result["series"]), 0,
                             method)
            self.assertIn("agreement, which is not proof", result["summary"])

    def test_one_seed_with_sound_where_another_is_silent_is_flagged(self):
        for method in ("envelope", "bands") if _has_numpy() else ("envelope",):
            result = D.compare(self._targets(False), method=method)
            self.assertEqual(len(result["spans"]), 1, method)
            span = result["spans"][0]
            self.assertEqual((span["start_s"], span["end_s"]), (1.5, 2.0))
            self.assertEqual(span["kind"], "presence")
            self.assertEqual((span["loud"], span["silent"]), ([2], [1, 3]))
            self.assertIn("seed 2 has sound where seed 1, 3 is silent",
                          D.span_sentence(span))
            self.assertEqual(result["method"],
                             D.BANDS if method == "bands" else D.ENVELOPE)

    def test_the_band_measure_sees_a_swap_the_envelope_cannot(self):
        if not _has_numpy():
            self.skipTest("numpy is not installed here")
        a = M.write_wav(self.tmp / "a.wav", M.tone(1.0, freq=300, amp=0.5))
        b = M.write_wav(self.tmp / "b.wav", M.tone(1.0, freq=5000, amp=0.5))
        env = D.compare({1: a, 2: b}, method="envelope")
        bands = D.compare({1: a, 2: b}, method="bands")
        self.assertEqual(env["spans"], [], "same loudness, so no envelope flag")
        self.assertTrue(bands["spans"], "different sound, so a band flag")

    def test_an_empty_target_is_a_broken_run_never_agreement(self):
        empty = M.write_wav(self.tmp / "e1.wav", [], fmt="float32")
        empty2 = M.write_wav(self.tmp / "e2.wav", [], fmt="float32")
        with self.assertRaisesRegex(MediaError, "empty target"):
            D.compare({1: empty, 2: empty2}, method="envelope")

    def test_one_seed_is_nothing_to_compare_not_agreement(self):
        result = D.compare({1: self._targets(True)[1]})
        self.assertEqual(result["spans"], [])
        self.assertIn("nothing to compare", result["summary"])

    def test_without_numpy_auto_falls_back_and_says_so(self):
        with mock.patch.object(D, "_numpy", return_value=None):
            self.assertEqual(D.method_available("auto"), "envelope")
            with self.assertRaisesRegex(MediaError, "needs numpy"):
                D.method_available("bands")
            result = D.compare(self._targets(False))
        self.assertEqual(result["method"], D.ENVELOPE)


if __name__ == "__main__":
    unittest.main()
