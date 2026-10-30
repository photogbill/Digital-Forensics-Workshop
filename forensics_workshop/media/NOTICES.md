# Notices — media recovery (FORENSICS_PLAN §12.9, §12.10, §13)

Nothing below is bundled in this repository. The engine runs these
components as **separate processes** with weights the operator downloads;
these notices travel with the code that drives them.

**SAM Audio and audio.cpp were removed on 2026-10-29** (Bill's decision): no
code here runs them any longer, so their notices are gone with them. A case
made before then may still hold SAM outputs; they keep their `.invented`
names and recipes.

## FFmpeg

Video input is reduced to audio by an FFmpeg executable the host passes in
(ATK: `bin\ffmpeg\ffmpeg.exe`), run as a separate process; nothing of it is
linked or shipped by this engine. Its licence is ATK's review (§1.1).

## SpeechBrain and its models — Apache License 2.0

`vp_worker.py` and `restore_worker.py` import **SpeechBrain 1.1.1**
(<https://github.com/speechbrain/speechbrain>, Apache-2.0), installed by
ATK's `get_speechbrain.bat` into `envs\atk_audio`, and load four models it
downloads from Hugging Face into `models\speechbrain\` — each released by
the SpeechBrain project under **Apache-2.0** (model cards, read
2026-10-09):

| model | use | trained on |
|---|---|---|
| `speechbrain/spkrec-ecapa-voxceleb` | voice comparison (§13.1) | VoxCeleb 1 + 2 |
| `speechbrain/metricgan-plus-voicebank` | speech enhancement | VoiceBank-DEMAND |
| `speechbrain/sepformer-dns4-16k-enhancement` | speech enhancement | DNS Challenge 4 |
| `speechbrain/sepformer-whamr16k` | two-voice separation | WHAMR! |

`get_speechbrain.bat` saves SpeechBrain's licence text as
`models\speechbrain\LICENSE-speechbrain.txt`. SpeechBrain asks that work
using it cite "SpeechBrain: A General-Purpose Speech Toolkit" (Ravanelli et
al., 2021) and "Open-Source Conversational AI with SpeechBrain 1.0"
(Ravanelli et al., 2024).

## LibriSpeech — CC BY 4.0

`get_speechbrain.bat` fetches LibriSpeech **test-clean** from OpenSLR
(<https://www.openslr.org/12>) to fit the first voice calibration. It is
used only on the examiner's machine and never shipped. Attribution:
V. Panayotov, G. Chen, D. Povey, S. Khudanpur, "LibriSpeech: an ASR corpus
based on public domain audio books", ICASSP 2015.

## DeepFilterNet 3 — Hendrik Schröter, MIT OR Apache-2.0

Restore Audio's "Speech enhancement — DeepFilterNet 3" option runs
`deep-filter.exe` (<https://github.com/Rikorose/DeepFilterNet>, release
**v0.5.6**, the DeepFilterNet3 model built into the program) as a separate
process. It is dual-licensed **MIT or Apache-2.0** at the user's option
("Copyright (c) 2021 Hendrik Schröter"). ATK's `get_speechbrain.bat`
downloads `deep-filter-0.5.6-x86_64-pc-windows-msvc.exe`, refuses it unless
its SHA-256 is `75e11fa16445f560cb6b021521ddb89e89270d13b83089705d98776f58fd7915`,
and saves both licence texts beside it in `bin\deepfilter\`. Citations the
authors ask for: H. Schröter, A. N. Escalante-B., T. Rosenkranz, A. Maier,
"DeepFilterNet: A Low Complexity Speech Enhancement Framework for Full-Band
Audio based on Deep Filtering", ICASSP 2022; and for the DeepFilterNet3
model, H. Schröter, T. Rosenkranz, A. N. Escalante-B., A. Maier,
"DeepFilterNet: Perceptually Motivated Real-Time Speech Enhancement",
INTERSPEECH 2023. **Made for speech** — the option and its outputs say so.

## RNNoise — FFmpeg's arnndn filter and the rnnoise-models

The "Speech denoiser — RNNoise" option is FFmpeg's `arnndn` filter (part of
FFmpeg; RNNoise by Jean-Marc Valin, BSD-3-Clause) with the model
`somnolent-hogwash-2018-09-01/sh.rnnn` from
<https://github.com/GregorR/rnnoise-models> (commit
3eee541a283fd3b8f81b85b1748e3b9ccbefa04d), whose README states that the
models are not creative work and **not subject to copyright**.
`get_speechbrain.bat` saves the model to `models\rnnoise\sh.rnnn` only if its
SHA-256 is `70bb6685eb0c2a1d18e2918dca3fbfbd39317010b1802eb1b6ea73a92f3fdec0`,
with that README beside it. **Made for speech** — the option and its outputs
say so.
