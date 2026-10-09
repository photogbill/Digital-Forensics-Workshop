# Notices — media recovery (FORENSICS_PLAN §12.9, §12.10, §13)

Nothing below is bundled in this repository. The engine runs these
components as **separate processes** with weights the operator downloads;
these notices travel with the code that drives them, and ATK's `get_sam.bat`
fetches the licence texts next to the weights it downloads.

## SAM Audio weights — Meta, SAM License (2025-11-19)

The `sam-audio-*.gguf` files from Hugging Face `audio-cpp/SAM-Audio-GGUF` are
Meta's SAM Audio checkpoints converted to GGUF. They are **subject to Meta's
SAM License**, supplied with the original checkpoint
(<https://github.com/facebookresearch/sam-audio/blob/main/LICENSE>; the same
text is the `LICENSE` file in the GGUF repository, which `get_sam.bat` saves
as `models\sam-audio\LICENSE-SAM.txt`).

The SAM License permits commercial use and derivatives, and **bans uses
related to military or warfare purposes, espionage, and ITAR-controlled
items**. ATK uses SAM Audio under an **owner exception** to its licence rule
(FORENSICS_PLAN §1.1, §12.0), granted by Bill on 2026-09-30 for
investigative leads and lifesaving recovery: *replace or remove it if ATK
goes to defense-related work.* SAM sits behind one adapter
(`forensics_workshop/media/sam_audio.py`) so that removal costs one adapter,
one manifest entry and one capability row.

**SAM Audio is acknowledged here as Meta's work.** "SAM Audio: Segment
Anything in Audio", Meta AI, December 2025 (arXiv 2512.18099).

## T5 text encoder — Google, Apache License 2.0

Each SAM Audio GGUF bundles the Google T5 Base text encoder and its
tokenizer, which retain their upstream **Apache-2.0** licence. The notice is
the `LICENSE-T5` file in the GGUF repository, saved by `get_sam.bat` as
`models\sam-audio\LICENSE-T5.txt`.

## audio.cpp — ShugoAI LLC, Apache License 2.0

`audiocpp_cli` is built from <https://github.com/0xShug0/audio.cpp>, tag
**v0.9.0** (commit 795c45fbde0a7d29c93b22199728ff5caaec02e5), under the
**Apache License, Version 2.0** — "Copyright 2026 ShugoAI LLC". `get_sam.bat`
copies the repository's `LICENSE` beside the executable as
`bin\audiocpp\LICENSE-audio.cpp.txt`. audio.cpp's own statement: model
weights keep the licence of their original release, separate from
audio.cpp's licence.

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
