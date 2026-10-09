# Notices — media recovery (FORENSICS_PLAN §12.9, §12.10)

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
