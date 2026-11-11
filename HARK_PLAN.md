# HARK — pulling voices and sounds out of noise

## Build status — 2026-11-11

**Built: increments 1–5 of the build order below, Move 3 (with M4), Move 7
part one and Move 8** — the hunter and surrogates, the per-file CEP, chain
choice on injected phrases, the auditor, Move 2 (warp and cyclic
extraction), the denoiser trained on the file itself, the speaker loop's
pitch-range narrowing, and the census of other sounds. **Not built: Move 4**
(the generative lane — it needs a speech prior trained on your GPU) and the
mad moves other than M4.

Tiers: hunt, calibrate, loop, census, score and audit are **Measured**;
Move 2's outputs and the machine cancellation are **Cleaned**; Move 3's
outputs are **Inferred**.

| Where | What |
| --- | --- |
| `forensics_workshop/media/hark.py` | The engine: eight stages (hunt, calibrate, loop, extract, census, selftrain, score, audit), each checkpointed in `hark.json` (a stopped run resumes), `media.hark.*` custody, every step in the run's recipe |
| `forensics_workshop/media/hark_worker.py` | The torch worker (ops `hunt`, `calibrate`, `extract`, `census`, `probe`, `score`, `audit`), run in `envs\atk_audio` like `restore_worker` |
| `forensics_workshop/media/selftrain_worker.py` | Move 3's worker: GTCRN (MIT, about 48 000 parameters, 16 kHz) ported to plain torch, trained on the file (`selftrain`) and applied (`apply`) |
| `forensics_workshop/media/restore.py` | One small change: `_run_option` can put an option's folder elsewhere and skip its custody event, so HARK runs every chain on its probe exactly as Restore Audio runs it |
| CLI | `hark` (with `--models-root`, `--deepfilter`, `--rnnoise-model`, `--gtcrn-weights`), `hark-list`, `hark-export` |
| ATK | The HARK section on the Restore Audio page: budget, Run HARK, verdict, map, tracks (machines and speaker-loop stretches marked), CEP, the census table, the restorations scored on this file's noise (best marked), audit flags, earlier runs, Finish stopped run. Move 2's VOICE and LIFT, Move 3's outputs and the machine cancellation appear in the results table like any option. `get_speechbrain.bat` fetches GTCRN's published weights (pinned commit, SHA-256 checked) |
| Tests | `tests/test_hark.py` (engine through fake workers; the science tests run the real workers when torch is present); ATK `test_dfw_pages_build.py` drives the page |

### What is new on 2026-11-11

**Move 3 — the file trains its own denoiser (Inferred).** GTCRN's
published weights (trained on DNS3) are fine-tuned on this recording alone,
RemixIT-style: the teacher is the published model's own output on the file;
each training example is a crop of that output plus a crop of the file's
own noise (its voice-free stretches, machines counted as noise) at a random
gain; the target is the teacher crop. BatchNorm stays frozen; the best
weights on a held-out check set are kept. The noise is dealt into two
halves — one to train on, one for increment 2b's probe — so Move 3 is never
scored on noise it trained on. The published model's output sits beside it
in the results as the yardstick. On Overnight and Full day it also trains
one **from nothing** (M4, "the file's own prior"), its teacher Move 2's
LIFT, so nothing it knows about speech came from outside the file.

**Measured — Move 3** (two LibriSpeech readers at −5 dB; 300 steps on
7–10 s of the file's noise, about Quick's length; ESTOI):

| Reader | Noise | Unprocessed | LIFT | GTCRN as published | Trained on the file |
| --- | --- | --- | --- | --- | --- |
| 3436 | Radio static | 0.465 | 0.498 | **0.609** | 0.570 |
| 3436 | Engine | 0.476 | 0.530 | 0.541 | **0.623** |
| 3436 | White | 0.395 | 0.440 | 0.495 | **0.509** |
| 5703 | Radio static | 0.342 | 0.379 | **0.432** | 0.416 |
| 5703 | Engine | 0.353 | 0.393 | 0.415 | **0.496** |
| 5703 | White | 0.289 | 0.317 | **0.358** | 0.334 |

In plain words: training on the file is a large win where the noise is
unlike anything the published model learnt from (an engine: +0.08 ESTOI for
both readers) and a small loss on noise it already knows (radio static,
white noise: −0.02 to −0.04). That is why increment 2b scores both on the
file's own noise and names the better one per file. An earlier experiment
(reader 198) agreed: radio 0.636 → 0.659, engine 0.574 → 0.635.

**Move 8 — the census of other sounds.** Three parts:
- *What pulses* (DEMON, new): ten log-spaced band envelopes; their
  modulation spectra over 8 s windows; each spectrum divided by its own
  local median (so a level that swings at random does not look periodic);
  the bands averaged and four multiples summed (a pulse train shows at its
  rate and every multiple). The false-alarm rate is the worse of two nulls:
  surrogates of the file's own noise, and a model null that assumes every
  band moves together (the worst case), extrapolated along its tail. Rates
  1–200 Hz; multiples of one rate merged into one source.
- *What hums* (machines, new): a pitch track whose run lasts at least 5 s,
  voiced for at least half of it, with its pitch held within 15% (90th to
  10th percentile), is a machine, not a voice — Move 2 leaves it alone and
  Move 3 counts it as noise. The census joins each machine's run across the
  moments the hunt lost it and cancels it along its own pitch (Move 2 in
  reverse, fitted over 24 cycles instead of 6): a restoration result with
  the recording **without** the machine and the **machine** alone
  (Cleaned), audited like every other.
- *What holds a tone*: the analysis's own tonal lines (§13.8), listed.

**Measured — census** (synthetic; 40–60 s of noise): pink, white and
randomly swinging (±4 dB) noise: nothing pulses. Noise whose loudness
pulses 8 times a second: found at 10% depth (false alarms 1×10⁻⁵ an hour),
at 8% depth (0.004 an hour), not at 5%. Footsteps every 0.55 s: one source
at 1.81 Hz, seen at several multiples. A voice reading at +10 dB showed as
a possible pulse at its own pitch (the census marks a rate that is a pitch
track's own pitch as the same sound); at 0 and −5 dB, nothing. An engine
(110 Hz ±4%, eleven harmonics, −4 dB under pink noise): the census
cancelled it to 11 dB below where it was, leaving the noise within 0.1 dB
(6 cycles left it 8 dB down; 48 and 96 cycles did worse again).

**Move 7 — the speaker loop, part one (Measured).** The strongest voice's
pitch range is learnt from what the hunt DETECTED (5th–95th percentile,
12% either side, at least half an octave), and the file is hunted again in
that range only. Fewer pitches means a lower line at the same false-alarm
rate — and the rate is measured on surrogates of the file's own noise over
the same range, so nothing is assumed. Both searches are then tested on the
**same** synthetic voices in that range, injected into the same stretches.
A round is kept only if the narrowed search tests no worse and either finds
more of the voice or finds the test voices quieter; otherwise it is rolled
back. Rounds repeat (Quick 1 … Full day 4) until the range settles. When a
round is kept, Move 2, Move 3's noise, the probe and the audit use the
narrowed search; the census still hears the whole range.

**Measured — Move 7** (60 s of pink noise, a voice at about 120 Hz): the
range 95–145 Hz holds 22 of the hunter's 111 pitches; the detection line
fell from 53.0 to 33.0 at the same false-alarm rate; test voices in the
range were found half the time 1.25 dB quieter (−7.5 against −6.25 dB) and
nine times in ten from −5.5 dB, where the whole-range search never reached
nine in ten. Eight test voices per level — a first measurement, not a
settled one.

**Fixed along the way — the hunter.** Engine and radio noise left no
voice-free stretches for Move 3, because the hunter tracked a drifting
whistle and an engine as voices. Three changes inside the harmonic
evidence: no single harmonic may count above the next strongest (it was
twice); a tolerance window counts its maximum only if it is a spectral peak;
and neighbouring harmonics whose maxima fall in one main lobe count once.
A regression test hides a whistle drifting 1050–1350 Hz in noise and
expects nothing DETECTED. The detection floors measured on 2026-11-10 were
taken before this change and have not been re-measured.

## Build status — 2026-11-10 (evening): increments 1–4

**Move 2 — how it works.** Each DETECTED track's pitch is refined (three
passes, ±3% down to ±0.2%, by the coherent noise-weighted energy at its
harmonics; measured precision about 0.03–0.06% on test voices), its phase
integrated sample by sample (warped time, where the voice is periodic), and
its harmonics fitted in blocks six pitch cycles long under a window laid out
in cycles. Each harmonic gets a Wiener weight from the noise measured by the
same fit half-way between harmonics. Overlapping tracks are fitted in turn,
each on what the other leaves. Two outputs: **VOICE** (the harmonics only)
and **LIFT** (the voice plus everything else through a classic
decision-directed Wiener filter on the file's own noise, so consonants
survive). The residual is the input less the voice.

**Increment 2b — how it works.** A probe is built from the file's own
voice-free stretches (extended with surrogates when short), with clean
phrases hidden at the calibration's levels in random order. Every candidate
chain runs on it exactly as Restore Audio runs it — same steps, same
parameters — and Move 2 runs on it as on the file (its tracks hunted with
the file's own false-alarm context). Each output is scored against the
clean phrases: ESTOI and scale-invariant SNR per level, and noise left in
the pauses. The best restoration for the file is the one with the highest
ESTOI at the level of the file's own DETECTED voices (corrected by the
calibration), and only if it beats leaving the recording alone by at least
0.02. Quick scores the chains already run; Thorough and longer score every
option.

**Fixed along the way:** the auditor called a phase-only filter (FFmpeg's
80 Hz high-pass near a voice's pitch) "REMOVED voice, 20–46%". The residual
of such a filter holds voice without any being lost. REMOVED now needs the
output itself to have lost at least 20% of the voice's harmonic power along
its track. A regression test turns every frequency 60° and expects nothing
flagged.

**Measured — Move 2 on real speech** (three LibriSpeech readers, CC BY 4.0,
from librosa's example set, mixed with synthetic noise; levels in the
60 Hz–4 kHz band; ESTOI 0.5 and up is generally intelligible; SI-SNR in the
60 Hz–5 kHz band; means over the three readers):

| Noise | Level | ESTOI unprocessed | LIFT | plain Wiener | SI-SNR unprocessed | LIFT |
| --- | --- | --- | --- | --- | --- | --- |
| White | 0 dB | 0.379 | 0.419 | 0.387 | −0.9 dB | +6.9 dB |
| White | −5 dB | 0.264 | 0.306 | 0.274 | −5.9 dB | +2.4 dB |
| White | −10 dB | 0.159 | 0.182 | 0.166 | −10.9 dB | −4.1 dB |
| Pink | 0 dB | 0.343 | 0.394 | 0.361 | −0.2 dB | +5.5 dB |
| Pink | −5 dB | 0.206 | 0.241 | 0.219 | −5.2 dB | −0.1 dB |
| Pink | −10 dB | 0.104 | 0.115 | 0.110 | −10.2 dB | −6.8 dB |

In plain words: LIFT never made any of the 18 mixtures less intelligible
and on average beat a plain Wiener filter in every condition (one
low-voiced reader came out level with it at −5 and −10 dB in pink noise),
but the intelligibility gain is modest — +0.03 to +0.05 ESTOI at 0 and
−5 dB, +0.01 to +0.02 at −10 dB. The noise reduction is large: SI-SNR up
5 to 8 dB at 0 and −5 dB, 3 to 7 dB at −10 dB. On synthetic voice-like
probes VOICE gains about +12 dB. One low-voiced reader gained least,
because the hunter found less of his voice.

**Measured — end to end** (real restore worker, real FFmpeg, Quick budget,
a 37 s file with a LibriSpeech reader in pink noise at −5 dB, about 73 s):
7.4 s DETECTED; Move 2 pulled out 7.1 s; on the probe at the voice's level
(−2 dB) LIFT scored ESTOI 0.37, FFmpeg's clean-up filters 0.32, the fixes
alone 0.29, unprocessed 0.29, so HARK named LIFT best. The audit flagged
nothing. The SpeechBrain models, DeepFilterNet and RNNoise are not in this
test environment; on your machine they are scored too.

**Where it departs from the proposal below:**

- The worker is torch, not numpy; a GPU is used when present.
- The budgets are measured, not the design targets in the table below:
  Quick 4 surrogates (null at least 15 min), 6 levels 0 to −25 dB, one probe
  phrase per level, the chains already run; Thorough 20 (2 h), 13 levels,
  two per level, every chain; Overnight 100 (10 h), four per level; Full day
  300 (24 h), 25 levels.
- Move 2's cyclic Wiener filter is its line-spectrum form: a Wiener weight
  per harmonic in warped time. Gardner's full FRESH filter also uses the
  coherence between harmonics; that is not built.
- LIFT's remainder goes through a classic Wiener filter (Cleaned), not
  through Move 3's self-trained denoiser (kept apart, so LIFT stays
  Cleaned and Move 3 Inferred).
- Move 3 trains on remixes with the published model's output as teacher
  (RemixIT), not on noisy-target pairs: noisy targets were measured to make
  it worse (it learnt to keep the noise). M4 (from nothing) uses LIFT as its
  teacher.
- Move 7 is the pitch-range half. Steering a target-speaker extractor with
  a self-made ECAPA profile waits for ClearerVoice, which is not built.
- Move 8's DEMON uses band envelopes and their modulation spectra, not
  Antoni's fast spectral correlation; its machines come from the pitch
  hunter, not a separate cyclic-notch search.
- The map is the whitened spectrogram to 2 kHz with each track drawn on it,
  not yet the provenance-coloured map.

**Not yet measured:** any of it on your own recordings or your own noise;
the SpeechBrain models and DeepFilterNet on the probe (they need your
machine); kill criteria 1, 2 and 6 against their bars.

**Known limits:** Move 2 only pulls out DETECTED voices (a possible one is
left as it was), only voiced sound (consonants survive only through LIFT's
Wiener filter), and follows a track's octave errors. The probe's phrases
skip the real channel, so its scores are an approximation. A truly steady
machine present throughout is part of the file's own noise to the hunter
(the surrogates keep it), so the census lists it among the steady tones
rather than cancelling it; the census cancels machines whose pitch moves
enough to be tracked. Move 3 on Quick trains a few minutes on a CPU; how
far longer training helps on your files is not yet measured. Move 7's
narrowed search finds test voices only in the speaker's range — that is its
point, and why its CEP is reported beside the whole-range one, not instead
of it.

**Defaults taken until you decide:** the name HARK; this file of its own,
with a pointer in FORENSICS_PLAN.md §15; the kill-criteria bars as proposed.

**Next:** Move 4, the generative lane — a speech prior trained on
LibriSpeech's training sets (CC BY 4.0) on your GPU, posterior sampling
with a noise model fitted to the file, many samples and an uncertainty map
(Invented). Then Move 7's second half (ClearerVoice steered by the
speaker's own profile), and the cheap mad moves (M3, consonants beside the
vowels; M5, stacking a voice across a case).

**Run it:** on the Restore Audio page, analyse and run options, then pick a
budget and press Run HARK. From the command line, in the ATK folder:

```
python -m forensics_workshop hark CASE RUN_ID --examiner NAME ^
  --python envs\atk_audio\Scripts\python.exe --scratch data\tmp\speechbrain ^
  --budget quick --ffmpeg bin\ffmpeg\ffmpeg.exe ^
  --phrases models\speechbrain\reference\LibriSpeech\test-clean ^
  --models-root models\speechbrain --deepfilter bin\deepfilter\deep-filter.exe ^
  --rnnoise-model models\rnnoise\sh.rnnn ^
  --gtcrn-weights models\gtcrn\model_trained_on_dns3.tar
python -m forensics_workshop hark-list CASE RUN_ID --examiner NAME --id HARK_ID
```

## The proposal (as written 2026-11-10)

The research proposal follows unchanged; its live copy is the Claude doc
https://claude.ai/artifact/JatE4K12pk3ZcASU19vp72.

A research proposal for the Digital Forensics Workshop · Nov 10, 2026 · @William

### Bottom line

**Yes, cyclostationary methods can pull voices out of noise, but their best job is detecting and auditing, not denoising alone.** The newest work on cyclic Wiener filtering of speech (TU Delft with the Netherlands Defence Academy, 2025–2026) shows large gains on synthetic voices that shrink on real speech. The reason is that the filter is very sensitive to errors in the pitch estimate. So the winning move is to spend the compute budget on the pitch track itself: hunt it the way radio astronomers hunt drifting pulsars, warp time so the voice is truly periodic, and only then filter.

Once you have that track, it does three jobs:

- **Finds speech** far below where a listener or an energy gate can. Pitch tracking with a harmonic model has been shown working at −15 dB SNR.
- **Extracts the voiced part faithfully.** It's a linear filter given the track, so it can't invent words. That makes it Cleaned tier.
- **Audits every other method.** If the speaker's pitch shows up in what a denoiser threw away, that denoiser ate voice. If harmonic structure appears in its output where the input had none, it made voice.

Four more moves turn the unlimited time budget into real gain:

1. **The file trains its own denoiser.** Self-supervised "noisy-target" training on its own pauses closes the mic-noise-versus-radio-noise gap that §12.4e names.
2. **Every file gets its own CEP.** Known phrases are injected into the file's own noise and the whole chain is scored on them. You learn how far this recording can be trusted, and which chain wins on it.
3. **The generative lane becomes a measured guess.** A speech prior is paired with a noise model fitted to this file, many samples are drawn, and the spread between them becomes a per-cell uncertainty map.
4. **A sonar-style census covers everything else.** Engines, drones, fans and footsteps are each found by their own periodic structure, and each becomes a stem you can solo or remove.

One hard limit stays. Unvoiced consonants (s, f, sh, t, k) and one-off sounds have no periodic structure to grab. Below their own level, nothing honest recovers them: the evidence is either in the file or it isn't.

### Where this sits

HARK is a new stage on the Restore Audio page, built on top of FORENSICS_PLAN §12–§13. It replaces nothing there. Most of what §13 calls "faint sounds" is already built. HARK adds what that work explicitly lacks: a voice-shaped (harmonic) detector, which is increment 6 there; measured trust per file; and methods that learn from the file itself.

| Already built or approved (§12–§13) | What HARK adds |
| --- | --- |
| Energy-gate triage; salience map with long integration; tonal lines | A pitch-track hunter that sees voiced speech below the salience map's floor, with a false-alarm rate measured on this file |
| Classical chain, DeepFilterNet, RNNoise, MetricGAN+, SepFormer | A time-warped cyclic filter (Cleaned) and a denoiser fine-tuned on this file's own noise (Inferred) |
| Ranking by severity and "measured best" from energy removed and added | Chain choice by measured recovery of injected test phrases on this file |
| Residual saved for the ear; "speaks on noise" negative control | An automatic auditor that finds voice in residuals and invented voice in outputs |
| Generative lane with seed disagreement (SAM, now removed) | Posterior sampling with a noise model fitted to the file, a per-cell uncertainty map, and a prior-swap test |
| Repeats, channels, shift into hearing, codec memory (approved) | A census of periodic non-speech sources (DEMON / cyclic modulation), each as a stem |

**Rules it keeps, unchanged:**

- The five trust tiers, with an output carrying the highest tier of any step.
- Recipes, residuals and custody on every output.
- The §1.1 licence rule: permissive or weak copyleft only. Where a paper's code has no licence, it is reimplemented from the paper.
- Offline only, nothing on C:, every model in its own short-lived process.
- Sized to the RTX 3080 Ti (16 GB) and 64 GB of RAM.
- "Not for court": leads that can save a life, with an invented syllable never shown as a recovered one.

Three of the moves (the hunter, injection-recovery and the auditor) carry straight over to RF detection below the floor in detection_design. The maths is the same; only the signal model changes.

### Where the decibels come from

On a single channel, gain comes from exactly four places, and each one runs out somewhere. Every move below draws on one or more of them.

| Source of gain | Why it works | Moves that use it | Where it stops |
| --- | --- | --- | --- |
| **Longer integration** | Averaging N noise-only looks shrinks the noise's spread by about 1/√N. A 40 ms frame at 120 Hz holds about 5 glottal cycles; a warped 0.5 s voiced stretch holds about 60. That is arithmetic, not a measured gain. | 1, 2, 8 | Pitch moves faster than the warp model; unvoiced sounds |
| **Few free parameters** | A voiced frame is described by one pitch plus a few dozen harmonic amplitudes. Fitting that small model to thousands of samples averages the noise across all of them, which is matched-filter logic. Generic denoisers judge every time-frequency cell on its own. | 1, 2, 6 | Breathy, creaky or jittery voice; overlapping talkers |
| **Knowing this file's noise** | A noise model fitted to the file's own pauses, a denoiser trained on them, and false-alarm rates measured on the file's own noise instead of textbook Gaussian noise. | 3, 4, 5 | Noise that changes character mid-file; files with almost no pauses |
| **Other people's speech** | A model of what speech usually sounds like fills gaps the recording does not cover. | 4, 7 | It adds information that was never recorded, so it is Invented by definition |

The first three only rearrange what the file already holds. The fourth is the only one that adds content, so it is the only one that can hallucinate. HARK uses it last, labels it, and measures how much it is guessing.

### Moves 1–2: find the voice, then pull it out

#### Move 1 — Hunt the pitch track like a pulsar (Measured)

**The hunter finds voiced speech by its pitch track before any threshold is applied, the way pulsar and radar searches find targets too weak to see in one look.** It runs three steps:

1. **Harmonic summing.** Each short frame scores every candidate pitch from 50 to 500 Hz by adding the evidence at all of its harmonics. Pulsar searches in PRESTO sum 16 to 32 harmonics this way to lift a faint periodic source.
2. **Slope templates.** It also scores candidate pitch slopes. That is the pulsar "acceleration search", which matched-filters a frequency that drifts during the observation. For speech, the fan-chirp transform does the same for a whole harmonic stack.
3. **Track-before-detect.** A Viterbi (dynamic-programming) pass finds the most likely continuous path through all frames. Only then is anything thresholded. Two or three tracks run at once: two talkers, or a talker and an engine.

**Evidence.** Tabrikian, Dubnov and Dickalov (2004) tracked pitch with a harmonic model and a Markov prior at SNRs as low as −15 dB. Singh and Demuynck (2025) pair harmonic summation with Viterbi continuity for noisy, reverberant speech. Neural pitch trackers such as SwiftF0 (2025) are benchmarked around 10 dB SNR, about 25 dB above our regime. They serve only as a second opinion on the louder stretches.

**Output.** For every frame: a likelihood ratio, a voiced-presence lane, a pitch contour per talker, and the speaker's pitch range. You get findings like "a voice about 18 dB under the noise for 40 s here", even when no word in it is recoverable.

**Cost and risk.** Cheap at the Quick budget. Overnight buys finer pitch grids, more slopes and three tracks. The classic failure is the octave error, locking on half or double the true pitch. It is countered with a subharmonic penalty, as in the SRH method, plus the continuity prior.

#### Move 2 — Warp time, then filter cyclically (Cleaned)

**With the track in hand, each voiced stretch is resampled so every glottal cycle has the same length. The voice then becomes truly periodic, and a cyclic filter can lock onto it.** Two extractors run in warped time, then the result is warped back:

- **Harmonic projection.** For each short block, fit the harmonic amplitudes and phases at the known pitch and keep only that fit. Everything else becomes the residual.
- **Single-channel cyclic Wiener (FRESH) filter.** Gardner's frequency-shift filter uses the correlation between harmonics, the property that tells voiced speech apart from stationary noise.

Unvoiced gaps pass through untouched, or go on to Move 3.

**Evidence.** Scott Wisdom's 2014 University of Washington thesis showed three things:

- Warping by the estimated pitch makes speech and propeller noise more stationary, so longer analysis frames can be used.
- A generalized DEMON detector with a frequency-variation model gained up to 6 dB on real passive-sonar data.
- Speech enhancement in the warped (fan-chirp) domain beat both short- and long-window processing.

Bologni and colleagues (2025) showed voiced speech is better modelled as cyclostationary than as stationary. Their cyclic Wiener filter gained strongly on synthetic data, but its high sensitivity to pitch errors limited it on real recordings. A 2026 follow-up found that using cyclostationarity as a prior helped more than adding model capacity, though that result was against harmonic interference. HARK's answer to the sensitivity is that the track comes from Move 1's global search, refined in a loop. Warping also removes the drift that smears harmonics inside a frame.

**Why Cleaned and not Inferred.** Given the track, both extractors are linear filters. They can remove real detail, which the residual keeps, but they cannot add any. The only nonlinear choice is which pitch to follow, and Move 6 audits that.

**The same machinery in reverse.** It can cancel periodic interferers: engines, fans, drone rotors. The Delft group's cMPDR work treats that kind of noise as almost-cyclostationary, but theirs is multichannel. A single-channel version, a cyclic notch that follows the machine's track, has to be built. Their repository states no licence, so it is reimplemented from the papers.

### Moves 3–4: let the file teach, and make the guessing honest

#### Move 3 — The file trains its own denoiser (Inferred)

**Every denoiser in §13 was trained on microphone noise. This move retrains one on the noise in this very file, with no clean speech and no dataset.** It works in three steps:

1. Take the stretches Move 1 marks as voice-free. On radio they must come from inside the transmission, per §12.4d's carrier rule.
2. Add more of that noise to the noisy recording, and train the network to remove what was added. Noise2Noise theory says a target corrupted by zero-mean noise teaches, on average, the same mapping a clean target would.
3. Run the tuned network on the original.

**The model.** GTCRN is MIT-licensed and has about 48,000 parameters, small enough to train for hours on one file on the 3080 Ti. It is fine-tuned from its published DNS3 weights. DeepFilterNet (MIT or Apache-2.0, training code in its repository) is the heavier option.

**Evidence.**

- Fujimura and colleagues (2021) trained speech enhancement without clean speech by adding noise to noisy speech (noisy-target training).
- Remixed2Remixed (2023) used the same principle to adapt models trained on synthetic data to real recordings.
- "Only-Noisy Training" (Wu et al., 2023) builds its training pairs from a single noisy audio file.
- Sivaraman and Kim (2022) personalised enhancement to one speaker by self-supervision, with no clean data from that speaker.

**Why it matters here.** §12.4e names the gap exactly: the denoisers were trained on microphone noise, not NBFM radio, and the planned fix (the NNR recipe) needs a dataset of off-air recordings. This move needs only the file in hand.

**Risks.** The pauses must be the same noise as what sits under the speech. A file with under about 30 s of pauses may not train well (an estimate, to be measured). The network could learn to swallow this speaker's quiet syllables. That is why Move 6 audits it and Move 5 scores it.

#### Move 4 — The generative lane as a measured guess (Invented, with an uncertainty map)

**Instead of a black-box generative enhancer, HARK uses unsupervised posterior sampling, which keeps the evidence and the prior explicitly separate.** The setup is a speech prior trained on clean speech only. At run time, a noise model is fitted to this file inside an expectation-maximisation loop while clean-speech samples are drawn. Nothing was trained on noisy-clean pairs, so the method assumes nothing about what the noise is.

**Evidence.** Nortier, Sadeghi and Serizel (2023) introduced this as UDiffSE. It generalised better than a supervised diffusion model to mismatched noise, at the cost of speed. Ayilo and colleagues (January 2026) found that treating the noise explicitly as a latent variable improves results, and their NMF noise model held up best in mismatched conditions. A 2025 paper from the same group (posterior transition modelling) was robust to domain shift, often matching or beating supervised baselines.

**What HARK adds on top:**

- **Many samples, one uncertainty map.** The day budget allows 16 to 100 samples. The spread in each time-frequency cell is that cell's uncertainty. ArtiFree (2025) found hallucinated phonemes vary from run to run while genuine content stays consistent, and that the spread of speech embeddings across samples predicted phonetic errors.
- **A consistency check.** The observed audio minus a speech sample must look like the noise model fitted from the pauses. Cells where it doesn't are flagged red.
- **A prior-swap test.** See the mad moves below.

**Practical cost.** The speech prior is ours to train, on CC BY 4.0 speech such as the LibriSpeech training sets. How long that takes on 16 GB is unknown, probably days. Run time per file is slow, which the day budget absorbs. Every code licence (UDiffSE, enudiffuse, their backbones) is read before use. Output is always Invented, and its words go into the §12.6 consensus only as proposals.

### Moves 5–6: measure the trust, audit the tools

#### Move 5 — Every file gets its own CEP (Measured)

**Gravitational-wave and exoplanet searches never take a pipeline's sensitivity on theory. They inject simulated signals into real detector data, run the same pipeline, and count what comes back. HARK does that for every file.** It is your "always test against a known-good emitter" rule, run automatically.

1. **Inject.** Known phrases from LibriSpeech test-clean (CC BY 4.0, already fetched by `get_speechbrain.bat`) go into the file's own voice-free stretches at stepped levels, +5 to −25 dB in 2.5 dB steps. Each phrase is band-limited to the file's measured content (§13.9) and, where the codec is known, re-encoded the same way.
2. **Score.** Every candidate chain runs on the injected copies and is scored four ways: detected or not (Move 1), ESTOI intelligibility, two-family ASR word error (§12.6), and invented words.
3. **Measure the background.** Surrogate copies of the file's noise, phase-randomised or block-shuffled, keep its spectrum and level statistics but destroy any periodic structure. Running the hunter on them gives its false-alarm rate on this file, not on textbook noise. Gravitational-wave searches use time-slides the same way.

**What it produces.** A recovery curve for this file and a position on it for every event. The verdict becomes a number, for example: "on this recording voiced speech is found down to X dB with one false alarm per hour, and is intelligible with chain C down to Y dB; event 4 sits at Z dB, so its words are leads." X, Y and Z come from the run; none are claimed here.

**Chain choice becomes measured.** The winning chain is the one that best recovers the injected phrases at the level of the real event. That replaces §13.3's severity-and-tier ranking, and the energy-based "measured best" pointer that §13.7 admits cannot hear a smeared consonant.

**Limits.** Injected speech never passed through the real channel: the room, the radio, the phone's automatic gain. Band-limiting, codec re-encoding and a measured channel equaliser narrow that gap but don't close it. Injections go only into pauses, so the real speech is never disturbed, and the injected copies are scratch files, never outputs.

#### Move 6 — The cyclic auditor (Measured)

**Every chain already saves a residual, because "if you hear words in it, the filter ate speech" (§12.2). The auditor stops relying on someone listening and runs Move 1's hunter on every residual and every output.** I found no published precedent for this; it is my own proposal.

- **Voice removed.** The speaker's pitch contour shows up in what a chain removed, above the surrogate threshold. Finding: "DeepFilterNet removed voice at 12.4–13.1 s."
- **Voice made.** Confident harmonic structure appears in an output where the input's hunter found nothing even at its loosest setting. Finding: "chain X made voice-like sound at 31.0 s." This invention flag is independent of ASR, so it cross-checks §12.6's consensus and §12.12's "speaks on noise" control.
- **Non-speech removed.** A periodic source track (an engine, a beacon) disappears through a speech-only model. That turns the generic SPEECH ONLY warning into a timestamped one.

It is cheap, because it reuses Move 1, and it works on every existing chain from day one. Its blind spot: it sees only voiced and periodic content. Consonant damage is left to the ASR consensus.

### Moves 7–8: learn the speaker, then everything else

#### Move 7 — Bootstrap the speaker in a turbo loop

**Once some of a voice is recovered confidently, what it teaches about that speaker makes the weak stretches easier, and the loop repeats.**

1. **Seed.** Start from the voiced stretches Move 1 found with high confidence.
2. **Learn.** Build the speaker's ECAPA voice profile (already built in §13, kept inside the case), plus their pitch range and how fast their pitch moves.
3. **Use it twice.** First, narrow Move 1's search in the weak stretches to that speaker's pitch range. Fewer trials means a lower threshold at the same false-alarm rate, the same trade the salience map makes with its +0.6 per tenfold cells. Second, steer target-speaker extraction (ClearerVoice, already planned) with this self-made profile instead of a hand-cut clip. Enrolment-free extraction already exists in the literature (self-enrolment, 2023; mixture-to-set embeddings, 2026).
4. **Iterate.** Like a turbo decoder: better extraction gives a better track, which gives better extraction. Stop when the track and profile stop changing.

**The risk is confirmation bias: a loop can talk itself into a voice.** So Move 5 scores every round on injected phrases and Move 6 audits it. A round that lowers injected-phrase recovery is rolled back. Profiles are built only from Cleaned or Inferred audio, as §13.1 already requires.

#### Move 8 — A sonar-style census of every other sound

**Passive sonar finds ships two ways: narrowband lines (LOFAR) and the pulsing envelope of broadband noise (DEMON). §13.8 already does the lines. HARK adds DEMON, and points the pitch hunter at machines.**

| Structure | Typical sources | How it's found | Status |
| --- | --- | --- | --- |
| Harmonic stack with drifting pitch | Voices, engines under load, drone rotors, sirens | Move 1 with a wider pitch range | New |
| Noise whose loudness pulses at a rate | Propellers, helicopters, a fan's blade rate, footstep cadence, typing | DEMON / cyclic modulation spectrum via the fast spectral correlation | New |
| Steady lines | Mains hum, whines, beacons | Tonal lines | Built (§13.8) |
| Exact repeats | Loops, beeps, played recordings | Beat spectrum and averaging | Built (§13.8) |
| One-off transients | Doors, impacts, bursts | Salience map; templates | Built / planned (§13 increment 6) |

Antoni's fast spectral correlation, and Borghesani and Antoni's 2018 refinement (which reports 2–3 orders of magnitude lower computational cost), make the full cyclic map affordable over long files. A drone rotor's blade-pass frequency is blade count times shaft rate, usually 50–300 Hz for consumer drones. It shows up as a drifting harmonic stack that Move 1 can follow, which links straight to Drone Discovery. Warping helps here as well: Wisdom's frequency-variation DEMON is the 6 dB sonar result quoted under Move 2.

Every source found becomes a labelled lane on the timeline and a stem. You can solo it (listen to just the engine) or cancel it with Move 2 run in reverse, to uncover what was underneath.

### Mad moves: my own ideas, with no research behind them

These are the gambles a PhD student would put in the last chapter. Each one is cheap to test once Moves 1 and 5 exist, and each has a clear way to fail.

**M1 — Ask the recording which reading it supports.** §12 worries about a faint "four-seven" turning into "four-one". Instead of enhancing and hoping, this tests the candidate readings directly against the evidence:

- Synthesise each candidate as a probe, timed to Move 1's pitch track. The local TTS can match the voice; the probes are never outputs.
- Under the noise model fitted from this file, compute how well each probe explains the noisy audio, in the noisy domain, with no enhancement in between.
- The result is a likelihood ratio between readings: a lead, not audio.

*It fails if* voice and timing mismatch in the probe swamp the difference between the words. So it is useful only for choosing between a few specific readings: digits, call signs, grid references.

**M2 — Prior-swap test.** Run Move 4 twice, with two different speech priors, for example one trained on English read speech and one on multilingual speech. Content that survives the swap came from the recording; content that flips came from the prior. In URGENT 2025, a generative enhancer turned low-SNR Japanese into something that sounded like English. That was the prior talking, and this test would catch it as a per-cell "prior dependence" map. *It fails if* both priors share the same bias, so they must differ on purpose.

**M3 — Hunt consonants where the vowels say they must be.** Nearly every syllable has a vowel at its core, so consonants sit beside the voiced islands Move 1 finds. Search only the 30–150 ms margins on either side, and only in the bands where fricatives and bursts live. Shrinking the search area cuts the number of trials, which lowers the threshold at the same false-alarm rate. The output is a probability that a consonant is there (Measured), never audio, and it tells the ASR consensus how many syllables to expect. *It fails if* real noise in those bands (hiss, wind) is too uneven for the margins to beat chance; Move 5's surrogates will show it.

**M4 — The file's own prior.** Train Move 3's small network from random weights on this file alone, with no pretrained weights. Whatever it knows about speech came only from this recording, so it cannot import anyone else's words. I expect it to be weaker than the fine-tuned model. Where the two agree, the content does not depend on any outside prior.

**M5 — Stack the voice across a case.** A case may hold 40 voice memos from one phone, or a bug's daily files. The same faint voice may sit in several, too weak to convince in any one. Accumulate the speaker's pitch statistics and voice embedding across all weak segments in all files, the way pulsar surveys stack observations. The result is a review-queue lead like "this voice is present, faintly, in 9 of 40 recordings". *It fails if* channel differences between files dominate the embedding; the calibration sets of §13.1 tell us.

**M6 — A speaker-specific prior.** Once the turbo loop holds minutes of confident speech, LoRA-tune Move 4's speech prior on it, the Palimpsest idea applied to a voice. The generative lane then guesses in this speaker's voice rather than a generic one. *The danger* is that it learns its own mistakes, so it runs only with Move 5 measuring before and after. It stays Invented regardless.

### Moves I would reject

Each of these would make the output sound better and the lead less trustworthy.

- **Feeding a transcript to an enhancer** (FlowSE- or Miipher-style). It turns a guess into convincing audio. §12 already bans it, and HARK keeps the ban.
- **Letting a language model complete words** during recognition. That is the prior talking. M1 asks the recording instead.
- **Picking chains by DNSMOS, UTMOS or any no-reference quality score.** In URGENT 2025, DNSMOS scored hallucinated speech well. Move 5's injected phrases are the yardstick instead.
- **Training or tuning an enhancer against ASR confidence.** In my judgement, not from a paper: it breeds artefacts that please the recogniser rather than the ear, the way adversarial examples do.
- **Bringing SAM Audio back.** It was removed on 2026-10-29 and is not re-proposed. Move 4 fills the generative role with code and weights that pass §1.1.

### The push-button pipeline and the time budget

**The operator picks a budget and presses one button. The budget sets how hard each stage searches, never which stages run or what the output may claim.**

The pipeline, in order: triage (§13) → hunt (Moves 1, 8) → calibrate (Move 5) → the three extraction lanes (Move 2 faithful, Move 3 self-trained, Move 4 generative) → audit (Move 6) → verdict and map; the turbo loop (Move 7) feeds a cleaner speaker estimate back into the hunt.

The hunt and the calibration run first, because every lane needs the tracks and pauses, and every lane is scored on the injected phrases. The auditor then checks each lane before anything reaches the map.

The durations below are design targets, not measurements.

| Stage | Quick (minutes) | Thorough (about an hour) | Overnight or full day |
| --- | --- | --- | --- |
| Triage (§13) | Same in all budgets | Same | Same |
| Hunt (Moves 1, 8) | Coarse pitch grid, 1 track | Fine grid, slope templates, 2 tracks | 3 tracks, wide range for machines, full cyclic map |
| Calibrate (Move 5) | 20 injections, 10 surrogates | 200 injections, 100 surrogates | 2,000+ injections across every chain, 1,000 surrogates |
| Warp and cyclic filter (Move 2) | On | On | On, re-run after each loop round |
| Self-trained denoiser (Move 3) | Off | 20-minute fine-tune | Hours, plus the from-scratch variant (M4) |
| Posterior sampling (Move 4) | Off | 8 samples | 32–100 samples, plus the prior swap (M2) |
| Turbo loop (Move 7) | Off | 1 round | Until stable |
| Audit (Move 6) | Every output | Every output | Every output, every round |

**How a day-long run stays safe:**

- **Checkpoints.** Each stage is its own short-lived worker process, as `restore_worker` and `vp_worker` already are. It writes its outputs and a checkpoint before the next stage starts, so a crash, reboot or sleep resumes at the last finished stage.
- **Logging.** Everything goes to `atk.log` under its own component, with per-stage timing and the reason for every automatic decision.
- **Nothing on C:.** Scratch, model caches and outputs live on D: beside ATK, as §13.2 already does for SpeechBrain.
- **Queue manners.** It runs in ATK's AI queue and yields the GPU to priority-one work such as the medic relay.

### What the operator sees

**One button, one budget choice, then a verdict in plain words over a map coloured by how every piece of sound was produced.** That follows your design rule: officers see the bright, clear picture first, and the colours have to tell the truth.

**The controls.** A HARK button on the Restore Audio page, a budget drop-down (Quick, Thorough, Overnight, Full day), and Start. A progress bar names the stage running and the time left. A day-long run checkpoints after every stage, so a reboot or sleep resumes instead of starting over.

**The verdict card**, written from the run's own numbers, for example:

> Two voices found (male range, female range). 14 minutes of voiced speech, 6 of them below hearing level. On this file, speech becomes intelligible above X dB, and 3 of the 9 events clear it. Best chain for this file: C, measured. One chain flagged for removing voice.

**The map** is the spectrogram coloured by provenance and agreement:

| Colour | Meaning |
| --- | --- |
| Green | Faithful lanes (Moves 2 and 8, Cleaned or Recovered) agree |
| Blue | Only the self-trained denoiser (Move 3, Inferred) holds it |
| Amber | Generative (Move 4), with low spread across samples |
| Red | Generative with high spread, failing the consistency check, or flipping under the prior swap |
| Violet | Machinery and tonal sources from the census |
| Grey | Noise |

Under the map run lanes for each talker's voiced presence, the pitch contours, the census sources, and auditor flags: a red tick wherever a chain ate voice or made it.

**Event cards.** One per detection, showing:

- its level against the noise;
- the detector's confidence, from the surrogates;
- the intelligibility expected at that level, from the injections.

Play buttons offer the original, faithful, self-trained, generative (labelled Invented), residual, and the binaural-unmasked clip from §13.10.1.

**Stems and exports.** One stem per talker, per machine, and one for the noise. Every export carries its recipe, tier and custody record, as §12.3 already does.

### How we would prove it

**The thesis claim:** below 0 dB SNR, statistics taken from the recording itself recover more true content and invent less than generic pretrained models. Those statistics are the pitch track, a noise model fitted to the file, and per-file injection calibration. The same machinery can also say, file by file, where it stops working.

**The test ladder**, extending §12.12's harness:

1. **Synthetic.** Voice-like harmonic signals with known pitch, in white, pink and exponential-power noise. Never tidy Gaussian-in-dB noise, per ATK's channel-gate lesson.
2. **Real speech in your real noise.** LibriSpeech mixed into your off-air captures (NBFM with carrier, HF static) and phone ambience, from +5 to −25 dB.
3. **The unpublished benchmark.** A background talker 15–25 dB below a foreground one, already planned in §12.12.
4. **Real files.** Your own listening against the per-file CEP card: does the card's "intelligible above X dB" match what you hear?

**The measures:**

- Detection curves (hit rate against false-alarm rate) for the hunter, the energy gate and the salience map.
- ESTOI intelligibility.
- Two-family ASR word error.
- Invented words on speech-absent noise.
- The auditor's precision against ground truth.

**Kill criteria.** The bars below are proposed. You set them.

| Move | Keeps its place if | Otherwise |
| --- | --- | --- |
| 1 Hunter | It detects voice at least 3 dB lower than the salience map at the same false-alarm rate, on your noise | It becomes one more lane on the salience map |
| 2 Warp and cyclic filter | It beats `afftdn` and DeepFilterNet on ESTOI below −5 dB without losing above it | It is kept only to support the auditor |
| 3 Self-trained denoiser | It beats its own base model on injected phrases in at least 2 of 3 noise types (NBFM, HF, phone) | Dropped; the NNR dataset plan stands |
| 4 Posterior sampling | It invents fewer words than UniPASE or GAP-URGENet at equal intelligibility | It stays a research toggle |
| 5 Per-file CEP | Its predicted intelligibility threshold lands within ±3 dB of the measured one on held-out real speech | It is labelled "approximate" |
| 6 Auditor | At least 90% of its "voice removed" flags are confirmed on ground-truth mixes | Its flags are shown as hints only |

### Build order

**Build the measuring instruments first.** Increments 1–3 add no new denoiser, but they make every existing and future chain measurable on each file, which is worth more than any one model. Each increment ships with its §12.12 harness results.

1. **Hunter and surrogates** (Move 1 plus the background half of Move 5). A numpy worker first, with an atkdsp C kernel once the method is proven. It delivers voice-presence lanes and pitch contours on the Restore Audio map, each with a false-alarm rate measured on the file.
2. **Injection harness** (Move 5). It uses the LibriSpeech test-clean already on disk. It delivers the per-file CEP card and measured chain choice for the chains that exist today.
3. **Auditor** (Move 6), over every existing chain's residual and output. It delivers timestamped "voice removed" and "voice made" flags.
4. **Warp and cyclic extraction** (Move 2): harmonic projection, the single-channel cyclic Wiener filter, and the cyclic notch for machines.
5. **Census** (Move 8): DEMON and the fast spectral correlation, with machine tracks as stems.
6. **Self-trained denoiser** (Move 3): GTCRN fine-tuning inside `envs\atk_audio`, where torch already lives.
7. **Turbo speaker loop** (Move 7). It needs 1–4, the ECAPA profiles (built) and ClearerVoice extraction (planned).
8. **Posterior sampling** (Move 4), then the mad moves M1–M6 as experiments behind a "research" toggle.

### Honest limits and open questions

**Nothing in this proposal is measured on your files yet. Every gain quoted belongs to someone else's data.**

**What doesn't carry over cleanly:**

- The −15 dB pitch-tracking result is from Tabrikian and colleagues in 2004, on their recordings.
- Wisdom's 6 dB is passive sonar, not speech.
- The Delft cyclic-filter gains are strongest on synthetic data.

**What the methods cannot see:**

- Moves 1, 2 and 6 see only voiced and periodic content. Unvoiced consonants and one-off sounds below their own level stay out of reach; M3 is only a gamble on that.
- Where two talkers' pitch tracks cross, warping follows one at a time and both blur at the crossing.
- Narrowband calls cost harmonics but don't kill the hunter. A 120 Hz voice still has about 25 harmonics between 300 and 3,400 Hz (arithmetic).
- Digital voice out of a vocoder is re-synthesised. The hunter will still detect it, but §12.4f's finding stands: no extraction gain is expected after the vocoder.

**Practical unknowns:**

- Self-training needs pauses. A file with wall-to-wall talk, or under about 30 s of pauses, may not train (an estimate).
- Injected phrases skip the real channel (room, radio, phone gain control), so the per-file CEP is an approximation.
- How long the diffusion speech prior takes to train on 16 GB is unknown.
- Licences to read before any code is touched: UDiffSE, enudiffuse, and the Delft repositories, which state none.
- Day-long runs share the GPU with the rest of ATK and need a place in the AI queue.

**Decisions for you:** the name, the kill-criteria bars, and whether this becomes §15 of FORENSICS_PLAN.md or a file of its own.

### Sources

**In the repository:** FORENSICS_PLAN.md §12–§13 and research/media_recovery_tools_2026-09-30.md in Digital Forensics Workshop. The URGENT 2025 and DNSMOS findings come from there.

**Cyclostationary speech and noise**

- [Cyclic Multichannel Wiener Filter for Acoustic Beamforming](https://arxiv.org/abs/2507.10159) — Bologni, Heusdens, Hendriks, WASPAA 2025
- [Harmonics to the Rescue: Why Voiced Speech is Not a WSS Process](https://arxiv.org/html/2507.10176v1) — Bologni et al., 2025
- [MPDR Beamforming for Almost-Cyclostationary Processes](https://arxiv.org/pdf/2510.18391v2) — Bologni et al., 2026
- [A two-step approach for low-SNR speech enhancement using cyclostationary beamforming and DNNs](https://arxiv.org/pdf/2602.12986) — Bologni, Arrieta Larraza et al., 2026
- [cMPDR code repository](https://github.com/Screeen/cMPDR) — no licence stated
- [Improved Statistical Signal Processing of Nonstationary Random Processes Using Time-Warping](https://digital.lib.washington.edu/server/api/core/bitstreams/ec09d3e5-7cec-4024-a0d9-35e4066886cf/content) — Scott Wisdom, M.S. thesis, University of Washington, 2014
- [Fast_SC: fast spectral correlation](https://www.mathworks.com/matlabcentral/fileexchange/60561-fast_sc-x-nw-alpha_max-fs-opt) — Antoni; [A faster algorithm for the fast spectral correlation](https://katalog.hcu-hamburg.de/vufind/Search2Record/ELV001615327) — Borghesani and Antoni, 2018

**Pitch tracking in noise, and pulsar search**

- [MAP pitch tracking in noisy environments using a harmonic model](https://cris.bgu.ac.il/en/publications/maximum-a-posteriori-probability-pitch-tracking-in-noisy-environm-2/) — Tabrikian, Dubnov, Dickalov, 2004
- [Harmonic summation-based robust pitch estimation in noisy and reverberant environments](https://arxiv.org/html/2509.16480v1) — Singh, Demuynck, 2025
- [Joint robust voicing detection and pitch estimation based on residual harmonics (SRH)](https://www.emergentmind.com/papers/2001.00459) — Drugman, Alwan
- [SwiftF0: fast and accurate monophonic pitch detection](https://arxiv.org/abs/2508.18440v1) — Nieradzik, 2025
- [Searching for pulsars with PRESTO](https://hosting.astro.cornell.edu/~shami/psrintro/papers/Ransom_PRESTO_tutorial.pdf) — Ransom; [A Fourier-domain jerk search for binary pulsars](https://www.arxiv.org/pdf/1807.07900) — Andersen, Ransom, 2018

**Learning from the noisy file itself**

- [Remixed2Remixed](https://arxiv.org/html/2312.16836v1), which summarises noisy-target training (Fujimura et al.) and Noisier2Noise
- [Self-supervised speech denoising using only noisy audio signals](https://www.bohrium.com/paper-details/self-supervised-speech-denoising-using-only-noisy-audio-signals/849055949304889344-2586) — Wu et al., 2023
- [Efficient personalized speech enhancement through self-supervised learning](https://par.nsf.gov/servlets/purl/10400775) — Sivaraman, Kim, 2022
- [GTCRN, MIT licence as carried on its model card](https://huggingface.co/agentable/gtcrn-simple-mlx) — upstream Xiaobin-Rong/gtcrn

**Unsupervised generative enhancement and uncertainty**

- [Unsupervised speech enhancement with diffusion-based generative models (UDiffSE)](https://arxiv.org/pdf/2309.10450) — Nortier, Sadeghi, Serizel, 2023
- [Diffusion-based frameworks for unsupervised speech enhancement](https://arxiv.org/pdf/2601.09931) — Ayilo et al., 2026
- [Posterior transition modeling for unsupervised diffusion-based speech enhancement](https://arxiv.org/pdf/2507.02391) — 2025
- [ArtiFree: detecting and reducing generative artifacts in diffusion-based speech enhancement](https://arxiv.org/html/2509.19495v1) — Chhaglani et al., 2025

**Injection-recovery practice**

- [Search for intermediate-mass-ratio inspirals in LVK O3](https://arxiv.org/pdf/2507.01083) — injection-recovery test with time-slide background
- [Kepler pipeline transit injections](https://ar5iv.arxiv.org/html/1605.05729)

**Speaker bootstrapping and drones**

- [Monaural target speaker extraction via distance and speaker information (self-enrolment)](https://www.isca-archive.org/interspeech_2023/lin23b_interspeech.html) — Lin et al., 2023
- [Mixture-to-set speaker embeddings for enrollment-free target speech extraction](https://arxiv.org/pdf/2604.03219) — 2026
- [Acoustic drone package delivery detection](https://arxiv.org/html/2602.09991) — Marcoux, Grondin, 2026; [acoustic drone detection notes (BPF 50–300 Hz)](https://www.jaredwatkins.com/research/drone-detection/open-source/acoustic-ml-pipeline/)
