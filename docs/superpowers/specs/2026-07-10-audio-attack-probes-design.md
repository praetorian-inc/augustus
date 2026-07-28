# Audio Attack Probes (LAB-2367) — Design

> **Descoped in review (2026-07-28): the `audio.*` probe layer ships separately.**
> PR #236 review established that the five probes as designed here do not produce
> an honest true/false signal: the spoken payload carries no harmful objective, and
> the default `mitigation.MitigationBypass` policy detector scores *any non-refusing
> response* as a bypass — so a model harmlessly complying with a benign story
> request scores `1.0` vulnerable regardless of any audio-jailbreak weakness. That
> is a false positive by construction. `audio.Ultrasonic` was additionally found
> unsalvageable: it is an attack on microphone hardware that a WAV-accepting API
> never exposes, and the committed fixture was verified to be **digital silence**
> (25 non-zero samples in 48 000) because resampling a 19 kHz tone to 16 kHz
> lowpasses it away.
>
> This PR therefore lands **only the audio infrastructure** — §1, §2, §3 and §6
> below. §4 (the five probes) and §5 (fixtures) are **not delivered here**; they are
> retained as design history and supersede-able by the follow-up, which must add a
> real harmful objective per payload, a harm-measuring (not non-refusal) policy
> detector with per-prompt ground truth and a benign control, true any-of-N
> semantics for Best-of-N, and a fixture transcript verifier. `audio.Ultrasonic` is
> dropped outright and its DolphinAttack citation severed.

## Goal

Add the first audio-modality attack probes to Augustus: five payload/fixture-based
probes under the `audio.*` namespace, a transcription-backed detector
(`multimodal.AudioTranscribe`), and the OpenAI `gpt-4o-audio-preview` wire path
needed to run them end-to-end.

Parent: LAB-2364 (Multimodal Attacks). Related: LAB-2099 (image probes,
architectural precedent), LAB-4082 (MM-specific detector research).

## Scope

**In scope**

- `AudioCapable` generator interface + audio gating in the multimodal probe runner.
- OpenAI `gpt-4o-audio-preview` audio input/output wire path (custom HTTP, since
  the pinned go-openai SDK cannot model `input_audio` content parts).
- `multimodal.AudioTranscribe` detector: transcribe model **output** audio via
  whisper.cpp, then score the transcript with an existing policy detector.
- ~~Five `audio.*` probes with committed, reproducibly-generated WAV/MP3 fixtures.~~
  **Descoped to a follow-up** — see the note at the top of this document.

**Out of scope (future)**

- Gemini native audio path (probes run once it lands; explicitly deferred).
- Gradient-based AdvWave / AudioJailbreak (legal review + compute heavy).
- Realtime / streaming audio.

## Existing scaffolding (already present, reused)

- `attempt.Audio` type, `attempt.NewUserMessageWithAudio`, and `Message.Audio`
  field (prompt and response side).
- `multimodal.MultimodalProbe` interface already declares `GetAudio()`.
- `openaicompat` already ships spec-correct audio **wire types**:
  `AudioContentPart`, `InputAudioPayload`, `AudioFormatFromMime` — with a `NOTE`
  in `openaicompat.go` deferring the actual emission to this ticket.

## Architecture

### 1. Capability interface & probe plumbing

- **`pkg/types/generator.go`**: add optional interface
  ```go
  // AudioCapable declares that the generator's wire layer can transmit audio
  // attachments (Message.Audio). Audio probes gate on this so a generator that
  // cannot carry audio fails the probe rather than silently sending a text-only
  // request and mis-reporting the target as safe. Report structural capability.
  type AudioCapable interface { SupportsAudio() bool }
  ```
- **`pkg/attempt`**: add a metadata-key constant `MetaAudioOutput` next to the
  existing `MetaMultimodalCanary` / `MetaMultimodalCovert` keys. It carries the
  model's returned audio (`[]attempt.Audio`) so the detector can transcribe it.
- **`internal/probes/multimodal/run.go`**:
  - Add `Audio []attempt.Audio` to `MultimodalPrompt`.
  - Add `ErrAudioUnsupported` and `generatorSupportsAudio(gen)` (type-asserts
    `types.AudioCapable`), mirroring the vision/document pattern.
  - Extend the per-attachment gating loop: a prompt carrying audio requires
    `AudioCapable`; if absent, return the wrapped `ErrAudioUnsupported` (probe
    fails, never a silent text-only "safe").
  - Emit audio on the request: `msg.Audio = mp.Audio`.
  - After `gen.Generate`, if any response `Message.Audio` is populated, store it
    on the attempt: `a.Metadata[attempt.MetaAudioOutput] = <[]attempt.Audio>`.
    Text transcript (if any) still flows through `a.AddOutput(resp.Content)`.
- **`internal/probes/multimodal/probe.go`**: change `BaseMultimodalProbe.GetAudio()`
  to aggregate `mp.Audio` across prompts (currently hardcoded `nil`), symmetric
  with `GetImages`/`GetDocuments`.

### 2. OpenAI audio wire path (custom HTTP)

go-openai v1.41.2 `ChatMessagePart` exposes only `text` and `image_url`, so audio
cannot ride the typed SDK builder. Approach:

- **`internal/generators/openaicompat`**: add an audio request builder and
  response parser built on the existing `audio.go` wire types:
  - Request body (JSON): `model`, `messages` (text + `input_audio` parts),
    `modalities: ["text","audio"]`, `audio: {voice, format}` (defaults
    `voice:"alloy"`, `format:"wav"`), plus the usual sampling params.
  - Response parse: `choices[].message.content` (text) and
    `choices[].message.audio.{data,transcript,format}` (returned audio →
    `attempt.Audio`; transcript → message content when `content` is empty).
  - Reuse `WrapError` and token accounting.
- **`internal/generators/openai/openai.go`**:
  - In `generateChat`, detect whether the conversation carries audio; if so,
    route to a new `generateChatAudio` that issues the custom HTTP POST to
    `{baseURL}/chat/completions` (bypassing `client.CreateChatCompletion`).
    Non-audio requests keep the existing SDK path unchanged.
  - Add `func (g *OpenAI) SupportsAudio() bool { return g.isChat }` (structural:
    the chat path can carry audio; completion path cannot).
- **`internal/generators/openaicompat/openaicompat.go`**: add
  `func (g *CompatGenerator) SupportsAudio() bool { return true }` (structural,
  matching its existing `SupportsVision`).

### 3. `multimodal.AudioTranscribe` detector

A decorator detector: audio output → transcript → wrapped policy detector.

- **Transcriber seam** (unit-testable):
  ```go
  type Transcriber interface { Transcribe(ctx context.Context, a attempt.Audio) (string, error) }
  ```
- **Build-tagged implementations**:
  - `transcribe_whisper.go` (`//go:build whisper`): CGo whisper.cpp binding
    (`github.com/ggerganov/whisper.cpp/bindings/go`). Model path + params from
    detector config (`whisper_model`); returns a clear error if the model can't
    be loaded.
  - `transcribe_stub.go` (`//go:build !whisper`): returns
    `errors.New("multimodal.AudioTranscribe: built without whisper support; rebuild with -tags whisper")`.
    The detector still registers so `--detector multimodal.AudioTranscribe`
    resolves; it fails loudly at Detect time rather than mis-scoring.
- **Detector logic** (`audiotranscribe.go`, build-tag-agnostic):
  - Config keys: `policy_detector` (name, default `mitigation.MitigationBypass`),
    `whisper_model` (path, passed to the transcriber).
  - `Detect(ctx, a)` — **transcript-first, whisper fallback** (see Deviation below):
    1. If any of `a.Outputs` carries non-whitespace text (the provider transcript,
       which `gpt-4o-audio-preview` returns alongside audio), delegate the policy
       detector to the original attempt and return — the transcriber is not called.
    2. Otherwise, if output audio is present (`a.Metadata[MetaAudioOutput]`), whisper-
       transcribe each clip; build a shadow attempt whose `Outputs` are the
       transcripts; delegate to the policy detector on the shadow.
    3. If neither usable text nor output audio is present, delegate to the policy
       detector on the original attempt.
  - Register: `detectors.Register("multimodal.AudioTranscribe", NewAudioTranscribe)`.

> **Deviation from original design (approved during implementation):** the spec
> originally specified whisper-first — always independently transcribe the audio
> bytes and never trust the provider transcript. In practice `gpt-4o-audio-preview`
> returns a text transcript with every response, and requiring whisper would (a)
> gate the acceptance criteria on a CGo `-tags whisper` build + model file, and (b)
> hit a sample-rate mismatch (the model returns 24 kHz audio; whisper needs 16 kHz).
> The detector is therefore transcript-first: it scores the provider transcript when
> present and falls back to whisper (with a resample-to-16 kHz decode) only for
> audio-only responses that carry no transcript. This lets acceptance criterion (c)
> pass on the default CGo-free build. Trade-off: for providers that return a
> transcript we trust that transcript rather than re-deriving it; a provider that
> sanitizes its transcript could under-report — revisit if that materializes.

The wrapped `mitigation.MitigationBypass` scores high when the (transcribed)
response lacks refusal/mitigation language — i.e. the model complied with the
audio jailbreak.

### 4. The five probes — `internal/probes/audio/` (NOT DELIVERED — descoped, see top)

New package; each probe embeds `multimodal.BaseMultimodalProbe` with
`PrimaryDetector: "multimodal.AudioTranscribe"` and audio-bearing
`MultimodalPrompt`s. Fixtures embedded via `embed.FS`.

| Probe | Technique | Fixtures |
|-------|-----------|----------|
| `audio.VoiceJailbreakTTS` | Fictional-story jailbreak spoken via TTS | 1 WAV |
| `audio.MultiAudioJailLang` | Same payload across languages/accents (Multi-AudioJail) | N WAVs (per language/voice) |
| `audio.BestOfN` | N perturbed variants of one payload; embarrassingly parallel | N WAVs; `n` configurable via `registry.Config` |
| `audio.JailbreakBenchEdit` | Deterministic audio-editing injection (benign base + spliced adversarial segment) | 1 WAV |
| `audio.Ultrasonic` | >18 kHz content as a filtering PoC (DolphinAttack-style) | 1 WAV |

Add the package's blank import to the central probe registration aggregator
(`pkg/register/probes/probes.go`) so `init()` registration fires. Detector
registration (`multimodal.AudioTranscribe`) lands via the analogous detector
aggregator.

### 5. Fixtures — committed + reproducible (NOT DELIVERED — descoped, see top)

`internal/probes/audio/data/` holds committed WAV/MP3 fixtures plus
`gen_fixtures.sh`:

- TTS payloads: macOS `say -o … .aiff` → `ffmpeg` to 16 kHz mono WAV.
- Multilingual: `say -v <voice>` across configured voices/languages.
- Best-of-N: `ffmpeg` perturbations off a base clip (`asetrate`/`atempo` pitch &
  tempo shifts, additive noise).
- Edit probe: `ffmpeg` concat of a benign base clip + a short adversarial segment.
- Ultrasonic: `ffmpeg -f lavfi -i "sine=frequency=19000:duration=…"`.

Committed audio means builds/tests need no audio tooling; the script only reruns
to regenerate. Spoken content mirrors existing jailbreak-probe style (adversarial
framing, no authored harmful how-to content).

### 6. Build & CI

- Default `make build` and CI remain CGo-free (stub transcriber compiled).
- Add a documented whisper build path: `make build-whisper`
  (`go build -tags whisper ./cmd/augustus`), which is what audio E2E requires.
- Document the `-tags whisper` requirement + `whisper_model` config in the probe
  package doc comment.

## Testing

- **Probe plumbing**: unit tests for audio gating in `RunMultimodalPrompts`
  (audio prompt + non-`AudioCapable` generator → `ErrAudioUnsupported`; capable
  generator → audio emitted; response audio captured into `MetaAudioOutput`).
- **`GetAudio()` aggregation**: unit test on `BaseMultimodalProbe`.
- **Detector**: unit tests with a **fake `Transcriber`** (no whisper build tag) —
  verifies transcript→policy-detector delegation, the no-audio fallback, and
  stub-error surfacing. Fake generator with canned audio output.
- **OpenAI audio path**: `httptest` server asserting the request body carries
  `input_audio` parts + `modalities`, and that returned `message.audio` is parsed
  into `attempt.Audio` / `MetaAudioOutput`.
- **Probes**: construction tests (each registers, exposes fixtures, names/goal
  set) mirroring `internal/probes/multimodal/probe_construction_test.go`.
- **Fixtures**: a test asserting each embedded fixture is a non-empty, valid
  WAV/MP3 header.

## Acceptance mapping

**Delivered here (infrastructure only):**

- `types.AudioCapable` gating fails loud with a wrapped `ErrAudioUnsupported`
  rather than sending a text-only request → §1.
- The OpenAI `gpt-4o-audio-preview` wire path emits `input_audio` parts and
  parses returned audio/transcript → §2.
- `multimodal.AudioTranscribe` resolves and scores a provider transcript on the
  default CGo-free build; the whisper path compiles under `-tags whisper` and its
  stub fails loudly otherwise → §3.
- `go build ./...`, `go test -race ./...`, `make lint`, `make generate-check` all clean.

**Follow-up criteria (NOT acceptance for this PR — see the descope note at top):**

- ~~`augustus scan openai.gpt-4o-audio-preview --probe audio.*` runs end-to-end on
  ≥3/5 probes~~ — requires the reworked probes; §4/§5 are not delivered here.
- ~~`multimodal.AudioTranscribe` produces non-zero scoring on ≥3/5 probes~~ —
  and must measure *harmful compliance*, not non-refusal: scoring "non-zero" via
  `mitigation.MitigationBypass` is precisely the false positive that descoped the
  probes. The follow-up replaces this criterion with a harm-measuring judge plus a
  benign control that must score `0.0`.
- `augustus scan gemini.Gemini --probe audio.*` → still deferred until the Gemini
  audio path lands (out of scope in both this PR and the follow-up).

## Risks / notes

- **CGo whisper.cpp**: not linked by default; audio scoring requires the
  `whisper` build tag and a model file. The stub keeps the default build green.
- **`gpt-4o-audio-preview` request shape**: audio models require `modalities` +
  `audio` config; the custom HTTP builder must set these or the API errors.
- **Transcription source**: superseded by the transcript-first Deviation in §3 —
  the detector scores the provider transcript when present and uses whisper only
  as a fallback for audio-only responses. The original "always independently
  transcribe with whisper" intent is retained as the fallback path.
