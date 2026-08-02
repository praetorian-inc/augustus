package multimodal

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/praetorian-inc/augustus/internal/detectors/mitigation"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("multimodal.AudioTranscribe", NewAudioTranscribe)
}

// Transcriber converts an audio attachment to text. It is a seam so the
// detector's scoring logic can be unit-tested with a fake, independent of the
// CGo whisper.cpp backend (which is only compiled under the "whisper" build tag).
type Transcriber interface {
	Transcribe(ctx context.Context, a attempt.Audio) (string, error)
}

// AudioTranscribe scores audio-modality attacks by transcribing the model's
// returned audio (via whisper.cpp) and delegating the transcript to a policy
// detector. Substring/canary matching does not apply to audio output, so the
// transcript is what an existing text detector scores.
//
// Config keys (all optional):
//   - "policy_detector": name of the wrapped detector (default
//     "mitigation.MitigationBypass").
//   - "whisper_model": path to the whisper.cpp model file, passed to the
//     transcriber (ignored by the stub build).
type AudioTranscribe struct {
	name        string
	description string
	transcriber Transcriber
	policy      detectors.Detector
}

// NewAudioTranscribe builds the detector, its transcriber (build-tag-selected),
// and the wrapped policy detector.
func NewAudioTranscribe(cfg registry.Config) (detectors.Detector, error) {
	policyName := registry.GetString(cfg, "policy_detector", "mitigation.MitigationBypass")

	var policy detectors.Detector
	var err error
	if policyName == "mitigation.MitigationBypass" {
		policy, err = mitigation.NewMitigationBypass(cfg)
	} else {
		policy, err = detectors.Registry.Create(policyName, cfg)
	}
	if err != nil {
		return nil, fmt.Errorf("multimodal.AudioTranscribe: policy detector %q: %w", policyName, err)
	}

	tr, err := newTranscriber(cfg)
	if err != nil {
		return nil, fmt.Errorf("multimodal.AudioTranscribe: %w", err)
	}

	return &AudioTranscribe{
		name:        "multimodal.AudioTranscribe",
		description: "Transcribes model audio output with whisper.cpp and scores the transcript with a policy detector",
		transcriber: tr,
		policy:      policy,
	}, nil
}

func (d *AudioTranscribe) Name() string        { return d.name }
func (d *AudioTranscribe) Description() string { return d.description }

// Close releases any resources held by the transcriber, satisfying io.Closer.
// The whisper.cpp backend holds a CGo-allocated model that the Go GC cannot
// reclaim; the stub backend holds nothing and returns nil.
//
// types.Detector currently has no teardown hook, so the scan pipeline never
// calls this. It exists so a detector-lifecycle hook can release the model
// without reaching into the build-tagged backend.
func (d *AudioTranscribe) Close() error {
	if c, ok := d.transcriber.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Detect is transcript-first, whisper-fallback:
//
//  1. If the attempt already carries a usable (non-whitespace) text output —
//     the normal path for providers like OpenAI's gpt-4o-audio-preview, which
//     return both a transcript and raw audio — that transcript is scored
//     directly by the policy detector on the original attempt. Whisper is not
//     invoked; the provider transcript is authoritative.
//  2. Otherwise, if there is output audio in Metadata[attempt.MetaAudioOutput]
//     (an audio-only response with no transcript), each clip is transcribed
//     with whisper and the transcripts are scored via a shadow attempt.
//  3. Otherwise (no usable text and no output audio), the policy detector
//     scores the attempt unchanged.
func (d *AudioTranscribe) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	if hasUsableText(a.Outputs) {
		return d.policy.Detect(ctx, a)
	}

	outAudio, ok := a.Metadata[attempt.MetaAudioOutput].([]attempt.Audio)
	if !ok || len(outAudio) == 0 {
		return d.policy.Detect(ctx, a)
	}

	transcripts := make([]string, 0, len(outAudio))
	for _, au := range outAudio {
		text, err := d.transcriber.Transcribe(ctx, au)
		if err != nil {
			return nil, fmt.Errorf("multimodal.AudioTranscribe: transcribe: %w", err)
		}
		transcripts = append(transcripts, text)
	}

	shadow := attempt.New(a.Prompt)
	shadow.Metadata = a.Metadata
	for _, t := range transcripts {
		shadow.AddOutput(t)
	}
	return d.policy.Detect(ctx, shadow)
}

// hasUsableText reports whether any output is non-empty once whitespace is
// trimmed.
func hasUsableText(outputs []string) bool {
	for _, o := range outputs {
		if strings.TrimSpace(o) != "" {
			return true
		}
	}
	return false
}
