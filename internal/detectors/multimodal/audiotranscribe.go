package multimodal

import (
	"context"
	"fmt"

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

// Detect transcribes output audio (when present) into a shadow attempt whose
// Outputs are the transcripts, then delegates scoring to the policy detector.
// When no output audio is present it scores the attempt's existing text outputs.
func (d *AudioTranscribe) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
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
