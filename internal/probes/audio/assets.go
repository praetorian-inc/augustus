// Package audio provides audio-modality attack probes for Augustus.
//
// Probes embed multimodal.BaseMultimodalProbe with audio-bearing prompts backed
// by committed WAV fixtures (see data/gen_fixtures.sh). All probes use the
// multimodal.AudioTranscribe detector, which requires a whisper build
// (-tags whisper) plus a whisper_model config to produce non-zero scores.
package audio

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// loadAudio reads an embedded fixture into an attempt.Audio.
func loadAudio(path, mime string) (attempt.Audio, error) {
	data, err := audioData.ReadFile(path)
	if err != nil {
		return attempt.Audio{}, fmt.Errorf("loading embedded audio %q: %w", path, err)
	}
	return attempt.Audio{Data: data, MimeType: mime}, nil
}
