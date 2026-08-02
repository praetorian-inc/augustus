//go:build !whisper

package multimodal

import (
	"context"
	"errors"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// stubTranscriber is compiled when the binary is built without the "whisper"
// build tag. It registers so multimodal.AudioTranscribe resolves, but fails
// loudly at Detect time rather than mis-scoring audio as safe.
type stubTranscriber struct{}

func (stubTranscriber) Transcribe(_ context.Context, _ attempt.Audio) (string, error) {
	return "", errors.New("built without whisper support; rebuild with -tags whisper to score audio output")
}

func newTranscriber(_ registry.Config) (Transcriber, error) {
	return stubTranscriber{}, nil
}
