//go:build whisper

package multimodal

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	whisper "github.com/ggerganov/whisper.cpp/bindings/go/pkg/whisper"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// whisperTranscriber runs whisper.cpp over decoded audio samples. Compiled only
// under the "whisper" build tag (CGo). The model path comes from the
// "whisper_model" config key.
//
// UNVERIFIED: this file cannot be compiled or exercised in the environment it
// was authored in (no libwhisper installed, CGO cannot link against it). The
// shape of the whisper.Model/whisper.Context API below was confirmed by
// reading the resolved dependency's source
// (github.com/ggerganov/whisper.cpp/bindings/go/pkg/whisper@<resolved
// version>: interface.go, model.go) rather than by a live build. Re-verify
// with `go vet -tags whisper ./internal/detectors/multimodal/` on a machine
// with whisper.cpp built before relying on this in production.
type whisperTranscriber struct {
	model whisper.Model
}

// newTranscriber builds a whisper.cpp-backed Transcriber. Only compiled when
// the binary is built with -tags whisper (CGO_ENABLED=1 and libwhisper
// available at link time).
func newTranscriber(cfg registry.Config) (Transcriber, error) {
	path := registry.GetString(cfg, "whisper_model", "")
	if path == "" {
		return nil, fmt.Errorf("whisper_model config key is required when built with -tags whisper")
	}
	model, err := whisper.New(path)
	if err != nil {
		return nil, fmt.Errorf("load whisper model %q: %w", path, err)
	}
	return &whisperTranscriber{model: model}, nil
}

// Transcribe decodes the audio attachment (expected to be 16-bit PCM WAV,
// which is what the multimodal audio-attack fixtures produce) into the
// mono 16kHz float32 samples whisper.cpp expects, then runs the model over
// them and concatenates the resulting segments.
func (w *whisperTranscriber) Transcribe(_ context.Context, a attempt.Audio) (string, error) {
	b64, err := a.ToBase64()
	if err != nil {
		return "", err
	}
	if b64 == "" {
		return "", errors.New("transcribe: audio attachment has no data")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode audio: %w", err)
	}
	samples, err := decodeWAVToFloat32(raw)
	if err != nil {
		return "", fmt.Errorf("decode wav: %w", err)
	}

	ctx, err := w.model.NewContext()
	if err != nil {
		return "", fmt.Errorf("new whisper context: %w", err)
	}

	if err := ctx.Process(samples, nil, nil, nil); err != nil {
		return "", fmt.Errorf("whisper process: %w", err)
	}

	var out string
	for {
		seg, err := ctx.NextSegment()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", fmt.Errorf("whisper next segment: %w", err)
		}
		out += seg.Text
	}
	return out, nil
}

// --- Minimal WAV (RIFF/PCM) decoder -----------------------------------------
//
// whisper.cpp expects mono float32 samples in [-1, 1] at 16kHz. The
// multimodal audio fixtures ship as 16-bit PCM WAV, so a full-featured audio
// library is unnecessary; this parser handles the "fmt " and "data" chunks of
// a canonical WAV file and converts PCM16 samples to float32. It rejects
// anything it can't confidently convert (non-PCM formats, missing chunks)
// rather than silently mis-transcribing.
//
// It intentionally does not resample or downmix: callers are expected to
// supply 16kHz mono audio (as whisper.cpp itself requires), matching what the
// multimodal probes generate. If stereo or non-16kHz audio is encountered, an
// error is returned rather than guessing at a conversion.

const (
	wavFmtPCM        = 1
	wavHeaderMinSize = 44
	whisperSampleHz  = 16000
)

func decodeWAVToFloat32(b []byte) ([]float32, error) {
	if len(b) < wavHeaderMinSize {
		return nil, fmt.Errorf("wav: file too small (%d bytes)", len(b))
	}
	if string(b[0:4]) != "RIFF" || string(b[8:12]) != "WAVE" {
		return nil, errors.New("wav: missing RIFF/WAVE header")
	}

	var (
		numChannels   uint16
		sampleRate    uint32
		bitsPerSample uint16
		haveFmt       bool
		samples       []float32
	)

	offset := 12
	for offset+8 <= len(b) {
		chunkID := string(b[offset : offset+4])
		chunkSize := int(binary.LittleEndian.Uint32(b[offset+4 : offset+8]))
		body := offset + 8
		if body+chunkSize > len(b) {
			// Truncated chunk; stop parsing rather than reading OOB.
			break
		}

		switch chunkID {
		case "fmt ":
			if chunkSize < 16 {
				return nil, errors.New("wav: fmt chunk too small")
			}
			audioFormat := binary.LittleEndian.Uint16(b[body : body+2])
			if audioFormat != wavFmtPCM {
				return nil, fmt.Errorf("wav: unsupported audio format %d (only PCM is supported)", audioFormat)
			}
			numChannels = binary.LittleEndian.Uint16(b[body+2 : body+4])
			sampleRate = binary.LittleEndian.Uint32(b[body+4 : body+8])
			bitsPerSample = binary.LittleEndian.Uint16(b[body+14 : body+16])
			haveFmt = true
		case "data":
			if !haveFmt {
				return nil, errors.New("wav: data chunk before fmt chunk")
			}
			if bitsPerSample != 16 {
				return nil, fmt.Errorf("wav: unsupported bits-per-sample %d (only 16-bit PCM is supported)", bitsPerSample)
			}
			pcm := b[body : body+chunkSize]
			samples = make([]float32, len(pcm)/2)
			for i := range samples {
				v := int16(binary.LittleEndian.Uint16(pcm[i*2 : i*2+2]))
				samples[i] = float32(v) / 32768.0
			}
		}

		// Chunks are padded to even sizes.
		advance := chunkSize
		if advance%2 == 1 {
			advance++
		}
		offset = body + advance
	}

	if !haveFmt {
		return nil, errors.New("wav: missing fmt chunk")
	}
	if samples == nil {
		return nil, errors.New("wav: missing data chunk")
	}
	if sampleRate != whisperSampleHz {
		return nil, fmt.Errorf("wav: expected %d Hz sample rate, got %d", whisperSampleHz, sampleRate)
	}
	if numChannels != 1 {
		return nil, fmt.Errorf("wav: expected mono audio, got %d channels", numChannels)
	}

	return samples, nil
}
