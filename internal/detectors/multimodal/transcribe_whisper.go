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

// Close releases the CGo-owned whisper model. whisper.New allocates a full
// model copy outside Go's heap, so it is not reclaimed by the GC — only by this
// call or process exit.
//
// NOTE: types.Detector has no teardown hook, so nothing in the scan pipeline
// calls this yet; a whisper-enabled run holds one model for the process
// lifetime. This makes the resource releasable so that a detector-lifecycle
// hook can wire it up without touching the whisper backend again.
func (w *whisperTranscriber) Close() error {
	if w.model == nil {
		return nil
	}
	err := w.model.Close()
	w.model = nil // idempotent: a second Close is a no-op, never a double free
	return err
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
// whisper.cpp expects mono float32 samples in [-1, 1] at 16kHz. This decoder
// handles audio returned by the MODEL under test (e.g. OpenAI
// gpt-4o-audio-preview, which returns 24kHz mono PCM16 WAV), not just the
// probe's outbound fixtures, so the incoming sample rate is provider-set and
// not guaranteed to already be 16kHz mono. It parses the "fmt " and "data"
// chunks of a canonical WAV file, converts PCM16 samples to float32, downmixes
// multi-channel audio to mono, and resamples to whisper's required 16kHz
// using linear interpolation. It still rejects anything it can't confidently
// convert (non-PCM formats, missing chunks, unrecognized sample rates) rather
// than silently mis-transcribing.
//
// NOTE: this file is compiled only under the "whisper" build tag (see the
// build constraint at the top of the file) and this environment has no
// libwhisper installed, so the resampling logic below has NOT been exercised
// against a live whisper.cpp build or real provider audio — it is unverified
// beyond code review and the reasoning documented here. Re-verify with a real
// 24kHz sample from gpt-4o-audio-preview on a machine with whisper.cpp built.

const (
	wavFmtPCM        = 1
	wavHeaderMinSize = 44
	whisperSampleHz  = 16000
)

// supportedWAVSampleRates lists the PCM16 WAV sample rates this decoder will
// resample down to whisper's required 16kHz, rather than reject outright.
// These cover the common rates seen from LLM audio providers: 16000 (already
// whisper-native, e.g. some TTS/ASR pipelines), 24000 (OpenAI
// gpt-4o-audio-preview's response audio), 44100 and 48000 (standard CD/DAT and
// professional-audio rates other providers or client-side encoders may use).
var supportedWAVSampleRates = map[uint32]bool{
	16000: true,
	24000: true,
	44100: true,
	48000: true,
}

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
	if numChannels == 0 {
		return nil, errors.New("wav: fmt chunk declares 0 channels")
	}
	if !supportedWAVSampleRates[sampleRate] {
		return nil, fmt.Errorf("wav: unsupported sample rate %d Hz (supported: 16000, 24000, 44100, 48000)", sampleRate)
	}

	mono := downmixToMono(samples, int(numChannels))
	resampled := resampleLinear(mono, int(sampleRate), whisperSampleHz)

	return resampled, nil
}

// downmixToMono averages interleaved multi-channel PCM samples down to a
// single mono channel. If numChannels is 1, samples is returned unchanged.
func downmixToMono(samples []float32, numChannels int) []float32 {
	if numChannels <= 1 {
		return samples
	}
	frames := len(samples) / numChannels
	mono := make([]float32, frames)
	for i := 0; i < frames; i++ {
		var sum float32
		base := i * numChannels
		for c := 0; c < numChannels; c++ {
			sum += samples[base+c]
		}
		mono[i] = sum / float32(numChannels)
	}
	return mono
}

// resampleLinear converts mono float32 samples from srcHz to dstHz using
// linear interpolation. This is a low-fidelity resampler (no anti-aliasing
// filter), but it is adequate for feeding whisper.cpp, which is robust to
// modest resampling artifacts; a proper sinc/polyphase resampler is not
// warranted for this use case. If srcHz already equals dstHz, samples is
// returned unchanged.
func resampleLinear(samples []float32, srcHz, dstHz int) []float32 {
	if srcHz == dstHz || len(samples) == 0 {
		return samples
	}

	ratio := float64(srcHz) / float64(dstHz)
	outLen := int(float64(len(samples)) / ratio)
	if outLen < 1 {
		outLen = 1
	}
	out := make([]float32, outLen)
	for i := range out {
		srcPos := float64(i) * ratio
		idx := int(srcPos)
		frac := srcPos - float64(idx)

		if idx >= len(samples)-1 {
			out[i] = samples[len(samples)-1]
			continue
		}
		out[i] = samples[idx]*float32(1-frac) + samples[idx+1]*float32(frac)
	}
	return out
}
