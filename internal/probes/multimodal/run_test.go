package multimodal

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// mockGenerator implements types.Generator for testing RunMultimodalPrompts.
type mockGenerator struct {
	responses []attempt.Message
	err       error
	callCount int
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.callCount++
	if m.err != nil {
		return nil, m.err
	}
	return m.responses, nil
}

func (m *mockGenerator) ClearHistory() {}
func (m *mockGenerator) Name() string  { return "mock.Generator" }
func (m *mockGenerator) Description() string {
	return "Mock generator for testing"
}

// SupportsVision marks the mock as vision-capable so the pre-flight gate in
// RunMultimodalPrompts lets it through. See types.VisionCapable.
func (m *mockGenerator) SupportsVision() bool { return true }

// textOnlyGenerator is a generator that does NOT implement types.VisionCapable,
// used to verify multimodal probes skip image-blind targets.
type textOnlyGenerator struct {
	callCount int
}

func (g *textOnlyGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	g.callCount++
	return []attempt.Message{{Content: "ok"}}, nil
}
func (g *textOnlyGenerator) ClearHistory()       {}
func (g *textOnlyGenerator) Name() string        { return "text.Only" }
func (g *textOnlyGenerator) Description() string { return "Text-only generator for testing" }

func TestRunMultimodalPrompts_HappyPath(t *testing.T) {
	gen := &mockGenerator{
		responses: []attempt.Message{
			{Content: "response 1"},
		},
	}

	prompts := []MultimodalPrompt{
		{Text: "prompt 1", Images: []attempt.Image{{Data: []byte("img1"), MimeType: "image/png"}}},
		{Text: "prompt 2", Images: []attempt.Image{{Data: []byte("img2"), MimeType: "image/png"}}},
	}

	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "test.Probe", "test.Detector", true)
	require.NoError(t, err)
	require.Len(t, attempts, 2)

	for i, a := range attempts {
		assert.Equal(t, prompts[i].Text, a.Prompt, "attempt %d prompt mismatch", i)
		assert.Equal(t, "test.Probe", a.Probe, "attempt %d probe name mismatch", i)
		assert.Equal(t, "test.Detector", a.Detector, "attempt %d detector mismatch", i)
		assert.Equal(t, attempt.StatusComplete, a.Status, "attempt %d should be complete", i)
		assert.Len(t, a.Outputs, 1, "attempt %d should have one output", i)
		assert.Equal(t, "response 1", a.Outputs[0])
		assert.Empty(t, a.Error)
	}

	assert.Equal(t, 2, gen.callCount)
}

func TestRunMultimodalPrompts_GeneratorError(t *testing.T) {
	genErr := errors.New("model unavailable")
	gen := &mockGenerator{err: genErr}

	prompts := []MultimodalPrompt{
		{Text: "prompt 1", Images: []attempt.Image{{Data: []byte("img"), MimeType: "image/png"}}},
	}

	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "test.Probe", "test.Detector", true)
	// Per the contract: generator errors are recorded in the attempt, NOT returned.
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusError, a.Status)
	assert.Contains(t, a.Error, "model unavailable")
	assert.Empty(t, a.Outputs)
}

func TestRunMultimodalPrompts_ContextCancellation(t *testing.T) {
	gen := &mockGenerator{
		responses: []attempt.Message{{Content: "ok"}},
	}

	// Cancel context before calling.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	prompts := []MultimodalPrompt{
		{Text: "prompt 1", Images: []attempt.Image{{Data: []byte("img"), MimeType: "image/png"}}},
	}

	attempts, err := RunMultimodalPrompts(ctx, gen, prompts, "test.Probe", "test.Detector", true)
	// Context cancellation IS returned as an error.
	assert.ErrorIs(t, err, context.Canceled)
	// No prompts should have been executed.
	assert.Empty(t, attempts)
	assert.Equal(t, 0, gen.callCount)
}

func TestRunMultimodalPrompts_EmptyPrompts(t *testing.T) {
	gen := &mockGenerator{
		responses: []attempt.Message{{Content: "ok"}},
	}

	attempts, err := RunMultimodalPrompts(context.Background(), gen, nil, "test.Probe", "test.Detector", true)
	require.NoError(t, err)
	assert.Empty(t, attempts)
	assert.Equal(t, 0, gen.callCount)
}

func TestRunMultimodalPrompts_SkipsNonVisionGenerator(t *testing.T) {
	gen := &textOnlyGenerator{}

	prompts := []MultimodalPrompt{
		{Text: "prompt 1", Images: []attempt.Image{{Data: []byte("img"), MimeType: "image/png"}}},
	}

	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "test.Probe", "test.Detector", true)

	// The probe must fail loudly (ErrVisionUnsupported), never silently run the
	// image attack as a text-only request and report the target as safe.
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrVisionUnsupported)
	assert.Contains(t, err.Error(), "text.Only", "error should name the generator")
	assert.Nil(t, attempts, "no attempts should be produced for a skipped probe")
	assert.Equal(t, 0, gen.callCount, "generator must not be called at all")
}

// docMockGen is a generator that optionally supports vision and/or documents,
// and records how many document attachments it received across all turns.
type docMockGen struct {
	supportsDocs   bool
	supportsVision bool
	gotDocuments   int
}

func (m *docMockGen) Generate(_ context.Context, conv *attempt.Conversation, _ int) ([]attempt.Message, error) {
	for _, turn := range conv.Turns {
		m.gotDocuments += len(turn.Prompt.Documents)
	}
	return []attempt.Message{{Role: attempt.RoleAssistant, Content: "ok"}}, nil
}
func (m *docMockGen) ClearHistory()           {}
func (m *docMockGen) Name() string            { return "mock.Doc" }
func (m *docMockGen) Description() string     { return "doc mock" }
func (m *docMockGen) SupportsVision() bool    { return m.supportsVision }
func (m *docMockGen) SupportsDocuments() bool { return m.supportsDocs }

func TestRunMultimodalPrompts_DocumentDelivered(t *testing.T) {
	gen := &docMockGen{supportsDocs: true}
	prompts := []MultimodalPrompt{{
		Text:      "summarize",
		Documents: []attempt.Document{{Data: []byte("%PDF-1.7\n"), MimeType: "application/pdf"}},
		Canary:    "ABC123",
	}}
	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "pdf.Test", "multimodal.Canary", true)
	require.NoError(t, err)
	require.Len(t, attempts, 1)
	require.Equal(t, 1, gen.gotDocuments, "document must reach the generator")
	require.Equal(t, "ABC123", attempts[0].Metadata[attempt.MetaMultimodalCanary])
	require.Equal(t, true, attempts[0].Metadata[attempt.MetaMultimodalCovert])
}

func TestRunMultimodalPrompts_DocumentUnsupported(t *testing.T) {
	gen := &docMockGen{supportsDocs: false}
	prompts := []MultimodalPrompt{{
		Text:      "summarize",
		Documents: []attempt.Document{{Data: []byte("%PDF-1.7\n"), MimeType: "application/pdf"}},
	}}
	_, err := RunMultimodalPrompts(context.Background(), gen, prompts, "pdf.Test", "multimodal.Canary", true)
	require.ErrorIs(t, err, ErrDocumentUnsupported)
}

// audioGen is an audio-capable fake generator that echoes a canned audio reply.
type audioGen struct{}

func (audioGen) Name() string        { return "fake.audio" }
func (audioGen) Description() string { return "audio-capable fake generator" }
func (audioGen) ClearHistory()       {}
func (audioGen) SupportsAudio() bool { return true }
func (audioGen) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	reply := attempt.NewAssistantMessage("here is the transcript")
	reply.Audio = []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}
	return []attempt.Message{reply}, nil
}

// textOnlyGen does not implement AudioCapable.
type textOnlyGen struct{}

func (textOnlyGen) Name() string        { return "fake.textonly" }
func (textOnlyGen) Description() string { return "text-only fake generator" }
func (textOnlyGen) ClearHistory()       {}
func (textOnlyGen) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	return []attempt.Message{attempt.NewAssistantMessage("ok")}, nil
}

func TestRunMultimodalPrompts_AudioUnsupported(t *testing.T) {
	prompts := []MultimodalPrompt{{Text: "hi", Audio: []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}}}
	_, err := RunMultimodalPrompts(context.Background(), textOnlyGen{}, prompts, "audio.Test", "multimodal.AudioTranscribe", false)
	if !errors.Is(err, ErrAudioUnsupported) {
		t.Fatalf("err = %v, want ErrAudioUnsupported", err)
	}
}

func TestRunMultimodalPrompts_AudioCaptured(t *testing.T) {
	prompts := []MultimodalPrompt{{Text: "hi", Audio: []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}}}
	attempts, err := RunMultimodalPrompts(context.Background(), audioGen{}, prompts, "audio.Test", "multimodal.AudioTranscribe", false)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	got, ok := attempts[0].Metadata[attempt.MetaAudioOutput].([]attempt.Audio)
	if !ok || len(got) != 1 || got[0].Base64 != "UklGRg==" {
		t.Fatalf("output audio not captured: %#v", attempts[0].Metadata[attempt.MetaAudioOutput])
	}
}
