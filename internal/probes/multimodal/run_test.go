package multimodal

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "test.Probe", "test.Detector")
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

	attempts, err := RunMultimodalPrompts(context.Background(), gen, prompts, "test.Probe", "test.Detector")
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

	attempts, err := RunMultimodalPrompts(ctx, gen, prompts, "test.Probe", "test.Detector")
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

	attempts, err := RunMultimodalPrompts(context.Background(), gen, nil, "test.Probe", "test.Detector")
	require.NoError(t, err)
	assert.Empty(t, attempts)
	assert.Equal(t, 0, gen.callCount)
}
