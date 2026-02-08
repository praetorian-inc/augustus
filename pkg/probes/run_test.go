package probes_test

import (
	"context"
	"errors"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGen is a mock implementation of types.Generator for testing.
type mockGen struct {
	generateFunc func(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
	err          error
}

func (m *mockGen) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if m.generateFunc != nil {
		return m.generateFunc(ctx, conv, n)
	}
	if m.err != nil {
		return nil, m.err
	}
	return []attempt.Message{{Content: "mock response"}}, nil
}

func (m *mockGen) ClearHistory() {}

func (m *mockGen) Name() string {
	return "mock-generator"
}

func (m *mockGen) Description() string {
	return "Mock generator for testing"
}

func TestRunPrompts_Basic(t *testing.T) {
	gen := &mockGen{}
	prompts := []string{"prompt1", "prompt2", "prompt3"}

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil)

	require.NoError(t, err)
	assert.Len(t, attempts, 3, "should return one attempt per prompt")

	for i, att := range attempts {
		assert.Equal(t, prompts[i], att.Prompt, "prompt should match input")
		assert.Equal(t, []string{prompts[i]}, att.Prompts, "prompts slice should contain single prompt")
		assert.Equal(t, []string{"mock response"}, att.Outputs, "should contain generator response")
		assert.Equal(t, attempt.StatusComplete, att.Status, "status should be complete")
		assert.Empty(t, att.Error, "error should be empty")
		assert.Equal(t, "test-probe", att.Probe, "probe name should be set")
		assert.Equal(t, "test-detector", att.Detector, "detector should be set")
	}
}

func TestRunPrompts_GeneratorError(t *testing.T) {
	expectedErr := errors.New("generation failed")
	gen := &mockGen{err: expectedErr}
	prompts := []string{"prompt1"}

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil)

	require.NoError(t, err, "RunPrompts should not return error on generation failure")
	require.Len(t, attempts, 1)

	att := attempts[0]
	assert.Equal(t, attempt.StatusError, att.Status, "status should be error")
	assert.Contains(t, att.Error, "generation failed", "error message should contain generator error")
	assert.Empty(t, att.Outputs, "outputs should be empty on error")
}

func TestRunPrompts_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	gen := &mockGen{}
	prompts := []string{"prompt1"}

	attempts, err := probes.RunPrompts(ctx, gen, prompts, "test-probe", "test-detector", nil)

	require.Error(t, err, "should return error when context is cancelled")
	assert.Contains(t, err.Error(), "context canceled", "error should indicate context cancellation")
	assert.Empty(t, attempts, "should not return attempts when context cancelled")
}

func TestRunPrompts_MetadataFn(t *testing.T) {
	gen := &mockGen{}
	prompts := []string{"prompt1", "prompt2"}

	// MetadataFn that adds custom metadata to each attempt
	metadataFn := func(i int, prompt string, att *attempt.Attempt) {
		att.Metadata["test_key"] = "test_value"
		att.Metadata["prompt_length"] = len(prompt)
		att.Metadata["index"] = i
	}

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", metadataFn)

	require.NoError(t, err)
	require.Len(t, attempts, 2)

	for i, att := range attempts {
		// Verify custom metadata was added
		assert.Equal(t, "test_value", att.Metadata["test_key"], "custom metadata should be present")
		assert.Equal(t, len(prompts[i]), att.Metadata["prompt_length"], "prompt length should be recorded")
		assert.Equal(t, i, att.Metadata["index"], "index should be recorded")
	}
}

func TestRunPrompts_EmptyPrompts(t *testing.T) {
	gen := &mockGen{}
	prompts := []string{}

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil)

	require.NoError(t, err)
	assert.Empty(t, attempts, "should return empty slice for empty prompts")
}
