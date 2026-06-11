package templates

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockGenerator implements types.Generator for testing
type mockGenerator struct {
	responses []string
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	messages := make([]attempt.Message, 0, len(m.responses))
	for _, content := range m.responses {
		messages = append(messages, attempt.NewAssistantMessage(content))
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory() {}

func (m *mockGenerator) Name() string { return "mock" }

func (m *mockGenerator) Description() string { return "Mock generator for testing" }

func TestTemplateProbeImplementsProber(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.TestProbe",
		Info: ProbeInfo{
			Name:        "Test Probe",
			Description: "A test probe",
			Goal:        "test goal",
			Detector:    "test.Detector",
		},
		Prompts: []string{"prompt 1", "prompt 2"},
	}

	probe := NewTemplateProbe(tmpl)

	// Verify it implements Prober interface
	var _ types.Prober = probe

	assert.Equal(t, "test.TestProbe", probe.Name())
	assert.Equal(t, "A test probe", probe.Description())
	assert.Equal(t, "test goal", probe.Goal())
	assert.Equal(t, "test.Detector", probe.GetPrimaryDetector())
	assert.Equal(t, []string{"prompt 1", "prompt 2"}, probe.GetPrompts())
}

func TestTemplateProbeProbe(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.TestProbe",
		Info: ProbeInfo{
			Name:     "Test Probe",
			Goal:     "test",
			Detector: "test.Detector",
		},
		Prompts: []string{"prompt 1"},
	}

	probe := NewTemplateProbe(tmpl)
	gen := &mockGenerator{responses: []string{"response 1"}}

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	assert.Equal(t, "prompt 1", attempts[0].Prompt)
	assert.Equal(t, "test.TestProbe", attempts[0].Probe)
	assert.Equal(t, "test.Detector", attempts[0].Detector)
	assert.Contains(t, attempts[0].Outputs, "response 1")
}

func TestTemplateProbeGoalMetadata(t *testing.T) {
	t.Run("detector_goal set", func(t *testing.T) {
		tmpl := &ProbeTemplate{
			ID: "test.GoalProbe",
			Info: ProbeInfo{
				Name:         "Goal Probe",
				Goal:         "probe goal",
				Detector:     "judge.Judge",
				DetectorGoal: "specific detector goal",
			},
			Prompts: []string{"prompt 1"},
		}

		probe := NewTemplateProbe(tmpl)
		gen := &mockGenerator{responses: []string{"response"}}

		attempts, err := probe.Probe(context.Background(), gen)
		require.NoError(t, err)
		require.Len(t, attempts, 1)

		assert.Equal(t, "specific detector goal", attempts[0].Metadata["goal"],
			"detector_goal should take precedence over probe goal")
	})

	t.Run("detector_goal empty falls back to probe goal", func(t *testing.T) {
		tmpl := &ProbeTemplate{
			ID: "test.FallbackProbe",
			Info: ProbeInfo{
				Name:     "Fallback Probe",
				Goal:     "probe goal",
				Detector: "judge.Judge",
			},
			Prompts: []string{"prompt 1"},
		}

		probe := NewTemplateProbe(tmpl)
		gen := &mockGenerator{responses: []string{"response"}}

		attempts, err := probe.Probe(context.Background(), gen)
		require.NoError(t, err)
		require.Len(t, attempts, 1)

		assert.Equal(t, "probe goal", attempts[0].Metadata["goal"],
			"should fall back to probe goal when detector_goal is empty")
	})
}

// TestTemplateProbe_GetSecondaryDetectors_EmptyWhenAbsent verifies that
// GetSecondaryDetectors() returns nil (not an empty slice) when the template
// has no secondary_detectors block, preserving backward-compatible behavior.
func TestTemplateProbe_GetSecondaryDetectors_EmptyWhenAbsent(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.NoSecondary",
		Info: ProbeInfo{
			Name:     "No Secondary",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
		},
		Prompts: []string{"Hello."},
	}
	probe := NewTemplateProbe(tmpl)
	assert.Nil(t, probe.GetSecondaryDetectors(),
		"GetSecondaryDetectors() must return nil when secondary_detectors is absent")
}

// TestTemplateProbe_GetSecondaryDetectors_MapsYAMLToTypes verifies that
// GetSecondaryDetectors() correctly maps SecondaryDetectorYAML entries to
// types.SecondaryDetector structs (name and config preserved).
func TestTemplateProbe_GetSecondaryDetectors_MapsYAMLToTypes(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.WithSecondary",
		Info: ProbeInfo{
			Name:     "With Secondary",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			SecondaryDetectors: []SecondaryDetectorYAML{
				{
					Name:   "agent.ArgumentExfiltration",
					Config: map[string]any{"forbidden_patterns": []any{"(?i)evil"}},
				},
			},
		},
		Prompts: []string{"Hello."},
	}
	probe := NewTemplateProbe(tmpl)
	secs := probe.GetSecondaryDetectors()
	require.Len(t, secs, 1)
	assert.Equal(t, "agent.ArgumentExfiltration", secs[0].Name)
	require.NotNil(t, secs[0].Config)
	assert.Equal(t, []any{"(?i)evil"}, secs[0].Config["forbidden_patterns"])
}

// TestTemplateProbe_Probe_ToolsOnly_SingleTurn verifies that a TemplateProbe
// with tools but no ToolResults routes to RunPrompts (single-turn path).
// The attempt should have the probe name, detector, and the generator output.
func TestTemplateProbe_Probe_ToolsOnly_SingleTurn(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.ToolsOnly",
		Info: ProbeInfo{
			Name:     "Tools Only",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools: []ToolDefinition{
				{Name: "web_search", Description: "search"},
			},
			ToolChoice: "auto",
		},
		Prompts: []string{"test prompt"},
	}

	probe := NewTemplateProbe(tmpl)
	gen := &mockGenerator{responses: []string{"tool response"}}

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	assert.Equal(t, "test.ToolsOnly", attempts[0].Probe)
	assert.Equal(t, "agent.ToolManipulation", attempts[0].Detector)
}

// mockGeneratorWithToolCalls implements types.Generator for 2-turn testing.
// The first Generate call returns a message with ToolCalls; subsequent calls
// return plain text responses.
type mockGeneratorWithToolCalls struct {
	callCount int
	toolCalls []map[string]any
	textResp  string
}

func (m *mockGeneratorWithToolCalls) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.callCount++
	if m.callCount == 1 {
		msg := attempt.NewAssistantMessage("")
		msg.ToolCalls = m.toolCalls
		return []attempt.Message{msg}, nil
	}
	return []attempt.Message{attempt.NewAssistantMessage(m.textResp)}, nil
}

func (m *mockGeneratorWithToolCalls) ClearHistory() {}
func (m *mockGeneratorWithToolCalls) Name() string  { return "mock-tool-calls" }
func (m *mockGeneratorWithToolCalls) Description() string {
	return "Mock generator that returns tool calls on first call"
}

// TestTemplateProbe_Probe_ToolsAndResults_TwoTurn verifies that a TemplateProbe
// with both tools and ToolResults routes to RunTwoTurnPrompts (2-turn path).
// The attempt should have outputs from both turns and "tool_calls" in metadata.
func TestTemplateProbe_Probe_ToolsAndResults_TwoTurn(t *testing.T) {
	tmpl := &ProbeTemplate{
		ID: "test.TwoTurn",
		Info: ProbeInfo{
			Name:     "Two Turn",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools: []ToolDefinition{
				{Name: "web_search", Description: "search"},
			},
			ToolChoice: "auto",
			ToolResults: map[string]string{
				"web_search": "search result data",
			},
		},
		Prompts: []string{"test prompt"},
	}

	probe := NewTemplateProbe(tmpl)
	gen := &mockGeneratorWithToolCalls{
		toolCalls: []map[string]any{
			{"name": "web_search", "id": "call_1", "args": map[string]any{"q": "test"}},
		},
		textResp: "turn 2 response",
	}

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.Len(t, attempts, 1)

	a := attempts[0]
	assert.Equal(t, "test.TwoTurn", a.Probe)
	assert.Equal(t, "agent.ToolManipulation", a.Detector)

	// Both turns should produce outputs.
	assert.NotEmpty(t, a.Outputs, "expected outputs from 2-turn probe")

	// Metadata must contain "tool_calls" key because Turn 1 returned tool calls.
	_, hasToolCalls := a.GetMetadata("tool_calls")
	assert.True(t, hasToolCalls, "expected 'tool_calls' key in attempt metadata")
}
