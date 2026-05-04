package templates

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
