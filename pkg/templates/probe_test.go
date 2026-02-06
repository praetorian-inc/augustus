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
