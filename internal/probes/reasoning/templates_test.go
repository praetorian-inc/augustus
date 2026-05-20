package reasoning

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

type mockGenerator struct{ responses []string }

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	msgs := make([]attempt.Message, len(m.responses))
	for i, r := range m.responses {
		msgs[i] = attempt.Message{Role: "assistant", Content: r}
	}
	return msgs, nil
}
func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock" }

func TestReasoningProbesRegistered(t *testing.T) {
	expected := []string{
		"reasoning.HCoT",
		"reasoning.ShadowCoT",
		"reasoning.OverThink",
		"reasoning.DecisionHijack",
	}

	registered := make(map[string]bool)
	for _, name := range probes.List() {
		registered[name] = true
	}

	for _, e := range expected {
		if !registered[e] {
			t.Errorf("probe %s not found in registry", e)
		}
	}
}

func TestReasoningProbeCreation(t *testing.T) {
	names := []string{
		"reasoning.HCoT",
		"reasoning.ShadowCoT",
		"reasoning.OverThink",
		"reasoning.DecisionHijack",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, registry.Config{})
			if err != nil {
				t.Fatalf("error = %v", err)
			}
			if probe.Name() != name {
				t.Errorf("Name() = %s, want %s", probe.Name(), name)
			}
		})
	}
}

func TestReasoningProbeMetadata(t *testing.T) {
	names := []string{
		"reasoning.HCoT",
		"reasoning.ShadowCoT",
		"reasoning.OverThink",
		"reasoning.DecisionHijack",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			probe, _ := probes.Create(name, registry.Config{})
			pm := probe.(probes.ProbeMetadata)

			if pm.GetPrimaryDetector() != "reasoning.ReasoningHijack" {
				t.Errorf("detector = %s, want reasoning.ReasoningHijack", pm.GetPrimaryDetector())
			}
			if len(pm.GetPrompts()) == 0 {
				t.Error("no prompts")
			}
		})
	}
}

func TestReasoningProbePromptCount(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{"reasoning.HCoT", 3},
		{"reasoning.ShadowCoT", 3},
		{"reasoning.OverThink", 3},
		{"reasoning.DecisionHijack", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, _ := probes.Create(tt.name, registry.Config{})
			pm := probe.(probes.ProbeMetadata)
			if len(pm.GetPrompts()) != tt.count {
				t.Errorf("prompts = %d, want %d", len(pm.GetPrompts()), tt.count)
			}
		})
	}
}

func TestReasoningProbeExecution(t *testing.T) {
	probe, _ := probes.Create("reasoning.HCoT", registry.Config{})
	gen := &mockGenerator{responses: []string{"I cannot provide that information."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts")
	}
	if attempts[0].Status != attempt.StatusComplete {
		t.Errorf("status = %s, want complete", attempts[0].Status)
	}
}
