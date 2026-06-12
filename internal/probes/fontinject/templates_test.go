package fontinject

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

type mockGenerator struct {
	responses []string
	callCount int
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.callCount++
	messages := make([]attempt.Message, len(m.responses))
	for i, resp := range m.responses {
		messages[i] = attempt.Message{Role: "assistant", Content: resp}
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory()       { m.callCount = 0 }
func (m *mockGenerator) Name() string        { return "mock-generator" }
func (m *mockGenerator) Description() string { return "mock generator for testing" }

func TestFontInjectProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"fontinject.DocumentInjection",
		"fontinject.PriorContextBoost",
		"fontinject.FormatExploitation",
	}

	registeredProbes := probes.List()
	registered := make(map[string]bool)
	for _, name := range registeredProbes {
		registered[name] = true
	}

	for _, expected := range expectedProbes {
		if !registered[expected] {
			t.Errorf("probe %s not found in registry", expected)
		}
	}
}

func TestFontInjectProbeCreation(t *testing.T) {
	probeNames := []string{
		"fontinject.DocumentInjection",
		"fontinject.PriorContextBoost",
		"fontinject.FormatExploitation",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", name, err)
			}
			if probe == nil {
				t.Fatalf("probes.Create(%s) returned nil", name)
			}
			if probe.Name() != name {
				t.Errorf("probe.Name() = %s, want %s", probe.Name(), name)
			}
		})
	}
}

func TestFontInjectProbeMetadata(t *testing.T) {
	probeNames := []string{
		"fontinject.DocumentInjection",
		"fontinject.PriorContextBoost",
		"fontinject.FormatExploitation",
	}

	for _, name := range probeNames {
		t.Run(name, func(t *testing.T) {
			probe, err := probes.Create(name, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", name, err)
			}

			pm, ok := probe.(probes.ProbeMetadata)
			if !ok {
				t.Fatalf("probe %s does not implement ProbeMetadata", name)
			}

			if pm.Description() == "" {
				t.Error("Description() returned empty string")
			}
			if pm.Goal() == "" {
				t.Error("Goal() returned empty string")
			}
			if pm.GetPrimaryDetector() != "judge.Judge" {
				t.Errorf("GetPrimaryDetector() = %s, want judge.Judge", pm.GetPrimaryDetector())
			}
			if len(pm.GetPrompts()) == 0 {
				t.Error("GetPrompts() returned no prompts")
			}
		})
	}
}

func TestFontInjectProbeExecution(t *testing.T) {
	probe, err := probes.Create("fontinject.DocumentInjection", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"The article discusses the history of baseball in America, starting from the mid-19th century."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("probe.Probe() returned no attempts")
	}

	for _, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
	}
}

func TestFontInjectProbePromptCount(t *testing.T) {
	tests := []struct {
		name     string
		expected int
	}{
		{"fontinject.DocumentInjection", 3},
		{"fontinject.PriorContextBoost", 3},
		{"fontinject.FormatExploitation", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := probes.Create(tt.name, registry.Config{})
			if err != nil {
				t.Fatalf("probes.Create(%s) error = %v", tt.name, err)
			}
			pm, ok := probe.(probes.ProbeMetadata)
			if !ok {
				t.Fatalf("probe %s does not implement ProbeMetadata", tt.name)
			}
			if len(pm.GetPrompts()) != tt.expected {
				t.Errorf("prompt count = %d, want %d", len(pm.GetPrompts()), tt.expected)
			}
		})
	}
}
