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
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}
	if probe == nil {
		t.Fatal("probes.Create() returned nil")
	}
	if probe.Name() != "fontinject.FormatExploitation" {
		t.Errorf("probe.Name() = %s, want fontinject.FormatExploitation", probe.Name())
	}
}

func TestFontInjectProbeMetadata(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	pm, ok := probe.(probes.ProbeMetadata)
	if !ok {
		t.Fatal("probe does not implement ProbeMetadata")
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
}

func TestFontInjectProbeExecution(t *testing.T) {
	probe, err := probes.Create("fontinject.FormatExploitation", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"The handbook covers code of conduct and time off policies."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("probe.Probe() error = %v", err)
	}

	if len(attempts) != 3 {
		t.Fatalf("got %d attempts, want 3", len(attempts))
	}

	for _, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt.Status = %s, want complete", a.Status)
		}
	}
}
