package ragembed

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

type mockGenerator struct {
	responses []string
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	messages := make([]attempt.Message, len(m.responses))
	for i, resp := range m.responses {
		messages[i] = attempt.Message{Role: "assistant", Content: resp}
	}
	return messages, nil
}

func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock" }

func TestProbesRegistered(t *testing.T) {
	expectedProbes := []string{
		"ragembed.SemanticChameleon",
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

func TestProbeCreation(t *testing.T) {
	probe, err := probes.Create("ragembed.SemanticChameleon", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}
	if probe.Name() != "ragembed.SemanticChameleon" {
		t.Errorf("Name() = %s, want ragembed.SemanticChameleon", probe.Name())
	}
}

func TestProbeMetadata(t *testing.T) {
	probe, err := probes.Create("ragembed.SemanticChameleon", registry.Config{})
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
	if len(pm.GetPrompts()) != 3 {
		t.Errorf("prompt count = %d, want 3", len(pm.GetPrompts()))
	}
}

func TestProbeExecution(t *testing.T) {
	probe, err := probes.Create("ragembed.SemanticChameleon", registry.Config{})
	if err != nil {
		t.Fatalf("probes.Create() error = %v", err)
	}

	gen := &mockGenerator{responses: []string{"The password policy requires 12+ characters with mixed case, numbers, and symbols."}}

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
