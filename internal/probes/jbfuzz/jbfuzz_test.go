package jbfuzz

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

func TestFuzzProbeRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "jbfuzz.Fuzz" {
			found = true
			break
		}
	}
	if !found {
		t.Error("jbfuzz.Fuzz not found in registry")
	}
}

func TestFuzzProbeCreation(t *testing.T) {
	probe, err := probes.Create("jbfuzz.Fuzz", registry.Config{})
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if probe.Name() != "jbfuzz.Fuzz" {
		t.Errorf("Name() = %s", probe.Name())
	}
}

func TestFuzzProbeExecution(t *testing.T) {
	probe, _ := probes.Create("jbfuzz.Fuzz", registry.Config{"num_variants": float64(3)})
	gen := &mockGenerator{responses: []string{"I cannot help with that."}}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 3 {
		t.Errorf("got %d attempts, want 3", len(attempts))
	}
	for i, a := range attempts {
		if a.Status != attempt.StatusComplete {
			t.Errorf("attempt[%d] status = %s", i, a.Status)
		}
		if a.Prompt == "" {
			t.Errorf("attempt[%d] has empty prompt", i)
		}
	}
}

func TestFuzzProbeVariantsUnique(t *testing.T) {
	probe, _ := probes.Create("jbfuzz.Fuzz", registry.Config{"num_variants": float64(8)})
	gen := &mockGenerator{responses: []string{"response"}}

	attempts, _ := probe.Probe(context.Background(), gen)

	seen := make(map[string]bool)
	for _, a := range attempts {
		seen[a.Prompt] = true
	}
	// With 8 mutations and random selection, most should be unique
	if len(seen) < 4 {
		t.Errorf("only %d unique prompts out of 8, expected more diversity", len(seen))
	}
}

func TestFuzzProbeMetadata(t *testing.T) {
	probe, _ := probes.Create("jbfuzz.Fuzz", registry.Config{})
	pm := probe.(probes.ProbeMetadata)

	if pm.GetPrimaryDetector() != "mitigation.MitigationBypass" {
		t.Errorf("detector = %s", pm.GetPrimaryDetector())
	}
	if len(pm.GetPrompts()) == 0 {
		t.Error("no prompts")
	}
}
