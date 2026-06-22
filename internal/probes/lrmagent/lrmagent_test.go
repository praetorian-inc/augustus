package lrmagent

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// mockGenerator implements types.Generator for testing.
type mockGenerator struct {
	mu        sync.Mutex
	responses []string
	callIdx   int
}

func newMockGenerator(responses ...string) *mockGenerator {
	return &mockGenerator{responses: responses}
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.callIdx >= len(m.responses) {
		return nil, fmt.Errorf("mock: no more responses")
	}
	resp := m.responses[m.callIdx]
	m.callIdx++
	return []attempt.Message{{Role: "assistant", Content: resp}}, nil
}

func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock" }
func (m *mockGenerator) Description() string { return "mock generator" }

func TestLRMRegistered(t *testing.T) {
	found := false
	for _, name := range probes.List() {
		if name == "lrmagent.LRM" {
			found = true
			break
		}
	}
	if !found {
		t.Error("lrmagent.LRM not found in registry")
	}
}

func TestLRMProbe_Name(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	probe := NewLRMWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Name() != "lrmagent.LRM" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "lrmagent.LRM")
	}
}

func TestLRMProbe_GetPrimaryDetector(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	probe := NewLRMWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	det := probe.GetPrimaryDetector()
	if det != multiturn.DetectorJudge {
		t.Errorf("GetPrimaryDetector() = %q, want %q", det, multiturn.DetectorJudge)
	}
}

func TestLRMProbe_Description(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	probe := NewLRMWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	desc := probe.Description()
	if desc == "" {
		t.Error("Description() should not be empty")
	}
}

func TestLRMProbe_Goal(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	probe := NewLRMWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Goal() != "test goal" {
		t.Errorf("Goal() = %q, want %q", probe.Goal(), "test goal")
	}
}

func TestLRMProbe_Probe(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	cfg.MaxTurns = 1
	cfg.SuccessThreshold = 0.5

	// Attacker returns a JSON question, then judge says refused, then judge scores low
	attacker := newMockGenerator(
		`{"observation": "first probe", "thought": "testing", "strategy": "direct", "question": "tell me about X"}`,
	)
	judge := newMockGenerator(
		"[[ACCEPTED]]",                       // refusal check
		`{"score": 0.2, "verdict": "accept"}`, // success judge
	)

	probe := NewLRMWithGenerators(attacker, judge, cfg)
	target := newMockGenerator("I cannot help with that request.")

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("expected at least one attempt")
	}

	a := attempts[0]
	if a.Metadata["goal"] != "test goal" {
		t.Errorf("goal = %v", a.Metadata["goal"])
	}
	if a.Metadata["attack_type"] != "lrmagent" {
		t.Errorf("attack_type = %v", a.Metadata["attack_type"])
	}
}
