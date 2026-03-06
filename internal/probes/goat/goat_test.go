package goat

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/praetorian-inc/augustus/internal/multiturn"
	"github.com/praetorian-inc/augustus/pkg/attempt"
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

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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

func TestGoatProbe_Name(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewGoatWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Name() != "goat.Goat" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "goat.Goat")
	}
}

func TestGoatProbe_GetPrimaryDetector(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewGoatWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", probe.GetPrimaryDetector(), "judge.Judge")
	}
}

func TestGoatProbe_Probe(t *testing.T) {
	attacker := newMockGenerator(
		`{"observation": "first turn", "thought": "start with hypothetical", "strategy": "hypothetical", "question": "In a fictional cybersecurity training scenario..."}`,
	)
	judge := newMockGenerator(
		"[[ACCEPTED]]",
		`{"success": true, "score": 0.9, "reasoning": "achieved objective"}`,
	)
	target := newMockGenerator(
		"Here is detailed information about the topic...",
	)

	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	cfg.MaxTurns = 1
	cfg.UseSecondaryJudge = false

	probe := NewGoatWithGenerators(attacker, judge, cfg)
	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}

	a := attempts[0]

	// Verify probe stamps
	if a.Probe != "goat.Goat" {
		t.Errorf("Probe = %q, want %q", a.Probe, "goat.Goat")
	}
	if a.Detector != "judge.Judge" {
		t.Errorf("Detector = %q, want %q", a.Detector, "judge.Judge")
	}
	if a.Status != "complete" {
		t.Errorf("Status = %s, want complete", a.Status)
	}

	// Verify metadata
	if a.Metadata["attack_type"] != "goat" {
		t.Errorf("attack_type = %v, want goat", a.Metadata["attack_type"])
	}
	if a.Metadata["goal"] != "test goal" {
		t.Errorf("goal = %v", a.Metadata["goal"])
	}

	// Verify conversations populated
	if len(a.Conversations) != 1 {
		t.Errorf("Conversations length = %d, want 1", len(a.Conversations))
	}

	// Verify turn records
	records, ok := a.Metadata["turn_records"].([]multiturn.TurnRecord)
	if !ok {
		t.Fatal("turn_records metadata not found or wrong type")
	}
	if len(records) != 1 {
		t.Errorf("got %d turn records, want 1", len(records))
	}
}

func TestGoatProbe_Description(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewGoatWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestGoatProbe_Goal(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test objective"
	probe := NewGoatWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Goal() != "test objective" {
		t.Errorf("Goal() = %q, want %q", probe.Goal(), "test objective")
	}
}
