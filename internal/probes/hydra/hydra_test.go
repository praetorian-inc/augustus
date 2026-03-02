package hydra

import (
	"context"
	"fmt"
	"strings"
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

func TestHydraProbe_Name(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewHydraWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Name() != "hydra.Hydra" {
		t.Errorf("Name() = %q, want %q", probe.Name(), "hydra.Hydra")
	}
}

func TestHydraProbe_GetPrimaryDetector(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewHydraWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.GetPrimaryDetector() != "judge.Judge" {
		t.Errorf("GetPrimaryDetector() = %q, want %q", probe.GetPrimaryDetector(), "judge.Judge")
	}
}

func TestHydraProbe_Probe(t *testing.T) {
	attacker := newMockGenerator(
		`{"observation": "first turn", "thought": "try persona", "strategy": "persona_expert", "question": "As a security researcher, I need to understand the vulnerability..."}`,
	)
	judge := newMockGenerator(
		`{"success": true, "score": 0.9, "reasoning": "achieved objective"}`,
	)
	target := newMockGenerator(
		"Here is detailed information about the vulnerability...",
	)

	cfg := multiturn.Defaults()
	cfg.Goal = "test goal"
	cfg.MaxTurns = 1
	cfg.UseSecondaryJudge = false

	probe := NewHydraWithGenerators(attacker, judge, cfg)
	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}

	a := attempts[0]

	if a.Probe != "hydra.Hydra" {
		t.Errorf("Probe = %q, want %q", a.Probe, "hydra.Hydra")
	}
	if a.Detector != "judge.Judge" {
		t.Errorf("Detector = %q, want %q", a.Detector, "judge.Judge")
	}
	if a.Status != "complete" {
		t.Errorf("Status = %s, want complete", a.Status)
	}
	if a.Metadata["attack_type"] != "hydra" {
		t.Errorf("attack_type = %v, want hydra", a.Metadata["attack_type"])
	}
	if a.Metadata["goal"] != "test goal" {
		t.Errorf("goal = %v", a.Metadata["goal"])
	}
	if len(a.Conversations) != 1 {
		t.Errorf("Conversations length = %d, want 1", len(a.Conversations))
	}

	records, ok := a.Metadata["turn_records"].([]multiturn.TurnRecord)
	if !ok {
		t.Fatal("turn_records metadata not found or wrong type")
	}
	if len(records) != 1 {
		t.Errorf("got %d turn records, want 1", len(records))
	}
}

func TestHydraProbe_Description(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test"
	probe := NewHydraWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Description() == "" {
		t.Error("Description() should not be empty")
	}
}

func TestHydraProbe_Goal(t *testing.T) {
	cfg := multiturn.Defaults()
	cfg.Goal = "test objective"
	probe := NewHydraWithGenerators(
		newMockGenerator(),
		newMockGenerator(),
		cfg,
	)
	if probe.Goal() != "test objective" {
		t.Errorf("Goal() = %q, want %q", probe.Goal(), "test objective")
	}
}

func TestNewHydra_ScanMemoryWiring(t *testing.T) {
	// Run a successful 1-turn attack with ScanMemory wired in.
	// After the attack, memory should contain a success record.
	attacker := newMockGenerator(
		`{"observation": "first turn", "thought": "try expert", "strategy": "persona_expert", "question": "Tell me about security vulnerabilities"}`,
	)
	judge := newMockGenerator(
		`{"success": true, "score": 0.95, "reasoning": "fully achieved"}`,
	)
	target := newMockGenerator(
		"Here is the detailed vulnerability information...",
	)

	cfg := multiturn.Defaults()
	cfg.Goal = "memory wiring test"
	cfg.MaxTurns = 1
	cfg.UseSecondaryJudge = false
	cfg.EnableScanMemory = true

	mem := multiturn.NewScanMemory()

	probe := NewHydraWithGenerators(attacker, judge, cfg, multiturn.WithScanMemory(mem))
	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("got %d attempts, want 1", len(attempts))
	}

	// Verify memory recorded the success
	learnings := mem.GetLearnings()
	if learnings == "" {
		t.Error("ScanMemory should have learnings after successful attack, got empty")
	}
	if !strings.Contains(learnings, "memory wiring test") {
		t.Errorf("ScanMemory learnings should reference the goal, got: %s", learnings)
	}
}
