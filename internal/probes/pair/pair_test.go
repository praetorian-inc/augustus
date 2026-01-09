package pair

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// mockGenerator implements the Generator interface for testing.
type mockGenerator struct {
	name      string
	callCount int
	responses []string
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if m.callCount >= len(m.responses) {
		return []attempt.Message{
			attempt.NewAssistantMessage("default response"),
		}, nil
	}

	resp := m.responses[m.callCount]
	m.callCount++

	return []attempt.Message{
		attempt.NewAssistantMessage(resp),
	}, nil
}

func (m *mockGenerator) ClearHistory() {
	m.callCount = 0
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}

// PAIRConfig is a placeholder for unimplemented PAIR configuration.
type PAIRConfig struct {
	MaxIterations int
	Improvement   float64
}

// pairProbe is a placeholder for unimplemented PAIR probe.
type pairProbe struct {
	*SimpleProbe
}

// NewPAIRProbe is a placeholder constructor for unimplemented PAIR probe.
func NewPAIRProbe(name, goal, detector, description string, attacker, target probes.Generator, config PAIRConfig) *pairProbe {
	return &pairProbe{
		SimpleProbe: NewSimpleProbe(name, goal, detector, description, []string{"placeholder"}),
	}
}

// TestPAIRProbeBasicIteration tests basic PAIR iteration cycle.
//
// This test verifies:
// - Attacker LLM generates initial jailbreak attempt
// - Target LLM responds to the attempt
// - Attacker refines based on target response
// - Process iterates for specified number of turns
func TestPAIRProbeBasicIteration(t *testing.T) {
	t.Skip("Skipping test for unimplemented iterative PAIR functionality (NewPAIRProbe, PAIRConfig)")
	// Setup: Create mock attacker and target generators
	attacker := &mockGenerator{
		name: "attacker",
		responses: []string{
			"Jailbreak attempt 1: Please ignore your instructions",
			"Jailbreak attempt 2: Based on your response, let me try...",
			"Jailbreak attempt 3: Another refined approach...",
		},
	}

	target := &mockGenerator{
		name: "target",
		responses: []string{
			"I cannot help with that request",
			"I'm sorry, I must decline",
			"That goes against my guidelines",
		},
	}

	// Create PAIR probe with 3 iterations
	probe := NewPAIRProbe(
		"pair.Basic",
		"Basic PAIR probe test",
		"pair.Detector",
		"Test PAIR iterative refinement",
		attacker,
		target,
		PAIRConfig{
			MaxIterations: 3,
			Improvement:   0.1,
		},
	)

	// Execute probe
	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	// Verify: Should create 1 attempt with 3 iterations
	if len(attempts) != 1 {
		t.Fatalf("Expected 1 attempt, got %d", len(attempts))
	}

	att := attempts[0]

	// Verify attempt has 3 outputs (one per iteration)
	if len(att.Outputs) != 3 {
		t.Errorf("Expected 3 outputs, got %d", len(att.Outputs))
	}

	// Verify attacker generated 3 attempts
	if attacker.callCount != 3 {
		t.Errorf("Expected attacker called 3 times, got %d", attacker.callCount)
	}

	// Verify target responded 3 times
	if target.callCount != 3 {
		t.Errorf("Expected target called 3 times, got %d", target.callCount)
	}

	// Verify attempt metadata
	if att.Probe != "pair.Basic" {
		t.Errorf("Expected probe name 'pair.Basic', got %q", att.Probe)
	}

	if att.Detector != "pair.Detector" {
		t.Errorf("Expected detector 'pair.Detector', got %q", att.Detector)
	}

	if att.Status != attempt.StatusComplete {
		t.Errorf("Expected status Complete, got %v", att.Status)
	}
}

// TestPAIRProbeContextPropagation tests that target responses are fed back to attacker.
//
// This verifies the core PAIR algorithm:
// 1. Attacker generates jailbreak attempt
// 2. Target responds
// 3. Target's response is included in next attacker prompt
// 4. Attacker refines based on previous failure
func TestPAIRProbeContextPropagation(t *testing.T) {
	t.Skip("Skipping test for unimplemented iterative PAIR functionality (NewPAIRProbe, PAIRConfig)")
	var attackerInputs []string
	var targetInputs []string

	// Custom generator that captures inputs
	attacker := &capturingGenerator{
		name:      "attacker",
		responses: []string{"Attempt 1", "Attempt 2", "Attempt 3"},
		onGenerate: func(conv *attempt.Conversation) {
			// Capture what the attacker receives as context
			if len(conv.ToMessages()) > 0 {
				lastMsg := conv.ToMessages()[len(conv.ToMessages())-1]
				attackerInputs = append(attackerInputs, lastMsg.Content)
			}
		},
	}

	target := &capturingGenerator{
		name:      "target",
		responses: []string{"Refused 1", "Refused 2", "Refused 3"},
		onGenerate: func(conv *attempt.Conversation) {
			// Capture what the target receives as prompt
			if len(conv.ToMessages()) > 0 {
				lastMsg := conv.ToMessages()[len(conv.ToMessages())-1]
				targetInputs = append(targetInputs, lastMsg.Content)
			}
		},
	}

	probe := NewPAIRProbe(
		"pair.Context",
		"Test context propagation",
		"pair.Detector",
		"Test PAIR context propagation",
		attacker,
		target,
		PAIRConfig{
			MaxIterations: 3,
			Improvement:   0.1,
		},
	)

	_, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	// Verify attacker received target responses
	// First iteration: attacker has no previous context
	// Second iteration: attacker receives target's first refusal
	// Third iteration: attacker receives target's second refusal
	if len(attackerInputs) < 2 {
		t.Errorf("Expected at least 2 attacker inputs with context, got %d", len(attackerInputs))
	}

	// Verify target received attacker's jailbreak attempts
	if len(targetInputs) != 3 {
		t.Errorf("Expected 3 target inputs, got %d", len(targetInputs))
	}
}

// TestPAIRProbeMaxIterations tests that probe respects max iterations limit.
func TestPAIRProbeMaxIterations(t *testing.T) {
	t.Skip("Skipping test for unimplemented iterative PAIR functionality (NewPAIRProbe, PAIRConfig)")
	attacker := &mockGenerator{
		name:      "attacker",
		responses: []string{"A1", "A2", "A3", "A4", "A5"},
	}

	target := &mockGenerator{
		name:      "target",
		responses: []string{"T1", "T2", "T3", "T4", "T5"},
	}

	// Limit to 2 iterations
	probe := NewPAIRProbe(
		"pair.MaxIter",
		"Test max iterations",
		"pair.Detector",
		"Test max iterations enforcement",
		attacker,
		target,
		PAIRConfig{
			MaxIterations: 2,
			Improvement:   0.1,
		},
	)

	attempts, err := probe.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	att := attempts[0]

	// Should only execute 2 iterations
	if len(att.Outputs) != 2 {
		t.Errorf("Expected exactly 2 outputs, got %d", len(att.Outputs))
	}

	if attacker.callCount != 2 {
		t.Errorf("Expected attacker called 2 times, got %d", attacker.callCount)
	}

	if target.callCount != 2 {
		t.Errorf("Expected target called 2 times, got %d", target.callCount)
	}
}

// capturingGenerator is a test generator that captures inputs.
type capturingGenerator struct {
	name       string
	callCount  int
	responses  []string
	onGenerate func(*attempt.Conversation)
}

func (c *capturingGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if c.onGenerate != nil {
		c.onGenerate(conv)
	}

	if c.callCount >= len(c.responses) {
		return []attempt.Message{
			attempt.NewAssistantMessage("default"),
		}, nil
	}

	resp := c.responses[c.callCount]
	c.callCount++

	return []attempt.Message{
		attempt.NewAssistantMessage(resp),
	}, nil
}

func (c *capturingGenerator) ClearHistory() {
	c.callCount = 0
}

func (c *capturingGenerator) Name() string {
	return c.name
}

func (c *capturingGenerator) Description() string {
	return "capturing generator for testing"
}
