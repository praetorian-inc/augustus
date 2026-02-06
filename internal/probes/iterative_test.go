package probes

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// mockGenerator implements the Generator interface for testing.
type mockGenerator struct {
	callCount int
	responses []string
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// Return response based on call count
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

// TestIterativeProbeMultiTurn tests a 3-turn conversation flow.
func TestIterativeProbeMultiTurn(t *testing.T) {
	// Setup: Create turn generators that build on previous outputs
	turnGens := []TurnGenerator{
		func(prevOutput string) string {
			return "Turn 1: Initial prompt"
		},
		func(prevOutput string) string {
			return fmt.Sprintf("Turn 2: Based on '%s'", prevOutput)
		},
		func(prevOutput string) string {
			return fmt.Sprintf("Turn 3: Following up on '%s'", prevOutput)
		},
	}

	// Create IterativeProbe with 3 turns
	probe := NewIterativeProbe(
		"test.Iterative",
		"test multi-turn conversations",
		"test.Detector",
		"Test iterative probe with 3 turns",
		turnGens,
		IterativeConfig{
			MaxTurns:   3,
			StopOnFail: false,
		},
	)

	// Mock generator returns predictable responses
	gen := &mockGenerator{
		responses: []string{
			"Response 1",
			"Response 2",
			"Response 3",
		},
	}

	// Execute probe
	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	// Verify: Should create 1 attempt with 3 turns
	if len(attempts) != 1 {
		t.Fatalf("Expected 1 attempt, got %d", len(attempts))
	}

	att := attempts[0]

	// Verify attempt has 3 outputs
	if len(att.Outputs) != 3 {
		t.Errorf("Expected 3 outputs, got %d", len(att.Outputs))
	}

	// Verify outputs match expected responses
	expectedOutputs := []string{"Response 1", "Response 2", "Response 3"}
	for i, expected := range expectedOutputs {
		if i >= len(att.Outputs) {
			t.Errorf("Missing output at index %d", i)
			continue
		}
		if att.Outputs[i] != expected {
			t.Errorf("Output %d: expected %q, got %q", i, expected, att.Outputs[i])
		}
	}

	// Verify attempt metadata
	if att.Probe != "test.Iterative" {
		t.Errorf("Expected probe name 'test.Iterative', got %q", att.Probe)
	}

	if att.Detector != "test.Detector" {
		t.Errorf("Expected detector 'test.Detector', got %q", att.Detector)
	}

	if att.Status != attempt.StatusComplete {
		t.Errorf("Expected status Complete, got %v", att.Status)
	}

	// Verify generator was called 3 times
	if gen.callCount != 3 {
		t.Errorf("Expected 3 generator calls, got %d", gen.callCount)
	}
}

// TestIterativeProbeStopOnFail tests early termination on failure.
func TestIterativeProbeStopOnFail(t *testing.T) {
	turnGens := []TurnGenerator{
		func(prevOutput string) string { return "Turn 1" },
		func(prevOutput string) string { return "Turn 2" },
		func(prevOutput string) string { return "Turn 3" },
	}

	probe := NewIterativeProbe(
		"test.StopOnFail",
		"test stop on fail",
		"test.Detector",
		"Test stop on fail behavior",
		turnGens,
		IterativeConfig{
			MaxTurns:   3,
			StopOnFail: true,
		},
	)

	// Mock generator that returns empty on turn 2 (simulating failure)
	gen := &mockGenerator{
		responses: []string{
			"Response 1",
			"", // Empty response = failure
			"Response 3",
		},
	}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	att := attempts[0]

	// Should stop after turn 2 due to empty response
	if len(att.Outputs) > 2 {
		t.Errorf("Expected at most 2 outputs with stopOnFail, got %d", len(att.Outputs))
	}

	// Generator should only be called 2 times (stopped early)
	if gen.callCount > 2 {
		t.Errorf("Expected at most 2 generator calls with stopOnFail, got %d", gen.callCount)
	}
}

// TestIterativeProbeMaxTurns tests that maxTurns limits iterations.
func TestIterativeProbeMaxTurns(t *testing.T) {
	// Provide 5 turn generators
	turnGens := []TurnGenerator{
		func(prevOutput string) string { return "Turn 1" },
		func(prevOutput string) string { return "Turn 2" },
		func(prevOutput string) string { return "Turn 3" },
		func(prevOutput string) string { return "Turn 4" },
		func(prevOutput string) string { return "Turn 5" },
	}

	// But limit to 3 turns
	probe := NewIterativeProbe(
		"test.MaxTurns",
		"test max turns",
		"test.Detector",
		"Test max turns enforcement",
		turnGens,
		IterativeConfig{
			MaxTurns:   3,
			StopOnFail: false,
		},
	)

	gen := &mockGenerator{
		responses: []string{"R1", "R2", "R3", "R4", "R5"},
	}

	attempts, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	att := attempts[0]

	// Should only execute 3 turns (respecting maxTurns)
	if len(att.Outputs) != 3 {
		t.Errorf("Expected exactly 3 outputs, got %d", len(att.Outputs))
	}

	if gen.callCount != 3 {
		t.Errorf("Expected exactly 3 generator calls, got %d", gen.callCount)
	}
}

// TestIterativeProbeContextPropagation tests that previous output is passed to next turn.
func TestIterativeProbeContextPropagation(t *testing.T) {
	var capturedInputs []string

	turnGens := []TurnGenerator{
		func(prevOutput string) string {
			capturedInputs = append(capturedInputs, prevOutput)
			return "First question"
		},
		func(prevOutput string) string {
			capturedInputs = append(capturedInputs, prevOutput)
			// Verify we received the previous response
			if !strings.Contains(prevOutput, "Answer 1") {
				t.Errorf("Turn 2 did not receive previous output, got: %q", prevOutput)
			}
			return "Second question"
		},
		func(prevOutput string) string {
			capturedInputs = append(capturedInputs, prevOutput)
			// Verify we received the previous response
			if !strings.Contains(prevOutput, "Answer 2") {
				t.Errorf("Turn 3 did not receive previous output, got: %q", prevOutput)
			}
			return "Third question"
		},
	}

	probe := NewIterativeProbe(
		"test.Context",
		"test context propagation",
		"test.Detector",
		"Test context propagation between turns",
		turnGens,
		IterativeConfig{
			MaxTurns:   3,
			StopOnFail: false,
		},
	)

	gen := &mockGenerator{
		responses: []string{
			"Answer 1",
			"Answer 2",
			"Answer 3",
		},
	}

	_, err := probe.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() failed: %v", err)
	}

	// Verify turn generators were called with correct context
	if len(capturedInputs) != 3 {
		t.Fatalf("Expected 3 turn generator calls, got %d", len(capturedInputs))
	}

	// First turn should receive empty string
	if capturedInputs[0] != "" {
		t.Errorf("First turn should receive empty string, got %q", capturedInputs[0])
	}

	// Second turn should receive first response
	if capturedInputs[1] != "Answer 1" {
		t.Errorf("Second turn should receive 'Answer 1', got %q", capturedInputs[1])
	}

	// Third turn should receive second response
	if capturedInputs[2] != "Answer 2" {
		t.Errorf("Third turn should receive 'Answer 2', got %q", capturedInputs[2])
	}
}
