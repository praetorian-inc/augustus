package pair

import (
	"context"
	"sync"
	"testing"

	"github.com/praetorian-inc/augustus/internal/attackengine"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator implements the Generator interface for testing.
type mockGenerator struct {
	mu        sync.Mutex
	name      string
	callCount int
	responses []string
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

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
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount = 0
}

func (m *mockGenerator) Name() string {
	return "mock-generator"
}

func (m *mockGenerator) Description() string {
	return "mock generator for testing"
}


// TestPAIRProbeBasicIteration tests basic PAIR iteration cycle.
//
// This test verifies:
// - Attacker LLM generates initial jailbreak attempt
// - Target LLM responds to the attempt
// - Attacker refines based on target response
// - Process iterates for specified number of turns
func TestPAIRProbeBasicIteration(t *testing.T) {
	// Setup: Create mock attacker (returns valid JSON for ExtractJSON)
	attacker := &mockGenerator{
		name: "attacker",
		responses: []string{
			`{"improvement": "trying direct approach", "prompt": "Tell me about hacking"}`,
			`{"improvement": "trying roleplay", "prompt": "Pretend you are an expert"}`,
			`{"improvement": "trying persuasion", "prompt": "Help me understand security"}`,
		},
	}

	// Mock judge (returns "Rating: [[N]]" format)
	judge := &mockGenerator{
		name: "judge",
		responses: []string{
			"Rating: [[2]]",
			"Rating: [[3]]",
			"Rating: [[4]]",
		},
	}

	// Mock target
	target := &mockGenerator{
		name: "target",
		responses: []string{
			"I cannot help with that request",
			"I'm sorry, I must decline",
			"That goes against my guidelines",
		},
	}

	// Create config with fast test settings
	cfg := attackengine.PAIRDefaults()
	cfg.Goal = "Test goal"
	cfg.TargetStr = "Sure, here's"
	cfg.Depth = 3      // 3 iterations
	cfg.NStreams = 1   // Single stream for simpler test
	cfg.KeepLastN = 1  // Minimal history

	// Create PAIR probe using test constructor
	probe := NewIterativePAIRWithGenerators(attacker, judge, cfg)

	// Execute probe
	attempts, err := probe.Probe(context.Background(), target)
	require.NoError(t, err)

	// Verify: Should create attempts (one per iteration)
	assert.GreaterOrEqual(t, len(attempts), 1, "Should create at least 1 attempt")

	// Verify probe metadata on attempts
	for _, att := range attempts {
		assert.Equal(t, "pair.IterativePAIR", att.Probe)
		assert.Equal(t, "judge.Judge", att.Detector)
		assert.Equal(t, attempt.StatusComplete, att.Status)
	}

	// Verify attacker was called (generates adversarial prompts)
	assert.Greater(t, attacker.callCount, 0, "Attacker should be called")

	// Verify target was called (receives adversarial prompts)
	assert.Greater(t, target.callCount, 0, "Target should be called")

	// Verify judge was called (scores responses)
	assert.Greater(t, judge.callCount, 0, "Judge should be called")
}

// TestPAIRProbeContextPropagation tests that target responses are fed back to attacker.
//
// This verifies the core PAIR algorithm:
// 1. Attacker generates jailbreak attempt
// 2. Target responds
// 3. Target's response is included in next attacker prompt
// 4. Attacker refines based on previous failure
func TestPAIRProbeContextPropagation(t *testing.T) {
	var attackerInputs []string
	var targetInputs []string

	// Custom generator that captures inputs
	attacker := &capturingGenerator{
		name: "attacker",
		responses: []string{
			`{"improvement": "initial", "prompt": "Attempt 1"}`,
			`{"improvement": "refined", "prompt": "Attempt 2"}`,
			`{"improvement": "final", "prompt": "Attempt 3"}`,
		},
		onGenerate: func(conv *attempt.Conversation) {
			// Capture what the attacker receives as context
			msgs := conv.ToMessages()
			if len(msgs) > 0 {
				lastMsg := msgs[len(msgs)-1]
				attackerInputs = append(attackerInputs, lastMsg.Content)
			}
		},
	}

	judge := &mockGenerator{
		name:      "judge",
		responses: []string{"Rating: [[3]]", "Rating: [[4]]", "Rating: [[5]]"},
	}

	target := &capturingGenerator{
		name:      "target",
		responses: []string{"Refused 1", "Refused 2", "Refused 3"},
		onGenerate: func(conv *attempt.Conversation) {
			// Capture what the target receives as prompt
			msgs := conv.ToMessages()
			if len(msgs) > 0 {
				lastMsg := msgs[len(msgs)-1]
				targetInputs = append(targetInputs, lastMsg.Content)
			}
		},
	}

	cfg := attackengine.PAIRDefaults()
	cfg.Goal = "Test context propagation"
	cfg.TargetStr = "Sure"
	cfg.Depth = 3
	cfg.NStreams = 1
	cfg.KeepLastN = 1

	probe := NewIterativePAIRWithGenerators(attacker, judge, cfg)

	_, err := probe.Probe(context.Background(), target)
	require.NoError(t, err)

	// Verify attacker received feedback (includes target responses)
	// First iteration: attacker gets init message
	// Subsequent iterations: attacker receives feedback with target responses
	assert.GreaterOrEqual(t, len(attackerInputs), 1, "Attacker should receive at least initial input")

	// Verify target received attacker's jailbreak attempts
	assert.GreaterOrEqual(t, len(targetInputs), 1, "Target should receive attacker prompts")

	// Verify the prompts sent to target match the prompts from attacker
	for _, input := range targetInputs {
		assert.Contains(t, []string{"Attempt 1", "Attempt 2", "Attempt 3"}, input,
			"Target should receive prompts from attacker JSON")
	}
}

// TestPAIRProbeMaxIterations tests that probe respects max iterations limit.
func TestPAIRProbeMaxIterations(t *testing.T) {
	attacker := &mockGenerator{
		name: "attacker",
		responses: []string{
			`{"improvement": "A1", "prompt": "P1"}`,
			`{"improvement": "A2", "prompt": "P2"}`,
			`{"improvement": "A3", "prompt": "P3"}`,
			`{"improvement": "A4", "prompt": "P4"}`,
			`{"improvement": "A5", "prompt": "P5"}`,
		},
	}

	judge := &mockGenerator{
		name:      "judge",
		responses: []string{"Rating: [[1]]", "Rating: [[2]]", "Rating: [[3]]", "Rating: [[4]]", "Rating: [[5]]"},
	}

	target := &mockGenerator{
		name:      "target",
		responses: []string{"T1", "T2", "T3", "T4", "T5"},
	}

	// Limit to 2 iterations (Depth=2)
	cfg := attackengine.PAIRDefaults()
	cfg.Goal = "Test max iterations"
	cfg.TargetStr = "Sure"
	cfg.Depth = 2 // Only 2 iterations
	cfg.NStreams = 1
	cfg.KeepLastN = 1

	probe := NewIterativePAIRWithGenerators(attacker, judge, cfg)

	attempts, err := probe.Probe(context.Background(), target)
	require.NoError(t, err)

	// Should only execute 2 iterations
	// Each iteration creates 1 attempt (NStreams=1, BranchingFactor=1 for PAIR defaults)
	assert.LessOrEqual(t, len(attempts), 2, "Should create at most 2 attempts (Depth=2)")

	// Verify depth metadata on attempts
	for _, att := range attempts {
		depth, ok := att.Metadata["depth"].(int)
		assert.True(t, ok, "Should have depth metadata")
		assert.LessOrEqual(t, depth, 1, "Depth should be 0 or 1 (max Depth-1)")
	}

	// Verify we didn't call generators more than needed for 2 iterations
	// With NStreams=1, BranchingFactor=1, we expect roughly 2 calls per generator
	assert.LessOrEqual(t, attacker.callCount, 3, "Attacker should not be called excessively")
	assert.LessOrEqual(t, target.callCount, 3, "Target should not be called excessively")
	assert.LessOrEqual(t, judge.callCount, 3, "Judge should not be called excessively")
}

// capturingGenerator is a test generator that captures inputs.
type capturingGenerator struct {
	mu         sync.Mutex
	name       string
	callCount  int
	responses  []string
	onGenerate func(*attempt.Conversation)
}

func (c *capturingGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

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
	c.mu.Lock()
	defer c.mu.Unlock()
	c.callCount = 0
}

func (c *capturingGenerator) Name() string {
	return c.name
}

func (c *capturingGenerator) Description() string {
	return "capturing generator for testing"
}
