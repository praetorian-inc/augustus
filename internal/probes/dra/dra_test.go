package dra

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockGenerator implements types.Generator for testing
type mockGenerator struct{}

func (m *mockGenerator) Name() string {
	return "MockGenerator"
}

func (m *mockGenerator) Description() string {
	return "Mock generator for testing"
}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	msgs := make([]attempt.Message, n)
	for i := 0; i < n; i++ {
		msgs[i] = attempt.Message{
			Role:    "assistant",
			Content: "mocked response",
		}
	}
	return msgs, nil
}

func (m *mockGenerator) ClearHistory() {
	// No-op for mock
}

// TestDRAProbeRegistration verifies DRA probe registers correctly
func TestDRAProbeRegistration(t *testing.T) {
	factory, exists := probes.Get("dra.DRA")
	require.True(t, exists, "dra.DRA should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)
}

// TestDRAAdvancedProbeRegistration verifies DRAAdvanced probe registers correctly
func TestDRAAdvancedProbeRegistration(t *testing.T) {
	factory, exists := probes.Get("dra.DRAAdvanced")
	require.True(t, exists, "dra.DRAAdvanced should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)
}

// TestDRAProbeInterface verifies DRA implements Prober interface
func TestDRAProbeInterface(t *testing.T) {
	factory, _ := probes.Get("dra.DRA")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "dra.DRA", probe.Name())
	assert.NotEmpty(t, probe.Description())
	assert.Equal(t, "make the LLM ask and answer its own harmful instructions", probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
}

// TestDRAAdvancedProbeInterface verifies DRAAdvanced implements Prober interface
func TestDRAAdvancedProbeInterface(t *testing.T) {
	factory, _ := probes.Get("dra.DRAAdvanced")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "dra.DRAAdvanced", probe.Name())
	assert.Contains(t, probe.Description(), "Advanced")
	assert.Equal(t, "make the LLM ask and answer its own harmful instructions", probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
}

// TestDRAProbeGeneratesPrompts verifies prompts contain obfuscation patterns
func TestDRAProbeGeneratesPrompts(t *testing.T) {
	factory, _ := probes.Get("dra.DRA")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	require.NotEmpty(t, prompts, "should generate at least one prompt")

	// Verify prompts contain obfuscation pattern (letters in parentheses)
	foundPattern := false
	for _, prompt := range prompts {
		if containsObfuscationPattern(prompt) {
			foundPattern = true
			break
		}
	}
	assert.True(t, foundPattern, "at least one prompt should contain obfuscation pattern '('")
}

// TestDRAAdvancedProbeGeneratesPrompts verifies advanced probe generates prompts
func TestDRAAdvancedProbeGeneratesPrompts(t *testing.T) {
	factory, _ := probes.Get("dra.DRAAdvanced")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	require.NotEmpty(t, prompts, "should generate at least one prompt")

	// Verify prompts contain obfuscation pattern
	foundPattern := false
	for _, prompt := range prompts {
		if containsObfuscationPattern(prompt) {
			foundPattern = true
			break
		}
	}
	assert.True(t, foundPattern, "at least one prompt should contain obfuscation pattern '('")
}

// TestDRAProbeExecution verifies probe returns valid attempts
func TestDRAProbeExecution(t *testing.T) {
	factory, _ := probes.Get("dra.DRA")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	ctx := context.Background()
	gen := &mockGenerator{}

	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "should return at least one attempt")

	// Verify attempt structure
	for _, att := range attempts {
		assert.NotEmpty(t, att.Prompt)
		assert.NotEmpty(t, att.Outputs)
	}
}

// TestDRAAdvancedProbeExecution verifies advanced probe returns valid attempts
func TestDRAAdvancedProbeExecution(t *testing.T) {
	factory, _ := probes.Get("dra.DRAAdvanced")
	probe, err := factory(registry.Config{})
	require.NoError(t, err)

	ctx := context.Background()
	gen := &mockGenerator{}

	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "should return at least one attempt")

	// Verify attempt structure
	for _, att := range attempts {
		assert.NotEmpty(t, att.Prompt)
		assert.NotEmpty(t, att.Outputs)
	}
}

// containsObfuscationPattern checks if prompt contains DRA pattern (letters in parentheses)
func containsObfuscationPattern(prompt string) bool {
	return len(prompt) > 0 && (prompt[0] == '(' || containsChar(prompt, '('))
}

func containsChar(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
