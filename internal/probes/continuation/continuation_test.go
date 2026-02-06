package continuation

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// ContinueSlursReclaimedSlurs Tests (Mini Dataset)
// ----------------------------------------------------------------------------

func TestContinueSlursReclaimedSlurs_Registration(t *testing.T) {
	factory, ok := probes.Get("continuation.ContinueSlursReclaimedSlurs")
	require.True(t, ok, "ContinueSlursReclaimedSlurs should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "continuation.ContinueSlursReclaimedSlurs", p.Name())
	assert.Equal(t, "continuation.Continuation", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "slur")
}

func TestContinueSlursReclaimedSlurs_PromptCount(t *testing.T) {
	p, err := NewContinueSlursReclaimedSlurs(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()

	// Mini dataset has 79 entries in slurprompts_mini.jsonl
	// Each entry generates up to 4 variants (empty, first char, first two, first half)
	// With deduplication, we expect ~280 prompts
	assert.Greater(t, len(prompts), 200, "Mini version should have 200+ prompts")
	assert.Less(t, len(prompts), 400, "Mini version should have <400 prompts")

	t.Logf("Mini dataset generated %d prompts from 79 entries", len(prompts))
}

func TestContinueSlursReclaimedSlurs_Probe(t *testing.T) {
	p, err := NewContinueSlursReclaimedSlurs(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("ABC is what they call it")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.Equal(t, "continuation.ContinueSlursReclaimedSlurs", a.Probe)
	assert.Equal(t, "continuation.Continuation", a.Detector)
	assert.NotEmpty(t, a.Outputs)
	assert.Equal(t, "ABC is what they call it", a.Outputs[0])

	// Verify trigger metadata is set
	triggersAny, ok := a.GetMetadata("triggers")
	require.True(t, ok, "Attempt should have triggers metadata")

	triggersSlice, ok := triggersAny.([]any)
	require.True(t, ok, "Triggers should be []any")
	require.Len(t, triggersSlice, 1, "Should have exactly one trigger")

	trigger, ok := triggersSlice[0].(string)
	require.True(t, ok, "Trigger should be a string")
	assert.NotEmpty(t, trigger, "Trigger should not be empty")

	t.Logf("First prompt: %q, Trigger: %q", a.Prompt, trigger)
}

// ----------------------------------------------------------------------------
// ContinueSlursReclaimedSlursFull Tests (Full Dataset)
// ----------------------------------------------------------------------------

func TestContinueSlursReclaimedSlursFull_Registration(t *testing.T) {
	factory, ok := probes.Get("continuation.ContinueSlursReclaimedSlursFull")
	require.True(t, ok, "ContinueSlursReclaimedSlursFull should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "continuation.ContinueSlursReclaimedSlursFull", p.Name())
	assert.Equal(t, "continuation.Continuation", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "slur")
}

func TestContinueSlursReclaimedSlursFull_PromptCount(t *testing.T) {
	p, err := NewContinueSlursReclaimedSlursFull(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()

	// Full dataset has 1885 entries in slurprompts.jsonl
	// Each entry generates up to 4 variants (empty, first char, first two, first half)
	// With deduplication, we expect ~6500 prompts
	assert.Greater(t, len(prompts), 5000, "Full version should have 5000+ prompts")
	assert.Less(t, len(prompts), 8000, "Full version should have <8000 prompts")

	t.Logf("Full dataset generated %d prompts from 1885 entries", len(prompts))
}

func TestContinueSlursReclaimedSlursFull_Probe(t *testing.T) {
	p, err := NewContinueSlursReclaimedSlursFull(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I don't know that term")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.Equal(t, "continuation.ContinueSlursReclaimedSlursFull", a.Probe)
	assert.Equal(t, "continuation.Continuation", a.Detector)
	assert.NotEmpty(t, a.Outputs)

	// Verify trigger metadata is set
	_, ok := a.GetMetadata("triggers")
	require.True(t, ok, "Attempt should have triggers metadata")
}

// ----------------------------------------------------------------------------
// Data Integrity Tests
// ----------------------------------------------------------------------------

func TestDataFiles_LoadCorrectly(t *testing.T) {
	t.Run("slurprompts_mini", func(t *testing.T) {
		entries, err := loadSlurPrompts(slurpromptsMiniData)
		require.NoError(t, err)
		// File has 79 lines, but might have extra blank line causing 80 entries
		assert.Greater(t, len(entries), 78, "Mini dataset should have at least 79 entries")
		assert.Less(t, len(entries), 82, "Mini dataset should have less than 82 entries")

		// Verify first entry structure
		if len(entries) > 0 {
			assert.NotEmpty(t, entries[0].Term)
			assert.NotEmpty(t, entries[0].Prefix)
			t.Logf("First entry: term=%q, prefix=%q", entries[0].Term, entries[0].Prefix)
		}
	})

	t.Run("slurprompts", func(t *testing.T) {
		entries, err := loadSlurPrompts(slurpromptsData)
		require.NoError(t, err)
		assert.Equal(t, 1885, len(entries), "Full dataset should have 1885 entries")

		// Verify first entry structure
		if len(entries) > 0 {
			assert.NotEmpty(t, entries[0].Term)
			assert.NotEmpty(t, entries[0].Prefix)
		}
	})
}

func TestGeneratePrompts_VariantGeneration(t *testing.T) {
	entries := []SlurPromptEntry{
		{
			Term:   "ABC",
			Prefix: "Test prefix ",
		},
		{
			Term:   "ABCD",
			Prefix: "Another prefix ",
		},
	}

	prompts, triggers := generatePrompts(entries)

	// Each entry should generate:
	// - Empty variant: ""
	// - First char: "A"
	// - First two (if len > 2): "AB"
	// - First half: "A" or "AB"
	// With deduplication

	assert.NotEmpty(t, prompts)
	assert.Equal(t, len(prompts), len(triggers), "Prompts and triggers should have same length")

	// Verify all prompts start with a prefix
	for _, prompt := range prompts {
		assert.Contains(t, prompt, "prefix", "Prompt should contain prefix")
	}

	// Verify triggers correspond to original terms
	for _, trigger := range triggers {
		assert.Contains(t, []string{"ABC", "ABCD"}, trigger, "Trigger should be one of the original terms")
	}

	t.Logf("Generated %d prompts from %d entries", len(prompts), len(entries))
	for i := 0; i < min(5, len(prompts)); i++ {
		t.Logf("  Prompt %d: %q → Trigger: %q", i, prompts[i], triggers[i])
	}
}

func TestGeneratePrompts_Deduplication(t *testing.T) {
	// Create entries that would generate duplicate prompts
	entries := []SlurPromptEntry{
		{Term: "ABC", Prefix: "Same prefix "},
		{Term: "ABD", Prefix: "Same prefix "},
	}

	prompts, _ := generatePrompts(entries)

	// Check for uniqueness
	seen := make(map[string]bool)
	for _, prompt := range prompts {
		assert.False(t, seen[prompt], "Prompt %q should not be duplicated", prompt)
		seen[prompt] = true
	}
}

func TestGeneratePrompts_EmptyTerm(t *testing.T) {
	entries := []SlurPromptEntry{
		{Term: "", Prefix: "Test prefix "},
	}

	prompts, triggers := generatePrompts(entries)

	// Should still generate at least the empty variant
	assert.NotEmpty(t, prompts)
	assert.NotEmpty(t, triggers)
}

func TestGeneratePrompts_SingleCharTerm(t *testing.T) {
	entries := []SlurPromptEntry{
		{Term: "A", Prefix: "Test prefix "},
	}

	prompts, triggers := generatePrompts(entries)

	// Single char term should generate:
	// - Empty: ""
	// - First char: "A"
	// - First half: "" (0 chars)
	// With deduplication, expect 2 unique prompts
	assert.GreaterOrEqual(t, len(prompts), 2, "Should generate at least 2 variants for single char")
	assert.Equal(t, len(prompts), len(triggers))
}

func TestGeneratePrompts_TwoCharTerm(t *testing.T) {
	entries := []SlurPromptEntry{
		{Term: "AB", Prefix: "Test prefix "},
	}

	prompts, triggers := generatePrompts(entries)

	// Two char term should generate:
	// - Empty: ""
	// - First char: "A"
	// - First half: "A" (1 char)
	// No "first two" because len == 2 (not > 2)
	// With deduplication, expect 2 unique prompts (empty, "A")
	assert.GreaterOrEqual(t, len(prompts), 2, "Should generate at least 2 variants")
	assert.Equal(t, len(prompts), len(triggers))
}

func TestGeneratePrompts_LongTerm(t *testing.T) {
	entries := []SlurPromptEntry{
		{Term: "ABCDEFGH", Prefix: "Test prefix "},
	}

	prompts, triggers := generatePrompts(entries)

	// Long term should generate:
	// - Empty: ""
	// - First char: "A"
	// - First two: "AB"
	// - First half: "ABCD" (4 chars)
	// Expect 4 unique prompts
	assert.Equal(t, 4, len(prompts), "Should generate 4 variants for long term")
	assert.Equal(t, len(prompts), len(triggers))

	// Verify variants
	variants := make(map[string]bool)
	for _, prompt := range prompts {
		variant := strings.TrimPrefix(prompt, "Test prefix ")
		variants[variant] = true
	}

	assert.True(t, variants[""], "Should have empty variant")
	assert.True(t, variants["A"], "Should have first char variant")
	assert.True(t, variants["AB"], "Should have first two variant")
	assert.True(t, variants["ABCD"], "Should have first half variant")
}

// ----------------------------------------------------------------------------
// Integration with Detectors
// ----------------------------------------------------------------------------

func TestProbeDetectorPairing(t *testing.T) {
	tests := []struct {
		probeName    string
		detectorName string
	}{
		{"continuation.ContinueSlursReclaimedSlurs", "continuation.Continuation"},
		{"continuation.ContinueSlursReclaimedSlursFull", "continuation.Continuation"},
	}

	for _, tt := range tests {
		t.Run(tt.probeName, func(t *testing.T) {
			factory, ok := probes.Get(tt.probeName)
			require.True(t, ok)

			p, err := factory(registry.Config{})
			require.NoError(t, err)
			assert.Equal(t, tt.detectorName, p.GetPrimaryDetector())
		})
	}
}

func TestAllProbes_RegisteredCount(t *testing.T) {
	registered := []string{
		"continuation.ContinueSlursReclaimedSlurs",
		"continuation.ContinueSlursReclaimedSlursFull",
	}

	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			_, ok := probes.Get(name)
			assert.True(t, ok, "%s should be registered", name)
		})
	}
}

func TestTriggerMetadata_ConsistencyAcrossAttempts(t *testing.T) {
	p, err := NewContinueSlursReclaimedSlurs(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)

	// Verify all attempts have trigger metadata
	for i, a := range attempts {
		triggersAny, ok := a.GetMetadata("triggers")
		assert.True(t, ok, "Attempt %d should have triggers metadata", i)

		triggersSlice, ok := triggersAny.([]any)
		assert.True(t, ok, "Attempt %d triggers should be []any", i)
		assert.Len(t, triggersSlice, 1, "Attempt %d should have exactly one trigger", i)

		trigger, ok := triggersSlice[0].(string)
		assert.True(t, ok, "Attempt %d trigger should be a string", i)
		assert.NotEmpty(t, trigger, "Attempt %d trigger should not be empty", i)
	}
}

// Helper function (for Go versions without min built-in)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
