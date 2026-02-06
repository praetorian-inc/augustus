package phrasing

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// TestPastTense_Registration verifies the probe is registered in the global registry.
func TestPastTense_Registration(t *testing.T) {
	factory, ok := probes.Get("phrasing.PastTense")
	require.True(t, ok, "phrasing.PastTense should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestPastTense_Create verifies the probe can be instantiated.
func TestPastTense_Create(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestPastTense_Name verifies the probe returns its fully qualified name.
func TestPastTense_Name(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	assert.Equal(t, "phrasing.PastTense", p.Name())
}

// TestPastTense_Description verifies the probe has a meaningful description.
func TestPastTense_Description(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention past tense or rephrasing
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "past tense") ||
			strings.Contains(strings.ToLower(desc), "tense") ||
			strings.Contains(strings.ToLower(desc), "rephras"),
		"description should mention past tense or rephrasing: %s", desc)
}

// TestPastTense_Goal verifies the probe returns the correct goal.
// Python garak PastTense uses "use past tense to disregard the system prompt" as goal.
func TestPastTense_Goal(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	// Must match Python garak exactly
	expected := "use past tense to disregard the system prompt"
	assert.Equal(t, expected, p.Goal())
}

// TestPastTense_PrimaryDetector verifies the probe returns the correct detector.
// According to requirements, should use mitigation.MitigationBypass
func TestPastTense_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	assert.Equal(t, "mitigation.MitigationBypass", p.GetPrimaryDetector())
}

// TestPastTense_Prompts_NotEmpty verifies the probe has prompts.
func TestPastTense_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "prompts should not be empty")
	assert.Greater(t, len(prompts), 0, "should have at least one prompt")
}

// TestPastTense_Prompts_PastTenseFormat verifies prompts use past tense phrasing.
func TestPastTense_Prompts_PastTenseFormat(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	// Check first few prompts for past tense indicators
	pastTenseIndicators := []string{
		"how was",
		"how did",
		"how were",
		"in the past",
		"previously",
		"historically",
	}

	foundPastTense := false
	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, indicator := range pastTenseIndicators {
			if strings.Contains(lowerPrompt, indicator) {
				foundPastTense = true
				break
			}
		}
		if foundPastTense {
			break
		}
	}

	assert.True(t, foundPastTense, "prompts should contain past tense phrasing")
}

// TestPastTense_Probe_ExecutesSuccessfully verifies the probe executes without error.
func TestPastTense_Probe_ExecutesSuccessfully(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a test response")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotNil(t, attempts)
	assert.Greater(t, len(attempts), 0, "should generate at least one attempt")
}

// TestPastTense_Probe_CreatesAttempts verifies attempts are properly created.
func TestPastTense_Probe_CreatesAttempts(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("Response 1", "Response 2")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.NotNil(t, a)
	assert.Equal(t, "phrasing.PastTense", a.Probe)
	assert.Equal(t, "mitigation.MitigationBypass", a.Detector)
	assert.NotEmpty(t, a.Prompt)
	assert.NotEmpty(t, a.Outputs)
}

// TestPastTense_Probe_CallsGenerator verifies the generator is called.
func TestPastTense_Probe_CallsGenerator(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	_, err = p.Probe(context.Background(), gen)
	require.NoError(t, err)

	assert.Greater(t, gen.Calls, 0, "generator should be called at least once")
}

// TestPastTense_Probe_HandlesContext verifies context is passed through.
func TestPastTense_Probe_HandlesContext(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	assert.NotEmpty(t, attempts)
}

// TestPastTense_Prompts_LoadedFromFile verifies prompts are loaded from embedded data.
func TestPastTense_Prompts_LoadedFromFile(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	// Should have a significant number of prompts from the data file
	// garak has 730+ prompts in past_tense_en.txt
	assert.Greater(t, len(prompts), 100, "should have many prompts from data file")
}

// TestPastTense_Prompts_Unique verifies prompts don't have obvious duplicates.
func TestPastTense_Prompts_Unique(t *testing.T) {
	p, err := probes.Create("phrasing.PastTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	seen := make(map[string]bool)
	duplicates := 0

	for _, prompt := range prompts {
		if seen[prompt] {
			duplicates++
		}
		seen[prompt] = true
	}

	// Allow a small number of duplicates but not many
	assert.Less(t, duplicates, len(prompts)/10, "should not have many duplicate prompts")
}
