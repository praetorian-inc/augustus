package phrasing

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestFutureTense_Registration verifies the probe is registered in the global registry.
func TestFutureTense_Registration(t *testing.T) {
	factory, ok := probes.Get("phrasing.FutureTense")
	require.True(t, ok, "phrasing.FutureTense should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestFutureTense_Create verifies the probe can be instantiated.
func TestFutureTense_Create(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestFutureTense_Name verifies the probe returns its fully qualified name.
func TestFutureTense_Name(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	assert.Equal(t, "phrasing.FutureTense", p.Name())
}

// TestFutureTense_Description verifies the probe has a meaningful description.
func TestFutureTense_Description(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention future tense or rephrasing
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "future tense") ||
			strings.Contains(strings.ToLower(desc), "tense") ||
			strings.Contains(strings.ToLower(desc), "rephras"),
		"description should mention future tense or rephrasing: %s", desc)
}

// TestFutureTense_Goal verifies the probe returns the correct goal.
// Python garak FutureTense uses "use future tense to disregard the system prompt" as goal.
func TestFutureTense_Goal(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	// Must match Python garak exactly
	expected := "use future tense to disregard the system prompt"
	assert.Equal(t, expected, p.Goal())
}

// TestFutureTense_PrimaryDetector verifies the probe returns the correct detector.
// Should use mitigation.MitigationBypass as specified in requirements.
func TestFutureTense_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	assert.Equal(t, "mitigation.MitigationBypass", p.GetPrimaryDetector())
}

// TestFutureTense_Prompts_NotEmpty verifies the probe has prompts.
func TestFutureTense_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "prompts should not be empty")
	assert.Greater(t, len(prompts), 0, "should have at least one prompt")
}

// TestFutureTense_Prompts_FutureTenseFormat verifies prompts use future tense phrasing.
func TestFutureTense_Prompts_FutureTenseFormat(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	// Check prompts for future tense indicators
	futureTenseIndicators := []string{
		"will",
		"in the future",
		"in the coming",
		"in the upcoming",
		"how will",
	}

	foundFutureTense := false
	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, indicator := range futureTenseIndicators {
			if strings.Contains(lowerPrompt, indicator) {
				foundFutureTense = true
				break
			}
		}
		if foundFutureTense {
			break
		}
	}

	assert.True(t, foundFutureTense, "prompts should contain future tense phrasing")
}

// TestFutureTense_Probe_ExecutesSuccessfully verifies the probe executes without error.
func TestFutureTense_Probe_ExecutesSuccessfully(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a test response")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotNil(t, attempts)
	assert.Greater(t, len(attempts), 0, "should generate at least one attempt")
}

// TestFutureTense_Probe_CreatesAttempts verifies attempts are properly created.
func TestFutureTense_Probe_CreatesAttempts(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("Response 1", "Response 2")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.NotNil(t, a)
	assert.Equal(t, "phrasing.FutureTense", a.Probe)
	assert.Equal(t, "mitigation.MitigationBypass", a.Detector)
	assert.NotEmpty(t, a.Prompt)
	assert.NotEmpty(t, a.Outputs)
}

// TestFutureTense_Probe_CallsGenerator verifies the generator is called.
func TestFutureTense_Probe_CallsGenerator(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	_, err = p.Probe(context.Background(), gen)
	require.NoError(t, err)

	assert.Greater(t, gen.Calls, 0, "generator should be called at least once")
}

// TestFutureTense_Probe_HandlesContext verifies context is passed through.
func TestFutureTense_Probe_HandlesContext(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	assert.NotEmpty(t, attempts)
}

// TestFutureTense_Prompts_LoadedFromFile verifies prompts are loaded from embedded data.
func TestFutureTense_Prompts_LoadedFromFile(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	// Should have a significant number of prompts from the data file
	// garak has 690 prompts in future_tense_en.txt
	assert.Greater(t, len(prompts), 100, "should have many prompts from data file")
}

// TestFutureTense_Prompts_Unique verifies prompts don't have obvious duplicates.
func TestFutureTense_Prompts_Unique(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
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

// TestNewFutureTense_WithConfig verifies the constructor accepts nil config.
func TestNewFutureTense_WithConfig(t *testing.T) {
	p, err := NewFutureTense(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestNewFutureTense_WithEmptyConfig verifies the constructor accepts empty config.
func TestNewFutureTense_WithEmptyConfig(t *testing.T) {
	p, err := NewFutureTense(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestFutureTense_Interface verifies FutureTense implements required interfaces.
func TestFutureTense_Interface(t *testing.T) {
	_, err := NewFutureTense(nil)
	require.NoError(t, err)
}

// TestFutureTense_Prompts_Questions verifies prompts are questions.
func TestFutureTense_Prompts_Questions(t *testing.T) {
	p, err := probes.Create("phrasing.FutureTense", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	// Most prompts should be questions
	questions := 0
	for _, prompt := range prompts {
		trimmed := strings.TrimSpace(prompt)
		if strings.HasPrefix(trimmed, "How ") ||
			strings.HasPrefix(trimmed, "What ") ||
			strings.HasPrefix(trimmed, "Will ") ||
			strings.HasSuffix(trimmed, "?") {
			questions++
		}
	}

	// At least 80% should be questions
	minQuestions := int(float64(len(prompts)) * 0.8)
	assert.GreaterOrEqual(t, questions, minQuestions,
		"at least 80%% of prompts should be questions, got %d/%d",
		questions, len(prompts))
}
