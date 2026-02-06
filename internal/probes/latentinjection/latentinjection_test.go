package latentinjection

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// TestLatentJailbreak_Registration verifies the probe is registered in the global registry.
func TestLatentJailbreak_Registration(t *testing.T) {
	factory, ok := probes.Get("latentinjection.LatentJailbreak")
	require.True(t, ok, "latentinjection.LatentJailbreak should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestLatentJailbreak_Create verifies the probe can be instantiated.
func TestLatentJailbreak_Create(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestLatentJailbreak_Name verifies the probe returns its fully qualified name.
func TestLatentJailbreak_Name(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	assert.Equal(t, "latentinjection.LatentJailbreak", p.Name())
}

// TestLatentJailbreak_Description verifies the probe has a meaningful description.
func TestLatentJailbreak_Description(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention latent, indirect, or hidden
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "latent") ||
			strings.Contains(strings.ToLower(desc), "indirect") ||
			strings.Contains(strings.ToLower(desc), "hidden"),
		"description should mention latent/indirect/hidden: %s", desc)
}

// TestLatentJailbreak_Goal verifies the probe returns the correct goal.
func TestLatentJailbreak_Goal(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	goal := p.Goal()
	assert.NotEmpty(t, goal)
	assert.Contains(t, strings.ToLower(goal), "inject", "goal should mention injection")
}

// TestLatentJailbreak_GetPrimaryDetector verifies the probe returns a valid detector.
func TestLatentJailbreak_GetPrimaryDetector(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	detector := p.GetPrimaryDetector()
	assert.NotEmpty(t, detector)
}

// TestLatentJailbreak_GetPrompts verifies the probe returns prompts.
func TestLatentJailbreak_GetPrompts(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "should have at least one prompt")
}

// TestLatentJailbreak_Probe verifies the probe generates attempts with prompts.
func TestLatentJailbreak_Probe(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentJailbreak", nil)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{
		GenName:   "test-model",
		Responses: []string{"test response"},
	}

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "should generate at least one attempt")

	// Verify first attempt has expected structure
	attempt := attempts[0]
	assert.Equal(t, "latentinjection.LatentJailbreak", attempt.Probe)
	assert.NotEmpty(t, attempt.Prompt)
	assert.NotEmpty(t, attempt.Outputs)
}

// TestLatentRefusal_Registration verifies the probe is registered in the global registry.
func TestLatentRefusal_Registration(t *testing.T) {
	factory, ok := probes.Get("latentinjection.LatentRefusal")
	require.True(t, ok, "latentinjection.LatentRefusal should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestLatentRefusal_Create verifies the probe can be instantiated.
func TestLatentRefusal_Create(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestLatentRefusal_Name verifies the probe returns its fully qualified name.
func TestLatentRefusal_Name(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	assert.Equal(t, "latentinjection.LatentRefusal", p.Name())
}

// TestLatentRefusal_Description verifies the probe has a meaningful description.
func TestLatentRefusal_Description(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention refusal or trigger
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "refusal") ||
			strings.Contains(strings.ToLower(desc), "trigger"),
		"description should mention refusal/trigger: %s", desc)
}

// TestLatentRefusal_Goal verifies the probe returns the correct goal.
func TestLatentRefusal_Goal(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	goal := p.Goal()
	assert.NotEmpty(t, goal)
}

// TestLatentRefusal_GetPrimaryDetector verifies the probe returns a valid detector.
func TestLatentRefusal_GetPrimaryDetector(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	detector := p.GetPrimaryDetector()
	assert.NotEmpty(t, detector)
}

// TestLatentRefusal_GetPrompts verifies the probe returns prompts.
func TestLatentRefusal_GetPrompts(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "should have at least one prompt")
}

// TestLatentRefusal_Probe verifies the probe generates attempts with prompts.
func TestLatentRefusal_Probe(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentRefusal", nil)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{
		GenName:   "test-model",
		Responses: []string{"test response"},
	}

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "should generate at least one attempt")

	// Verify first attempt has expected structure
	attempt := attempts[0]
	assert.Equal(t, "latentinjection.LatentRefusal", attempt.Probe)
	assert.NotEmpty(t, attempt.Prompt)
	assert.NotEmpty(t, attempt.Outputs)
}

// TestLatentExtraction_Registration verifies the probe is registered in the global registry.
func TestLatentExtraction_Registration(t *testing.T) {
	factory, ok := probes.Get("latentinjection.LatentExtraction")
	require.True(t, ok, "latentinjection.LatentExtraction should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestLatentExtraction_Create verifies the probe can be instantiated.
func TestLatentExtraction_Create(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestLatentExtraction_Name verifies the probe returns its fully qualified name.
func TestLatentExtraction_Name(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	assert.Equal(t, "latentinjection.LatentExtraction", p.Name())
}

// TestLatentExtraction_Description verifies the probe has a meaningful description.
func TestLatentExtraction_Description(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention extraction or data
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "extract") ||
			strings.Contains(strings.ToLower(desc), "data"),
		"description should mention extraction/data: %s", desc)
}

// TestLatentExtraction_Goal verifies the probe returns the correct goal.
func TestLatentExtraction_Goal(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	goal := p.Goal()
	assert.NotEmpty(t, goal)
}

// TestLatentExtraction_GetPrimaryDetector verifies the probe returns a valid detector.
func TestLatentExtraction_GetPrimaryDetector(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	detector := p.GetPrimaryDetector()
	assert.NotEmpty(t, detector)
}

// TestLatentExtraction_GetPrompts verifies the probe returns prompts.
func TestLatentExtraction_GetPrompts(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "should have at least one prompt")
}

// TestLatentExtraction_Probe verifies the probe generates attempts with prompts.
func TestLatentExtraction_Probe(t *testing.T) {
	p, err := probes.Create("latentinjection.LatentExtraction", nil)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{
		GenName:   "test-model",
		Responses: []string{"test response"},
	}

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "should generate at least one attempt")

	// Verify first attempt has expected structure
	attempt := attempts[0]
	assert.Equal(t, "latentinjection.LatentExtraction", attempt.Probe)
	assert.NotEmpty(t, attempt.Prompt)
	assert.NotEmpty(t, attempt.Outputs)
}
