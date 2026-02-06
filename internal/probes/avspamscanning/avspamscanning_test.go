package avspamscanning

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

// =============================================================================
// EICAR Probe Tests
// =============================================================================

// TestEICAR_Registration verifies the probe is registered in the global registry.
func TestEICAR_Registration(t *testing.T) {
	factory, ok := probes.Get("avspamscanning.EICAR")
	require.True(t, ok, "avspamscanning.EICAR should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestEICAR_Create verifies the probe can be instantiated.
func TestEICAR_Create(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestEICAR_Name verifies the probe returns its fully qualified name.
func TestEICAR_Name(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	assert.Equal(t, "avspamscanning.EICAR", p.Name())
}

// TestEICAR_Description verifies the probe has a meaningful description.
func TestEICAR_Description(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention virus, antivirus, or EICAR
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "virus") ||
			strings.Contains(strings.ToLower(desc), "antivirus") ||
			strings.Contains(strings.ToLower(desc), "eicar"),
		"description should mention virus/antivirus/EICAR: %s", desc)
}

// TestEICAR_Goal verifies the probe returns the correct goal.
// Must match Python garak exactly.
func TestEICAR_Goal(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	expected := "output antivirus test codes"
	assert.Equal(t, expected, p.Goal())
}

// TestEICAR_PrimaryDetector verifies the probe returns the correct detector.
func TestEICAR_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	assert.Equal(t, "knownbadsignatures.EICAR", p.GetPrimaryDetector())
}

// TestEICAR_Prompts_Count verifies the probe has 5 prompts.
func TestEICAR_Prompts_Count(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 5, len(prompts), "should have 5 prompts (one per template)")
}

// TestEICAR_Prompts_ContainSignature verifies all prompts contain the EICAR signature.
func TestEICAR_Prompts_ContainSignature(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.Contains(t, prompt, EICARSignature,
			"prompt %d should contain EICAR signature", i)
	}
}

// TestEICAR_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestEICAR_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	// Should return one attempt per prompt (5 prompts)
	assert.Len(t, attempts, 5)
}

// TestEICAR_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestEICAR_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("avspamscanning.EICAR", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "avspamscanning.EICAR", a.Probe, "attempt should have probe name")
		assert.Equal(t, "knownbadsignatures.EICAR", a.Detector, "attempt should have detector name")
	}
}

// TestNewEICAR_WithConfig verifies the constructor accepts nil config.
func TestNewEICAR_WithConfig(t *testing.T) {
	p, err := NewEICAR(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestNewEICAR_WithEmptyConfig verifies the constructor accepts empty config.
func TestNewEICAR_WithEmptyConfig(t *testing.T) {
	p, err := NewEICAR(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)
}

// =============================================================================
// GTUBE Probe Tests
// =============================================================================

// TestGTUBE_Registration verifies the probe is registered in the global registry.
func TestGTUBE_Registration(t *testing.T) {
	factory, ok := probes.Get("avspamscanning.GTUBE")
	require.True(t, ok, "avspamscanning.GTUBE should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestGTUBE_Create verifies the probe can be instantiated.
func TestGTUBE_Create(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestGTUBE_Name verifies the probe returns its fully qualified name.
func TestGTUBE_Name(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	assert.Equal(t, "avspamscanning.GTUBE", p.Name())
}

// TestGTUBE_Description verifies the probe has a meaningful description.
func TestGTUBE_Description(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention spam or GTUBE
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "spam") ||
			strings.Contains(strings.ToLower(desc), "gtube"),
		"description should mention spam/GTUBE: %s", desc)
}

// TestGTUBE_Goal verifies the probe returns the correct goal.
// Must match Python garak exactly.
func TestGTUBE_Goal(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	expected := "output email spam"
	assert.Equal(t, expected, p.Goal())
}

// TestGTUBE_PrimaryDetector verifies the probe returns the correct detector.
func TestGTUBE_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	assert.Equal(t, "knownbadsignatures.GTUBE", p.GetPrimaryDetector())
}

// TestGTUBE_Prompts_Count verifies the probe has 5 prompts.
func TestGTUBE_Prompts_Count(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 5, len(prompts), "should have 5 prompts (one per template)")
}

// TestGTUBE_Prompts_ContainSignature verifies all prompts contain the GTUBE signature.
func TestGTUBE_Prompts_ContainSignature(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.Contains(t, prompt, GTUBESignature,
			"prompt %d should contain GTUBE signature", i)
	}
}

// TestGTUBE_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestGTUBE_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	// Should return one attempt per prompt (5 prompts)
	assert.Len(t, attempts, 5)
}

// TestGTUBE_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestGTUBE_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTUBE", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "avspamscanning.GTUBE", a.Probe, "attempt should have probe name")
		assert.Equal(t, "knownbadsignatures.GTUBE", a.Detector, "attempt should have detector name")
	}
}

// TestNewGTUBE_WithConfig verifies the constructor accepts nil config.
func TestNewGTUBE_WithConfig(t *testing.T) {
	p, err := NewGTUBE(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestNewGTUBE_WithEmptyConfig verifies the constructor accepts empty config.
func TestNewGTUBE_WithEmptyConfig(t *testing.T) {
	p, err := NewGTUBE(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)
}

// =============================================================================
// GTphish Probe Tests
// =============================================================================

// TestGTphish_Registration verifies the probe is registered in the global registry.
func TestGTphish_Registration(t *testing.T) {
	factory, ok := probes.Get("avspamscanning.GTphish")
	require.True(t, ok, "avspamscanning.GTphish should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestGTphish_Create verifies the probe can be instantiated.
func TestGTphish_Create(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestGTphish_Name verifies the probe returns its fully qualified name.
func TestGTphish_Name(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	assert.Equal(t, "avspamscanning.GTphish", p.Name())
}

// TestGTphish_Description verifies the probe has a meaningful description.
func TestGTphish_Description(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention phishing or GTphish
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "phish") ||
			strings.Contains(strings.ToLower(desc), "gtphish"),
		"description should mention phishing/GTphish: %s", desc)
}

// TestGTphish_Goal verifies the probe returns the correct goal.
// Must match Python garak exactly.
func TestGTphish_Goal(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	expected := "output email phishing"
	assert.Equal(t, expected, p.Goal())
}

// TestGTphish_PrimaryDetector verifies the probe returns the correct detector.
func TestGTphish_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	assert.Equal(t, "knownbadsignatures.GTphish", p.GetPrimaryDetector())
}

// TestGTphish_Prompts_Count verifies the probe has 5 prompts.
func TestGTphish_Prompts_Count(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 5, len(prompts), "should have 5 prompts (one per template)")
}

// TestGTphish_Prompts_ContainSignature verifies all prompts contain the GTphish signature.
func TestGTphish_Prompts_ContainSignature(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.Contains(t, prompt, GTphishSignature,
			"prompt %d should contain GTphish signature", i)
	}
}

// TestGTphish_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestGTphish_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	// Should return one attempt per prompt (5 prompts)
	assert.Len(t, attempts, 5)
}

// TestGTphish_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestGTphish_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("avspamscanning.GTphish", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "avspamscanning.GTphish", a.Probe, "attempt should have probe name")
		assert.Equal(t, "knownbadsignatures.GTphish", a.Detector, "attempt should have detector name")
	}
}

// TestNewGTphish_WithConfig verifies the constructor accepts nil config.
func TestNewGTphish_WithConfig(t *testing.T) {
	p, err := NewGTphish(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestNewGTphish_WithEmptyConfig verifies the constructor accepts empty config.
func TestNewGTphish_WithEmptyConfig(t *testing.T) {
	p, err := NewGTphish(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)
}

// =============================================================================
// Shared Tests
// =============================================================================

// TestGeneratePrompts_Count verifies generatePrompts creates correct number of prompts.
func TestGeneratePrompts_Count(t *testing.T) {
	prompts := generatePrompts("TEST_SIGNATURE")
	assert.Equal(t, 5, len(prompts), "should generate 5 prompts")
}

// TestGeneratePrompts_SubstitutesSignature verifies signature substitution works.
func TestGeneratePrompts_SubstitutesSignature(t *testing.T) {
	signature := "TEST_SIGNATURE_XYZ"
	prompts := generatePrompts(signature)

	for i, prompt := range prompts {
		assert.Contains(t, prompt, signature,
			"prompt %d should contain signature", i)
	}
}

// TestAllProbes_Registered verifies all 3 probes are registered.
func TestAllProbes_Registered(t *testing.T) {
	allProbes := probes.List()

	expectedProbes := []string{
		"avspamscanning.EICAR",
		"avspamscanning.GTUBE",
		"avspamscanning.GTphish",
	}

	for _, expected := range expectedProbes {
		assert.Contains(t, allProbes, expected,
			"probe %s should be registered", expected)
	}
}
