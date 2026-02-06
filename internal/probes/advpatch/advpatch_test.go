package advpatch

import (
	"context"
	"image"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestUniversalPatch_Registration verifies the probe is registered in the global registry.
func TestUniversalPatch_Registration(t *testing.T) {
	factory, ok := probes.Get("advpatch.UniversalPatch")
	require.True(t, ok, "advpatch.UniversalPatch should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestUniversalPatch_Create verifies the probe can be instantiated.
func TestUniversalPatch_Create(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestUniversalPatch_Name verifies the probe returns its fully qualified name.
func TestUniversalPatch_Name(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.UniversalPatch", p.Name())
}

// TestUniversalPatch_Description verifies the probe has a meaningful description.
func TestUniversalPatch_Description(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	// Should mention adversarial or patch
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "adversarial") ||
			strings.Contains(strings.ToLower(desc), "patch"),
		"description should mention adversarial or patch: %s", desc)
}

// TestUniversalPatch_Goal verifies the probe returns the correct goal.
func TestUniversalPatch_Goal(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	expected := "bypass vision-language model safety"
	assert.Equal(t, expected, p.Goal())
}

// TestUniversalPatch_PrimaryDetector verifies the probe returns the correct detector.
func TestUniversalPatch_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.Universal", p.GetPrimaryDetector())
}

// TestUniversalPatch_Prompts_NotEmpty verifies the probe has prompts.
func TestUniversalPatch_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
}

// TestUniversalPatch_Prompts_ContainsKeyElements verifies the prompt contains key elements.
func TestUniversalPatch_Prompts_ContainsKeyElements(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	require.NotEmpty(t, prompts)

	prompt := prompts[0]

	// Key elements for adversarial patch testing
	keyElements := []string{
		"image",
		"adversarial",
		"patch",
	}

	for _, element := range keyElements {
		assert.Contains(t, strings.ToLower(prompt), element,
			"prompt should contain '%s'", element)
	}
}

// TestUniversalPatch_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestUniversalPatch_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I see a person")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	// Should return attempts
	assert.NotEmpty(t, attempts)
}

// TestUniversalPatch_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestUniversalPatch_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("advpatch.UniversalPatch", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I see a person")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "advpatch.UniversalPatch", a.Probe, "attempt should have probe name")
		assert.Equal(t, "advpatch.Universal", a.Detector, "attempt should have detector name")
	}
}

// TestTargetedPatch_Registration verifies the targeted patch probe is registered.
func TestTargetedPatch_Registration(t *testing.T) {
	factory, ok := probes.Get("advpatch.TargetedPatch")
	require.True(t, ok, "advpatch.TargetedPatch should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestTargetedPatch_Create verifies the targeted patch probe can be instantiated.
func TestTargetedPatch_Create(t *testing.T) {
	p, err := probes.Create("advpatch.TargetedPatch", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestTargetedPatch_Name verifies the targeted patch probe returns correct name.
func TestTargetedPatch_Name(t *testing.T) {
	p, err := probes.Create("advpatch.TargetedPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.TargetedPatch", p.Name())
}

// TestTargetedPatch_PrimaryDetector verifies the targeted patch probe returns correct detector.
func TestTargetedPatch_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("advpatch.TargetedPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.Targeted", p.GetPrimaryDetector())
}

// TestTransferPatch_Registration verifies the transfer patch probe is registered.
func TestTransferPatch_Registration(t *testing.T) {
	factory, ok := probes.Get("advpatch.TransferPatch")
	require.True(t, ok, "advpatch.TransferPatch should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestTransferPatch_Create verifies the transfer patch probe can be instantiated.
func TestTransferPatch_Create(t *testing.T) {
	p, err := probes.Create("advpatch.TransferPatch", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestTransferPatch_Name verifies the transfer patch probe returns correct name.
func TestTransferPatch_Name(t *testing.T) {
	p, err := probes.Create("advpatch.TransferPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.TransferPatch", p.Name())
}

// TestTransferPatch_PrimaryDetector verifies the transfer patch probe returns correct detector.
func TestTransferPatch_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("advpatch.TransferPatch", nil)
	require.NoError(t, err)

	assert.Equal(t, "advpatch.Transfer", p.GetPrimaryDetector())
}

// TestAllAdvPatchProbes_Registration verifies all adversarial patch probes are properly registered.
func TestAllAdvPatchProbes_Registration(t *testing.T) {
	tests := []struct {
		name             string
		expectedDetector string
	}{
		{"advpatch.UniversalPatch", "advpatch.Universal"},
		{"advpatch.TargetedPatch", "advpatch.Targeted"},
		{"advpatch.TransferPatch", "advpatch.Transfer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Check registration
			factory, ok := probes.Get(tt.name)
			require.True(t, ok, "%s should be registered", tt.name)
			require.NotNil(t, factory, "factory should not be nil")

			// Create probe
			p, err := probes.Create(tt.name, nil)
			require.NoError(t, err)
			require.NotNil(t, p)

			// Verify name
			assert.Equal(t, tt.name, p.Name())

			// Verify goal
			assert.Equal(t, "bypass vision-language model safety", p.Goal())

			// Verify detector
			assert.Equal(t, tt.expectedDetector, p.GetPrimaryDetector())

			// Verify description not empty
			assert.NotEmpty(t, p.Description())

			// Verify has prompts
			prompts := p.GetPrompts()
			assert.NotEmpty(t, prompts, "%s should have prompts", tt.name)
		})
	}
}

// TestAllAdvPatchProbes_Probe verifies all adversarial patch probes can execute and return attempts.
func TestAllAdvPatchProbes_Probe(t *testing.T) {
	probeNames := []string{
		"advpatch.UniversalPatch",
		"advpatch.TargetedPatch",
		"advpatch.TransferPatch",
	}

	for _, probeName := range probeNames {
		t.Run(probeName, func(t *testing.T) {
			p, err := probes.Create(probeName, nil)
			require.NoError(t, err)

			gen := testutil.NewMockGenerator("test response")
			ctx := context.Background()

			attempts, err := p.Probe(ctx, gen)
			require.NoError(t, err)

			// Should return attempts
			assert.NotEmpty(t, attempts)

			// Verify attempts have correct metadata
			if len(attempts) > 0 {
				assert.Equal(t, probeName, attempts[0].Probe)
				assert.NotEmpty(t, attempts[0].Detector)
			}
		})
	}
}

// TestNewAdvPatchProbe_WithConfig verifies the constructor accepts nil config.
func TestNewAdvPatchProbe_WithConfig(t *testing.T) {
	p, err := NewUniversalPatch(nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestNewAdvPatchProbe_WithEmptyConfig verifies the constructor accepts empty config.
func TestNewAdvPatchProbe_WithEmptyConfig(t *testing.T) {
	p, err := NewUniversalPatch(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestAdvPatchProbe_ImplementsProber verifies AdvPatchProbe implements probes.Prober interface.
func TestAdvPatchProbe_ImplementsProber(t *testing.T) {
	p, err := NewUniversalPatch(nil)
	require.NoError(t, err)

	// This will fail to compile if AdvPatchProbe doesn't implement probes.Prober
	var _ probes.Prober = p
}

// TestGeneratePatch_ReturnsImage verifies GeneratePatch returns an image.
func TestGeneratePatch_ReturnsImage(t *testing.T) {
	// Create a simple test image
	testImg := image.NewRGBA(image.Rect(0, 0, 224, 224))

	patchedImg, err := GeneratePatch(testImg, "person")
	require.NoError(t, err)
	require.NotNil(t, patchedImg)

	// Verify dimensions are preserved
	bounds := patchedImg.Bounds()
	assert.Equal(t, 224, bounds.Dx())
	assert.Equal(t, 224, bounds.Dy())
}

// TestGeneratePatch_WithNilImage verifies GeneratePatch handles nil image.
func TestGeneratePatch_WithNilImage(t *testing.T) {
	_, err := GeneratePatch(nil, "person")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "image")
}

// TestGeneratePatch_WithEmptyTarget verifies GeneratePatch handles empty target.
func TestGeneratePatch_WithEmptyTarget(t *testing.T) {
	testImg := image.NewRGBA(image.Rect(0, 0, 224, 224))

	_, err := GeneratePatch(testImg, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target")
}

// TestPatchType_Constants verifies PatchType constants are defined.
func TestPatchType_Constants(t *testing.T) {
	// Verify constants exist and have expected values
	assert.Equal(t, PatchType(0), UniversalPatch)
	assert.Equal(t, PatchType(1), TargetedPatch)
	assert.Equal(t, PatchType(2), TransferPatch)

	// Verify they are distinct
	assert.NotEqual(t, UniversalPatch, TargetedPatch)
	assert.NotEqual(t, TargetedPatch, TransferPatch)
	assert.NotEqual(t, UniversalPatch, TransferPatch)
}
