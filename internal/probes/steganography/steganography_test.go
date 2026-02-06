package steganography

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

// TestSteganographyProbe_Registration verifies all variants are registered.
func TestSteganographyProbe_Registration(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"steganography.LSB"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			factory, ok := probes.Get(tt.name)
			require.True(t, ok, "%s should be registered", tt.name)
			require.NotNil(t, factory, "factory should not be nil")
		})
	}
}

// TestSteganographyProbe_Create verifies probes can be instantiated.
func TestSteganographyProbe_Create(t *testing.T) {
	tests := []string{
		"steganography.LSB",
	}

	for _, probeName := range tests {
		t.Run(probeName, func(t *testing.T) {
			p, err := probes.Create(probeName, nil)
			require.NoError(t, err)
			require.NotNil(t, p)
		})
	}
}

// TestSteganographyProbe_Name verifies probe returns correct name.
func TestSteganographyProbe_Name(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)
	assert.Equal(t, "steganography.LSB", p.Name())
}

// TestSteganographyProbe_Description verifies probe has meaningful description.
func TestSteganographyProbe_Description(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	desc := p.Description()
	assert.NotEmpty(t, desc)
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "steganograph") ||
			strings.Contains(strings.ToLower(desc), "image") ||
			strings.Contains(strings.ToLower(desc), "hidden"),
		"description should mention steganography concept: %s", desc)
}

// TestSteganographyProbe_Goal verifies probe returns correct goal.
func TestSteganographyProbe_Goal(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	goal := p.Goal()
	assert.NotEmpty(t, goal)
	assert.Contains(t, strings.ToLower(goal), "instruction")
}

// TestSteganographyProbe_PrimaryDetector verifies probe returns detector.
func TestSteganographyProbe_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	detector := p.GetPrimaryDetector()
	assert.Equal(t, "steganography.ImageInstruction", detector)
}

// TestSteganographyProbe_GetPrompts verifies probe returns prompts.
func TestSteganographyProbe_GetPrompts(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
	assert.Greater(t, len(prompts), 0, "should have at least one prompt")
}

// TestSteganographyProbe_Probe_ReturnsAttempts verifies probe execution.
func TestSteganographyProbe_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{GenName: "TestModel", Responses: []string{"Sure, I'll help with that"}}
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	// Should return attempts based on prompts
	prompts := p.GetPrompts()
	assert.Len(t, attempts, len(prompts))
}

// TestSteganographyProbe_Probe_AttemptsHaveMetadata verifies attempt metadata.
func TestSteganographyProbe_Probe_AttemptsHaveMetadata(t *testing.T) {
	p, err := probes.Create("steganography.LSB", nil)
	require.NoError(t, err)

	gen := &testutil.MockGenerator{GenName: "TestModel", Responses: []string{"response"}}
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "steganography.LSB", a.Probe, "attempt should have probe name")
		assert.Equal(t, "steganography.ImageInstruction", a.Detector, "attempt should have detector name")
	}
}

// TestNewLSB_WithConfig verifies constructor accepts config.
func TestNewLSB_WithConfig(t *testing.T) {
	p, err := NewLSB(nil)
	require.NoError(t, err)
	require.NotNil(t, p)

	p2, err := NewLSB(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, p2)
}

// TestSteganographyProbe_AllVariants verifies all embed methods work.
func TestSteganographyProbe_AllVariants(t *testing.T) {
	tests := []struct {
		name              string
		expectedDetector  string
	}{
		{"steganography.LSB", "steganography.ImageInstruction"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := probes.Create(tt.name, nil)
			require.NoError(t, err)

			// Verify name
			assert.Equal(t, tt.name, p.Name())

			// Verify detector
			assert.Equal(t, tt.expectedDetector, p.GetPrimaryDetector())

			// Verify goal
			goal := p.Goal()
			assert.NotEmpty(t, goal)
			assert.Contains(t, strings.ToLower(goal), "instruction")

			// Verify description
			desc := p.Description()
			assert.NotEmpty(t, desc)

			// Verify prompts
			prompts := p.GetPrompts()
			assert.NotEmpty(t, prompts)

			// Verify probe execution
			gen := &testutil.MockGenerator{GenName: "TestModel", Responses: []string{"test"}}
			ctx := context.Background()
			attempts, err := p.Probe(ctx, gen)
			require.NoError(t, err)
			assert.Len(t, attempts, len(prompts))
		})
	}
}
