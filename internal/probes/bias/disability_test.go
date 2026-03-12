package bias_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/augustus/internal/probes/bias"
	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// TestDisability_Registration verifies the probe is registered in the global registry.
func TestDisability_Registration(t *testing.T) {
	factory, ok := probes.Get("bias.Disability")
	require.True(t, ok, "bias.Disability should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestDisability_Create verifies the probe can be instantiated.
func TestDisability_Create(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestDisability_Name verifies the probe returns its fully qualified name.
func TestDisability_Name(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	assert.Equal(t, "bias.Disability", p.Name())
}

// TestDisability_Description verifies the probe has a meaningful description.
func TestDisability_Description(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	desc := pm.Description()
	assert.NotEmpty(t, desc)
	// Should mention disability or discrimination
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "disability") ||
			strings.Contains(strings.ToLower(desc), "disabled") ||
			strings.Contains(strings.ToLower(desc), "discrimination"),
		"description should mention disability or discrimination: %s", desc)
}

// TestDisability_Goal verifies the probe returns the correct goal.
func TestDisability_Goal(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	expected := "elicit disability-discriminatory responses that make unfounded assumptions about disabled people's capabilities"
	assert.Equal(t, expected, pm.Goal())
}

// TestDisability_PrimaryDetector verifies the probe returns the correct detector.
func TestDisability_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	assert.Equal(t, "judge.Judge", pm.GetPrimaryDetector())
}

// TestDisability_Prompts_NotEmpty verifies the probe has prompts.
func TestDisability_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
}

// TestDisability_Prompts_ContainsDisabilityKeyElements verifies prompts contain disability-related content.
func TestDisability_Prompts_ContainsDisabilityKeyElements(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	// At least one prompt should contain disability-related terms
	hasDisabilityContent := false
	disabilityTerms := []string{
		"disability",
		"disabled",
		"wheelchair",
		"blind",
		"deaf",
		"autism",
		"mental health",
		"physical",
		"cognitive",
		"accessible",
		"accessibility",
		"impairment",
	}

	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, term := range disabilityTerms {
			if strings.Contains(lowerPrompt, term) {
				hasDisabilityContent = true
				break
			}
		}
		if hasDisabilityContent {
			break
		}
	}

	assert.True(t, hasDisabilityContent,
		"at least one prompt should contain disability-related content")
}

// TestDisability_Prompts_AllNonEmpty verifies all prompts have content.
func TestDisability_Prompts_AllNonEmpty(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.NotEmpty(t, prompt, "prompt %d should not be empty", i)
		assert.Greater(t, len(prompt), 10,
			"prompt %d should be substantive (>10 chars), got %d", i, len(prompt))
	}
}

// TestDisability_Prompts_ReasonableLength verifies prompts are reasonably sized.
func TestDisability_Prompts_ReasonableLength(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		// Prompts should be at least 10 characters and less than 10KB
		assert.Greater(t, len(prompt), 10,
			"prompt %d should be at least 10 characters", i)
		assert.Less(t, len(prompt), 10000,
			"prompt %d should be less than 10KB", i)
	}
}

// TestDisability_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestDisability_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I understand your concern about workplace accessibility.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Should return one attempt per prompt
	prompts := pm.GetPrompts()
	assert.Len(t, attempts, len(prompts),
		"should return one attempt per prompt")
}

// TestDisability_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestDisability_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I believe everyone deserves equal opportunities.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.Equal(t, "bias.Disability", a.Probe,
			"attempt %d should have correct probe name", i)
		assert.Equal(t, "judge.Judge", a.Detector,
			"attempt %d should have correct detector name", i)
		assert.NotEmpty(t, a.Status,
			"attempt %d should have a status", i)
	}
}

// TestDisability_Probe_AttemptsHavePromptAndOutputs verifies attempts contain prompts and outputs.
func TestDisability_Probe_AttemptsHavePromptAndOutputs(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	mockResponse := "Let me provide a thoughtful response about accessibility."
	gen := testutil.NewMockGenerator(mockResponse)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		// Verify prompt is set
		assert.NotEmpty(t, a.Prompt,
			"attempt %d should have a prompt", i)

		// Verify outputs are present
		assert.NotEmpty(t, a.Outputs,
			"attempt %d should have outputs", i)
	}
}

// TestDisability_Probe_OutputsContent verifies the outputs contain actual content.
func TestDisability_Probe_OutputsContent(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	mockResponse := "Accessibility is an important consideration."
	gen := testutil.NewMockGenerator(mockResponse)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		require.NotEmpty(t, a.Outputs,
			"attempt %d should have outputs", i)
		assert.Equal(t, mockResponse, a.Outputs[0],
			"attempt %d: output should match mock response", i)
	}
}

// TestDisability_Probe_MultipleResponses verifies the probe handles multiple mock responses.
func TestDisability_Probe_MultipleResponses(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	responses := []string{
		"First response about accessibility",
		"Second response about inclusion",
		"Third response about accommodations",
	}
	gen := testutil.NewMockGenerator(responses...)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	assert.NotEmpty(t, attempts, "should return attempts")

	// Verify generator was called
	assert.Greater(t, gen.Calls, 0, "generator should have been called")
}

// TestDisability_Probe_ContextCancellation verifies the probe respects context cancellation.
func TestDisability_Probe_ContextCancellation(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("response")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err = p.Probe(ctx, gen)
	// Should return context error
	assert.Error(t, err, "should return error on cancelled context")
}

// TestDisability_Metadata_Consistency verifies metadata is consistent across calls.
func TestDisability_Metadata_Consistency(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Call methods multiple times to ensure consistency
	for i := 0; i < 3; i++ {
		assert.Equal(t, "bias.Disability", p.Name(),
			"name should be consistent on call %d", i)
		assert.Equal(t, "judge.Judge", pm.GetPrimaryDetector(),
			"detector should be consistent on call %d", i)
		assert.Equal(t,
			"elicit disability-discriminatory responses that make unfounded assumptions about disabled people's capabilities",
			pm.Goal(),
			"goal should be consistent on call %d", i)
		assert.NotEmpty(t, pm.Description(),
			"description should be non-empty on call %d", i)
		assert.NotEmpty(t, pm.GetPrompts(),
			"prompts should be non-empty on call %d", i)
	}
}

// TestDisability_Probe_EmptyResponse verifies the probe handles empty generator responses.
func TestDisability_Probe_EmptyResponse(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("") // Empty response
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.Len(t, attempts, len(prompts),
		"should return attempts even with empty response")

	// Verify attempts have correct structure even with empty response
	for i, a := range attempts {
		assert.Equal(t, "bias.Disability", a.Probe,
			"attempt %d should have correct probe name", i)
		assert.Equal(t, "judge.Judge", a.Detector,
			"attempt %d should have correct detector name", i)
	}
}

// TestDisability_ProbeInterface verifies the probe implements required interfaces.
func TestDisability_ProbeInterface(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)

	// Verify it implements Probe interface (has Name and Probe methods)
	assert.NotEmpty(t, p.Name(), "should implement Name()")

	// Verify it implements ProbeMetadata interface
	_, ok := p.(probes.ProbeMetadata)
	assert.True(t, ok, "should implement ProbeMetadata interface")
}

// TestDisability_CreateWithNilConfig verifies the probe can be created with nil config.
func TestDisability_CreateWithNilConfig(t *testing.T) {
	p, err := probes.Create("bias.Disability", nil)
	require.NoError(t, err)
	require.NotNil(t, p)

	assert.Equal(t, "bias.Disability", p.Name())
}
