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

// TestAge_Registration verifies the probe is registered in the global registry.
func TestAge_Registration(t *testing.T) {
	factory, ok := probes.Get("bias.Age")
	require.True(t, ok, "bias.Age should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestAge_Create verifies the probe can be instantiated.
func TestAge_Create(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestAge_Name verifies the probe returns its fully qualified name.
func TestAge_Name(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	assert.Equal(t, "bias.Age", p.Name())
}

// TestAge_Description verifies the probe has a meaningful description.
func TestAge_Description(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	desc := pm.Description()
	assert.NotEmpty(t, desc)
	// Should mention age or discrimination
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "age") ||
			strings.Contains(strings.ToLower(desc), "discrimin"),
		"description should mention age or discrimination: %s", desc)
}

// TestAge_Goal verifies the probe returns the correct goal.
func TestAge_Goal(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	expected := "elicit age-discriminatory responses that treat people differently based on age group"
	assert.Equal(t, expected, pm.Goal())
}

// TestAge_PrimaryDetector verifies the probe returns the correct detector.
func TestAge_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	assert.Equal(t, "judge.Judge", pm.GetPrimaryDetector())
}

// TestAge_Prompts_NotEmpty verifies the probe has prompts.
func TestAge_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
}

// TestAge_Prompts_ContainsAgeReferences verifies prompts contain age-related content.
func TestAge_Prompts_ContainsAgeReferences(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	// At least one prompt should contain age-related terms
	foundAgeReference := false
	ageTerms := []string{"age", "old", "young", "elderly", "senior", "millennial", "generation", "boomer"}

	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, term := range ageTerms {
			if strings.Contains(lowerPrompt, term) {
				foundAgeReference = true
				break
			}
		}
		if foundAgeReference {
			break
		}
	}

	assert.True(t, foundAgeReference, "at least one prompt should contain age-related terms")
}

// TestAge_Prompts_AllValid verifies all prompts are non-empty strings.
func TestAge_Prompts_AllValid(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.NotEmpty(t, prompt, "prompt %d should not be empty", i)
		assert.Greater(t, len(prompt), 10, "prompt %d should be meaningful (>10 chars), got %d", i, len(prompt))
	}
}

// TestAge_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestAge_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Should return one attempt per prompt
	prompts := pm.GetPrompts()
	assert.Len(t, attempts, len(prompts))
}

// TestAge_Probe_AttemptsHaveCorrectProbe verifies attempts have the correct probe name.
func TestAge_Probe_AttemptsHaveCorrectProbe(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.Equal(t, "bias.Age", a.Probe, "attempt %d should have probe name bias.Age", i)
	}
}

// TestAge_Probe_AttemptsHaveCorrectDetector verifies attempts have the correct detector.
func TestAge_Probe_AttemptsHaveCorrectDetector(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.Equal(t, "judge.Judge", a.Detector, "attempt %d should have detector judge.Judge", i)
	}
}

// TestAge_Probe_AttemptsHaveStatus verifies attempts have a status field set.
func TestAge_Probe_AttemptsHaveStatus(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.NotEmpty(t, a.Status, "attempt %d should have a status", i)
	}
}

// TestAge_Probe_AttemptsHaveCorrectMetadata verifies attempts have all correct metadata.
func TestAge_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.Equal(t, "bias.Age", a.Probe, "attempt %d should have probe name", i)
		assert.Equal(t, "judge.Judge", a.Detector, "attempt %d should have detector name", i)
		assert.NotEmpty(t, a.Status, "attempt %d should have status", i)
	}
}

// TestAge_Probe_WithDifferentResponses verifies the probe handles different generator responses.
func TestAge_Probe_WithDifferentResponses(t *testing.T) {
	testCases := []struct {
		name     string
		response string
	}{
		{
			name:     "neutral response",
			response: "I can help with that request.",
		},
		{
			name:     "age-related response",
			response: "Older workers may not be as productive as younger ones.",
		},
		{
			name:     "refusal response",
			response: "I cannot make judgments based on age.",
		},
		{
			name:     "empty response",
			response: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := probes.Create("bias.Age", nil)
			require.NoError(t, err)

			gen := testutil.NewMockGenerator(tc.response)
			ctx := context.Background()

			attempts, err := p.Probe(ctx, gen)
			require.NoError(t, err)
			require.NotEmpty(t, attempts)

			// Verify all attempts have correct metadata regardless of response
			for _, a := range attempts {
				assert.Equal(t, "bias.Age", a.Probe)
				assert.Equal(t, "judge.Judge", a.Detector)
				assert.NotEmpty(t, a.Status)
			}
		})
	}
}

// TestAge_Probe_MultipleExecutions verifies the probe can be executed multiple times.
func TestAge_Probe_MultipleExecutions(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	// Execute multiple times
	for i := 0; i < 3; i++ {
		attempts, err := p.Probe(ctx, gen)
		require.NoError(t, err, "execution %d should succeed", i)
		require.NotEmpty(t, attempts, "execution %d should return attempts", i)

		pm, ok := p.(probes.ProbeMetadata)
		require.True(t, ok, "probe should implement ProbeMetadata")
		prompts := pm.GetPrompts()
		assert.Len(t, attempts, len(prompts), "execution %d should return correct number of attempts", i)
	}
}

// TestAge_Probe_GeneratorCalls verifies the probe calls the generator.
func TestAge_Probe_GeneratorCalls(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I can help with that request.")
	ctx := context.Background()

	initialCalls := gen.Calls
	_, err = p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")
	prompts := pm.GetPrompts()

	// Should call generator once per prompt
	assert.Equal(t, initialCalls+len(prompts), gen.Calls,
		"generator should be called once per prompt")
}

// TestAge_Category verifies the probe is in the bias category.
func TestAge_Category(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	name := p.Name()
	assert.True(t, strings.HasPrefix(name, "bias."),
		"probe name should start with 'bias.' prefix")
}

// TestAge_InterfaceImplementation verifies the probe implements required interfaces.
func TestAge_InterfaceImplementation(t *testing.T) {
	p, err := probes.Create("bias.Age", nil)
	require.NoError(t, err)

	// Should implement ProbeMetadata
	_, ok := p.(probes.ProbeMetadata)
	assert.True(t, ok, "probe should implement ProbeMetadata interface")
}
