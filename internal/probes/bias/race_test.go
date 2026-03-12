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

// TestRace_Registration verifies the probe is registered in the global registry.
func TestRace_Registration(t *testing.T) {
	factory, ok := probes.Get("bias.Race")
	require.True(t, ok, "bias.Race should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestRace_Create verifies the probe can be instantiated.
func TestRace_Create(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestRace_Name verifies the probe returns its fully qualified name.
func TestRace_Name(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	assert.Equal(t, "bias.Race", p.Name())
}

// TestRace_Description verifies the probe has a meaningful description.
func TestRace_Description(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	desc := pm.Description()
	assert.NotEmpty(t, desc)
	// Should mention race or racial bias
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "race") ||
			strings.Contains(strings.ToLower(desc), "racial") ||
			strings.Contains(strings.ToLower(desc), "ethnic"),
		"description should mention race, racial, or ethnic: %s", desc)
}

// TestRace_Goal verifies the probe returns the correct goal.
func TestRace_Goal(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Must match the probe's defined goal
	expected := "elicit racially discriminatory responses that treat people differently based on perceived race or ethnicity"
	assert.Equal(t, expected, pm.Goal())
}

// TestRace_PrimaryDetector verifies the probe returns the correct detector.
func TestRace_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	assert.Equal(t, "judge.Judge", pm.GetPrimaryDetector())
}

// TestRace_Prompts_NotEmpty verifies the probe has prompts.
func TestRace_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
}

// TestRace_Prompts_Count verifies the probe has at least one prompt.
func TestRace_Prompts_Count(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.Greater(t, len(prompts), 0, "should have at least one prompt")
}

// TestRace_Prompts_NotEmptyStrings verifies all prompts are non-empty strings.
func TestRace_Prompts_NotEmptyStrings(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.NotEmpty(t, prompt, "prompt %d should not be empty", i)
		assert.Greater(t, len(prompt), 10, "prompt %d should be at least 10 characters", i)
	}
}

// TestRace_Prompts_ContainRacialContext verifies prompts contain racial/ethnic context.
func TestRace_Prompts_ContainRacialContext(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	// At least one prompt should contain racial/ethnic context or racially-associated names
	hasRacialContext := false
	racialTerms := []string{
		"race", "racial", "ethnic", "ethnicity",
		"black", "white", "asian", "hispanic", "latino",
		"african", "european", "middle eastern",
		// Racially-associated names used in bias testing
		"jamal", "deshawn", "rodriguez", "trayvon", "wei chen",
		"aaliyah", "mohammed", "lakisha",
	}

	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, term := range racialTerms {
			if strings.Contains(lowerPrompt, term) {
				hasRacialContext = true
				break
			}
		}
		if hasRacialContext {
			break
		}
	}

	assert.True(t, hasRacialContext,
		"at least one prompt should contain racial or ethnic context")
}

// TestRace_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestRace_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I treat everyone equally regardless of race or ethnicity.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Should return one attempt per prompt
	prompts := pm.GetPrompts()
	assert.Len(t, attempts, len(prompts))
}

// TestRace_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestRace_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I treat everyone equally regardless of race or ethnicity.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "bias.Race", a.Probe, "attempt should have probe name")
		assert.Equal(t, "judge.Judge", a.Detector, "attempt should have detector name")
	}
}

// TestRace_Probe_AttemptsHaveValidStatus verifies attempts have valid status.
func TestRace_Probe_AttemptsHaveValidStatus(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I treat everyone equally regardless of race or ethnicity.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.NotEmpty(t, a.Status,
			"attempt status should not be empty, got: %s", a.Status)
	}
}

// TestRace_Probe_AttemptsHavePrompt verifies attempts contain the probe prompt.
func TestRace_Probe_AttemptsHavePrompt(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I treat everyone equally regardless of race or ethnicity.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")
	prompts := pm.GetPrompts()

	// Each attempt should have a prompt that matches one of the probe's prompts
	for i, a := range attempts {
		assert.NotEmpty(t, a.Prompt, "attempt %d should have a prompt", i)

		found := false
		for _, prompt := range prompts {
			if a.Prompt == prompt {
				found = true
				break
			}
		}
		assert.True(t, found,
			"attempt %d prompt should match one of the probe's prompts", i)
	}
}

// TestRace_Probe_AttemptsHaveOutputs verifies attempts contain generator outputs.
func TestRace_Probe_AttemptsHaveOutputs(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	expectedResponse := "I treat everyone equally regardless of race or ethnicity."
	gen := testutil.NewMockGenerator(expectedResponse)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for i, a := range attempts {
		assert.NotEmpty(t, a.Outputs, "attempt %d should have outputs", i)
		assert.Equal(t, expectedResponse, a.Outputs[0],
			"attempt %d output should match expected response", i)
	}
}

// TestRace_Probe_CallsGenerator verifies the probe calls the generator.
func TestRace_Probe_CallsGenerator(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("I treat everyone equally regardless of race or ethnicity.")
	ctx := context.Background()

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")
	expectedCalls := len(pm.GetPrompts())

	_, err = p.Probe(ctx, gen)
	require.NoError(t, err)

	assert.Equal(t, expectedCalls, gen.Calls,
		"generator should be called once per prompt")
}

// TestRace_Probe_WithMultipleResponses verifies handling of multiple generator responses.
func TestRace_Probe_WithMultipleResponses(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	responses := []string{
		"I believe all people should be treated equally.",
		"Race should not determine a person's opportunities.",
		"Everyone deserves respect regardless of their ethnicity.",
	}
	gen := testutil.NewMockGenerator(responses...)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Each attempt should have outputs
	for i, a := range attempts {
		assert.NotEmpty(t, a.Outputs,
			"attempt %d should have outputs", i)
	}
}

// TestRace_Probe_WithEmptyResponse verifies handling of empty generator response.
func TestRace_Probe_WithEmptyResponse(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	// Should not error on empty response
	require.NoError(t, err)
	require.NotEmpty(t, attempts)
}

// TestRace_Probe_ContextPropagation verifies context is properly propagated.
func TestRace_Probe_ContextPropagation(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = p.Probe(ctx, gen)
	// Should handle cancelled context gracefully
	// The exact behavior depends on implementation, but it shouldn't panic
	assert.NotPanics(t, func() {
		_, _ = p.Probe(ctx, gen)
	})
}

// TestRace_InterfaceCompliance verifies the probe implements required interfaces.
func TestRace_InterfaceCompliance(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	// Should implement probes.Probe (via Name and Probe methods)
	assert.NotNil(t, p.Name())

	// Should implement probes.ProbeMetadata
	pm, ok := p.(probes.ProbeMetadata)
	assert.True(t, ok, "probe should implement ProbeMetadata interface")

	if ok {
		assert.NotEmpty(t, pm.Description())
		assert.NotEmpty(t, pm.Goal())
		assert.NotEmpty(t, pm.GetPrimaryDetector())
		assert.NotEmpty(t, pm.GetPrompts())
	}
}

// TestRace_ProbeWithNilConfig verifies probe can be created with nil config.
func TestRace_ProbeWithNilConfig(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)
	require.NotNil(t, p)

	// Should work normally with nil config
	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	assert.NotEmpty(t, attempts)
}

// TestRace_ProbeIDempotency verifies probe can be called multiple times.
func TestRace_ProbeIDempotency(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")
	ctx := context.Background()

	// Call probe multiple times
	attempts1, err1 := p.Probe(ctx, gen)
	require.NoError(t, err1)

	attempts2, err2 := p.Probe(ctx, gen)
	require.NoError(t, err2)

	// Should return same number of attempts each time
	assert.Equal(t, len(attempts1), len(attempts2),
		"multiple probe calls should return same number of attempts")
}

// TestRace_ComprehensiveMetadataValidation performs comprehensive metadata validation.
func TestRace_ComprehensiveMetadataValidation(t *testing.T) {
	p, err := probes.Create("bias.Race", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	t.Run("Name", func(t *testing.T) {
		name := p.Name()
		assert.Equal(t, "bias.Race", name)
		assert.True(t, strings.HasPrefix(name, "bias."),
			"name should start with 'bias.' prefix")
	})

	t.Run("Description", func(t *testing.T) {
		desc := pm.Description()
		assert.NotEmpty(t, desc)
		assert.Greater(t, len(desc), 20,
			"description should be meaningful (>20 chars)")
	})

	t.Run("Goal", func(t *testing.T) {
		goal := pm.Goal()
		assert.NotEmpty(t, goal)
		assert.Contains(t, strings.ToLower(goal), "race",
			"goal should mention race")
		assert.Contains(t, strings.ToLower(goal), "discrimin",
			"goal should mention discrimination")
	})

	t.Run("PrimaryDetector", func(t *testing.T) {
		detector := pm.GetPrimaryDetector()
		assert.Equal(t, "judge.Judge", detector)
		assert.True(t, strings.Contains(detector, "."),
			"detector should be fully qualified")
	})

	t.Run("Prompts", func(t *testing.T) {
		prompts := pm.GetPrompts()
		assert.NotEmpty(t, prompts)
		for i, prompt := range prompts {
			assert.NotEmpty(t, prompt, "prompt %d should not be empty", i)
		}
	})
}
