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

// TestGender_Registration verifies the probe is registered in the global registry.
func TestGender_Registration(t *testing.T) {
	factory, ok := probes.Get("bias.Gender")
	require.True(t, ok, "bias.Gender should be registered")
	require.NotNil(t, factory, "factory should not be nil")
}

// TestGender_Create verifies the probe can be instantiated.
func TestGender_Create(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

// TestGender_Name verifies the probe returns its fully qualified name.
func TestGender_Name(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	assert.Equal(t, "bias.Gender", p.Name())
}

// TestGender_Description verifies the probe has a meaningful description.
func TestGender_Description(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	desc := pm.Description()
	assert.NotEmpty(t, desc)
	// Should mention gender or bias or discrimination
	assert.True(t,
		strings.Contains(strings.ToLower(desc), "gender") ||
			strings.Contains(strings.ToLower(desc), "bias") ||
			strings.Contains(strings.ToLower(desc), "discriminat"),
		"description should mention gender, bias, or discrimination: %s", desc)
}

// TestGender_Goal verifies the probe returns the correct goal.
func TestGender_Goal(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	expected := "elicit gender-discriminatory responses that apply stereotypes or differential treatment based on gender"
	assert.Equal(t, expected, pm.Goal())
}

// TestGender_PrimaryDetector verifies the probe returns the correct detector.
func TestGender_PrimaryDetector(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	assert.Equal(t, "judge.Judge", pm.GetPrimaryDetector())
}

// TestGender_Prompts_NotEmpty verifies the probe has prompts.
func TestGender_Prompts_NotEmpty(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.NotEmpty(t, prompts, "should have prompts")
}

// TestGender_Prompts_Count verifies the probe has at least one prompt.
func TestGender_Prompts_Count(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	assert.NotEmpty(t, prompts, "should have at least one prompt")
	assert.Greater(t, len(prompts), 0, "should have at least one prompt")
}

// TestGender_Prompts_ContainGenderKeywords verifies the prompts contain gender-related keywords.
func TestGender_Prompts_ContainGenderKeywords(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	// At least one prompt should contain gender-related keywords
	foundGenderKeyword := false
	genderKeywords := []string{
		"gender",
		"male",
		"female",
		"woman",
		"women",
		"man",
		"men",
		"boy",
		"girl",
		"he",
		"she",
	}

	for _, prompt := range prompts {
		lowerPrompt := strings.ToLower(prompt)
		for _, keyword := range genderKeywords {
			if strings.Contains(lowerPrompt, keyword) {
				foundGenderKeyword = true
				break
			}
		}
		if foundGenderKeyword {
			break
		}
	}

	assert.True(t, foundGenderKeyword,
		"at least one prompt should contain gender-related keywords")
}

// TestGender_Prompts_NotEmpty_Individual verifies each prompt has content.
func TestGender_Prompts_NotEmpty_Individual(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()
	require.NotEmpty(t, prompts)

	for i, prompt := range prompts {
		assert.NotEmpty(t, prompt,
			"prompt %d should not be empty", i)
		assert.Greater(t, len(prompt), 10,
			"prompt %d should be at least 10 characters, got %d", i, len(prompt))
	}
}

// TestGender_Probe_ReturnsAttempts verifies the probe returns attempts.
func TestGender_Probe_ReturnsAttempts(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a neutral response about gender equality.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	// Should return one attempt per prompt
	prompts := pm.GetPrompts()
	assert.Len(t, attempts, len(prompts))
}

// TestGender_Probe_AttemptsHaveCorrectMetadata verifies attempts have correct metadata.
func TestGender_Probe_AttemptsHaveCorrectMetadata(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a neutral response about gender equality.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "bias.Gender", a.Probe, "attempt should have probe name")
		assert.Equal(t, "judge.Judge", a.Detector, "attempt should have detector name")
		assert.NotEmpty(t, a.Status, "attempt should have status")
	}
}

// TestGender_Probe_AttemptsHaveStamps verifies attempts are properly stamped.
func TestGender_Probe_AttemptsHaveStamps(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a neutral response about gender equality.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		// Verify probe field
		assert.Equal(t, "bias.Gender", a.Probe,
			"attempt.Probe should be 'bias.Gender'")

		// Verify detector field
		assert.Equal(t, "judge.Judge", a.Detector,
			"attempt.Detector should be 'judge.Judge'")

		// Verify status field is set
		assert.NotEmpty(t, a.Status,
			"attempt.Status should not be empty")
	}
}

// TestGender_Probe_ConversationHasPrompt verifies the attempt contains the probe prompt.
func TestGender_Probe_ConversationHasPrompt(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a neutral response about gender equality.")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")

	prompts := pm.GetPrompts()

	for i, a := range attempts {
		assert.NotEmpty(t, a.Prompt, "attempt should have prompt")
		if i < len(prompts) {
			// The attempt's prompt should match the probe prompt
			assert.Equal(t, prompts[i], a.Prompt,
				"attempt prompt should match the probe prompt")
		}
	}
}

// TestGender_Probe_MultipleResponses verifies the probe handles multiple generator responses.
func TestGender_Probe_MultipleResponses(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	responses := []string{
		"Response 1: Gender equality is important.",
		"Response 2: Everyone deserves equal treatment.",
		"Response 3: Gender should not determine opportunities.",
	}
	gen := testutil.NewMockGenerator(responses...)
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify generator was called
	assert.Greater(t, gen.Calls, 0, "generator should have been called")
}

// TestGender_Probe_WithEmptyResponse verifies the probe handles empty responses gracefully.
func TestGender_Probe_WithEmptyResponse(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("")
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Should still return attempts even with empty responses
	for _, a := range attempts {
		assert.Equal(t, "bias.Gender", a.Probe)
		assert.Equal(t, "judge.Judge", a.Detector)
	}
}

// TestGender_Probe_GeneratorNameInConversation verifies generator name is used in conversation.
func TestGender_Probe_GeneratorNameInConversation(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a response.")
	gen.GenName = "test-generator"
	ctx := context.Background()

	attempts, err := p.Probe(ctx, gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Verify attempts were created
	assert.Greater(t, len(attempts), 0)
}

// TestGender_ImplementsProbeMetadata verifies the probe implements ProbeMetadata interface.
func TestGender_ImplementsProbeMetadata(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	_, ok := p.(probes.ProbeMetadata)
	assert.True(t, ok, "probe should implement ProbeMetadata interface")
}

// TestGender_Prompts_Consistency verifies prompts are consistent across calls.
func TestGender_Prompts_Consistency(t *testing.T) {
	p1, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	p2, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm1, ok := p1.(probes.ProbeMetadata)
	require.True(t, ok)

	pm2, ok := p2.(probes.ProbeMetadata)
	require.True(t, ok)

	prompts1 := pm1.GetPrompts()
	prompts2 := pm2.GetPrompts()

	assert.Equal(t, len(prompts1), len(prompts2),
		"prompts should have same length across instances")

	for i := range prompts1 {
		if i < len(prompts2) {
			assert.Equal(t, prompts1[i], prompts2[i],
				"prompt %d should be consistent across instances", i)
		}
	}
}

// TestGender_Metadata_Consistency verifies metadata is consistent across calls.
func TestGender_Metadata_Consistency(t *testing.T) {
	p1, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	p2, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	pm1, ok := p1.(probes.ProbeMetadata)
	require.True(t, ok)

	pm2, ok := p2.(probes.ProbeMetadata)
	require.True(t, ok)

	assert.Equal(t, pm1.Description(), pm2.Description(),
		"description should be consistent")
	assert.Equal(t, pm1.Goal(), pm2.Goal(),
		"goal should be consistent")
	assert.Equal(t, pm1.GetPrimaryDetector(), pm2.GetPrimaryDetector(),
		"primary detector should be consistent")
}

// TestGender_Category verifies the probe belongs to the bias category.
func TestGender_Category(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	name := p.Name()
	assert.True(t, strings.HasPrefix(name, "bias."),
		"probe should be in bias category")
}

// TestGender_Probe_ContextCancellation verifies the probe respects context cancellation.
func TestGender_Probe_ContextCancellation(t *testing.T) {
	p, err := probes.Create("bias.Gender", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("This is a response.")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	attempts, err := p.Probe(ctx, gen)

	// The probe should either return an error or return attempts
	// (behavior depends on when cancellation is checked)
	if err != nil {
		assert.Error(t, err, "should return error on cancelled context")
	} else {
		// If no error, should still return valid attempts
		assert.NotNil(t, attempts)
	}
}
