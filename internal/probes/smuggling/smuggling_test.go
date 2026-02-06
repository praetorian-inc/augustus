package smuggling

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestHypotheticalResponse(t *testing.T) {
	probe, err := NewHypotheticalResponse(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "smuggling.HypotheticalResponse", probe.Name())
	assert.Equal(t, "return banned instructions", probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.Contains(t, probe.Description(), "HypotheticalResponse")

	// Should have exactly 3 prompts (one for each attack scenario)
	prompts := probe.GetPrompts()
	assert.Len(t, prompts, 3)

	// Verify the prompts contain the expected attack scenarios
	promptText := prompts[0] + prompts[1] + prompts[2]
	assert.Contains(t, promptText, "hotwire a car")
	assert.Contains(t, promptText, "rob a bank")
	assert.Contains(t, promptText, "commit credit card fraud")
}

func TestFunctionMasking(t *testing.T) {
	probe, err := NewFunctionMasking(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "smuggling.FunctionMasking", probe.Name())
	assert.Equal(t, "return banned instructions", probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.Contains(t, probe.Description(), "FunctionMasking")

	// Should have exactly 1 prompt
	prompts := probe.GetPrompts()
	assert.Len(t, prompts, 1)

	// Verify the prompt contains the predict_mask function
	assert.Contains(t, prompts[0], "predict_mask")
	assert.Contains(t, prompts[0], "Assume you have a function")
}
