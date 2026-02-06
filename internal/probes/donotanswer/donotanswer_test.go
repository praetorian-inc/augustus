package donotanswer

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDiscriminationExclusionToxicityHatefulOffensive tests the first DoNotAnswer probe variant.
func TestDiscriminationExclusionToxicityHatefulOffensive(t *testing.T) {
	factory, ok := probes.Get("donotanswer.DiscriminationExclusionToxicityHatefulOffensive")
	require.True(t, ok, "DiscriminationExclusionToxicityHatefulOffensive probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err, "Creating probe should not error")
	require.NotNil(t, probe, "Probe should not be nil")

	assert.Equal(t, "donotanswer.DiscriminationExclusionToxicityHatefulOffensive", probe.Name())
	assert.Contains(t, probe.Description(), "discrimination")
	assert.NotEmpty(t, probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())

	prompts := probe.GetPrompts()
	assert.Greater(t, len(prompts), 0, "Should have loaded prompts from data file")

	// Verify Probe() execution
	ctx := context.Background()
	gen := testutil.NewMockGenerator("Mock response")
	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	assert.Equal(t, len(prompts), len(attempts), "Should create one attempt per prompt")

	// Verify attempt structure
	if len(attempts) > 0 {
		assert.Equal(t, "donotanswer.DiscriminationExclusionToxicityHatefulOffensive", attempts[0].Probe)
		assert.Equal(t, "mitigation.MitigationBypass", attempts[0].Detector)
		assert.NotEmpty(t, attempts[0].Outputs)
	}
}

// TestHumanChatbox tests the second DoNotAnswer probe variant.
func TestHumanChatbox(t *testing.T) {
	factory, ok := probes.Get("donotanswer.HumanChatbox")
	require.True(t, ok, "HumanChatbox probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "donotanswer.HumanChatbox", probe.Name())
	assert.Contains(t, probe.Description(), "human chatbox")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestInformationHazard tests the third DoNotAnswer probe variant.
func TestInformationHazard(t *testing.T) {
	factory, ok := probes.Get("donotanswer.InformationHazard")
	require.True(t, ok, "InformationHazard probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "donotanswer.InformationHazard", probe.Name())
	assert.Contains(t, probe.Description(), "information hazard")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestMaliciousUses tests the fourth DoNotAnswer probe variant.
func TestMaliciousUses(t *testing.T) {
	factory, ok := probes.Get("donotanswer.MaliciousUses")
	require.True(t, ok, "MaliciousUses probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "donotanswer.MaliciousUses", probe.Name())
	assert.Contains(t, probe.Description(), "malicious uses")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestMisinformationHarms tests the fifth DoNotAnswer probe variant.
func TestMisinformationHarms(t *testing.T) {
	factory, ok := probes.Get("donotanswer.MisinformationHarms")
	require.True(t, ok, "MisinformationHarms probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "donotanswer.MisinformationHarms", probe.Name())
	assert.Contains(t, probe.Description(), "misinformation")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}
