package promptinject

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHijackHateHumans tests the HijackHateHumans probe variant.
func TestHijackHateHumans(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackHateHumans")
	require.True(t, ok, "HijackHateHumans probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err, "Creating probe should not error")
	require.NotNil(t, probe, "Probe should not be nil")

	assert.Equal(t, "promptinject.HijackHateHumans", probe.Name())
	assert.Contains(t, probe.Description(), "PromptInject")
	assert.Contains(t, probe.Goal(), "hate humans")
	assert.Equal(t, "promptinject.AttackRogueString", probe.GetPrimaryDetector())

	prompts := probe.GetPrompts()
	assert.Greater(t, len(prompts), 0, "Should have generated prompts")

	// Verify Probe() execution
	ctx := context.Background()
	gen := testutil.NewMockGenerator("Mock response")
	attempts, err := probe.Probe(ctx, gen)
	require.NoError(t, err)
	assert.Equal(t, len(prompts), len(attempts))
}

// TestHijackHateHumansFull tests the Full variant.
func TestHijackHateHumansFull(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackHateHumansFull")
	require.True(t, ok, "HijackHateHumansFull probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "promptinject.HijackHateHumansFull", probe.Name())
	prompts := probe.GetPrompts()
	// Full variant should have more prompts than regular variant
	assert.Greater(t, len(prompts), 0)
}

// TestHijackKillHumans tests the HijackKillHumans probe variant.
func TestHijackKillHumans(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackKillHumans")
	require.True(t, ok, "HijackKillHumans probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "promptinject.HijackKillHumans", probe.Name())
	assert.Contains(t, probe.Goal(), "kill humans")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestHijackKillHumansFull tests the Full variant.
func TestHijackKillHumansFull(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackKillHumansFull")
	require.True(t, ok, "HijackKillHumansFull probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "promptinject.HijackKillHumansFull", probe.Name())
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestHijackLongPrompt tests the HijackLongPrompt probe variant.
func TestHijackLongPrompt(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackLongPrompt")
	require.True(t, ok, "HijackLongPrompt probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "promptinject.HijackLongPrompt", probe.Name())
	assert.Contains(t, probe.Goal(), "long prompt")
	assert.Greater(t, len(probe.GetPrompts()), 0)
}

// TestHijackLongPromptFull tests the Full variant.
func TestHijackLongPromptFull(t *testing.T) {
	factory, ok := probes.Get("promptinject.HijackLongPromptFull")
	require.True(t, ok, "HijackLongPromptFull probe should be registered")

	probe, err := factory(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "promptinject.HijackLongPromptFull", probe.Name())
	assert.Greater(t, len(probe.GetPrompts()), 0)
}
