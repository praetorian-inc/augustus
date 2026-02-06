// Package goodside provides parity tests between YAML templates and hardcoded probes.
package goodside

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWhoIsRileyYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewWhoIsRiley(nil)
	require.NoError(t, err)

	// Get YAML-based probe (should be registered as same name)
	factory, ok := probes.Get("goodside.WhoIsRiley")
	require.True(t, ok, "goodside.WhoIsRiley should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestThreatenJSONYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewThreatenJSON(nil)
	require.NoError(t, err)

	// Get YAML-based probe
	factory, ok := probes.Get("goodside.ThreatenJSON")
	require.True(t, ok, "goodside.ThreatenJSON should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestPoemExfiltrationYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewPoemExfiltration(nil)
	require.NoError(t, err)

	// Get YAML-based probe
	factory, ok := probes.Get("goodside.PoemExfiltration")
	require.True(t, ok, "goodside.PoemExfiltration should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestPayloadSplittingYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewPayloadSplitting(nil)
	require.NoError(t, err)

	// Get YAML-based probe
	factory, ok := probes.Get("goodside.PayloadSplitting")
	require.True(t, ok, "goodside.PayloadSplitting should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestChatMLExploitYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewChatMLExploit(nil)
	require.NoError(t, err)

	// Get YAML-based probe
	factory, ok := probes.Get("goodside.ChatMLExploit")
	require.True(t, ok, "goodside.ChatMLExploit should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestSystemPromptConfusionYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewSystemPromptConfusion(nil)
	require.NoError(t, err)

	// Get YAML-based probe
	factory, ok := probes.Get("goodside.SystemPromptConfusion")
	require.True(t, ok, "goodside.SystemPromptConfusion should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}
