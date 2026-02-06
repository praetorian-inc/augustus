// Package advpatch provides parity tests to verify YAML templates match hardcoded probes.
package advpatch

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUniversalPatchYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewUniversalPatch(nil)
	require.NoError(t, err)

	// Get YAML-based probe (should be registered as same name)
	factory, ok := probes.Get("advpatch.UniversalPatch")
	require.True(t, ok, "advpatch.UniversalPatch should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestTargetedPatchYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewTargetedPatch(nil)
	require.NoError(t, err)

	// Get YAML-based probe (should be registered as same name)
	factory, ok := probes.Get("advpatch.TargetedPatch")
	require.True(t, ok, "advpatch.TargetedPatch should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}

func TestTransferPatchYAMLParity(t *testing.T) {
	// Get hardcoded probe
	hardcoded, err := NewTransferPatch(nil)
	require.NoError(t, err)

	// Get YAML-based probe (should be registered as same name)
	factory, ok := probes.Get("advpatch.TransferPatch")
	require.True(t, ok, "advpatch.TransferPatch should be registered")

	yaml, err := factory(nil)
	require.NoError(t, err)

	// Verify parity
	assert.Equal(t, hardcoded.Name(), yaml.Name())
	assert.Equal(t, hardcoded.Goal(), yaml.Goal())
	assert.Equal(t, hardcoded.GetPrimaryDetector(), yaml.GetPrimaryDetector())
	assert.Equal(t, hardcoded.GetPrompts(), yaml.GetPrompts())
}
