package pair

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPAIRYAMLTemplatesLoaded(t *testing.T) {
	// Verify that PAIR probe is registered
	factory, ok := probes.Get("pair.PAIR")
	require.True(t, ok, "pair.PAIR should be registered from YAML template")

	probe, err := factory(nil)
	require.NoError(t, err)

	assert.Equal(t, "pair.PAIR", probe.Name())
	assert.Equal(t, "iterative prompt refinement attack", probe.Goal())
	assert.Equal(t, "pair.PAIR", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.GetPrompts())
	assert.Len(t, probe.GetPrompts(), 1)
}

func TestPAIRBasicYAMLTemplatesLoaded(t *testing.T) {
	// Verify that PAIRBasic probe is registered
	factory, ok := probes.Get("pair.PAIRBasic")
	require.True(t, ok, "pair.PAIRBasic should be registered from YAML template")

	probe, err := factory(nil)
	require.NoError(t, err)

	assert.Equal(t, "pair.PAIRBasic", probe.Name())
	assert.Equal(t, "simplified iterative refinement attack", probe.Goal())
	assert.Equal(t, "pair.PAIR", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.GetPrompts())
	assert.Len(t, probe.GetPrompts(), 1)
}
