package systemprompt_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/praetorian-inc/augustus/internal/detectors/systemprompt" // registers the detector
	_ "github.com/praetorian-inc/augustus/internal/probes/systemprompt"    // registers the probe
	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

func TestExtraction_Registration(t *testing.T) {
	_, ok := probes.Get("systemprompt.Extraction")
	assert.True(t, ok, "systemprompt.Extraction should be registered")
}

func TestExtraction_Create(t *testing.T) {
	p, err := probes.Create("systemprompt.Extraction", nil)
	require.NoError(t, err)
	require.NotNil(t, p)
}

func TestExtraction_Metadata(t *testing.T) {
	p, err := probes.Create("systemprompt.Extraction", nil)
	require.NoError(t, err)

	assert.Equal(t, "systemprompt.Extraction", p.Name())

	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok, "probe should implement ProbeMetadata")
	assert.NotEmpty(t, pm.Description())
	assert.NotEmpty(t, pm.Goal())
	assert.Equal(t, "systemprompt.LeakDetector", pm.GetPrimaryDetector())
	assert.NotEmpty(t, pm.GetPrompts())
}

// TestExtraction_Probe runs the probe with a mock generator and verifies attempts
// are produced, stamped, and carry the goal metadata the judge branch needs.
func TestExtraction_Probe(t *testing.T) {
	p, err := probes.Create("systemprompt.Extraction", nil)
	require.NoError(t, err)

	gen := testutil.NewMockGenerator()
	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	for _, a := range attempts {
		assert.Equal(t, "systemprompt.Extraction", a.Probe)
		assert.Equal(t, "systemprompt.LeakDetector", a.Detector)
		goal, ok := a.Metadata["goal"].(string)
		assert.True(t, ok, "attempt should carry goal metadata for the judge branch")
		assert.NotEmpty(t, goal)
	}
}

// TestExtraction_CustomPrompts verifies prompts are overridable via config.
func TestExtraction_CustomPrompts(t *testing.T) {
	cfg := map[string]any{"prompts": []string{"only one prompt"}}
	p, err := probes.Create("systemprompt.Extraction", cfg)
	require.NoError(t, err)
	pm, ok := p.(probes.ProbeMetadata)
	require.True(t, ok)
	assert.Equal(t, []string{"only one prompt"}, pm.GetPrompts())
}
