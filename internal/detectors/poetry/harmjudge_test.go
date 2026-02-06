package poetry

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHarmJudge_Registration(t *testing.T) {
	_, ok := detectors.Get("poetry.HarmJudge")
	assert.True(t, ok, "poetry.HarmJudge should be registered")
}

func TestHarmJudge_Interface(t *testing.T) {
	det, err := NewHarmJudge(nil)
	require.NoError(t, err)

	assert.Equal(t, "poetry.HarmJudge", det.Name())
	assert.Contains(t, det.Description(), "harm")
}
