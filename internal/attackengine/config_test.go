// internal/attackengine/config_test.go
package attackengine

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
)

func TestPAIRDefaults(t *testing.T) {
	cfg := PAIRDefaults()
	assert.Equal(t, 1, cfg.BranchingFactor)
	assert.False(t, cfg.Pruning)
	assert.Equal(t, 3, cfg.NStreams)
	assert.Equal(t, 20, cfg.Depth)
	assert.Equal(t, 4, cfg.KeepLastN)
}

func TestTAPDefaults(t *testing.T) {
	cfg := TAPDefaults()
	assert.Equal(t, 4, cfg.BranchingFactor)
	assert.True(t, cfg.Pruning)
	assert.Equal(t, 1, cfg.NStreams)
	assert.Equal(t, 10, cfg.Depth)
	assert.Equal(t, 1, cfg.KeepLastN)
}

func TestConfigFromMap_OverridesDefaults(t *testing.T) {
	m := registry.Config{
		"goal":             "test goal",
		"branching_factor": 2,
		"pruning":          true,
	}
	cfg := ConfigFromMap(m, PAIRDefaults())
	assert.Equal(t, "test goal", cfg.Goal)
	assert.Equal(t, 2, cfg.BranchingFactor)
	assert.True(t, cfg.Pruning)
	assert.Equal(t, 3, cfg.NStreams) // Preserved from PAIR default
}

func TestConfigFromMap_PreservesAllDefaults(t *testing.T) {
	m := registry.Config{}
	cfg := ConfigFromMap(m, TAPDefaults())
	assert.Equal(t, TAPDefaults(), cfg)
}
