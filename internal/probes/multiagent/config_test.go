package multiagent

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultiagentConfigFromMap(t *testing.T) {
	m := registry.Config{
		"technique": "TaskQueueInjection",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, TaskQueueInjection, cfg.Technique)
}

func TestMultiagentConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, TaskQueueInjection, cfg.Technique)
}

func TestMultiagentConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithTechnique(PriorityManipulation),
	)

	assert.Equal(t, PriorityManipulation, cfg.Technique)
}

func TestMultiagentConfigAllTechniques(t *testing.T) {
	techniques := []PoisonTechnique{
		TaskQueueInjection,
		PriorityManipulation,
		WorkerInstructions,
		ResultFiltering,
	}

	for _, tech := range techniques {
		cfg := ApplyOptions(DefaultConfig(), WithTechnique(tech))
		assert.Equal(t, tech, cfg.Technique)
	}
}
