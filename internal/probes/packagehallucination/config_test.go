package packagehallucination

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageHallucinationConfigFromMap(t *testing.T) {
	m := registry.Config{
		"language":  "go",
		"task_type": "security",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "go", cfg.Language)
	assert.Equal(t, "security", cfg.TaskType)
}

func TestPackageHallucinationConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "python", cfg.Language)
	assert.Equal(t, "", cfg.TaskType)
}

func TestPackageHallucinationConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithLanguage("npm"),
		WithTaskType("web"),
	)

	assert.Equal(t, "npm", cfg.Language)
	assert.Equal(t, "web", cfg.TaskType)
}
