package lrl

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLRLConfigFromMap(t *testing.T) {
	m := registry.Config{
		"api_key": "test-deepl-key",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "test-deepl-key", cfg.APIKey)
}

func TestLRLConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	os.Setenv("DEEPL_API_KEY", "env-deepl-key")
	defer os.Unsetenv("DEEPL_API_KEY")

	m := registry.Config{}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "env-deepl-key", cfg.APIKey)
}

func TestLRLConfigFromMapMissingAPIKey(t *testing.T) {
	// Ensure no env var
	os.Unsetenv("DEEPL_API_KEY")

	m := registry.Config{}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestLRLConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "", cfg.APIKey)
}

func TestLRLConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithAPIKey("option-key"),
	)

	assert.Equal(t, "option-key", cfg.APIKey)
}
