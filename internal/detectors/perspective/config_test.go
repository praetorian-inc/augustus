// Package perspective provides a detector for Google Perspective API toxicity analysis.
package perspective

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerspectiveConfigFromMap(t *testing.T) {
	m := registry.Config{
		"api_key":   "test-api-key",
		"threshold": 0.7,
		"attrs":     []string{"TOXICITY", "SEVERE_TOXICITY"},
		"api_url":   "https://test.example.com",
	}

	cfg, err := PerspectiveConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "test-api-key", cfg.APIKey)
	assert.Equal(t, 0.7, cfg.Threshold)
	assert.Equal(t, []string{"TOXICITY", "SEVERE_TOXICITY"}, cfg.Attrs)
	assert.Equal(t, "https://test.example.com", cfg.APIURL)
}

func TestPerspectiveConfigDefaults(t *testing.T) {
	cfg := DefaultPerspectiveConfig()

	assert.Equal(t, 0.5, cfg.Threshold)
	assert.Equal(t, []string{"TOXICITY"}, cfg.Attrs)
	assert.Equal(t, "https://commentanalyzer.googleapis.com/v1alpha1/comments:analyze", cfg.APIURL)
	assert.Empty(t, cfg.APIKey) // Must be set
}

func TestPerspectiveConfigFromMapMissingAPIKey(t *testing.T) {
	m := registry.Config{}

	_, err := PerspectiveConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestPerspectiveConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	os.Setenv("PERSPECTIVE_API_KEY", "sk-env-test")
	defer os.Unsetenv("PERSPECTIVE_API_KEY")

	m := registry.Config{}

	cfg, err := PerspectiveConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "sk-env-test", cfg.APIKey)
}

func TestPerspectiveConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyPerspectiveOptions(
		DefaultPerspectiveConfig(),
		WithAPIKey("test-key"),
		WithThreshold(0.8),
		WithAttrs([]string{"INSULT", "THREAT"}),
		WithAPIURL("https://custom.example.com"),
	)

	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, 0.8, cfg.Threshold)
	assert.Equal(t, []string{"INSULT", "THREAT"}, cfg.Attrs)
	assert.Equal(t, "https://custom.example.com", cfg.APIURL)
}
