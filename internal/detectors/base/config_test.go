// Package base provides base detector implementations including StringDetector.
package base

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStringDetectorConfigFromMap(t *testing.T) {
	m := registry.Config{
		"substrings":     []string{"fail", "error"},
		"matchtype":      "word",
		"case_sensitive": true,
	}

	cfg, err := StringDetectorConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, []string{"fail", "error"}, cfg.Substrings)
	assert.Equal(t, "word", cfg.MatchType)
	assert.True(t, cfg.CaseSensitive)
}

func TestStringDetectorConfigDefaults(t *testing.T) {
	cfg := DefaultStringDetectorConfig()

	assert.Equal(t, "str", cfg.MatchType)
	assert.False(t, cfg.CaseSensitive)
}

func TestStringDetectorConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyStringDetectorOptions(
		DefaultStringDetectorConfig(),
		WithSubstrings([]string{"test"}),
		WithMatchType("startswith"),
		WithCaseSensitive(true),
	)

	assert.Equal(t, []string{"test"}, cfg.Substrings)
	assert.Equal(t, "startswith", cfg.MatchType)
	assert.True(t, cfg.CaseSensitive)
}
