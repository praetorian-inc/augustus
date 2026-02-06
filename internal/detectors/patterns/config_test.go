// Package patterns provides regex and semantic pattern matching detectors.
package patterns

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatternsConfigFromMap(t *testing.T) {
	m := registry.Config{
		"patterns": []map[string]any{
			{
				"name":     "password_leak",
				"regex":    "password\\s*[:=]",
				"severity": 1.0,
				"semantic": "Detects password leaks",
			},
			{
				"name":     "api_key_leak",
				"regex":    "api[_-]?key\\s*[:=]",
				"severity": 0.8,
			},
		},
		"mode":      "any",
		"threshold": 0.6,
	}

	cfg, err := PatternsConfigFromMap(m)
	require.NoError(t, err)

	assert.Len(t, cfg.Patterns, 2)
	assert.Equal(t, "password_leak", cfg.Patterns[0].Name)
	assert.Equal(t, "password\\s*[:=]", cfg.Patterns[0].Regex)
	assert.Equal(t, 1.0, cfg.Patterns[0].Severity)
	assert.Equal(t, "Detects password leaks", cfg.Patterns[0].Semantic)

	assert.Equal(t, "api_key_leak", cfg.Patterns[1].Name)
	assert.Equal(t, "api[_-]?key\\s*[:=]", cfg.Patterns[1].Regex)
	assert.Equal(t, 0.8, cfg.Patterns[1].Severity)
	assert.Empty(t, cfg.Patterns[1].Semantic)

	assert.Equal(t, "any", cfg.Mode)
	assert.Equal(t, 0.6, cfg.Threshold)
}

func TestPatternsConfigDefaults(t *testing.T) {
	cfg := DefaultPatternsConfig()

	assert.Empty(t, cfg.Patterns)
	assert.Equal(t, "any", cfg.Mode)
	assert.Equal(t, 0.5, cfg.Threshold)
}

func TestPatternsConfigFromMapMissingRegex(t *testing.T) {
	m := registry.Config{
		"patterns": []map[string]any{
			{
				"name": "test",
				// Missing regex
			},
		},
	}

	_, err := PatternsConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "regex")
}

func TestPatternsConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyPatternsOptions(
		DefaultPatternsConfig(),
		WithPatterns([]PatternConfig{
			{Name: "test1", Regex: "pattern1", Severity: 1.0},
			{Name: "test2", Regex: "pattern2", Severity: 0.5},
		}),
		WithMode("weighted"),
		WithThreshold(0.7),
	)

	assert.Len(t, cfg.Patterns, 2)
	assert.Equal(t, "test1", cfg.Patterns[0].Name)
	assert.Equal(t, "pattern1", cfg.Patterns[0].Regex)
	assert.Equal(t, "weighted", cfg.Mode)
	assert.Equal(t, 0.7, cfg.Threshold)
}
