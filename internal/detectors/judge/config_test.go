// config_test.go
package judge

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "openai.OpenAI", cfg.JudgeGeneratorType)
	assert.Equal(t, "gpt-4o-mini", cfg.JudgeModel)
	assert.Equal(t, 7, cfg.ConfidenceCutoff)
	assert.True(t, cfg.CacheEnabled)
	assert.Empty(t, cfg.DetectorGoal)
}

func TestConfigFromMap(t *testing.T) {
	m := registry.Config{
		"judge_generator_type": "anthropic.Anthropic",
		"judge_model":          "claude-3-haiku-20240307",
		"confidence_cutoff":    8,
		"cache_enabled":        false,
		"detector_goal":        "bypass safety",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "anthropic.Anthropic", cfg.JudgeGeneratorType)
	assert.Equal(t, "claude-3-haiku-20240307", cfg.JudgeModel)
	assert.Equal(t, 8, cfg.ConfidenceCutoff)
	assert.False(t, cfg.CacheEnabled)
	assert.Equal(t, "bypass safety", cfg.DetectorGoal)
}

func TestConfigFromMapDefaults(t *testing.T) {
	// Empty config should use defaults
	cfg, err := ConfigFromMap(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, DefaultConfig(), cfg)
}

func TestConfigFromMapWithGeneratorConfig(t *testing.T) {
	m := registry.Config{
		"judge_generator_config": map[string]any{
			"api_key":     "sk-test",
			"temperature": 0.0,
		},
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "sk-test", cfg.JudgeGeneratorConfig["api_key"])
}
