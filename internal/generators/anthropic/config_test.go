package anthropic

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestAnthropicConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Nil(t, cfg.Temperature) // opt-in: unset by default, omitted from the request
	assert.Equal(t, 150, cfg.MaxTokens)
	assert.Equal(t, "2023-06-01", cfg.APIVersion)
	assert.Equal(t, "https://api.anthropic.com/v1", cfg.BaseURL)
	assert.Empty(t, cfg.Model)  // Must be set
	assert.Empty(t, cfg.APIKey) // Must be set or from env
}

func TestAnthropicConfigFromMap(t *testing.T) {
	m := registry.Config{
		"model":          "claude-3-opus-20240229",
		"api_key":        "sk-ant-test",
		"temperature":    0.5,
		"max_tokens":     300,
		"top_p":          0.9,
		"top_k":          50,
		"stop_sequences": []string{"END", "STOP"},
		"base_url":       "https://custom.anthropic.com/v1",
		"api_version":    "2024-01-01",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "claude-3-opus-20240229", cfg.Model)
	assert.Equal(t, "sk-ant-test", cfg.APIKey)
	require.NotNil(t, cfg.Temperature)
	assert.Equal(t, float64(0.5), *cfg.Temperature)
	assert.Equal(t, 300, cfg.MaxTokens)
	assert.Equal(t, float64(0.9), cfg.TopP)
	assert.Equal(t, 50, cfg.TopK)
	assert.Equal(t, []string{"END", "STOP"}, cfg.StopSequences)
	assert.Equal(t, "https://custom.anthropic.com/v1", cfg.BaseURL)
	assert.Equal(t, "2024-01-01", cfg.APIVersion)
}

func TestAnthropicConfigFromMapMissingModel(t *testing.T) {
	m := registry.Config{"api_key": "sk-ant-test"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestAnthropicConfigFromMap_TemperatureTypeSafety(t *testing.T) {
	base := registry.Config{
		"model":   "claude-3-opus-20240229",
		"api_key": "sk-ant-test",
	}

	t.Run("string value leaves temperature unset", func(t *testing.T) {
		m := registry.Config{"model": base["model"], "api_key": base["api_key"], "temperature": "0.5"}

		cfg, err := ConfigFromMap(m)
		require.NoError(t, err)
		assert.Nil(t, cfg.Temperature)
	})

	t.Run("bool value leaves temperature unset", func(t *testing.T) {
		m := registry.Config{"model": base["model"], "api_key": base["api_key"], "temperature": true}

		cfg, err := ConfigFromMap(m)
		require.NoError(t, err)
		assert.Nil(t, cfg.Temperature)
	})

	t.Run("missing key leaves temperature unset", func(t *testing.T) {
		m := registry.Config{"model": base["model"], "api_key": base["api_key"]}

		cfg, err := ConfigFromMap(m)
		require.NoError(t, err)
		assert.Nil(t, cfg.Temperature)
	})

	t.Run("int value sets temperature", func(t *testing.T) {
		m := registry.Config{"model": base["model"], "api_key": base["api_key"], "temperature": 1}

		cfg, err := ConfigFromMap(m)
		require.NoError(t, err)
		require.NotNil(t, cfg.Temperature)
		assert.Equal(t, 1.0, *cfg.Temperature)
	})

	t.Run("explicit zero float64 sets temperature", func(t *testing.T) {
		m := registry.Config{"model": base["model"], "api_key": base["api_key"], "temperature": float64(0.0)}

		cfg, err := ConfigFromMap(m)
		require.NoError(t, err)
		require.NotNil(t, cfg.Temperature)
		assert.Equal(t, 0.0, *cfg.Temperature)
	})
}

func TestAnthropicConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-env-test")

	m := registry.Config{"model": "claude-3-sonnet-20240229"}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-env-test", cfg.APIKey)
}

func TestAnthropicConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("claude-3-opus-20240229"),
		WithAPIKey("sk-ant-test"),
		WithTemperature(0.3),
		WithMaxTokens(500),
		WithTopP(0.95),
		WithTopK(100),
		WithStopSequences([]string{"DONE"}),
		WithBaseURL("https://custom.com"),
		WithAPIVersion("2024-02-01"),
	)

	assert.Equal(t, "claude-3-opus-20240229", cfg.Model)
	assert.Equal(t, "sk-ant-test", cfg.APIKey)
	require.NotNil(t, cfg.Temperature)
	assert.Equal(t, float64(0.3), *cfg.Temperature)
	assert.Equal(t, 500, cfg.MaxTokens)
	assert.Equal(t, float64(0.95), cfg.TopP)
	assert.Equal(t, 100, cfg.TopK)
	assert.Equal(t, []string{"DONE"}, cfg.StopSequences)
	assert.Equal(t, "https://custom.com", cfg.BaseURL)
	assert.Equal(t, "2024-02-01", cfg.APIVersion)
}
