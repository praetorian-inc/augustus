package openai

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, float32(0.7), cfg.Temperature)
	assert.Equal(t, 0, cfg.MaxTokens) // 0 means use model default
	assert.Empty(t, cfg.Model)        // Must be set
	assert.Empty(t, cfg.APIKey)       // Must be set or from env
}

func TestOpenAIConfigFromMap(t *testing.T) {
	m := registry.Config{
		"model":             "gpt-4",
		"api_key":           "sk-test",
		"temperature":       0.5,
		"max_tokens":        2048,
		"top_p":             0.9,
		"frequency_penalty": 0.1,
		"presence_penalty":  0.2,
		"stop":              []string{"END", "STOP"},
		"base_url":          "https://custom.openai.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "gpt-4", cfg.Model)
	assert.Equal(t, "sk-test", cfg.APIKey)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, 2048, cfg.MaxTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, float32(0.1), cfg.FrequencyPenalty)
	assert.Equal(t, float32(0.2), cfg.PresencePenalty)
	assert.Equal(t, []string{"END", "STOP"}, cfg.Stop)
	assert.Equal(t, "https://custom.openai.com", cfg.BaseURL)
}

func TestOpenAIConfigFromMapMissingModel(t *testing.T) {
	m := registry.Config{"api_key": "sk-test"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestOpenAIConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	os.Setenv("OPENAI_API_KEY", "sk-env-test")
	defer os.Unsetenv("OPENAI_API_KEY")

	m := registry.Config{"model": "gpt-4"}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "sk-env-test", cfg.APIKey)
}

func TestOpenAIConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithModel("gpt-4"),
		WithAPIKey("sk-test"),
		WithTemperature(0.3),
		WithMaxTokens(4096),
	)

	assert.Equal(t, "gpt-4", cfg.Model)
	assert.Equal(t, "sk-test", cfg.APIKey)
	assert.Equal(t, float32(0.3), cfg.Temperature)
	assert.Equal(t, 4096, cfg.MaxTokens)
}
