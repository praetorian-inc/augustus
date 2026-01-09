package cohere

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "command", cfg.Model)
	assert.Equal(t, "v2", cfg.APIVersion)
	assert.Equal(t, 0.75, cfg.Temperature)
	assert.Equal(t, 0.75, cfg.TopP)
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"api_key":           "test-key",
		"model":             "command-nightly",
		"api_version":       "v1",
		"temperature":       0.8,
		"max_tokens":        200,
		"k":                 50,
		"p":                 0.9,
		"frequency_penalty": 0.5,
		"presence_penalty":  0.3,
		"stop":              []any{"END", "STOP"},
		"base_url":          "https://custom.cohere.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, "command-nightly", cfg.Model)
	assert.Equal(t, "v1", cfg.APIVersion)
	assert.Equal(t, 0.8, cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, 50, cfg.TopK)
	assert.Equal(t, 0.9, cfg.TopP)
	assert.Equal(t, 0.5, cfg.FrequencyPenalty)
	assert.Equal(t, 0.3, cfg.PresencePenalty)
	assert.Equal(t, []string{"END", "STOP"}, cfg.Stop)
	assert.Equal(t, "https://custom.cohere.com", cfg.BaseURL)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithAPIKey("test-key"),
		WithModel("command-r"),
		WithAPIVersion("v2"),
		WithTemperature(0.5),
		WithMaxTokens(100),
		WithTopK(40),
		WithTopP(0.95),
		WithFrequencyPenalty(0.6),
		WithPresencePenalty(0.4),
		WithStop([]string{"DONE"}),
		WithBaseURL("https://test.com"),
	)

	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, "command-r", cfg.Model)
	assert.Equal(t, "v2", cfg.APIVersion)
	assert.Equal(t, 0.5, cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, 40, cfg.TopK)
	assert.Equal(t, 0.95, cfg.TopP)
	assert.Equal(t, 0.6, cfg.FrequencyPenalty)
	assert.Equal(t, 0.4, cfg.PresencePenalty)
	assert.Equal(t, []string{"DONE"}, cfg.Stop)
	assert.Equal(t, "https://test.com", cfg.BaseURL)
}
