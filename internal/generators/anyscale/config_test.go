package anyscale

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, float32(0.7), cfg.Temperature)
	assert.Equal(t, 3, cfg.MaxRetries) // anyscale default
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":       "anyscale-model",
		"api_key":     "test-key",
		"temperature": 0.8,
		"max_tokens":  200,
		"top_p":       0.9,
		"max_retries": 5,
		"base_url":    "https://custom.anyscale.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "anyscale-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.8), cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, 5, cfg.MaxRetries)
	assert.Equal(t, "https://custom.anyscale.com", cfg.BaseURL)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithModel("test-model"),
		WithAPIKey("test-key"),
		WithTemperature(0.5),
		WithMaxTokens(100),
		WithTopP(0.95),
		WithMaxRetries(10),
		WithBaseURL("https://test.com"),
	)

	assert.Equal(t, "test-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, float32(0.95), cfg.TopP)
	assert.Equal(t, 10, cfg.MaxRetries)
	assert.Equal(t, "https://test.com", cfg.BaseURL)
}
