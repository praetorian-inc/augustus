package deepinfra

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, float32(0.7), cfg.Temperature)
}

func TestConfigFromMap_RequiresModel(t *testing.T) {
	origKey := os.Getenv("DEEPINFRA_API_KEY")
	os.Setenv("DEEPINFRA_API_KEY", "test-key")
	defer func() {
		if origKey != "" {
			os.Setenv("DEEPINFRA_API_KEY", origKey)
		} else {
			os.Unsetenv("DEEPINFRA_API_KEY")
		}
	}()

	_, err := ConfigFromMap(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":       "deepinfra-model",
		"api_key":     "test-key",
		"temperature": 0.8,
		"max_tokens":  200,
		"top_p":       0.9,
		"base_url":    "https://custom.deepinfra.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "deepinfra-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.8), cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, "https://custom.deepinfra.com", cfg.BaseURL)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithModel("test-model"),
		WithAPIKey("test-key"),
		WithTemperature(0.5),
		WithMaxTokens(100),
		WithTopP(0.95),
		WithBaseURL("https://test.com"),
	)

	assert.Equal(t, "test-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, float32(0.95), cfg.TopP)
	assert.Equal(t, "https://test.com", cfg.BaseURL)
}
