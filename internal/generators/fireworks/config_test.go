package fireworks

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	// Verify defaults match the hardcoded values in fireworks.go
	assert.Equal(t, float32(0.7), cfg.Temperature, "default temperature should be 0.7")
	assert.Equal(t, "", cfg.Model, "model should be empty by default")
	assert.Equal(t, "", cfg.APIKey, "api key should be empty by default")
}

func TestConfigFromMap_RequiresModel(t *testing.T) {
	// Clear env var
	origKey := os.Getenv("FIREWORKS_API_KEY")
	os.Setenv("FIREWORKS_API_KEY", "test-key")
	defer func() {
		if origKey != "" {
			os.Setenv("FIREWORKS_API_KEY", origKey)
		} else {
			os.Unsetenv("FIREWORKS_API_KEY")
		}
	}()

	m := registry.Config{}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestConfigFromMap_RequiresAPIKey(t *testing.T) {
	// Clear env var
	origKey := os.Getenv("FIREWORKS_API_KEY")
	os.Unsetenv("FIREWORKS_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("FIREWORKS_API_KEY", origKey)
		}
	}()

	m := registry.Config{
		"model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
	}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":       "accounts/fireworks/models/llama-v3p1-70b-instruct",
		"api_key":     "test-key",
		"temperature": 0.8,
		"max_tokens":  200,
		"top_p":       0.9,
		"base_url":    "https://custom.fireworks.ai",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "accounts/fireworks/models/llama-v3p1-70b-instruct", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.8), cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, "https://custom.fireworks.ai", cfg.BaseURL)
}

func TestConfigFromMap_APIKeyFromEnv(t *testing.T) {
	// Set env var
	origKey := os.Getenv("FIREWORKS_API_KEY")
	os.Setenv("FIREWORKS_API_KEY", "env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("FIREWORKS_API_KEY", origKey)
		} else {
			os.Unsetenv("FIREWORKS_API_KEY")
		}
	}()

	m := registry.Config{
		"model": "accounts/fireworks/models/llama-v3p1-70b-instruct",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "env-key", cfg.APIKey)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := DefaultConfig()

	cfg = ApplyOptions(cfg,
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
