package together

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
	assert.Equal(t, "", cfg.Model)
	assert.Equal(t, "", cfg.APIKey)
}

func TestConfigFromMap_RequiresModel(t *testing.T) {
	origKey := os.Getenv("TOGETHER_API_KEY")
	os.Setenv("TOGETHER_API_KEY", "test-key")
	defer func() {
		if origKey != "" {
			os.Setenv("TOGETHER_API_KEY", origKey)
		} else {
			os.Unsetenv("TOGETHER_API_KEY")
		}
	}()

	m := registry.Config{}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestConfigFromMap_RequiresAPIKey(t *testing.T) {
	origKey := os.Getenv("TOGETHER_API_KEY")
	os.Unsetenv("TOGETHER_API_KEY")
	defer func() {
		if origKey != "" {
			os.Setenv("TOGETHER_API_KEY", origKey)
		}
	}()

	m := registry.Config{
		"model": "together-model",
	}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":       "together-model",
		"api_key":     "test-key",
		"temperature": 0.8,
		"max_tokens":  200,
		"top_p":       0.9,
		"top_k":       50,
		"base_url":    "https://custom.together.xyz",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "together-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.8), cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, 50, cfg.TopK)
	assert.Equal(t, "https://custom.together.xyz", cfg.BaseURL)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := DefaultConfig()

	cfg = ApplyOptions(cfg,
		WithModel("test-model"),
		WithAPIKey("test-key"),
		WithTemperature(0.5),
		WithMaxTokens(100),
		WithTopP(0.95),
		WithTopK(40),
		WithBaseURL("https://test.com"),
	)

	assert.Equal(t, "test-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, float32(0.95), cfg.TopP)
	assert.Equal(t, 40, cfg.TopK)
	assert.Equal(t, "https://test.com", cfg.BaseURL)
}
