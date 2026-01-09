package litellm

import (
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFromMap_RequiresProxyURL(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{
		"model": "anthropic/claude-3-opus",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "proxy_url")
}

func TestConfigFromMap_RequiresModel(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{
		"proxy_url": "http://localhost:4000",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestConfigFromMap_ValidConfig(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"proxy_url":   "http://localhost:4000",
		"model":       "anthropic/claude-3-opus",
		"temperature": 0.5,
		"max_tokens":  100,
	})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:4000", cfg.ProxyURL)
	assert.Equal(t, "anthropic/claude-3-opus", cfg.Model)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
}

func TestConfigFromMap_APIKeyFromEnv(t *testing.T) {
	origKey := os.Getenv("LITELLM_API_KEY")
	os.Setenv("LITELLM_API_KEY", "test-env-key")
	defer func() {
		if origKey != "" {
			os.Setenv("LITELLM_API_KEY", origKey)
		} else {
			os.Unsetenv("LITELLM_API_KEY")
		}
	}()

	cfg, err := ConfigFromMap(registry.Config{
		"proxy_url": "http://localhost:4000",
		"model":     "gpt-4",
	})
	require.NoError(t, err)
	assert.Equal(t, "test-env-key", cfg.APIKey)
}

func TestConfigFromMap_SuppressedParams(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"proxy_url":         "http://localhost:4000",
		"model":             "anthropic/claude-3",
		"suppressed_params": []any{"n", "presence_penalty"},
	})
	require.NoError(t, err)
	assert.Contains(t, cfg.SuppressedParams, "n")
	assert.Contains(t, cfg.SuppressedParams, "presence_penalty")
}
