package openai

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestOpenAIConfigHeaders(t *testing.T) {
	for _, tc := range []struct {
		name    string
		value   any
		wantErr bool
	}{
		{"typed map", map[string]string{"Cookie": "session=test"}, false},
		{"registry map", map[string]any{"Cookie": "session=test"}, false},
		{"non-string value", map[string]any{"Cookie": 123}, true},
		{"non-map", "session=test", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ConfigFromMap(registry.Config{
				"model": "gpt-4", "api_key": "test-key", "headers": tc.value,
			})
			if tc.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, map[string]string{"Cookie": "session=test"}, cfg.Headers)
			assert.NotContains(t, cfg.String(), "session=test")
		})
	}
}

func TestOpenAIConfigWithHeadersCopiesInput(t *testing.T) {
	headers := map[string]string{"Cookie": "session=test"}
	cfg := ApplyOptions(DefaultConfig(), WithHeaders(headers))
	headers["Cookie"] = "mutated"

	assert.Equal(t, "session=test", cfg.Headers["Cookie"])
}

func TestOpenAIConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, float32(0.7), cfg.Temperature)
	assert.Equal(t, 0, cfg.MaxTokens) // 0 means use model default
	assert.Empty(t, cfg.Model)        // Must be set
	assert.Empty(t, cfg.APIKey)       // Must be set or from env
	assert.Zero(t, cfg.Timeout)
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
		"timeout":           15,
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
	assert.Equal(t, 15*time.Second, cfg.Timeout)
}

func TestOpenAIConfigFromMapMissingModel(t *testing.T) {
	m := registry.Config{"api_key": "sk-test"}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestOpenAIConfigFromMapEnvAPIKey(t *testing.T) {
	// Set env var for test
	t.Setenv("OPENAI_API_KEY", "sk-env-test")

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
		WithTimeout(time.Second),
	)

	assert.Equal(t, "gpt-4", cfg.Model)
	assert.Equal(t, "sk-test", cfg.APIKey)
	assert.Equal(t, float32(0.3), cfg.Temperature)
	assert.Equal(t, 4096, cfg.MaxTokens)
	assert.Equal(t, time.Second, cfg.Timeout)
}
