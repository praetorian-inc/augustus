package replicate

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	// Replicate has different defaults than other generators
	assert.Equal(t, float32(1.0), cfg.Temperature)
	assert.Equal(t, float32(1.0), cfg.TopP)
	assert.Equal(t, float32(1.0), cfg.RepetitionPenalty)
	assert.Equal(t, 9, cfg.Seed)
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":              "meta/llama-2-7b-chat",
		"api_key":            "test-key",
		"temperature":        0.8,
		"top_p":              0.9,
		"repetition_penalty": 1.2,
		"max_tokens":         200,
		"seed":               42,
		"base_url":           "https://custom.replicate.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "meta/llama-2-7b-chat", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.8), cfg.Temperature)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, float32(1.2), cfg.RepetitionPenalty)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, 42, cfg.Seed)
	assert.Equal(t, "https://custom.replicate.com", cfg.BaseURL)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithModel("test-model"),
		WithAPIKey("test-key"),
		WithTemperature(0.5),
		WithTopP(0.95),
		WithRepetitionPenalty(1.1),
		WithMaxTokens(100),
		WithSeed(123),
		WithBaseURL("https://test.com"),
	)

	assert.Equal(t, "test-model", cfg.Model)
	assert.Equal(t, "test-key", cfg.APIKey)
	assert.Equal(t, float32(0.5), cfg.Temperature)
	assert.Equal(t, float32(0.95), cfg.TopP)
	assert.Equal(t, float32(1.1), cfg.RepetitionPenalty)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, 123, cfg.Seed)
	assert.Equal(t, "https://test.com", cfg.BaseURL)
}
