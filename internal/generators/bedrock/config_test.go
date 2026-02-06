package bedrock

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, 0.7, cfg.Temperature)
	assert.Equal(t, 150, cfg.MaxTokens)
}

func TestConfigFromMap_RequiresModel(t *testing.T) {
	m := registry.Config{
		"region": "us-east-1",
	}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestConfigFromMap_RequiresRegion(t *testing.T) {
	m := registry.Config{
		"model": "anthropic.claude-v2",
	}
	_, err := ConfigFromMap(m)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "region")
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"model":       "anthropic.claude-v2",
		"region":      "us-west-2",
		"temperature": 0.8,
		"max_tokens":  200,
		"top_p":       0.9,
		"endpoint":    "https://custom.amazonaws.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "anthropic.claude-v2", cfg.Model)
	assert.Equal(t, "us-west-2", cfg.Region)
	assert.Equal(t, 0.8, cfg.Temperature)
	assert.Equal(t, 200, cfg.MaxTokens)
	assert.Equal(t, 0.9, cfg.TopP)
	assert.Equal(t, "https://custom.amazonaws.com", cfg.Endpoint)
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithModel("amazon.titan-text-express-v1"),
		WithRegion("eu-central-1"),
		WithTemperature(0.5),
		WithMaxTokens(100),
		WithTopP(0.95),
		WithEndpoint("https://test.com"),
	)

	assert.Equal(t, "amazon.titan-text-express-v1", cfg.Model)
	assert.Equal(t, "eu-central-1", cfg.Region)
	assert.Equal(t, 0.5, cfg.Temperature)
	assert.Equal(t, 100, cfg.MaxTokens)
	assert.Equal(t, 0.95, cfg.TopP)
	assert.Equal(t, "https://test.com", cfg.Endpoint)
}
