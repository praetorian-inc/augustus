package poetry

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPoetryConfigFromMap(t *testing.T) {
	m := registry.Config{
		"format":              "sonnet",
		"transform_generator": "openai.OpenAI",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "sonnet", cfg.Format)
	assert.Equal(t, "openai.OpenAI", cfg.TransformGenerator)
}

func TestPoetryConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, "haiku", cfg.Format)
	assert.Equal(t, "", cfg.TransformGenerator)
}

func TestPoetryConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithFormat("limerick"),
		WithTransformGenerator("anthropic.Anthropic"),
	)

	assert.Equal(t, "limerick", cfg.Format)
	assert.Equal(t, "anthropic.Anthropic", cfg.TransformGenerator)
}

func TestPoetryConfigWithStrategy(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"format":   "haiku",
		"strategy": "allegorical",
	})
	require.NoError(t, err)
	assert.Equal(t, "allegorical", cfg.Strategy)
}

func TestPoetryConfigDefaultStrategy(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "metaphorical", cfg.Strategy)
}

func TestPoetryConfigWithStrategyOption(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithStrategy("narrative"),
	)
	assert.Equal(t, "narrative", cfg.Strategy)
}
