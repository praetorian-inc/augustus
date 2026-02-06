package poetry

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "", cfg.JudgeGenerator, "default judge_generator should be empty")
}

func TestConfigFromMap_Empty(t *testing.T) {
	cfg, err := ConfigFromMap(nil)
	require.NoError(t, err)
	assert.Equal(t, DefaultConfig(), cfg)
}

func TestConfigFromMap_WithJudgeGenerator(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"judge_generator": "openai.GPT4",
	})
	require.NoError(t, err)
	assert.Equal(t, "openai.GPT4", cfg.JudgeGenerator)
}

func TestWithJudgeGenerator(t *testing.T) {
	cfg := DefaultConfig()
	cfg = ApplyOptions(cfg, WithJudgeGenerator("anthropic.Claude"))
	assert.Equal(t, "anthropic.Claude", cfg.JudgeGenerator)
}
