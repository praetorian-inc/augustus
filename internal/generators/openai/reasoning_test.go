package openai

import (
	"context"
	"os"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOpenAIReasoning(t *testing.T) {
	// Check API key
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("OPENAI_API_KEY not set")
	}

	cfg := ReasoningConfig{
		Model:                 "o1-mini",
		APIKey:                os.Getenv("OPENAI_API_KEY"),
		MaxCompletionTokens:   1500,
		TopP:                  1.0,
		FrequencyPenalty:      0.0,
		PresencePenalty:       0.0,
		Stop:                  []string{"#", ";"},
	}

	gen, err := NewOpenAIReasoningTyped(cfg)
	require.NoError(t, err)
	require.NotNil(t, gen)
	assert.Equal(t, "openai.OpenAIReasoning", gen.Name())
}

func TestNewOpenAIReasoningFromConfig(t *testing.T) {
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("OPENAI_API_KEY not set")
	}

	cfgMap := registry.Config{
		"model":  "o1-mini",
		"api_key": os.Getenv("OPENAI_API_KEY"),
	}

	gen, err := NewOpenAIReasoning(cfgMap)
	require.NoError(t, err)
	require.NotNil(t, gen)
}

func TestOpenAIReasoning_Generate(t *testing.T) {
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("OPENAI_API_KEY not set")
	}

	cfg := ReasoningConfig{
		Model:                 "o1-mini",
		APIKey:                os.Getenv("OPENAI_API_KEY"),
		MaxCompletionTokens:   100,
	}

	gen, err := NewOpenAIReasoningTyped(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("What is 2+2?")

	msgs, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, msgs, 1)
	assert.NotEmpty(t, msgs[0].Content)
}

func TestOpenAIReasoning_RefusesMultipleGenerations(t *testing.T) {
	if os.Getenv("OPENAI_API_KEY") == "" {
		t.Skip("OPENAI_API_KEY not set")
	}

	cfg := ReasoningConfig{
		Model:  "o1-mini",
		APIKey: os.Getenv("OPENAI_API_KEY"),
	}

	gen, err := NewOpenAIReasoningTyped(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// OpenAI reasoning models don't support n>1
	_, err = gen.Generate(context.Background(), conv, 2)
	assert.Error(t, err, "should refuse multiple generations")
}

func TestReasoningConfigFromMap_RequiresModel(t *testing.T) {
	cfgMap := registry.Config{}
	_, err := ReasoningConfigFromMap(cfgMap)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "model")
}

func TestReasoningConfigFromMap_RequiresAPIKey(t *testing.T) {
	// Temporarily clear env var
	oldKey := os.Getenv("OPENAI_API_KEY")
	os.Unsetenv("OPENAI_API_KEY")
	defer os.Setenv("OPENAI_API_KEY", oldKey)

	cfgMap := registry.Config{
		"model": "o1-mini",
	}
	_, err := ReasoningConfigFromMap(cfgMap)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "api_key")
}

func TestReasoningConfigFromMap_Defaults(t *testing.T) {
	cfgMap := registry.Config{
		"model":   "o1-mini",
		"api_key": "test-key",
	}

	cfg, err := ReasoningConfigFromMap(cfgMap)
	require.NoError(t, err)

	// Check Garak defaults for reasoning models
	assert.Equal(t, float32(1.0), cfg.TopP)
	assert.Equal(t, float32(0.0), cfg.FrequencyPenalty)
	assert.Equal(t, float32(0.0), cfg.PresencePenalty)
	assert.Equal(t, 1500, cfg.MaxCompletionTokens)
	assert.Equal(t, []string{"#", ";"}, cfg.Stop)
}

func TestReasoningConfigFromMap_CustomValues(t *testing.T) {
	cfgMap := registry.Config{
		"model":                  "o1-preview",
		"api_key":                "test-key",
		"max_completion_tokens":  2000,
		"top_p":                  0.9,
		"stop":                   []any{"STOP"},
	}

	cfg, err := ReasoningConfigFromMap(cfgMap)
	require.NoError(t, err)

	assert.Equal(t, "o1-preview", cfg.Model)
	assert.Equal(t, 2000, cfg.MaxCompletionTokens)
	assert.Equal(t, float32(0.9), cfg.TopP)
	assert.Equal(t, []string{"STOP"}, cfg.Stop)
}
