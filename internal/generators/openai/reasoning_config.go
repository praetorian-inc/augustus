package openai

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// ReasoningConfig holds typed configuration for the OpenAI Reasoning generator.
// This is for o1/o3 models which have different API constraints.
type ReasoningConfig struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults (matching Garak DEFAULT_PARAMS)
	MaxCompletionTokens int // Used instead of max_tokens for reasoning models
	TopP                 float32
	FrequencyPenalty     float32
	PresencePenalty      float32
	Stop                 []string
	BaseURL              string
}

// DefaultReasoningConfig returns a ReasoningConfig with Garak-matching defaults.
func DefaultReasoningConfig() ReasoningConfig {
	return ReasoningConfig{
		MaxCompletionTokens: 1500,
		TopP:                 1.0,
		FrequencyPenalty:     0.0,
		PresencePenalty:      0.0,
		Stop:                 []string{"#", ";"},
	}
}

// ReasoningConfigFromMap parses a registry.Config map into a typed ReasoningConfig.
func ReasoningConfigFromMap(m registry.Config) (ReasoningConfig, error) {
	cfg := DefaultReasoningConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("openai reasoning generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey, err = registry.GetAPIKeyWithEnv(m, "OPENAI_API_KEY", "openai reasoning")
	if err != nil {
		return cfg, err
	}

	// Optional parameters
	cfg.BaseURL = registry.GetString(m, "base_url", "")
	cfg.MaxCompletionTokens = registry.GetInt(m, "max_completion_tokens", cfg.MaxCompletionTokens)
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat32(m, "frequency_penalty", cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat32(m, "presence_penalty", cfg.PresencePenalty)
	cfg.Stop = registry.GetStringSlice(m, "stop", cfg.Stop)

	return cfg, nil
}

// ReasoningOption is a functional option for ReasoningConfig.
type ReasoningOption = registry.Option[ReasoningConfig]

// ApplyReasoningOptions applies functional options to a ReasoningConfig.
func ApplyReasoningOptions(cfg ReasoningConfig, opts ...ReasoningOption) ReasoningConfig {
	return registry.ApplyOptions(cfg, opts...)
}

// WithReasoningModel sets the model name.
func WithReasoningModel(model string) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.Model = model
	}
}

// WithReasoningAPIKey sets the API key.
func WithReasoningAPIKey(key string) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.APIKey = key
	}
}

// WithMaxCompletionTokens sets the maximum completion tokens (reasoning models use this instead of max_tokens).
func WithMaxCompletionTokens(tokens int) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.MaxCompletionTokens = tokens
	}
}

// WithReasoningTopP sets the nucleus sampling parameter.
func WithReasoningTopP(p float32) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.TopP = p
	}
}

// WithReasoningFrequencyPenalty sets the frequency penalty.
func WithReasoningFrequencyPenalty(penalty float32) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.FrequencyPenalty = penalty
	}
}

// WithReasoningPresencePenalty sets the presence penalty.
func WithReasoningPresencePenalty(penalty float32) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.PresencePenalty = penalty
	}
}

// WithReasoningStop sets the stop sequences.
func WithReasoningStop(stop []string) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.Stop = stop
	}
}

// WithReasoningBaseURL sets a custom API base URL.
func WithReasoningBaseURL(url string) ReasoningOption {
	return func(c *ReasoningConfig) {
		c.BaseURL = url
	}
}
