package openai

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the OpenAI generator.
type Config struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults
	Temperature      float32
	MaxTokens        int
	TopP             float32
	FrequencyPenalty float32
	PresencePenalty  float32
	Stop             []string
	BaseURL          string
}

// DefaultConfig returns an OpenAIConfig with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature: 0.7, // Match Python garak default
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("openai generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey, err = registry.GetAPIKeyWithEnv(m, "OPENAI_API_KEY", "openai")
	if err != nil {
		return cfg, err
	}

	// Optional parameters
	cfg.BaseURL = registry.GetString(m, "base_url", "")
	cfg.Temperature = registry.GetFloat32(m, "temperature", cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat32(m, "frequency_penalty", cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat32(m, "presence_penalty", cfg.PresencePenalty)
	cfg.Stop = registry.GetStringSlice(m, "stop", nil)

	return cfg, nil
}

// Option is a functional option for OpenAIConfig.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithModel sets the model name.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithTemperature sets the sampling temperature.
func WithTemperature(temp float32) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithMaxTokens sets the maximum tokens for completion.
func WithMaxTokens(tokens int) Option {
	return func(c *Config) {
		c.MaxTokens = tokens
	}
}

// WithTopP sets the nucleus sampling parameter.
func WithTopP(p float32) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithFrequencyPenalty sets the frequency penalty.
func WithFrequencyPenalty(penalty float32) Option {
	return func(c *Config) {
		c.FrequencyPenalty = penalty
	}
}

// WithPresencePenalty sets the presence penalty.
func WithPresencePenalty(penalty float32) Option {
	return func(c *Config) {
		c.PresencePenalty = penalty
	}
}

// WithStop sets the stop sequences.
func WithStop(stop []string) Option {
	return func(c *Config) {
		c.Stop = stop
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}
