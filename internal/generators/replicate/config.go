package replicate

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Replicate generator.
type Config struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults (matching Python garak defaults)
	Temperature       float32
	TopP              float32
	RepetitionPenalty float32
	MaxTokens         int
	Seed              int
	BaseURL           string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature:       1.0, // Match replicate.go default
		TopP:              1.0,
		RepetitionPenalty: 1.0,
		Seed:              9, // Python default seed
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("replicate generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey, err = registry.GetAPIKeyWithEnv(m, "REPLICATE_API_TOKEN", "replicate")
	if err != nil {
		return cfg, err
	}

	// Optional parameters
	cfg.BaseURL = registry.GetString(m, "base_url", "")
	cfg.Temperature = registry.GetFloat32(m, "temperature", cfg.Temperature)
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)
	cfg.RepetitionPenalty = registry.GetFloat32(m, "repetition_penalty", cfg.RepetitionPenalty)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.Seed = registry.GetInt(m, "seed", cfg.Seed)

	return cfg, nil
}

// Option is a functional option for Config.
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

// WithTopP sets the nucleus sampling parameter.
func WithTopP(p float32) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithRepetitionPenalty sets the repetition penalty parameter.
func WithRepetitionPenalty(penalty float32) Option {
	return func(c *Config) {
		c.RepetitionPenalty = penalty
	}
}

// WithMaxTokens sets the maximum tokens for completion.
func WithMaxTokens(tokens int) Option {
	return func(c *Config) {
		c.MaxTokens = tokens
	}
}

// WithSeed sets the random seed for reproducibility.
func WithSeed(seed int) Option {
	return func(c *Config) {
		c.Seed = seed
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}
