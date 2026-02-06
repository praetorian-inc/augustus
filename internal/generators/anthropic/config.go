package anthropic

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Anthropic generator.
type Config struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults
	Temperature   float64
	MaxTokens     int
	TopP          float64
	TopK          int
	StopSequences []string
	BaseURL       string
	APIVersion    string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature: defaultTemperature,
		MaxTokens:   defaultMaxTokens,
		APIVersion:  defaultAPIVersion,
		BaseURL:     defaultBaseURL,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("anthropic generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey, err = registry.GetAPIKeyWithEnv(m, "ANTHROPIC_API_KEY", "anthropic")
	if err != nil {
		return cfg, err
	}

	// Optional parameters
	cfg.BaseURL = registry.GetString(m, "base_url", cfg.BaseURL)
	cfg.APIVersion = registry.GetString(m, "api_version", cfg.APIVersion)
	cfg.Temperature = registry.GetFloat64(m, "temperature", cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopP = registry.GetFloat64(m, "top_p", cfg.TopP)
	cfg.TopK = registry.GetInt(m, "top_k", cfg.TopK)
	cfg.StopSequences = registry.GetStringSlice(m, "stop_sequences", nil)

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
func WithTemperature(temp float64) Option {
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
func WithTopP(p float64) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithTopK sets the top-k sampling parameter.
func WithTopK(k int) Option {
	return func(c *Config) {
		c.TopK = k
	}
}

// WithStopSequences sets the stop sequences.
func WithStopSequences(stop []string) Option {
	return func(c *Config) {
		c.StopSequences = stop
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// WithAPIVersion sets the API version.
func WithAPIVersion(version string) Option {
	return func(c *Config) {
		c.APIVersion = version
	}
}
