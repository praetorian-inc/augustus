// modules/augustus/pkg/generators/together/config.go
package together

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Together generator.
type Config struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults
	Temperature float32
	MaxTokens   int
	TopP        float32
	TopK        int
	BaseURL     string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature: 0.7, // Match default from together.go
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("together generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey = registry.GetString(m, "api_key", "")
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("TOGETHER_API_KEY")
	}
	if cfg.APIKey == "" {
		return cfg, fmt.Errorf("together generator requires 'api_key' configuration or TOGETHER_API_KEY environment variable")
	}

	// Optional parameters
	cfg.BaseURL = registry.GetString(m, "base_url", "")
	cfg.Temperature = float32(registry.GetFloat64(m, "temperature", float64(cfg.Temperature)))
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopP = float32(registry.GetFloat64(m, "top_p", float64(cfg.TopP)))
	cfg.TopK = registry.GetInt(m, "top_k", cfg.TopK)

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

// WithTopK sets the top-k sampling parameter.
func WithTopK(k int) Option {
	return func(c *Config) {
		c.TopK = k
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}
