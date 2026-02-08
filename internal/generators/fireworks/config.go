// Package fireworks provides a Fireworks generator for Augustus.
package fireworks

import (
	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds configuration for the Fireworks generator.
// It embeds BaseConfig for common fields.
type Config struct {
	openaicompat.BaseConfig
	// Provider-specific fields can be added here if needed in the future
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BaseConfig: openaicompat.DefaultBaseConfig(),
	}
}

// ConfigFromMap creates a Config from a registry.Config map.
func ConfigFromMap(m registry.Config) (Config, error) {
	baseConfig, err := openaicompat.BaseConfigFromMap(m, "FIREWORKS_API_KEY", "fireworks")
	if err != nil {
		return Config{}, err
	}

	return Config{BaseConfig: baseConfig}, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// WithModel returns an Option that sets the model.
func WithModel(model string) Option {
	return func(cfg *Config) {
		cfg.Model = model
	}
}

// WithAPIKey returns an Option that sets the API key.
func WithAPIKey(key string) Option {
	return func(cfg *Config) {
		cfg.APIKey = key
	}
}

// WithBaseURL returns an Option that sets the base URL.
func WithBaseURL(url string) Option {
	return func(cfg *Config) {
		cfg.BaseURL = url
	}
}

// WithTemperature returns an Option that sets the temperature.
func WithTemperature(temp float32) Option {
	return func(cfg *Config) {
		cfg.Temperature = temp
	}
}

// WithMaxTokens returns an Option that sets max tokens.
func WithMaxTokens(tokens int) Option {
	return func(cfg *Config) {
		cfg.MaxTokens = tokens
	}
}

// WithTopP returns an Option that sets top_p.
func WithTopP(p float32) Option {
	return func(cfg *Config) {
		cfg.TopP = p
	}
}
