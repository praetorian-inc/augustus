package bedrock

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Bedrock generator.
type Config struct {
	// Required
	Model  string
	Region string

	// Optional with defaults
	MaxTokens   int
	Temperature float64
	TopP        float64
	Endpoint    string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature: 0.7,
		MaxTokens:   150,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("bedrock generator requires 'model' configuration")
	}
	cfg.Model = model

	// Required: region
	region, err := registry.RequireString(m, "region")
	if err != nil {
		return cfg, fmt.Errorf("bedrock generator requires 'region' configuration")
	}
	cfg.Region = region

	// Optional parameters
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.Temperature = registry.GetFloat64(m, "temperature", cfg.Temperature)
	cfg.TopP = registry.GetFloat64(m, "top_p", cfg.TopP)
	cfg.Endpoint = registry.GetString(m, "endpoint", "")

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithModel sets the model ID.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithRegion sets the AWS region.
func WithRegion(region string) Option {
	return func(c *Config) {
		c.Region = region
	}
}

// WithMaxTokens sets the maximum tokens for completion.
func WithMaxTokens(tokens int) Option {
	return func(c *Config) {
		c.MaxTokens = tokens
	}
}

// WithTemperature sets the sampling temperature.
func WithTemperature(temp float64) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithTopP sets the nucleus sampling parameter.
func WithTopP(p float64) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithEndpoint sets a custom API endpoint.
func WithEndpoint(endpoint string) Option {
	return func(c *Config) {
		c.Endpoint = endpoint
	}
}
