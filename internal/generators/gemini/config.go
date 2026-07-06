package gemini

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Gemini generator.
type Config struct {
	// Required
	Model  string
	APIKey string

	// Optional with defaults
	BaseURL         string
	Temperature     float64
	MaxOutputTokens int
	TopP            float64
	TopK            int
	StopSequences   []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature:     defaultTemperature,
		MaxOutputTokens: defaultMaxOutputTokens,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("gemini generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key from config or GEMINI_API_KEY environment variable.
	cfg.APIKey = registry.GetOptionalAPIKeyWithEnv(m, "GEMINI_API_KEY")

	cfg.BaseURL = registry.GetString(m, "base_url", "")
	cfg.Temperature = registry.GetFloat64(m, "temperature", cfg.Temperature)
	cfg.MaxOutputTokens = registry.GetInt(m, "max_output_tokens", cfg.MaxOutputTokens)
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

func WithModel(model string) Option {
	return func(c *Config) { c.Model = model }
}

func WithAPIKey(key string) Option {
	return func(c *Config) { c.APIKey = key }
}

func WithBaseURL(u string) Option {
	return func(c *Config) { c.BaseURL = u }
}

func WithTemperature(temp float64) Option {
	return func(c *Config) { c.Temperature = temp }
}

func WithMaxOutputTokens(tokens int) Option {
	return func(c *Config) { c.MaxOutputTokens = tokens }
}

func WithTopP(p float64) Option {
	return func(c *Config) { c.TopP = p }
}

func WithTopK(k int) Option {
	return func(c *Config) { c.TopK = k }
}

func WithStopSequences(stop []string) Option {
	return func(c *Config) { c.StopSequences = stop }
}
