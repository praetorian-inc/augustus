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

	// Optional with defaults.
	//
	// Temperature is a pointer so "unset" (nil) is distinct from an explicit 0:
	// when nil the field is omitted from the request entirely, rather than
	// injecting a default the operator never asked for. This matters because the
	// newest Anthropic models (e.g. claude-sonnet-5, claude-opus-4-x) reject the
	// `temperature` field outright ("temperature is deprecated for this model"),
	// so a hardcoded default would make them unusable out of the box. Mirrors the
	// ollama generator's pointer handling.
	Temperature   *float64
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
		// Temperature intentionally left nil (unset): only sent when the operator
		// explicitly configures it. See the Config.Temperature doc comment.
		MaxTokens:  defaultMaxTokens,
		APIVersion: defaultAPIVersion,
		BaseURL:    defaultBaseURL,
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
	// Temperature is opt-in: only set when the key is present, so an absent key
	// leaves it nil (unsent) rather than defaulting. JSON/YAML numbers decode to
	// float64; an int is accepted for hand-built maps.
	if _, ok := m["temperature"]; ok {
		temp := registry.GetFloat64(m, "temperature", 0)
		cfg.Temperature = &temp
	}
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

// WithTemperature sets the sampling temperature. Calling it marks temperature
// as explicitly set (including 0); leaving it uncalled keeps temperature unset,
// so the field is omitted from the request.
func WithTemperature(temp float64) Option {
	return func(c *Config) {
		c.Temperature = &temp
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

// String returns a string representation with API key masked.
// This prevents accidental credential leakage in logs or error messages.
func (c Config) String() string {
	maskedKey := registry.MaskAPIKey(c.APIKey)
	temp := "unset"
	if c.Temperature != nil {
		temp = fmt.Sprintf("%.2f", *c.Temperature)
	}
	return fmt.Sprintf("Config{Model=%s, APIKey=%s, Temperature=%s, MaxTokens=%d}",
		c.Model, maskedKey, temp, c.MaxTokens)
}
