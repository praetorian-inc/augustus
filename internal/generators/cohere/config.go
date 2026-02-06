package cohere

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Cohere generator.
type Config struct {
	// Required
	APIKey string

	// Optional with defaults
	Model            string
	BaseURL          string
	APIVersion       string
	Temperature      float64
	MaxTokens        int
	TopK             int
	TopP             float64
	FrequencyPenalty float64
	PresencePenalty  float64
	Stop             []string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Model:       "command",
		BaseURL:     "https://api.cohere.com",
		APIVersion:  "v2",
		Temperature: 0.75,
		TopP:        0.75,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// API key: from config or env var
	var err error
	cfg.APIKey, err = registry.GetAPIKeyWithEnv(m, "COHERE_API_KEY", "cohere")
	if err != nil {
		return cfg, err
	}

	// Optional parameters
	cfg.Model = registry.GetString(m, "model", cfg.Model)
	cfg.BaseURL = registry.GetString(m, "base_url", cfg.BaseURL)

	if apiVersion, ok := m["api_version"].(string); ok {
		if apiVersion == "v1" || apiVersion == "v2" {
			cfg.APIVersion = apiVersion
		}
	}

	cfg.Temperature = registry.GetFloat64(m, "temperature", cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopK = registry.GetInt(m, "k", cfg.TopK)
	cfg.TopP = registry.GetFloat64(m, "p", cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat64(m, "frequency_penalty", cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat64(m, "presence_penalty", cfg.PresencePenalty)

	// Parse stop sequences
	if stop, ok := m["stop"].([]any); ok {
		cfg.Stop = make([]string, 0, len(stop))
		for _, s := range stop {
			if str, ok := s.(string); ok {
				cfg.Stop = append(cfg.Stop, str)
			}
		}
	}

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithModel sets the model name.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithBaseURL sets the base API URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// WithAPIVersion sets the API version ("v1" or "v2").
func WithAPIVersion(version string) Option {
	return func(c *Config) {
		c.APIVersion = version
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

// WithTopK sets the top-k sampling parameter.
func WithTopK(k int) Option {
	return func(c *Config) {
		c.TopK = k
	}
}

// WithTopP sets the top-p (nucleus) sampling parameter.
func WithTopP(p float64) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithFrequencyPenalty sets the frequency penalty.
func WithFrequencyPenalty(penalty float64) Option {
	return func(c *Config) {
		c.FrequencyPenalty = penalty
	}
}

// WithPresencePenalty sets the presence penalty.
func WithPresencePenalty(penalty float64) Option {
	return func(c *Config) {
		c.PresencePenalty = penalty
	}
}

// WithStop sets the stop sequences.
func WithStop(sequences []string) Option {
	return func(c *Config) {
		c.Stop = sequences
	}
}
