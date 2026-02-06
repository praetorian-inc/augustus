// Package litellm provides a LiteLLM generator for Augustus.
//
// LiteLLM is a unified LLM gateway that provides OpenAI-compatible API
// access to 100+ LLM providers including OpenAI, Anthropic, Azure,
// Bedrock, Cohere, Replicate, and more.
//
// This generator requires a running LiteLLM proxy server. Start one with:
//
//	pip install 'litellm[proxy]'
//	litellm --model gpt-4o --port 4000
//
// Or configure a full proxy with config.yaml for multi-model routing.
package litellm

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the LiteLLM generator.
type Config struct {
	// Required
	ProxyURL string // URL of the LiteLLM proxy server (e.g., "http://localhost:4000")
	Model    string // Model name with provider prefix (e.g., "anthropic/claude-3-opus")

	// Optional with defaults
	APIKey           string   // API key for LiteLLM proxy (defaults to LITELLM_API_KEY env var)
	Temperature      float32  // Sampling temperature (default: 0.7)
	MaxTokens        int      // Maximum tokens in response
	TopP             float32  // Nucleus sampling parameter
	FrequencyPenalty float32  // Frequency penalty
	PresencePenalty  float32  // Presence penalty
	Stop             []string // Stop sequences
	SuppressedParams []string // Parameters to suppress for certain providers
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Temperature: 0.7, // Match Garak default
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: proxy_url
	proxyURL := registry.GetString(m, "proxy_url", "")
	if proxyURL == "" {
		proxyURL = registry.GetString(m, "api_base", "") // Alternative key
	}
	if proxyURL == "" {
		return cfg, fmt.Errorf("litellm generator requires 'proxy_url' configuration")
	}
	cfg.ProxyURL = proxyURL

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("litellm generator requires 'model' configuration")
	}
	cfg.Model = model

	// API key: from config or env var
	cfg.APIKey = registry.GetOptionalAPIKeyWithEnv(m, "LITELLM_API_KEY")
	if cfg.APIKey == "" {
		cfg.APIKey = "anything" // LiteLLM allows placeholder when keys are configured server-side
	}

	// Optional parameters
	cfg.Temperature = registry.GetFloat32(m, "temperature", cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat32(m, "frequency_penalty", cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat32(m, "presence_penalty", cfg.PresencePenalty)
	cfg.Stop = registry.GetStringSlice(m, "stop", nil)
	cfg.SuppressedParams = registry.GetStringSlice(m, "suppressed_params", nil)

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithProxyURL sets the LiteLLM proxy URL.
func WithProxyURL(url string) Option {
	return func(c *Config) {
		c.ProxyURL = url
	}
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

// WithMaxTokens sets the maximum tokens.
func WithMaxTokens(tokens int) Option {
	return func(c *Config) {
		c.MaxTokens = tokens
	}
}

// WithSuppressedParams sets parameters to suppress.
func WithSuppressedParams(params []string) Option {
	return func(c *Config) {
		c.SuppressedParams = params
	}
}
