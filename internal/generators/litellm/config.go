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

// Config keys accepted by ConfigFromMap. api_base is an alias for proxy_url;
// api_key is read by registry.GetOptionalAPIKeyWithEnv, which falls back to
// LITELLM_API_KEY.
const (
	keyProxyURL         = "proxy_url"
	keyAPIBase          = "api_base"
	keyModel            = "model"
	keyAPIKey           = "api_key"
	keyTemperature      = "temperature"
	keyMaxTokens        = "max_tokens"
	keyTopP             = "top_p"
	keyFrequencyPenalty = "frequency_penalty"
	keyPresencePenalty  = "presence_penalty"
	keyStop             = "stop"
	keySuppressedParams = "suppressed_params"
)

// RequiredKeys returns the config keys ConfigFromMap requires. A required key
// may be satisfied by one of its KeyAliases() instead.
func RequiredKeys() []string {
	return []string{keyProxyURL, keyModel}
}

// KeyAliases maps a required key to the keys ConfigFromMap accepts in its place.
func KeyAliases() map[string][]string {
	return map[string][]string{keyProxyURL: {keyAPIBase}}
}

// OptionalKeys returns the config keys ConfigFromMap accepts but does not require.
func OptionalKeys() []string {
	return []string{
		keyAPIBase, keyAPIKey, keyTemperature, keyMaxTokens, keyTopP,
		keyFrequencyPenalty, keyPresencePenalty, keyStop, keySuppressedParams,
	}
}

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
		Temperature: 0.7,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: proxy_url
	proxyURL := registry.GetString(m, keyProxyURL, "")
	if proxyURL == "" {
		proxyURL = registry.GetString(m, keyAPIBase, "") // Alternative key
	}
	if proxyURL == "" {
		return cfg, fmt.Errorf("litellm generator requires 'proxy_url' configuration")
	}
	cfg.ProxyURL = proxyURL

	// Required: model
	model, err := registry.RequireString(m, keyModel)
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
	cfg.Temperature = registry.GetFloat32(m, keyTemperature, cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, keyMaxTokens, cfg.MaxTokens)
	cfg.TopP = registry.GetFloat32(m, keyTopP, cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat32(m, keyFrequencyPenalty, cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat32(m, keyPresencePenalty, cfg.PresencePenalty)
	cfg.Stop = registry.GetStringSlice(m, keyStop, nil)
	cfg.SuppressedParams = registry.GetStringSlice(m, keySuppressedParams, nil)

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
