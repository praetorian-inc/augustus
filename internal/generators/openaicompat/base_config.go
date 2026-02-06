// Package openaicompat provides shared configuration for OpenAI-compatible generators.
package openaicompat

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// BaseConfig contains common configuration fields for OpenAI-compatible generators.
// Generator-specific configs can embed this struct and add provider-specific fields.
type BaseConfig struct {
	Model       string
	APIKey      string
	BaseURL     string
	Temperature float32
	MaxTokens   int
	TopP        float32
}

// DefaultBaseConfig returns a BaseConfig with sensible defaults.
func DefaultBaseConfig() BaseConfig {
	return BaseConfig{
		Temperature: 0.7,
		MaxTokens:   4096,
		TopP:        1.0,
	}
}

// BaseConfigFromMap parses a BaseConfig from registry.Config map.
// envVar is the environment variable name for the API key (e.g., "OPENAI_API_KEY").
// providerName is used in error messages (e.g., "openai").
func BaseConfigFromMap(m registry.Config, envVar, providerName string) (BaseConfig, error) {
	cfg := DefaultBaseConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("%s generator requires 'model': %w", providerName, err)
	}
	cfg.Model = model

	// Required: API key (from config or environment)
	apiKey, err := registry.GetAPIKeyWithEnv(m, envVar, providerName)
	if err != nil {
		return cfg, err
	}
	cfg.APIKey = apiKey

	// Optional: base_url (provider default if not specified)
	cfg.BaseURL = registry.GetString(m, "base_url", "")

	// Optional: temperature with default
	cfg.Temperature = registry.GetFloat32(m, "temperature", cfg.Temperature)

	// Optional: max_tokens with default
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)

	// Optional: top_p with default
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)

	return cfg, nil
}

// WithModel returns an Option that sets the model.
func WithModel(model string) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.Model = model
	}
}

// WithAPIKey returns an Option that sets the API key.
func WithAPIKey(key string) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.APIKey = key
	}
}

// WithBaseURL returns an Option that sets the base URL.
func WithBaseURL(url string) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.BaseURL = url
	}
}

// WithTemperature returns an Option that sets the temperature.
func WithTemperature(temp float32) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.Temperature = temp
	}
}

// WithMaxTokens returns an Option that sets max tokens.
func WithMaxTokens(tokens int) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.MaxTokens = tokens
	}
}

// WithTopP returns an Option that sets top_p.
func WithTopP(p float32) registry.Option[BaseConfig] {
	return func(cfg *BaseConfig) {
		cfg.TopP = p
	}
}

// ApplyOptions applies functional options to a BaseConfig.
func ApplyOptions(cfg BaseConfig, opts ...registry.Option[BaseConfig]) BaseConfig {
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// String returns a string representation of BaseConfig with API key masked.
// This prevents accidental credential leakage in logs or error messages.
func (c BaseConfig) String() string {
	maskedKey := maskAPIKey(c.APIKey)
	return fmt.Sprintf("BaseConfig{Model=%s, APIKey=%s, BaseURL=%s, Temperature=%.2f, MaxTokens=%d, TopP=%.2f}",
		c.Model, maskedKey, c.BaseURL, c.Temperature, c.MaxTokens, c.TopP)
}

// maskAPIKey masks an API key showing only prefix and suffix.
// Examples:
//   "sk-1234567890abcdef" -> "sk-***def"
//   "short" -> "***"
//   "" -> "<empty>"
func maskAPIKey(key string) string {
	if key == "" {
		return "<empty>"
	}
	if len(key) <= 6 {
		return "***"
	}
	// Show first 3 chars and last 3 chars
	return key[:3] + "***" + key[len(key)-3:]
}
