package azure

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds configuration for Azure OpenAI generator.
type Config struct {
	// Model is the Azure OpenAI model name (e.g., "gpt-4", "gpt-35-turbo").
	Model string

	// APIKey is the Azure OpenAI API key.
	APIKey string

	// Endpoint is the Azure OpenAI endpoint URL (e.g., "https://your-resource.openai.azure.com").
	Endpoint string

	// APIVersion is the Azure OpenAI API version (default: "2024-06-01").
	APIVersion string

	// Optional generation parameters
	Temperature      float32
	MaxTokens        int
	TopP             float32
	FrequencyPenalty float32
	PresencePenalty  float32
	Stop             []string
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() Config {
	return Config{
		APIVersion: "2024-06-01",
	}
}

// ConfigFromMap creates a typed Config from legacy registry.Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Model (from config or env)
	if model, ok := m["model"].(string); ok && model != "" {
		cfg.Model = model
	} else if envModel := os.Getenv("AZURE_MODEL_NAME"); envModel != "" {
		cfg.Model = envModel
	}

	// API Key (from config or env)
	cfg.APIKey = registry.GetOptionalAPIKeyWithEnv(m, "AZURE_API_KEY")

	// Endpoint (from config or env)
	if endpoint, ok := m["endpoint"].(string); ok && endpoint != "" {
		cfg.Endpoint = endpoint
	} else if envEndpoint := os.Getenv("AZURE_ENDPOINT"); envEndpoint != "" {
		cfg.Endpoint = envEndpoint
	}

	// API Version (optional)
	if apiVersion, ok := m["api_version"].(string); ok && apiVersion != "" {
		cfg.APIVersion = apiVersion
	}

	// Optional generation parameters
	cfg.Temperature = registry.GetFloat32(m, "temperature", cfg.Temperature)
	cfg.MaxTokens = registry.GetInt(m, "max_tokens", cfg.MaxTokens)
	cfg.TopP = registry.GetFloat32(m, "top_p", cfg.TopP)
	cfg.FrequencyPenalty = registry.GetFloat32(m, "frequency_penalty", cfg.FrequencyPenalty)
	cfg.PresencePenalty = registry.GetFloat32(m, "presence_penalty", cfg.PresencePenalty)

	if stop, ok := m["stop"].([]string); ok {
		cfg.Stop = stop
	}

	return cfg, nil
}

// Validate checks that required configuration is present.
func (c Config) Validate() error {
	if c.Model == "" {
		return fmt.Errorf("azure generator requires 'model'")
	}
	if c.APIKey == "" {
		return fmt.Errorf("azure generator requires 'api_key'")
	}
	if c.Endpoint == "" {
		return fmt.Errorf("azure generator requires 'endpoint'")
	}
	return nil
}

// Option is a functional option for configuring Azure generator.
type Option func(*Config)

// WithModel sets the model name.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(apiKey string) Option {
	return func(c *Config) {
		c.APIKey = apiKey
	}
}

// WithEndpoint sets the endpoint URL.
func WithEndpoint(endpoint string) Option {
	return func(c *Config) {
		c.Endpoint = endpoint
	}
}

// WithAPIVersion sets the API version.
func WithAPIVersion(version string) Option {
	return func(c *Config) {
		c.APIVersion = version
	}
}

// WithTemperature sets the temperature parameter.
func WithTemperature(temp float32) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithMaxTokens sets the max tokens parameter.
func WithMaxTokens(maxTokens int) Option {
	return func(c *Config) {
		c.MaxTokens = maxTokens
	}
}

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}
