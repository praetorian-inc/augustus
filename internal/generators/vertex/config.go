package vertex

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Vertex AI generator.
type Config struct {
	// Required
	Model     string
	ProjectID string

	// Optional with defaults
	Location        string
	APIKey          string
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
		Location:        defaultLocation,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("vertex generator requires 'model' configuration")
	}
	cfg.Model = model

	// Required: project_id
	projectID, err := registry.RequireString(m, "project_id")
	if err != nil {
		return cfg, fmt.Errorf("vertex generator requires 'project_id' configuration")
	}
	cfg.ProjectID = projectID

	// Optional: location (defaults to us-central1)
	cfg.Location = registry.GetString(m, "location", cfg.Location)

	// Optional: API key from config or env var (for testing/simple auth)
	// In production, ADC (Application Default Credentials) should be used
	cfg.APIKey = registry.GetOptionalAPIKeyWithEnv(m, "GOOGLE_API_KEY")

	// Optional: custom base URL (for testing)
	cfg.BaseURL = registry.GetString(m, "base_url", "")

	// Optional generation parameters
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

// WithModel sets the model name.
func WithModel(model string) Option {
	return func(c *Config) {
		c.Model = model
	}
}

// WithProjectID sets the Google Cloud project ID.
func WithProjectID(projectID string) Option {
	return func(c *Config) {
		c.ProjectID = projectID
	}
}

// WithLocation sets the Google Cloud location.
func WithLocation(location string) Option {
	return func(c *Config) {
		c.Location = location
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithBaseURL sets a custom API base URL.
func WithBaseURL(url string) Option {
	return func(c *Config) {
		c.BaseURL = url
	}
}

// WithTemperature sets the sampling temperature.
func WithTemperature(temp float64) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithMaxOutputTokens sets the maximum output tokens.
func WithMaxOutputTokens(tokens int) Option {
	return func(c *Config) {
		c.MaxOutputTokens = tokens
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
