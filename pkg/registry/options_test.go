package registry

import (
	"testing"
)

// Example config struct for testing
type ExampleConfig struct {
	Model       string
	APIKey      string
	Temperature float64
	MaxTokens   int
	Stop        []string
}

// DefaultExampleConfig returns config with sensible defaults
func DefaultExampleConfig() ExampleConfig {
	return ExampleConfig{
		Temperature: 0.7,
		MaxTokens:   1024,
	}
}

// Option type for ExampleConfig (using the generic Option type)
type ExampleOption = Option[ExampleConfig]

// WithModel sets the model
func WithModel(model string) ExampleOption {
	return func(c *ExampleConfig) {
		c.Model = model
	}
}

// WithAPIKey sets the API key
func WithAPIKey(key string) ExampleOption {
	return func(c *ExampleConfig) {
		c.APIKey = key
	}
}

// WithTemperature sets the temperature
func WithTemperature(temp float64) ExampleOption {
	return func(c *ExampleConfig) {
		c.Temperature = temp
	}
}

func TestFunctionalOptions(t *testing.T) {
	// Start with defaults
	cfg := DefaultExampleConfig()

	// Apply options
	opts := []ExampleOption{
		WithModel("gpt-4"),
		WithAPIKey("sk-test"),
		WithTemperature(0.5),
	}

	for _, opt := range opts {
		opt(&cfg)
	}

	if cfg.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", cfg.Model, "gpt-4")
	}
	if cfg.APIKey != "sk-test" {
		t.Errorf("APIKey = %q, want %q", cfg.APIKey, "sk-test")
	}
	if cfg.Temperature != 0.5 {
		t.Errorf("Temperature = %f, want %f", cfg.Temperature, 0.5)
	}
	if cfg.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d, want %d (default should be preserved)", cfg.MaxTokens, 1024)
	}
}

func TestApplyOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultExampleConfig(),
		WithModel("gpt-4"),
		WithTemperature(0.3),
	)

	if cfg.Model != "gpt-4" {
		t.Errorf("Model = %q, want %q", cfg.Model, "gpt-4")
	}
	if cfg.Temperature != 0.3 {
		t.Errorf("Temperature = %f, want %f", cfg.Temperature, 0.3)
	}
	if cfg.MaxTokens != 1024 {
		t.Errorf("MaxTokens = %d, want %d (default should be preserved)", cfg.MaxTokens, 1024)
	}
}
