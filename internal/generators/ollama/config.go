package ollama

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Ollama generator.
type Config struct {
	// Required
	Model string

	// Optional with defaults
	Host    string
	Timeout time.Duration

	// Optional generation parameters (pointers to distinguish unset from zero)
	Temperature *float64
	TopP        *float64
	TopK        *int
	NumPredict  *int
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Host:    DefaultHost,
		Timeout: DefaultTimeout * time.Second,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: model
	model, err := registry.RequireString(m, "model")
	if err != nil {
		return cfg, fmt.Errorf("ollama generator requires 'model' configuration")
	}
	cfg.Model = model

	// Optional: host from config or env var
	cfg.Host = registry.GetString(m, "host", "")
	if cfg.Host == "" {
		if envHost := os.Getenv("OLLAMA_HOST"); envHost != "" {
			cfg.Host = envHost
		} else {
			cfg.Host = DefaultHost
		}
	}

	// Ensure host doesn't have trailing slash
	cfg.Host = strings.TrimSuffix(cfg.Host, "/")

	// Optional: timeout (in seconds)
	timeout := registry.GetInt(m, "timeout", 0)
	if timeout > 0 {
		cfg.Timeout = time.Duration(timeout) * time.Second
	}

	// Optional generation parameters (use pointers to distinguish unset from zero)
	if temp, ok := m["temperature"].(float64); ok {
		cfg.Temperature = &temp
	}

	if topP, ok := m["top_p"].(float64); ok {
		cfg.TopP = &topP
	}

	if topK := registry.GetInt(m, "top_k", 0); topK != 0 {
		cfg.TopK = &topK
	}

	if numPredict := registry.GetInt(m, "num_predict", 0); numPredict != 0 {
		cfg.NumPredict = &numPredict
	}

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

// WithHost sets the Ollama host URL.
func WithHost(host string) Option {
	return func(c *Config) {
		c.Host = host
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.Timeout = timeout
	}
}

// WithTemperature sets the sampling temperature.
func WithTemperature(temp *float64) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithTopP sets the nucleus sampling parameter.
func WithTopP(p *float64) Option {
	return func(c *Config) {
		c.TopP = p
	}
}

// WithTopK sets the top-k sampling parameter.
func WithTopK(k *int) Option {
	return func(c *Config) {
		c.TopK = k
	}
}

// WithNumPredict sets the number of tokens to predict.
func WithNumPredict(n *int) Option {
	return func(c *Config) {
		c.NumPredict = n
	}
}
