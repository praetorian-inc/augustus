package batch

import (
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Batch harness.
type Config struct {
	// Concurrency is the maximum number of parallel probe executions.
	Concurrency int

	// Timeout is the timeout duration for probe execution.
	Timeout time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Concurrency: 10,
		Timeout:     30 * time.Second,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: concurrency (handles both int and float64 from JSON)
	cfg.Concurrency = registry.GetInt(m, "concurrency", cfg.Concurrency)

	// Optional: timeout (handles both string and time.Duration)
	if timeoutStr, ok := m["timeout"].(string); ok {
		if dur, err := time.ParseDuration(timeoutStr); err == nil {
			cfg.Timeout = dur
		}
	} else if timeoutDur, ok := m["timeout"].(time.Duration); ok {
		cfg.Timeout = timeoutDur
	}

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithConcurrency sets the maximum concurrency.
func WithConcurrency(concurrency int) Option {
	return func(c *Config) {
		c.Concurrency = concurrency
	}
}

// WithTimeout sets the timeout duration.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.Timeout = timeout
	}
}
