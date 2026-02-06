package poetry

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Poetry buff.
type Config struct {
	// Format is the poetry format (haiku, sonnet, limerick, etc).
	Format string

	// TransformGenerator is the optional LLM generator name for transformation.
	TransformGenerator string

	// Strategy is the semantic reframing approach (allegorical, metaphorical, narrative).
	// Defines how the harmful request is transformed into poetry.
	Strategy string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Format:             "haiku",
		TransformGenerator: "",
		Strategy:           "metaphorical",
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: format
	cfg.Format = registry.GetString(m, "format", cfg.Format)

	// Optional: transform_generator
	cfg.TransformGenerator = registry.GetString(m, "transform_generator", cfg.TransformGenerator)

	// Optional: strategy
	cfg.Strategy = registry.GetString(m, "strategy", cfg.Strategy)

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithFormat sets the poetry format.
func WithFormat(format string) Option {
	return func(c *Config) {
		c.Format = format
	}
}

// WithTransformGenerator sets the transform generator name.
func WithTransformGenerator(gen string) Option {
	return func(c *Config) {
		c.TransformGenerator = gen
	}
}

// WithStrategy sets the transformation strategy.
func WithStrategy(strategy string) Option {
	return func(c *Config) {
		c.Strategy = strategy
	}
}
