package lrl

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the LRL buff.
type Config struct {
	// APIKey is the DeepL API key.
	APIKey string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		APIKey: "",
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// API key: from config or env var
	cfg.APIKey = registry.GetString(m, "api_key", cfg.APIKey)
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("DEEPL_API_KEY")
	}

	// Validate required field
	if cfg.APIKey == "" {
		return cfg, fmt.Errorf("lrl buff requires 'api_key' configuration or DEEPL_API_KEY environment variable")
	}

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithAPIKey sets the DeepL API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}
