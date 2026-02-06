// Package perspective provides a detector for Google Perspective API toxicity analysis.
package perspective

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Perspective API detector.
type Config struct {
	// Required
	APIKey string

	// Optional with defaults
	Threshold float64  // Default: 0.5
	Attrs     []string // Default: ["TOXICITY"]
	APIURL    string   // Default: defaultAPIURL
}

// DefaultPerspectiveConfig returns a config with sensible defaults.
func DefaultPerspectiveConfig() Config {
	return Config{
		Threshold: defaultThreshold,
		Attrs:     []string{"TOXICITY"},
		APIURL:    defaultAPIURL,
	}
}

// PerspectiveConfigFromMap parses registry.Config into typed config.
func PerspectiveConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultPerspectiveConfig()

	// API key: from config or env var
	cfg.APIKey = registry.GetString(m, "api_key", "")
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("PERSPECTIVE_API_KEY")
	}
	if cfg.APIKey == "" {
		return cfg, fmt.Errorf("perspective detector requires 'api_key' configuration or PERSPECTIVE_API_KEY environment variable")
	}

	// Optional: threshold
	cfg.Threshold = registry.GetFloat64(m, "threshold", cfg.Threshold)

	// Optional: attrs
	cfg.Attrs = registry.GetStringSlice(m, "attrs", cfg.Attrs)

	// Optional: api_url
	cfg.APIURL = registry.GetString(m, "api_url", cfg.APIURL)

	return cfg, nil
}

// PerspectiveOption is a functional option for PerspectiveConfig.
type PerspectiveOption = registry.Option[Config]

// ApplyPerspectiveOptions applies options to a config.
func ApplyPerspectiveOptions(cfg Config, opts ...PerspectiveOption) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) PerspectiveOption {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithThreshold sets the detection threshold.
func WithThreshold(threshold float64) PerspectiveOption {
	return func(c *Config) {
		c.Threshold = threshold
	}
}

// WithAttrs sets the attributes to check.
func WithAttrs(attrs []string) PerspectiveOption {
	return func(c *Config) {
		c.Attrs = attrs
	}
}

// WithAPIURL sets the API endpoint URL.
func WithAPIURL(url string) PerspectiveOption {
	return func(c *Config) {
		c.APIURL = url
	}
}
