// Package base provides base detector implementations including StringDetector.
package base

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// StringDetectorConfig holds typed configuration for StringDetector.
type StringDetectorConfig struct {
	Substrings    []string
	MatchType     string // "str", "word", "startswith"
	CaseSensitive bool
}

// DefaultStringDetectorConfig returns a config with sensible defaults.
func DefaultStringDetectorConfig() StringDetectorConfig {
	return StringDetectorConfig{
		MatchType:     "str",
		CaseSensitive: false,
	}
}

// StringDetectorConfigFromMap parses registry.Config into typed config.
func StringDetectorConfigFromMap(m registry.Config) (StringDetectorConfig, error) {
	cfg := DefaultStringDetectorConfig()

	// Required: substrings
	substrings, err := registry.RequireStringSlice(m, "substrings")
	if err != nil {
		return cfg, fmt.Errorf("invalid substrings config: %w", err)
	}
	cfg.Substrings = substrings

	// Optional: matchtype
	cfg.MatchType = registry.GetString(m, "matchtype", cfg.MatchType)

	// Optional: case_sensitive
	cfg.CaseSensitive = registry.GetBool(m, "case_sensitive", cfg.CaseSensitive)

	return cfg, nil
}

// StringDetectorOption is a functional option for StringDetectorConfig.
type StringDetectorOption = registry.Option[StringDetectorConfig]

// ApplyStringDetectorOptions applies options to a config.
func ApplyStringDetectorOptions(cfg StringDetectorConfig, opts ...StringDetectorOption) StringDetectorConfig {
	return registry.ApplyOptions(cfg, opts...)
}

// WithSubstrings sets the substrings to match.
func WithSubstrings(s []string) StringDetectorOption {
	return func(c *StringDetectorConfig) {
		c.Substrings = s
	}
}

// WithMatchType sets the match type ("str", "word", "startswith").
func WithMatchType(mt string) StringDetectorOption {
	return func(c *StringDetectorConfig) {
		c.MatchType = mt
	}
}

// WithCaseSensitive sets case sensitivity.
func WithCaseSensitive(cs bool) StringDetectorOption {
	return func(c *StringDetectorConfig) {
		c.CaseSensitive = cs
	}
}
