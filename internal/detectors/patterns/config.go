// Package patterns provides regex and semantic pattern matching detectors.
package patterns

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// PatternConfig represents a single detection pattern configuration.
type PatternConfig struct {
	Name     string  // Optional descriptive identifier
	Regex    string  // Required regular expression
	Severity float64 // Optional severity score (0.0-1.0), default: 1.0
	Semantic string  // Optional semantic description
}

// Config holds typed configuration for the Patterns detector.
type Config struct {
	Patterns  []PatternConfig
	Mode      string  // "any", "all", or "weighted", default: "any"
	Threshold float64 // Default: 0.5
}

// DefaultPatternsConfig returns a config with sensible defaults.
func DefaultPatternsConfig() Config {
	return Config{
		Patterns:  []PatternConfig{},
		Mode:      "any",
		Threshold: 0.5,
	}
}

// PatternsConfigFromMap parses registry.Config into typed config.
func PatternsConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultPatternsConfig()

	// Parse patterns (required)
	if patternsRaw, ok := m["patterns"]; ok {
		patternList, ok := patternsRaw.([]map[string]any)
		if !ok {
			// Try type assertion for []any and convert
			if patternListIface, ok := patternsRaw.([]any); ok {
				patternList = make([]map[string]any, len(patternListIface))
				for i, p := range patternListIface {
					if pm, ok := p.(map[string]any); ok {
						patternList[i] = pm
					} else {
						return cfg, fmt.Errorf("pattern at index %d is not a map", i)
					}
				}
			} else {
				return cfg, fmt.Errorf("patterns must be an array of maps")
			}
		}

		for i, patternCfg := range patternList {
			name, _ := patternCfg["name"].(string)
			if name == "" {
				name = fmt.Sprintf("pattern_%d", i)
			}

			regexStr, ok := patternCfg["regex"].(string)
			if !ok {
				return cfg, fmt.Errorf("pattern %q missing required 'regex' field", name)
			}

			severity := 1.0
			if sev, ok := patternCfg["severity"].(float64); ok {
				severity = sev
			}

			semantic, _ := patternCfg["semantic"].(string)

			cfg.Patterns = append(cfg.Patterns, PatternConfig{
				Name:     name,
				Regex:    regexStr,
				Semantic: semantic,
				Severity: severity,
			})
		}
	}

	// Parse mode (optional)
	cfg.Mode = registry.GetString(m, "mode", cfg.Mode)

	// Parse threshold (optional)
	cfg.Threshold = registry.GetFloat64(m, "threshold", cfg.Threshold)

	return cfg, nil
}

// PatternsOption is a functional option for PatternsConfig.
type PatternsOption = registry.Option[Config]

// ApplyPatternsOptions applies options to a config.
func ApplyPatternsOptions(cfg Config, opts ...PatternsOption) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithPatterns sets the pattern list.
func WithPatterns(patterns []PatternConfig) PatternsOption {
	return func(c *Config) {
		c.Patterns = patterns
	}
}

// WithMode sets the match mode.
func WithMode(mode string) PatternsOption {
	return func(c *Config) {
		c.Mode = mode
	}
}

// WithThreshold sets the detection threshold.
func WithThreshold(threshold float64) PatternsOption {
	return func(c *Config) {
		c.Threshold = threshold
	}
}
