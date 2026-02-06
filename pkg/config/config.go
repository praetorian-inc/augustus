package config

import (
	"fmt"
	"strings"
	"time"
)

// Config represents the complete Augustus configuration
type Config struct {
	Run        RunConfig                  `yaml:"run" koanf:"run"`
	Generators map[string]GeneratorConfig `yaml:"generators" koanf:"generators"`
	Probes     ProbeConfig                `yaml:"probes" koanf:"probes"`
	Detectors  DetectorConfig             `yaml:"detectors" koanf:"detectors"`
	Buffs      BuffConfig                 `yaml:"buffs,omitempty" koanf:"buffs"`
	Output     OutputConfig               `yaml:"output" koanf:"output"`
	Profiles   map[string]Profile         `yaml:"profiles,omitempty" koanf:"profiles"`
}

// Profile represents a named configuration profile
type Profile struct {
	Run        RunConfig                  `yaml:"run"`
	Generators map[string]GeneratorConfig `yaml:"generators,omitempty"`
	Probes     ProbeConfig                `yaml:"probes,omitempty"`
	Detectors  DetectorConfig             `yaml:"detectors,omitempty"`
	Buffs      BuffConfig                 `yaml:"buffs,omitempty"`
	Output     OutputConfig               `yaml:"output,omitempty"`
}

// RunConfig contains runtime configuration
type RunConfig struct {
	MaxAttempts  int    `yaml:"max_attempts" koanf:"max_attempts" validate:"gte=0"`
	Timeout      string `yaml:"timeout" koanf:"timeout"`
	Concurrency  int    `yaml:"concurrency,omitempty" koanf:"concurrency" validate:"gte=0"`
	ProbeTimeout string `yaml:"probe_timeout,omitempty" koanf:"probe_timeout"`
}

// GeneratorConfig contains generator-specific configuration
type GeneratorConfig struct {
	Model       string  `yaml:"model" koanf:"model"`
	Temperature float64 `yaml:"temperature" koanf:"temperature" validate:"gte=0,lte=2"`
	APIKey      string  `yaml:"api_key,omitempty" koanf:"api_key"`
	RateLimit   float64 `yaml:"rate_limit,omitempty" koanf:"rate_limit" validate:"gte=0"` // Requests per second
}

// ProbeConfig contains probe-specific configuration
type ProbeConfig struct {
	Encoding EncodingProbeConfig `yaml:"encoding"`
}

// EncodingProbeConfig contains encoding probe configuration
type EncodingProbeConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DetectorConfig contains detector-specific configuration
type DetectorConfig struct {
	Always AlwaysDetectorConfig `yaml:"always"`
}

// BuffConfig contains buff-specific configuration
type BuffConfig struct {
	// Names is a list of buff names to apply
	Names []string `yaml:"names,omitempty" koanf:"names"`
	// Settings maps buff names to their specific configuration.
	// Each buff's settings may include:
	//   - "rate_limit" (float64): requests per second, 0 = no limit
	//   - "burst_size" (float64): max burst capacity
	//   - buff-specific keys (e.g., "api_key")
	Settings map[string]map[string]any `yaml:"settings,omitempty" koanf:"settings"`
}

// AlwaysDetectorConfig contains always detector configuration
type AlwaysDetectorConfig struct {
	Enabled bool `yaml:"enabled"`
}

// OutputConfig contains output configuration
type OutputConfig struct {
	Format string `yaml:"format" koanf:"format" validate:"omitempty,oneof=json jsonl csv txt table"`
	Path   string `yaml:"path" koanf:"path"`
}

// Validate validates the configuration and returns helpful error messages
func (c *Config) Validate() error {
	// Validate run config
	if c.Run.MaxAttempts < 0 {
		return fmt.Errorf("run.max_attempts must be non-negative, got: %d", c.Run.MaxAttempts)
	}

	// Validate concurrency (0 means "use default", negative is invalid)
	if c.Run.Concurrency < 0 {
		return fmt.Errorf("run.concurrency must be non-negative, got: %d", c.Run.Concurrency)
	}

	// Validate probe_timeout format if provided
	if c.Run.ProbeTimeout != "" {
		if _, err := time.ParseDuration(c.Run.ProbeTimeout); err != nil {
			return fmt.Errorf("invalid run.probe_timeout: %w", err)
		}
	}

	// Validate generator temperatures (0-2 is standard LLM API range)
	for name, gen := range c.Generators {
		if gen.Temperature < 0 || gen.Temperature > 2 {
			return fmt.Errorf("validation failed: generators.%s.temperature must be between 0 and 2, got: %f", name, gen.Temperature)
		}
	}

	// Validate output format
	validFormats := map[string]bool{
		"json":  true,
		"jsonl": true,
		"csv":   true,
		"txt":   true,
		"table": true,
	}
	if c.Output.Format != "" && !validFormats[c.Output.Format] {
		return fmt.Errorf("invalid output format: %s (valid: json, jsonl, csv, txt, table)", c.Output.Format)
	}

	return nil
}

// Merge merges another config into this one, with the other config taking precedence
func (c *Config) Merge(other *Config) {
	// Merge run config (simple override)
	if other.Run.MaxAttempts != 0 {
		c.Run.MaxAttempts = other.Run.MaxAttempts
	}
	if other.Run.Timeout != "" {
		c.Run.Timeout = other.Run.Timeout
	}
	if other.Run.Concurrency != 0 {
		c.Run.Concurrency = other.Run.Concurrency
	}
	if other.Run.ProbeTimeout != "" {
		c.Run.ProbeTimeout = other.Run.ProbeTimeout
	}

	// Merge generators
	if c.Generators == nil {
		c.Generators = make(map[string]GeneratorConfig)
	}
	for name, gen := range other.Generators {
		existing := c.Generators[name]
		if gen.Model != "" {
			existing.Model = gen.Model
		}
		if gen.Temperature != 0 {
			existing.Temperature = gen.Temperature
		}
		if gen.APIKey != "" {
			existing.APIKey = gen.APIKey
		}
		c.Generators[name] = existing
	}

	// Merge probes
	if other.Probes.Encoding.Enabled {
		c.Probes.Encoding.Enabled = other.Probes.Encoding.Enabled
	}

	// Merge detectors
	if other.Detectors.Always.Enabled {
		c.Detectors.Always.Enabled = other.Detectors.Always.Enabled
	}

	// Merge buffs
	if len(other.Buffs.Names) > 0 {
		c.Buffs.Names = other.Buffs.Names
	}
	if len(other.Buffs.Settings) > 0 {
		if c.Buffs.Settings == nil {
			c.Buffs.Settings = make(map[string]map[string]any)
		}
		for k, v := range other.Buffs.Settings {
			c.Buffs.Settings[k] = v
		}
	}

	// Merge output config
	if other.Output.Format != "" {
		c.Output.Format = other.Output.Format
	}
	if other.Output.Path != "" {
		c.Output.Path = other.Output.Path
	}
}

// ApplyProfile applies a named profile to this config
func (c *Config) ApplyProfile(profileName string) error {
	profile, exists := c.Profiles[profileName]
	if !exists {
		return fmt.Errorf("profile %q not found", profileName)
	}

	// Convert profile to Config for merging
	profileConfig := &Config{
		Run:        profile.Run,
		Generators: profile.Generators,
		Probes:     profile.Probes,
		Detectors:  profile.Detectors,
		Buffs:      profile.Buffs,
		Output:     profile.Output,
	}

	c.Merge(profileConfig)
	return nil
}

// interpolateEnvVars replaces ${VAR} with environment variable values
func interpolateEnvVars(s string, getenv func(string) (string, bool)) (string, error) {
	result := s
	start := 0
	for {
		// Find ${
		idx := strings.Index(result[start:], "${")
		if idx == -1 {
			break
		}
		idx += start

		// Find }
		endIdx := strings.Index(result[idx:], "}")
		if endIdx == -1 {
			return "", fmt.Errorf("unclosed environment variable reference at position %d", idx)
		}
		endIdx += idx

		// Extract variable name
		varName := result[idx+2 : endIdx]
		value, ok := getenv(varName)
		if !ok {
			return "", fmt.Errorf("environment variable %q is not set", varName)
		}

		// Replace ${VAR} with value
		result = result[:idx] + value + result[endIdx+1:]
		start = idx + len(value)
	}
	return result, nil
}
