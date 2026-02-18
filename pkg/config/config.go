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
	Judge      JudgeGlobalConfig          `yaml:"judge,omitempty" koanf:"judge"`
	Probes     ProbeConfig                `yaml:"probes" koanf:"probes"`
	Detectors  DetectorConfig             `yaml:"detectors" koanf:"detectors"`
	Buffs      BuffConfig                 `yaml:"buffs,omitempty" koanf:"buffs"`
	Output     OutputConfig               `yaml:"output" koanf:"output"`
	Profiles   map[string]Profile         `yaml:"profiles,omitempty" koanf:"profiles"`
}

// JudgeGlobalConfig defines the default LLM judge used across probes and detectors.
// This eliminates config duplication: probes (PAIR, TAP) and detectors (judge.Judge,
// judge.Refusal) both inherit from this section, with per-component overrides available.
type JudgeGlobalConfig struct {
	GeneratorType string         `yaml:"generator_type,omitempty" koanf:"generator_type"`
	Model         string         `yaml:"model,omitempty" koanf:"model"`
	Config        map[string]any `yaml:"config,omitempty" koanf:"config"`
}

// Profile represents a named configuration profile
type Profile struct {
	Run        RunConfig                  `yaml:"run"`
	Generators map[string]GeneratorConfig `yaml:"generators,omitempty"`
	Judge      JudgeGlobalConfig          `yaml:"judge,omitempty"`
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
	Model       string         `yaml:"model" koanf:"model"`
	Temperature float64        `yaml:"temperature" koanf:"temperature" validate:"gte=0,lte=2"`
	APIKey      string         `yaml:"api_key,omitempty" koanf:"api_key"`
	RateLimit   float64        `yaml:"rate_limit,omitempty" koanf:"rate_limit" validate:"gte=0"` // Requests per second
	Extra       map[string]any `yaml:",inline" koanf:",remain"`
}

// ToRegistryConfig converts GeneratorConfig to a registry config map,
// including both typed fields and Extra fields. Extra fields override typed fields if present.
func (g GeneratorConfig) ToRegistryConfig() map[string]any {
	cfg := make(map[string]any)

	// Layer 1: Add typed fields
	cfg["model"] = g.Model
	cfg["temperature"] = g.Temperature
	if g.APIKey != "" {
		cfg["api_key"] = g.APIKey
	}
	if g.RateLimit != 0 {
		cfg["rate_limit"] = g.RateLimit
	}

	// Layer 2: Add Extra fields (overrides typed fields if present)
	for k, v := range g.Extra {
		cfg[k] = v
	}

	return cfg
}

// ProbeConfig contains probe-specific configuration
type ProbeConfig struct {
	Encoding              EncodingProbeConfig        `yaml:"encoding"`
	AttackerGeneratorType string                     `yaml:"attacker_generator_type,omitempty" koanf:"attacker_generator_type"`
	AttackerConfig        map[string]any             `yaml:"attacker_config,omitempty" koanf:"attacker_config"`
	JudgeGeneratorType    string                     `yaml:"judge_generator_type,omitempty" koanf:"judge_generator_type"`
	JudgeConfig           map[string]any             `yaml:"judge_config,omitempty" koanf:"judge_config"`
	Settings              map[string]map[string]any  `yaml:"settings,omitempty" koanf:"settings"`
}

// EncodingProbeConfig contains encoding probe configuration
type EncodingProbeConfig struct {
	Enabled bool `yaml:"enabled"`
}

// DetectorConfig contains detector-specific configuration
type DetectorConfig struct {
	Always   AlwaysDetectorConfig       `yaml:"always"`
	Settings map[string]map[string]any  `yaml:"settings,omitempty" koanf:"settings"`
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

// injectJudgeConfig injects global judge config into a registry config map.
// typeKey and configKey are parameterized because probes use "judge_config"
// while detectors use "judge_generator_config" for the generator's config map.
func (c *Config) injectJudgeConfig(cfg map[string]any, typeKey, configKey string) {
	if c.Judge.GeneratorType != "" {
		cfg[typeKey] = c.Judge.GeneratorType
	}
	if c.Judge.Model != "" || len(c.Judge.Config) > 0 {
		genCfg := make(map[string]any)
		if c.Judge.Model != "" {
			genCfg["model"] = c.Judge.Model
		}
		for k, v := range c.Judge.Config {
			genCfg[k] = v
		}
		cfg[configKey] = genCfg
	}
}

// ResolveProbeConfig builds a registry config for a specific probe by merging
// global judge defaults, probe-level attacker/judge defaults, and per-probe settings.
// Resolution order: global judge → probe-level globals → per-probe settings.
func (c *Config) ResolveProbeConfig(probeName string) map[string]any {
	cfg := make(map[string]any)

	// Layer 0: Global judge config (lowest priority fallback)
	c.injectJudgeConfig(cfg, "judge_generator_type", "judge_config")

	// Layer 1: Global attacker/judge config from probes section (overrides global judge)
	if c.Probes.AttackerGeneratorType != "" {
		cfg["attacker_generator_type"] = c.Probes.AttackerGeneratorType
	}
	if c.Probes.AttackerConfig != nil {
		cfg["attacker_config"] = c.Probes.AttackerConfig
	}
	if c.Probes.JudgeGeneratorType != "" {
		cfg["judge_generator_type"] = c.Probes.JudgeGeneratorType
	}
	if c.Probes.JudgeConfig != nil {
		cfg["judge_config"] = c.Probes.JudgeConfig
	}

	// Layer 2: Per-probe settings override globals
	if c.Probes.Settings != nil {
		if settings, ok := c.Probes.Settings[probeName]; ok {
			for k, v := range settings {
				cfg[k] = v
			}
		}
	}

	return cfg
}

// ResolveDetectorConfig builds a registry config for a specific detector by merging
// global judge defaults with per-detector settings from the Settings map.
// Resolution order: global judge → per-detector settings.
func (c *Config) ResolveDetectorConfig(detectorName string) map[string]any {
	cfg := make(map[string]any)

	// Layer 0: Global judge config (inherited by all detectors; non-judge detectors ignore these keys)
	c.injectJudgeConfig(cfg, "judge_generator_type", "judge_generator_config")

	// Layer 1: Per-detector settings override globals
	if c.Detectors.Settings != nil {
		if settings, ok := c.Detectors.Settings[detectorName]; ok {
			for k, v := range settings {
				cfg[k] = v
			}
		}
	}

	return cfg
}

// ResolveBuffConfig builds a registry config for a specific buff
// from per-buff settings in the Settings map.
func (c *Config) ResolveBuffConfig(buffName string) map[string]any {
	cfg := make(map[string]any)

	if c.Buffs.Settings != nil {
		if settings, ok := c.Buffs.Settings[buffName]; ok {
			for k, v := range settings {
				cfg[k] = v
			}
		}
	}

	return cfg
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

	// Validate timeout format if provided
	if c.Run.Timeout != "" {
		if _, err := time.ParseDuration(c.Run.Timeout); err != nil {
			return fmt.Errorf("invalid run.timeout: %w", err)
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

	// Merge judge config
	if other.Judge.GeneratorType != "" {
		c.Judge.GeneratorType = other.Judge.GeneratorType
	}
	if other.Judge.Model != "" {
		c.Judge.Model = other.Judge.Model
	}
	if len(other.Judge.Config) > 0 {
		if c.Judge.Config == nil {
			c.Judge.Config = make(map[string]any)
		}
		for k, v := range other.Judge.Config {
			c.Judge.Config[k] = v
		}
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
		Judge:      profile.Judge,
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
