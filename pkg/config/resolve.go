package config

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/scanner"
)

// CLIOverrides captures CLI flag values that may override YAML config.
// Pointer fields (nil = not set by user) enable correct precedence:
// Kong populates defaults, but nil means "user didn't explicitly pass this flag".
type CLIOverrides struct {
	GeneratorName string
	ConfigJSON    string
	Concurrency   *int
	Timeout       *time.Duration
	ProbeTimeout  *time.Duration
	OutputFormat  string
	OutputFile    string
	HTMLFile      string
	ProfileName   string
}

// ResolvedConfig holds fully-resolved, ready-to-use configuration.
// Every field has a definitive value. No nil checks needed by callers.
type ResolvedConfig struct {
	ScannerOpts     scanner.Options
	GeneratorConfig registry.Config
	OutputFormat    string
	OutputFile      string
	HTMLFile        string
}

// Resolve produces fully-resolved configuration by applying the
// precedence chain: defaults -> YAML config -> CLI overrides.
func Resolve(yamlCfg *Config, cli CLIOverrides) (*ResolvedConfig, error) {
	resolved := &ResolvedConfig{}

	// Apply profile if requested
	if cli.ProfileName != "" && yamlCfg != nil {
		if err := yamlCfg.ApplyProfile(cli.ProfileName); err != nil {
			return nil, fmt.Errorf("applying profile: %w", err)
		}
	}

	// Phase 1: Scanner options (defaults -> YAML -> CLI)
	opts := scanner.DefaultOptions()
	if yamlCfg != nil {
		if err := applyYAMLRunConfig(&opts, yamlCfg.Run); err != nil {
			return nil, fmt.Errorf("resolving run config: %w", err)
		}
	}
	if cli.Concurrency != nil {
		opts.Concurrency = *cli.Concurrency
	}
	if cli.Timeout != nil {
		opts.Timeout = *cli.Timeout
	}
	if cli.ProbeTimeout != nil {
		opts.ProbeTimeout = *cli.ProbeTimeout
	}
	resolved.ScannerOpts = opts

	// Phase 2: Generator config (YAML -> CLI JSON overlay)
	genConfig, err := resolveGeneratorConfig(yamlCfg, cli)
	if err != nil {
		return nil, fmt.Errorf("resolving generator config: %w", err)
	}
	resolved.GeneratorConfig = genConfig

	// Phase 3: Output config (defaults -> YAML -> CLI)
	resolved.OutputFormat = resolveString("table", yamlGet(yamlCfg, func(c *Config) string { return c.Output.Format }), cli.OutputFormat)
	resolved.OutputFile = resolveString("", yamlGet(yamlCfg, func(c *Config) string { return c.Output.Path }), cli.OutputFile)
	resolved.HTMLFile = cli.HTMLFile

	return resolved, nil
}

// applyYAMLRunConfig overlays YAML run section onto scanner options.
func applyYAMLRunConfig(opts *scanner.Options, run RunConfig) error {
	if run.Timeout != "" {
		d, err := time.ParseDuration(run.Timeout)
		if err != nil {
			return fmt.Errorf("invalid run.timeout %q: %w", run.Timeout, err)
		}
		opts.Timeout = d
	}
	if run.Concurrency > 0 {
		opts.Concurrency = run.Concurrency
	}
	if run.ProbeTimeout != "" {
		d, err := time.ParseDuration(run.ProbeTimeout)
		if err != nil {
			return fmt.Errorf("invalid run.probe_timeout %q: %w", run.ProbeTimeout, err)
		}
		opts.ProbeTimeout = d
	}
	if run.MaxAttempts > 0 {
		opts.RetryCount = run.MaxAttempts
	}
	return nil
}

// resolveGeneratorConfig builds registry.Config for the generator.
func resolveGeneratorConfig(yamlCfg *Config, cli CLIOverrides) (registry.Config, error) {
	genConfig := registry.Config{}

	// YAML layer: full passthrough via ToRegistryConfig()
	if yamlCfg != nil {
		if gen, exists := yamlCfg.Generators[cli.GeneratorName]; exists {
			genConfig = gen.ToRegistryConfig()
		}
	}

	// CLI JSON overlay
	if cli.ConfigJSON != "" {
		var overlay registry.Config
		if err := json.Unmarshal([]byte(cli.ConfigJSON), &overlay); err != nil {
			return nil, fmt.Errorf("invalid config JSON: %w", err)
		}
		for k, v := range overlay {
			genConfig[k] = v
		}
	}

	return genConfig, nil
}

// resolveString returns the highest-precedence non-empty string.
func resolveString(defaultVal, yamlVal, cliVal string) string {
	result := defaultVal
	if yamlVal != "" {
		result = yamlVal
	}
	if cliVal != "" {
		result = cliVal
	}
	return result
}

// yamlGet safely extracts a value from Config, returning "" if cfg is nil.
func yamlGet(cfg *Config, fn func(*Config) string) string {
	if cfg == nil {
		return ""
	}
	return fn(cfg)
}
