package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadConfig loads and merges configuration files in hierarchical order
// Later configs override earlier ones: base → site → run → CLI
func LoadConfig(paths ...string) (*Config, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("no configuration files provided")
	}

	var result *Config

	// Load and merge each config file in order
	for _, path := range paths {
		cfg, err := loadSingleConfig(path)
		if err != nil {
			return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
		}

		if result == nil {
			result = cfg
		} else {
			result.Merge(cfg)
		}
	}

	// Interpolate environment variables
	if err := interpolateConfigEnvVars(result); err != nil {
		return nil, fmt.Errorf("failed to interpolate environment variables: %w", err)
	}

	// Validate the merged config
	if err := result.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return result, nil
}

// LoadConfigWithProfile loads a config file and applies a named profile
func LoadConfigWithProfile(path string, profileName string) (*Config, error) {
	cfg, err := loadSingleConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to load config from %s: %w", path, err)
	}

	// Apply the profile
	if err := cfg.ApplyProfile(profileName); err != nil {
		return nil, fmt.Errorf("failed to apply profile %q: %w", profileName, err)
	}

	// Interpolate environment variables
	if err := interpolateConfigEnvVars(cfg); err != nil {
		return nil, fmt.Errorf("failed to interpolate environment variables: %w", err)
	}

	// Validate the config
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

// loadSingleConfig loads a single YAML configuration file
func loadSingleConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml: %w", err)
	}

	return &cfg, nil
}

// interpolateMapEnvVars recursively interpolates env vars in map[string]any values
func interpolateMapEnvVars(m map[string]any, getenv func(string) (string, bool)) error {
	for k, v := range m {
		switch val := v.(type) {
		case string:
			interpolated, err := interpolateEnvVars(val, getenv)
			if err != nil {
				return err
			}
			m[k] = interpolated
		case map[string]any:
			if err := interpolateMapEnvVars(val, getenv); err != nil {
				return err
			}
		}
	}
	return nil
}

// interpolateConfigEnvVars interpolates environment variables in all string fields
func interpolateConfigEnvVars(cfg *Config) error {
	getenv := func(key string) (string, bool) {
		val := os.Getenv(key)
		if val == "" {
			return "", false
		}
		return val, true
	}

	// Interpolate run config
	if cfg.Run.Timeout != "" {
		timeout, err := interpolateEnvVars(cfg.Run.Timeout, getenv)
		if err != nil {
			return err
		}
		cfg.Run.Timeout = timeout
	}

	// Interpolate generator configs
	for name, gen := range cfg.Generators {
		if gen.Model != "" {
			model, err := interpolateEnvVars(gen.Model, getenv)
			if err != nil {
				return err
			}
			gen.Model = model
		}
		if gen.APIKey != "" {
			apiKey, err := interpolateEnvVars(gen.APIKey, getenv)
			if err != nil {
				return err
			}
			gen.APIKey = apiKey
		}
		cfg.Generators[name] = gen
	}

	// Interpolate judge config
	if cfg.Judge.Config != nil {
		if err := interpolateMapEnvVars(cfg.Judge.Config, getenv); err != nil {
			return err
		}
	}

	// Interpolate output config
	if cfg.Output.Path != "" {
		path, err := interpolateEnvVars(cfg.Output.Path, getenv)
		if err != nil {
			return err
		}
		cfg.Output.Path = path
	}
	if cfg.Output.Format != "" {
		format, err := interpolateEnvVars(cfg.Output.Format, getenv)
		if err != nil {
			return err
		}
		cfg.Output.Format = format
	}

	// Interpolate nested probe config maps
	if cfg.Probes.AttackerConfig != nil {
		if err := interpolateMapEnvVars(cfg.Probes.AttackerConfig, getenv); err != nil {
			return err
		}
	}
	if cfg.Probes.JudgeConfig != nil {
		if err := interpolateMapEnvVars(cfg.Probes.JudgeConfig, getenv); err != nil {
			return err
		}
	}
	if cfg.Probes.Settings != nil {
		for _, settings := range cfg.Probes.Settings {
			if err := interpolateMapEnvVars(settings, getenv); err != nil {
				return err
			}
		}
	}

	// Interpolate nested detector settings
	if cfg.Detectors.Settings != nil {
		for _, settings := range cfg.Detectors.Settings {
			if err := interpolateMapEnvVars(settings, getenv); err != nil {
				return err
			}
		}
	}

	// Interpolate nested buff settings
	if cfg.Buffs.Settings != nil {
		for _, settings := range cfg.Buffs.Settings {
			if err := interpolateMapEnvVars(settings, getenv); err != nil {
				return err
			}
		}
	}

	return nil
}
