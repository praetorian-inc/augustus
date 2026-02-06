package config

import (
	"fmt"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// LoadConfigKoanf loads configuration using Koanf with proper precedence:
// CLI Flags > Environment Variables > Config File > Defaults
func LoadConfigKoanf(configPath string) (*Config, error) {
	k := koanf.New(".")

	// 1. Load YAML config file (lowest priority)
	if configPath != "" {
		if err := k.Load(file.Provider(configPath), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("failed to load config file %s: %w", configPath, err)
		}
	}

	// 2. Load environment variables (higher priority)
	// AUGUSTUS_RUN__TIMEOUT -> run.timeout (double underscore becomes dot)
	// AUGUSTUS_RUN__MAX_ATTEMPTS -> run.max_attempts (single underscore preserved)
	// AUGUSTUS_OUTPUT__FORMAT -> output.format
	err := k.Load(env.Provider("AUGUSTUS_", ".", func(s string) string {
		s = strings.TrimPrefix(s, "AUGUSTUS_")
		s = strings.Replace(s, "__", ".", -1) // Only double underscores become dots
		s = strings.ToLower(s)
		return s
	}), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load environment variables: %w", err)
	}

	// 3. Unmarshal to struct
	var cfg Config
	if err := k.UnmarshalWithConf("", &cfg, koanf.UnmarshalConf{
		Tag: "koanf", // Use koanf tags that match env var transformation
	}); err != nil {
		return nil, fmt.Errorf("config unmarshal failed: %w", err)
	}

	// 4. Validate using validator library for struct tags
	v := validator.New()
	if err := v.Struct(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	// 5. Validate using custom validation method
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return &cfg, nil
}
