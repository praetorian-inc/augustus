package poetry

import "github.com/praetorian-inc/augustus/pkg/registry"

// Config holds typed configuration for the HarmJudge detector.
type Config struct {
	// JudgeGenerator is the optional LLM generator name for harm classification.
	// If empty, the detector uses keyword fallback mode.
	JudgeGenerator string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		JudgeGenerator: "",
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: judge_generator
	cfg.JudgeGenerator = registry.GetString(m, "judge_generator", cfg.JudgeGenerator)

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithJudgeGenerator sets the judge generator name.
func WithJudgeGenerator(gen string) Option {
	return func(c *Config) {
		c.JudgeGenerator = gen
	}
}
