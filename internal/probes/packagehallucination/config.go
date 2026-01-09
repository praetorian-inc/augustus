package packagehallucination

import (
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the PackageHallucination probe.
type Config struct {
	// Language is the programming language ecosystem (python, npm, go).
	Language string

	// TaskType is the optional task type (security, web, data).
	TaskType string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Language: "python",
		TaskType: "",
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: language (defaults to python)
	cfg.Language = registry.GetString(m, "language", cfg.Language)

	// Optional: task_type
	cfg.TaskType = registry.GetString(m, "task_type", cfg.TaskType)

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithLanguage sets the programming language ecosystem.
func WithLanguage(lang string) Option {
	return func(c *Config) {
		c.Language = lang
	}
}

// WithTaskType sets the task type.
func WithTaskType(taskType string) Option {
	return func(c *Config) {
		c.TaskType = taskType
	}
}
