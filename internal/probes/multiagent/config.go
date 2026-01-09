package multiagent

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the Orchestrator Poison probe.
type Config struct {
	// Technique is the type of orchestrator poisoning attack.
	Technique PoisonTechnique
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Technique: TaskQueueInjection,
	}
}

// ParseTechnique parses a string into a PoisonTechnique.
func ParseTechnique(s string) (PoisonTechnique, error) {
	switch s {
	case "TaskQueueInjection":
		return TaskQueueInjection, nil
	case "PriorityManipulation":
		return PriorityManipulation, nil
	case "WorkerInstructions":
		return WorkerInstructions, nil
	case "ResultFiltering":
		return ResultFiltering, nil
	default:
		return TaskQueueInjection, fmt.Errorf("unknown poison technique: %s", s)
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
// This enables backward compatibility with YAML/JSON configuration.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Optional: technique (string or PoisonTechnique)
	if techniqueStr, ok := m["technique"].(string); ok {
		tech, err := ParseTechnique(techniqueStr)
		if err != nil {
			return cfg, err
		}
		cfg.Technique = tech
	} else if tech, ok := m["technique"].(PoisonTechnique); ok {
		cfg.Technique = tech
	}

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithTechnique sets the poison technique.
func WithTechnique(tech PoisonTechnique) Option {
	return func(c *Config) {
		c.Technique = tech
	}
}
