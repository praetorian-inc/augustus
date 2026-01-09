// Package ragpoison provides detectors for RAG (Retrieval-Augmented Generation) poisoning attacks.
package ragpoison

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds typed configuration for the RAG Poison detector.
type Config struct {
	// Required
	ExpectedAnswer string

	// Optional with defaults
	Threshold float64 // Default: 0.8
}

// DefaultRAGPoisonConfig returns a config with sensible defaults.
func DefaultRAGPoisonConfig() Config {
	return Config{
		Threshold: 0.8, // Match default in ragpoison.go
	}
}

// RAGPoisonConfigFromMap parses registry.Config into typed config.
func RAGPoisonConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultRAGPoisonConfig()

	// Required: expected_answer
	expectedAnswer, err := registry.RequireString(m, "expected_answer")
	if err != nil {
		return cfg, fmt.Errorf("ragpoison detector requires 'expected_answer' in config")
	}
	cfg.ExpectedAnswer = expectedAnswer

	// Optional: threshold
	cfg.Threshold = registry.GetFloat64(m, "threshold", cfg.Threshold)

	return cfg, nil
}

// RAGPoisonOption is a functional option for RAGPoisonConfig.
type RAGPoisonOption = registry.Option[Config]

// ApplyRAGPoisonOptions applies options to a config.
func ApplyRAGPoisonOptions(cfg Config, opts ...RAGPoisonOption) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithExpectedAnswer sets the expected poisoned answer.
func WithExpectedAnswer(answer string) RAGPoisonOption {
	return func(c *Config) {
		c.ExpectedAnswer = answer
	}
}

// WithThreshold sets the similarity threshold.
func WithThreshold(threshold float64) RAGPoisonOption {
	return func(c *Config) {
		c.Threshold = threshold
	}
}
