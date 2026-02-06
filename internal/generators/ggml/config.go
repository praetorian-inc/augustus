package ggml

import (
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds configuration for GGML generator.
type Config struct {
	// ModelPath is the path to the GGUF model file.
	ModelPath string

	// GgmlMainPath is the path to the ggml executable (e.g., llama.cpp main).
	GgmlMainPath string

	// Optional generation parameters
	Temperature    float64
	TopK           int
	TopP           float64
	MaxTokens      int
	RepeatPenalty  float64
	ExtraFlags     []string
}

// DefaultConfig returns a Config with default values matching garak's defaults.
func DefaultConfig() Config {
	return Config{
		Temperature:   0.8,
		TopK:          40,
		TopP:          0.95,
		RepeatPenalty: 1.1,
	}
}

// ConfigFromMap creates a typed Config from legacy registry.Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Model path (required)
	if modelPath, ok := m["model"].(string); ok && modelPath != "" {
		cfg.ModelPath = modelPath
	}

	// GGML executable path (from config or env)
	if ggmlPath, ok := m["ggml_main_path"].(string); ok && ggmlPath != "" {
		cfg.GgmlMainPath = ggmlPath
	} else if envPath := os.Getenv("GGML_MAIN_PATH"); envPath != "" {
		cfg.GgmlMainPath = envPath
	}

	// Optional generation parameters
	if temp, ok := m["temperature"].(float64); ok {
		cfg.Temperature = temp
	}

	if topK, ok := m["top_k"].(int); ok {
		cfg.TopK = topK
	} else if topK, ok := m["top_k"].(float64); ok {
		cfg.TopK = int(topK)
	}

	if topP, ok := m["top_p"].(float64); ok {
		cfg.TopP = topP
	}

	if maxTokens, ok := m["max_tokens"].(int); ok {
		cfg.MaxTokens = maxTokens
	} else if maxTokens, ok := m["max_tokens"].(float64); ok {
		cfg.MaxTokens = int(maxTokens)
	}

	if repeatPenalty, ok := m["repeat_penalty"].(float64); ok {
		cfg.RepeatPenalty = repeatPenalty
	}

	if flags, ok := m["extra_ggml_flags"].([]string); ok {
		cfg.ExtraFlags = flags
	}

	return cfg, nil
}

// Validate checks that required configuration is present.
func (c Config) Validate() error {
	if c.ModelPath == "" {
		return fmt.Errorf("ggml generator requires 'model' path")
	}
	if c.GgmlMainPath == "" {
		return fmt.Errorf("ggml generator requires executable path (GGML_MAIN_PATH)")
	}
	return nil
}

// Option is a functional option for configuring GGML generator.
type Option func(*Config)

// WithModelPath sets the model file path.
func WithModelPath(path string) Option {
	return func(c *Config) {
		c.ModelPath = path
	}
}

// WithGgmlMainPath sets the ggml executable path.
func WithGgmlMainPath(path string) Option {
	return func(c *Config) {
		c.GgmlMainPath = path
	}
}

// WithTemperature sets the temperature parameter.
func WithTemperature(temp float64) Option {
	return func(c *Config) {
		c.Temperature = temp
	}
}

// WithTopK sets the top-k parameter.
func WithTopK(topK int) Option {
	return func(c *Config) {
		c.TopK = topK
	}
}

// WithTopP sets the top-p parameter.
func WithTopP(topP float64) Option {
	return func(c *Config) {
		c.TopP = topP
	}
}

// WithMaxTokens sets the max tokens parameter.
func WithMaxTokens(maxTokens int) Option {
	return func(c *Config) {
		c.MaxTokens = maxTokens
	}
}

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}
