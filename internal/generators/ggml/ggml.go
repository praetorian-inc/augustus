// Package ggml provides a GGML generator for Augustus.
//
// This package implements the Generator interface for GGML models in GGUF format,
// such as llama.cpp. It executes models via subprocess calls to the ggml executable.
//
// GGML models run locally, making them ideal for:
//   - Privacy-sensitive testing (no data leaves your machine)
//   - Cost-free testing after hardware investment
//   - Offline development and testing
//
// Configuration requires:
//   - ModelPath: Path to the GGUF model file
//   - GgmlMainPath: Path to the ggml executable (e.g., llama.cpp main binary)
//
// Configuration can be provided via:
//   - Direct configuration (Config struct or functional options)
//   - Environment variable GGML_MAIN_PATH for executable path
//   - Legacy registry.Config for backward compatibility
package ggml

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("ggml.Ggml", NewGgml)
}

// GGUF magic bytes for format validation.
var ggufMagic = []byte{0x47, 0x47, 0x55, 0x46}

// Ggml is a generator that executes GGML models via subprocess.
type Ggml struct {
	ggmlMainPath string
	modelPath    string

	// Generation parameters
	temperature   float64
	topK          int
	topP          float64
	maxTokens     int
	repeatPenalty float64
	extraFlags    []string
}

// NewGgml creates a new GGML generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewGgml(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewGgmlTyped(cfg)
}

// NewGgmlTyped creates a new GGML generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewGgmlTyped(cfg Config) (*Ggml, error) {
	// Apply defaults if not set
	defaults := DefaultConfig()
	if cfg.Temperature == 0 {
		cfg.Temperature = defaults.Temperature
	}
	if cfg.TopK == 0 {
		cfg.TopK = defaults.TopK
	}
	if cfg.TopP == 0 {
		cfg.TopP = defaults.TopP
	}
	if cfg.RepeatPenalty == 0 {
		cfg.RepeatPenalty = defaults.RepeatPenalty
	}

	// Load from environment if config is empty
	if cfg.GgmlMainPath == "" {
		cfg.GgmlMainPath = os.Getenv("GGML_MAIN_PATH")
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Validate executable exists
	if _, err := os.Stat(cfg.GgmlMainPath); err != nil {
		return nil, fmt.Errorf("ggml executable not found: %w", err)
	}

	// Validate model file exists
	if _, err := os.Stat(cfg.ModelPath); err != nil {
		return nil, fmt.Errorf("model file not found: %w", err)
	}

	// Validate GGUF magic bytes
	if err := validateGgufFormat(cfg.ModelPath); err != nil {
		return nil, err
	}

	g := &Ggml{
		ggmlMainPath:  cfg.GgmlMainPath,
		modelPath:     cfg.ModelPath,
		temperature:   cfg.Temperature,
		topK:          cfg.TopK,
		topP:          cfg.TopP,
		maxTokens:     cfg.MaxTokens,
		repeatPenalty: cfg.RepeatPenalty,
		extraFlags:    cfg.ExtraFlags,
	}

	return g, nil
}

// NewGgmlWithOptions creates a new GGML generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//   g, err := NewGgmlWithOptions(
//       WithModelPath("/path/to/model.gguf"),
//       WithGgmlMainPath("/path/to/llama.cpp/main"),
//       WithTemperature(0.7),
//   )
func NewGgmlWithOptions(opts ...Option) (*Ggml, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewGgmlTyped(cfg)
}

// validateGgufFormat checks that the file has valid GGUF magic bytes.
func validateGgufFormat(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open model file: %w", err)
	}
	defer f.Close()

	magic := make([]byte, len(ggufMagic))
	n, err := f.Read(magic)
	if err != nil {
		return fmt.Errorf("failed to read model file header: %w", err)
	}

	if n != len(ggufMagic) {
		return fmt.Errorf("model file too small to be GGUF format")
	}

	for i := range ggufMagic {
		if magic[i] != ggufMagic[i] {
			return fmt.Errorf("model file is not in GGUF format (invalid magic bytes)")
		}
	}

	return nil
}

// Generate sends the conversation to the GGML model and returns responses.
func (g *Ggml) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Get the last prompt from the conversation
	prompt := conv.LastPrompt()

	// GGML doesn't support n parameter, so we call multiple times
	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		msg, err := g.callGgml(ctx, prompt)
		if err != nil {
			return nil, err
		}
		responses = append(responses, msg)
	}

	return responses, nil
}

// callGgml makes a single call to the ggml executable.
func (g *Ggml) callGgml(ctx context.Context, prompt string) (attempt.Message, error) {
	// Build command arguments
	args := []string{
		"-m", g.modelPath,
		"-p", prompt,
	}

	// Add optional parameters if set
	if g.maxTokens > 0 {
		args = append(args, "-n", strconv.Itoa(g.maxTokens))
	}
	if g.temperature != 0 {
		args = append(args, "--temp", strconv.FormatFloat(g.temperature, 'f', -1, 64))
	}
	if g.topK > 0 {
		args = append(args, "--top-k", strconv.Itoa(g.topK))
	}
	if g.topP != 0 {
		args = append(args, "--top-p", strconv.FormatFloat(g.topP, 'f', -1, 64))
	}
	if g.repeatPenalty != 0 {
		args = append(args, "--repeat-penalty", strconv.FormatFloat(g.repeatPenalty, 'f', -1, 64))
	}

	// Add extra flags
	args = append(args, g.extraFlags...)

	// Execute command
	cmd := exec.CommandContext(ctx, g.ggmlMainPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return attempt.Message{}, fmt.Errorf("ggml: execution failed: %w (output: %s)", err, string(output))
	}

	// Extract response (strip the original prompt from output)
	response := strings.TrimSpace(string(output))
	response = strings.TrimPrefix(response, strings.TrimSpace(prompt))
	response = strings.TrimSpace(response)

	return attempt.NewAssistantMessage(response), nil
}

// ClearHistory is a no-op for GGML generator (stateless per call).
func (g *Ggml) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Ggml) Name() string {
	return "ggml.Ggml"
}

// Description returns a human-readable description.
func (g *Ggml) Description() string {
	return "ggml generator for local GGUF models (llama.cpp and compatible)"
}
