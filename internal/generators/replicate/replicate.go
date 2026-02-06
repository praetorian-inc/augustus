// Package replicate provides a Replicate generator for Augustus.
//
// This package implements the Generator interface for Replicate's model hosting
// platform. It supports both public models (meta/llama-2-7b-chat) and private
// deployments.
//
// Replicate is an API for running open-source AI models. Models are specified
// using the format "owner/model-name" or "owner/model-name:version".
//
// Configuration:
//   - model: Required. Model identifier (e.g., "meta/llama-2-7b-chat")
//   - api_key: API token (or set REPLICATE_API_TOKEN env var)
//   - temperature: Sampling temperature (default: 1.0)
//   - top_p: Nucleus sampling (default: 1.0)
//   - repetition_penalty: Repetition penalty (default: 1.0)
//   - max_tokens: Maximum output tokens (default: model-specific)
//   - seed: Random seed for reproducibility (default: 9)
//   - base_url: Custom API endpoint (for testing/proxies)
package replicate

import (
	"context"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	replicatego "github.com/replicate/replicate-go"
)

// Environment variable name for API token (matches Python garak)
const envVarName = "REPLICATE_API_TOKEN"

func init() {
	generators.Register("replicate.Replicate", NewReplicate)
}

// Replicate is a generator that wraps the Replicate API.
type Replicate struct {
	client *replicatego.Client
	model  string

	// Configuration parameters (matching Python garak defaults)
	temperature       float32
	topP              float32
	repetitionPenalty float32
	maxTokens         int
	seed              int
}

// NewReplicate creates a new Replicate generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewReplicate(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewReplicateTyped(cfg)
}

// NewReplicateTyped creates a new Replicate generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewReplicateTyped(cfg Config) (*Replicate, error) {
	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("replicate generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("replicate generator requires api_key")
	}

	g := &Replicate{
		model:             cfg.Model,
		temperature:       cfg.Temperature,
		topP:              cfg.TopP,
		repetitionPenalty: cfg.RepetitionPenalty,
		maxTokens:         cfg.MaxTokens,
		seed:              cfg.Seed,
	}

	// Build client options
	opts := []replicatego.ClientOption{
		replicatego.WithToken(cfg.APIKey),
	}

	// Optional: custom base URL (for testing)
	if cfg.BaseURL != "" {
		opts = append(opts, replicatego.WithBaseURL(cfg.BaseURL))
	}

	// Create client
	client, err := replicatego.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("replicate: failed to create client: %w", err)
	}
	g.client = client

	return g, nil
}

// NewReplicateWithOptions creates a new Replicate generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//
//	g, err := NewReplicateWithOptions(
//	    WithModel("meta/llama-2-7b-chat"),
//	    WithAPIKey("..."),
//	    WithTemperature(0.8),
//	)
func NewReplicateWithOptions(opts ...Option) (*Replicate, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewReplicateTyped(cfg)
}

// Generate sends the conversation to Replicate and returns responses.
// Replicate doesn't support multiple generations in one call (supports_multiple_generations = False),
// so we loop n times.
func (g *Replicate) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Get the last prompt (Python uses prompt.last_message().text)
	prompt := conv.LastPrompt()
	if prompt == "" {
		return nil, fmt.Errorf("replicate: conversation has no prompts")
	}

	// Build input parameters (matching Python garak _call_model)
	input := replicatego.PredictionInput{
		"prompt":             prompt,
		"temperature":        float64(g.temperature),
		"top_p":              float64(g.topP),
		"repetition_penalty": float64(g.repetitionPenalty),
		"seed":               g.seed,
	}

	// Only include max_length if set (Python uses max_tokens but sends as max_length)
	if g.maxTokens > 0 {
		input["max_length"] = g.maxTokens
	}

	// Generate n responses (Replicate doesn't support batch generation)
	responses := make([]attempt.Message, 0, n)
	for i := 0; i < n; i++ {
		output, err := g.client.Run(ctx, g.model, input, nil)
		if err != nil {
			return nil, g.wrapError(err)
		}

		// Process output - can be string or []string or []any
		text := g.extractText(output)
		responses = append(responses, attempt.NewAssistantMessage(text))
	}

	return responses, nil
}

// extractText converts Replicate output to a string.
// Output can be:
// - string: return as-is
// - []string: join all elements
// - []any: join string elements
func (g *Replicate) extractText(output replicatego.PredictionOutput) string {
	switch v := output.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, "")
	case []any:
		var parts []string
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "")
	default:
		// Fallback: convert to string representation
		return fmt.Sprintf("%v", output)
	}
}

// wrapError wraps Replicate API errors with more context.
func (g *Replicate) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*replicatego.APIError); ok {
		return fmt.Errorf("replicate: API error (status %d): %w", apiErr.Status, err)
	}

	// Check for context errors
	if ctx := context.Cause(context.Background()); ctx != nil {
		return fmt.Errorf("replicate: %w", err)
	}

	return fmt.Errorf("replicate: %w", err)
}

// ClearHistory is a no-op for Replicate generator (stateless per call).
func (g *Replicate) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Replicate) Name() string {
	return "replicate.Replicate"
}

// Description returns a human-readable description.
func (g *Replicate) Description() string {
	return "Replicate API generator for running open-source AI models (Llama, Mistral, etc.)"
}
