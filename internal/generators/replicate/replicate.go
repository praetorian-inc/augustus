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
	"os"
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

// NewReplicate creates a new Replicate generator from configuration.
func NewReplicate(cfg registry.Config) (generators.Generator, error) {
	g := &Replicate{
		// Python garak defaults from ReplicateGenerator.DEFAULT_PARAMS
		temperature:       1.0,
		topP:              1.0,
		repetitionPenalty: 1.0,
		seed:              9, // Python default seed
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("replicate generator requires 'model' configuration")
	}
	g.model = model

	// API key: from config or env var
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv(envVarName)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("replicate generator requires 'api_key' configuration or %s environment variable", envVarName)
	}

	// Build client options
	opts := []replicatego.ClientOption{
		replicatego.WithToken(apiKey),
	}

	// Optional: custom base URL (for testing)
	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		opts = append(opts, replicatego.WithBaseURL(baseURL))
	}

	// Create client
	client, err := replicatego.NewClient(opts...)
	if err != nil {
		return nil, fmt.Errorf("replicate: failed to create client: %w", err)
	}
	g.client = client

	// Optional: temperature
	if temp, ok := cfg["temperature"].(float64); ok {
		g.temperature = float32(temp)
	}

	// Optional: top_p
	if topP, ok := cfg["top_p"].(float64); ok {
		g.topP = float32(topP)
	}

	// Optional: repetition_penalty
	if repPenalty, ok := cfg["repetition_penalty"].(float64); ok {
		g.repetitionPenalty = float32(repPenalty)
	}

	// Optional: max_tokens
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	// Optional: seed
	if seed, ok := cfg["seed"].(int); ok {
		g.seed = seed
	} else if seed, ok := cfg["seed"].(float64); ok {
		g.seed = int(seed)
	}

	return g, nil
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

		// Process output - can be string or []string or []interface{}
		text := g.extractText(output)
		responses = append(responses, attempt.NewAssistantMessage(text))
	}

	return responses, nil
}

// extractText converts Replicate output to a string.
// Output can be:
// - string: return as-is
// - []string: join all elements
// - []interface{}: join string elements
func (g *Replicate) extractText(output replicatego.PredictionOutput) string {
	switch v := output.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, "")
	case []interface{}:
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
