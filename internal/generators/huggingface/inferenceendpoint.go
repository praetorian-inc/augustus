// Package huggingface provides generators using HuggingFace Inference API.
//
// This package implements the Generator interface for HuggingFace's custom
// Inference Endpoints. Unlike InferenceAPI, this POSTs directly to a custom
// endpoint URL without appending a model name.
package huggingface

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	libhttp "github.com/praetorian-inc/augustus/pkg/lib/http"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// DefaultEndpointTimeout is the default HTTP client timeout for endpoints.
	DefaultEndpointTimeout = 120 * time.Second
)

func init() {
	generators.Register("huggingface.InferenceEndpoint", NewInferenceEndpoint)
}

// InferenceEndpoint generates text using a custom HuggingFace Inference Endpoint.
type InferenceEndpoint struct {
	client      *libhttp.Client
	endpointURL string

	// Configuration
	maxTokens int
}

// NewInferenceEndpoint creates a new InferenceEndpoint generator from configuration.
func NewInferenceEndpoint(cfg registry.Config) (generators.Generator, error) {
	g := &InferenceEndpoint{}

	// Required: endpoint_url
	endpointURL, ok := cfg["endpoint_url"].(string)
	if !ok || endpointURL == "" {
		return nil, fmt.Errorf("huggingface.InferenceEndpoint requires 'endpoint_url' configuration")
	}
	g.endpointURL = endpointURL

	// Optional: api_key
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	}

	// Build HTTP client with options
	opts := []libhttp.Option{
		libhttp.WithTimeout(DefaultEndpointTimeout),
		libhttp.WithUserAgent("Augustus/1.0"),
	}

	if apiKey != "" {
		opts = append(opts, libhttp.WithBearerToken(apiKey))
	}

	g.client = libhttp.NewClient(opts...)

	// Optional: max_tokens
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	return g, nil
}

// Generate sends the conversation to the custom endpoint and returns responses.
func (g *InferenceEndpoint) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Inference Endpoints only support single generation
	if n > 1 {
		n = 1
	}

	// Build request payload
	payload := g.buildPayload(conv)

	// POST directly to endpoint URL (no model suffix)
	resp, err := g.client.Post(ctx, g.endpointURL, payload)
	if err != nil {
		return nil, fmt.Errorf("huggingface: endpoint request failed: %w", err)
	}

	// Handle errors
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		_ = resp.JSON(&errResp) // Intentionally ignore error; use fallback if parsing fails
		if errResp.Error != "" {
			return nil, fmt.Errorf("huggingface: endpoint error (status %d): %s", resp.StatusCode, errResp.Error)
		}
		return nil, fmt.Errorf("huggingface: endpoint error: status %d", resp.StatusCode)
	}

	// Parse successful response
	responses, err := g.parseResponse(resp)
	if err != nil {
		return nil, err
	}

	return responses, nil
}

// buildPayload constructs the endpoint API request payload.
func (g *InferenceEndpoint) buildPayload(conv *attempt.Conversation) map[string]any {
	payload := map[string]any{
		"messages":   g.conversationToMessages(conv),
		"parameters": map[string]any{},
	}

	// Add optional parameters
	params := payload["parameters"].(map[string]any)
	if g.maxTokens > 0 {
		params["max_new_tokens"] = g.maxTokens
	}

	return payload
}

// conversationToMessages converts an Augustus Conversation to HuggingFace message format.
func (g *InferenceEndpoint) conversationToMessages(conv *attempt.Conversation) []map[string]any {
	messages := make([]map[string]any, 0)

	// Add system message if present
	if conv.System != nil {
		messages = append(messages, map[string]any{
			"role":    "system",
			"content": conv.System.Content,
		})
	}

	// Add turns
	for _, turn := range conv.Turns {
		// Add user message
		messages = append(messages, map[string]any{
			"role":    "user",
			"content": turn.Prompt.Content,
		})

		// Add assistant response if present
		if turn.Response != nil {
			messages = append(messages, map[string]any{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	return messages
}

// parseResponse extracts messages from endpoint API response.
func (g *InferenceEndpoint) parseResponse(resp *libhttp.Response) ([]attempt.Message, error) {
	// Try parsing as array of objects with generated_text
	var results []struct {
		GeneratedText string `json:"generated_text"`
	}

	if err := resp.JSON(&results); err != nil {
		return nil, fmt.Errorf("huggingface: failed to parse endpoint response: %w", err)
	}

	messages := make([]attempt.Message, 0, len(results))
	for _, r := range results {
		messages = append(messages, attempt.NewAssistantMessage(r.GeneratedText))
	}

	return messages, nil
}

// ClearHistory is a no-op for InferenceEndpoint generator (stateless per call).
func (g *InferenceEndpoint) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *InferenceEndpoint) Name() string {
	return "huggingface.InferenceEndpoint"
}

// Description returns a human-readable description.
func (g *InferenceEndpoint) Description() string {
	return "HuggingFace Inference Endpoint generator for custom endpoints"
}
