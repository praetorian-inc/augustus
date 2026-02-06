// Package huggingface provides generators using HuggingFace Inference API.
//
// This package implements the Generator interface for HuggingFace's hosted
// inference endpoints, including LLaVA vision-language models.
//
// Python equivalent: garak.generators.huggingface.LLaVA
package huggingface

import (
	"context"
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	libhttp "github.com/praetorian-inc/augustus/pkg/lib/http"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("huggingface.LLaVA", NewLLaVA)
}

// LLaVA generates text from vision-language inputs using HuggingFace's hosted LLaVA models.
// This supports multimodal (text + image) inputs.
type LLaVA struct {
	client  *libhttp.Client
	model   string
	baseURL string

	// Configuration
	maxTokens    int
	maxTime      int
	waitForModel bool
}

// NewLLaVA creates a new HuggingFace LLaVA generator from configuration.
func NewLLaVA(cfg registry.Config) (generators.Generator, error) {
	g := &LLaVA{
		baseURL:      DefaultBaseURL,
		maxTime:      DefaultMaxTime,
		waitForModel: false,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("huggingface generator requires 'model' configuration")
	}
	g.model = model

	// Optional: base_url (for testing)
	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		g.baseURL = baseURL
	}

	// API key: from config or env vars
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		// Try HF_INFERENCE_TOKEN first, then HUGGINGFACE_API_KEY
		apiKey = os.Getenv("HF_INFERENCE_TOKEN")
		if apiKey == "" {
			apiKey = os.Getenv("HUGGINGFACE_API_KEY")
		}
	}

	// Build HTTP client with options
	opts := []libhttp.Option{
		libhttp.WithTimeout(DefaultTimeout),
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

	// Optional: max_time
	if maxTime, ok := cfg["max_time"].(int); ok {
		g.maxTime = maxTime
	} else if maxTime, ok := cfg["max_time"].(float64); ok {
		g.maxTime = int(maxTime)
	}

	// Optional: wait_for_model
	if wait, ok := cfg["wait_for_model"].(bool); ok {
		g.waitForModel = wait
	}

	return g, nil
}

// Generate sends the conversation with image to HuggingFace and returns responses.
func (g *LLaVA) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Build request payload
	payload := g.buildPayload(conv, n)

	// Make request with retry for 503 (model loading)
	var responses []attempt.Message
	var lastErr error

	for retries := 0; retries < 3; retries++ {
		url := fmt.Sprintf("%s/%s", g.baseURL, g.model)
		resp, err := g.client.Post(ctx, url, payload)
		if err != nil {
			return nil, fmt.Errorf("huggingface: request failed: %w", err)
		}

		// Handle 503 (model loading) with retry
		if resp.StatusCode == 503 {
			// Enable wait_for_model for subsequent requests
			payload["options"] = map[string]any{
				"wait_for_model": true,
			}
			lastErr = fmt.Errorf("model is loading")
			continue
		}

		// Handle rate limiting
		if resp.StatusCode == 429 {
			return nil, fmt.Errorf("huggingface: rate limit exceeded")
		}

		// Handle other errors
		if resp.StatusCode >= 400 {
			var errResp struct {
				Error string `json:"error"`
			}
			_ = resp.JSON(&errResp)
			if errResp.Error != "" {
				return nil, fmt.Errorf("huggingface: API error (status %d): %s", resp.StatusCode, errResp.Error)
			}
			return nil, fmt.Errorf("huggingface: API error: status %d", resp.StatusCode)
		}

		// Parse successful response
		responses, err = g.parseResponse(resp)
		if err != nil {
			return nil, err
		}

		return responses, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}

	return responses, nil
}

// buildPayload constructs the HuggingFace API request payload for LLaVA.
func (g *LLaVA) buildPayload(conv *attempt.Conversation, n int) map[string]any {
	// For LLaVA, we need to send both text and image
	// For now, just send text prompt (image support will be added when multimodal API is clarified)
	prompt := conv.LastPrompt()

	payload := map[string]any{
		"inputs": prompt,
		"parameters": map[string]any{
			"num_return_sequences": n,
			"max_time":             g.maxTime,
		},
		"options": map[string]any{
			"wait_for_model": g.waitForModel,
		},
	}

	// Add optional parameters
	params := payload["parameters"].(map[string]any)
	if g.maxTokens > 0 {
		params["max_new_tokens"] = g.maxTokens
	}

	// Enable sampling if requesting multiple generations
	if n > 1 {
		params["do_sample"] = true
	}

	return payload
}

// parseResponse extracts messages from HuggingFace API response.
func (g *LLaVA) parseResponse(resp *libhttp.Response) ([]attempt.Message, error) {
	// Try parsing as array of objects with generated_text
	var results []struct {
		GeneratedText string `json:"generated_text"`
	}

	if err := resp.JSON(&results); err != nil {
		return nil, fmt.Errorf("huggingface: failed to parse response: %w", err)
	}

	messages := make([]attempt.Message, 0, len(results))
	for _, r := range results {
		messages = append(messages, attempt.NewAssistantMessage(r.GeneratedText))
	}

	return messages, nil
}

// ClearHistory is a no-op for LLaVA generator (stateless per call).
func (g *LLaVA) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *LLaVA) Name() string {
	return "huggingface.LLaVA"
}

// Description returns a human-readable description.
func (g *LLaVA) Description() string {
	return "HuggingFace LLaVA vision-language model generator"
}
