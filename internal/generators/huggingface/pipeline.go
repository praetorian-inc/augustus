// Package huggingface provides generators using HuggingFace models.
//
// This package implements the Generator interface for HuggingFace models via:
//   - InferenceAPI: Remote inference via HuggingFace's hosted API
//   - Pipeline: Local inference via Text Generation Inference (TGI)
//
// # Pipeline Generator (Local Inference)
//
// The Pipeline generator connects to a locally-running HuggingFace TGI server.
// This enables cost-free testing during development without API rate limits.
//
// Prerequisites:
//
//  1. Install Docker
//  2. Pull and run TGI:
//     docker run --gpus all -p 8080:80 \
//       ghcr.io/huggingface/text-generation-inference:latest \
//       --model-id meta-llama/Llama-2-7b-chat-hf
//  3. Configure generator with host (default: http://127.0.0.1:8080)
//
// Configuration:
//
//   model: Required. The model ID (e.g., "meta-llama/Llama-2-7b-chat-hf")
//   host: Optional. TGI server address (default: http://127.0.0.1:8080)
//   max_tokens: Optional. Maximum tokens to generate
//   temperature: Optional. Sampling temperature
//   top_p: Optional. Nucleus sampling parameter
//
// Environment Variables:
//
//   TGI_HOST: Override default TGI host
//
// Python equivalent: garak.generators.huggingface.Pipeline
package huggingface

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	libhttp "github.com/praetorian-inc/augustus/pkg/lib/http"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

const (
	// DefaultTGIHost is the default Text Generation Inference server address.
	DefaultTGIHost = "http://127.0.0.1:8080"

	// DefaultPipelineTimeout is the default HTTP client timeout for TGI inference requests.
	// This is longer than DefaultTimeout because local model inference can be slower.
	DefaultPipelineTimeout = 120 * time.Second
)

func init() {
	generators.Register("huggingface.Pipeline", NewPipeline)
}

// Pipeline generates text using a locally-run HuggingFace model via TGI.
type Pipeline struct {
	client *libhttp.Client
	model  string
	host   string

	// Configuration
	maxTokens      int
	temperature    *float64
	topP           *float64
	deprefixPrompt bool
}

// NewPipeline creates a new HuggingFace Pipeline generator from configuration.
func NewPipeline(cfg registry.Config) (generators.Generator, error) {
	g := &Pipeline{
		host:           DefaultTGIHost,
		deprefixPrompt: true,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("huggingface.Pipeline requires 'model' configuration")
	}
	g.model = model

	// Optional: host (TGI server address)
	if host, ok := cfg["host"].(string); ok && host != "" {
		g.host = host
	} else if envHost := os.Getenv("TGI_HOST"); envHost != "" {
		g.host = envHost
	}

	// Build HTTP client
	g.client = libhttp.NewClient(
		libhttp.WithBaseURL(g.host),
		libhttp.WithTimeout(DefaultPipelineTimeout),
		libhttp.WithUserAgent("Augustus/1.0"),
	)

	// Optional parameters
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	if temp, ok := cfg["temperature"].(float64); ok {
		g.temperature = &temp
	}

	if topP, ok := cfg["top_p"].(float64); ok {
		g.topP = &topP
	}

	if deprefix, ok := cfg["deprefix_prompt"].(bool); ok {
		g.deprefixPrompt = deprefix
	}

	return g, nil
}

// Name returns the generator's fully qualified name.
func (g *Pipeline) Name() string {
	return "huggingface.Pipeline"
}

// Description returns a human-readable description.
func (g *Pipeline) Description() string {
	return "HuggingFace Pipeline generator for locally-run models via TGI"
}

// ClearHistory is a no-op (stateless per call).
func (g *Pipeline) ClearHistory() {}

// Generate sends the conversation to TGI and returns responses.
func (g *Pipeline) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Build request payload (OpenAI-compatible format)
	payload := g.buildPayload(conv, n)

	// Make request to TGI
	resp, err := g.client.Post(ctx, "/v1/chat/completions", payload)
	if err != nil {
		return nil, fmt.Errorf("huggingface: pipeline request failed: %w", err)
	}

	// Handle errors
	if resp.StatusCode >= 400 {
		var errResp struct {
			Error struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = resp.JSON(&errResp) // Intentionally ignore error; use fallback if parsing fails
		if errResp.Error.Message != "" {
			return nil, fmt.Errorf("huggingface: pipeline error (status %d): %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("huggingface: pipeline error: status %d", resp.StatusCode)
	}

	// Parse response
	return g.parseResponse(resp)
}

// buildPayload constructs the TGI request payload.
func (g *Pipeline) buildPayload(conv *attempt.Conversation, n int) map[string]any {
	payload := map[string]any{
		"model":    g.model,
		"messages": g.conversationToMessages(conv),
		"n":        n,
	}

	if g.maxTokens > 0 {
		payload["max_tokens"] = g.maxTokens
	}

	if g.temperature != nil {
		payload["temperature"] = *g.temperature
	}

	if g.topP != nil {
		payload["top_p"] = *g.topP
	}

	return payload
}

// conversationToMessages converts an Augustus Conversation to OpenAI message format.
func (g *Pipeline) conversationToMessages(conv *attempt.Conversation) []map[string]string {
	messages := make([]map[string]string, 0)

	if conv.System != nil {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": conv.System.Content,
		})
	}

	for _, turn := range conv.Turns {
		messages = append(messages, map[string]string{
			"role":    "user",
			"content": turn.Prompt.Content,
		})

		if turn.Response != nil {
			messages = append(messages, map[string]string{
				"role":    "assistant",
				"content": turn.Response.Content,
			})
		}
	}

	return messages
}

// parseResponse extracts messages from TGI response.
func (g *Pipeline) parseResponse(resp *libhttp.Response) ([]attempt.Message, error) {
	var result struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}

	if err := resp.JSON(&result); err != nil {
		return nil, fmt.Errorf("huggingface: failed to parse TGI response: %w", err)
	}

	messages := make([]attempt.Message, 0, len(result.Choices))
	for _, choice := range result.Choices {
		messages = append(messages, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return messages, nil
}
