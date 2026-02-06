// Package nemo provides a NVIDIA NeMo generator for Augustus.
//
// This package implements the Generator interface for NVIDIA's NeMo
// (NVIDIA Optimized Inference) endpoints. NeMo provides OpenAI-compatible
// APIs for models hosted on NVIDIA NGC.
package nemo

import (
	"context"
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

const (
	// DefaultBaseURL is the default NeMo API base URL.
	DefaultBaseURL = "https://api.llm.ngc.nvidia.com/v1"
)

func init() {
	generators.Register("nemo.NeMo", NewNeMo)
}

// NeMo is a generator that wraps NVIDIA NeMo endpoints using OpenAI-compatible API.
type NeMo struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
	topK        int
}

// NewNeMo creates a new NeMo generator from configuration.
func NewNeMo(cfg registry.Config) (generators.Generator, error) {
	g := &NeMo{
		temperature: 0.9, // Default temperature from Garak
		topP:        1.0, // Default top_p from Garak
		topK:        2,   // Default top_k from Garak
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("nemo generator requires 'model' configuration")
	}
	g.model = model

	// API key: from config or env var (NGC_API_KEY to match Garak)
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv("NGC_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("nemo generator requires 'api_key' configuration or NGC_API_KEY environment variable")
	}

	// Create client config
	config := goopenai.DefaultConfig(apiKey)

	// Base URL: from config or use default NeMo endpoint
	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		config.BaseURL = baseURL
	} else {
		config.BaseURL = DefaultBaseURL
	}

	g.client = goopenai.NewClientWithConfig(config)

	// Optional: temperature
	if temp, ok := cfg["temperature"].(float64); ok {
		g.temperature = float32(temp)
	}

	// Optional: max_tokens
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}

	// Optional: top_p
	if topP, ok := cfg["top_p"].(float64); ok {
		g.topP = float32(topP)
	}

	// Optional: top_k (NeMo-specific)
	if topK, ok := cfg["top_k"].(int); ok {
		g.topK = topK
	} else if topK, ok := cfg["top_k"].(float64); ok {
		g.topK = int(topK)
	}

	return g, nil
}

// Generate sends the conversation to NeMo and returns responses.
func (g *NeMo) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	return g.generateChat(ctx, conv, n)
}

// generateChat handles chat completion requests.
func (g *NeMo) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// Convert conversation to OpenAI message format
	messages := g.conversationToMessages(conv)

	req := goopenai.ChatCompletionRequest{
		Model:    g.model,
		Messages: messages,
		N:        n,
	}

	// Add optional parameters if set
	if g.temperature != 0 {
		req.Temperature = g.temperature
	}
	if g.maxTokens > 0 {
		req.MaxTokens = g.maxTokens
	}
	if g.topP != 0 {
		req.TopP = g.topP
	}

	resp, err := g.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, g.wrapError(err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// conversationToMessages converts an Augustus Conversation to OpenAI messages.
func (g *NeMo) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
	messages := make([]goopenai.ChatCompletionMessage, 0)

	// Add system message if present
	if conv.System != nil {
		messages = append(messages, goopenai.ChatCompletionMessage{
			Role:    goopenai.ChatMessageRoleSystem,
			Content: conv.System.Content,
		})
	}

	// Add turns
	for _, turn := range conv.Turns {
		// Add user message
		messages = append(messages, goopenai.ChatCompletionMessage{
			Role:    goopenai.ChatMessageRoleUser,
			Content: turn.Prompt.Content,
		})

		// Add assistant response if present
		if turn.Response != nil {
			messages = append(messages, goopenai.ChatCompletionMessage{
				Role:    goopenai.ChatMessageRoleAssistant,
				Content: turn.Response.Content,
			})
		}
	}

	return messages
}

// wrapError wraps NeMo API errors with more context.
func (g *NeMo) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return fmt.Errorf("nemo: rate limit exceeded: %w", err)
		case 400:
			return fmt.Errorf("nemo: bad request: %w", err)
		case 401:
			return fmt.Errorf("nemo: authentication error: %w", err)
		case 500, 502, 503, 504:
			return fmt.Errorf("nemo: server error: %w", err)
		default:
			return fmt.Errorf("nemo: API error: %w", err)
		}
	}

	return fmt.Errorf("nemo: %w", err)
}

// ClearHistory is a no-op for NeMo generator (stateless per call).
func (g *NeMo) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *NeMo) Name() string {
	return "nemo.NeMo"
}

// Description returns a human-readable description.
func (g *NeMo) Description() string {
	return "NVIDIA NeMo generator for models hosted on NGC"
}
