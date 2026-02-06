// Package together provides a Together.ai generator for Augustus.
//
// This package implements the Generator interface for Together.ai's API.
// It supports various open-source models hosted on Together.ai platform.
package together

import (
	"context"
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

func init() {
	generators.Register("together.Together", NewTogether)
}

// Together is a generator that wraps the Together.ai API.
type Together struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
	topK        int
}

// NewTogether creates a new Together.ai generator from configuration.
func NewTogether(cfg registry.Config) (generators.Generator, error) {
	g := &Together{
		temperature: 0.7,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("together generator requires 'model' configuration")
	}
	g.model = model

	// API key: from config or env var
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv("TOGETHER_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("together generator requires 'api_key' configuration or TOGETHER_API_KEY environment variable")
	}

	// Create client config (Together.ai uses OpenAI-compatible API)
	config := goopenai.DefaultConfig(apiKey)
	baseURL := "https://api.together.xyz"

	// Optional: custom base URL
	if customURL, ok := cfg["base_url"].(string); ok && customURL != "" {
		baseURL = customURL
	}

	config.BaseURL = baseURL + "/v1"
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

	// Optional: top_k
	if topK, ok := cfg["top_k"].(int); ok {
		g.topK = topK
	} else if topK, ok := cfg["top_k"].(float64); ok {
		g.topK = int(topK)
	}

	return g, nil
}

// Generate sends the conversation to Together.ai and returns responses.
func (g *Together) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

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
		return nil, fmt.Errorf("together: %w", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// conversationToMessages converts an Augustus Conversation to OpenAI messages.
func (g *Together) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// ClearHistory is a no-op for Together generator (stateless per call).
func (g *Together) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Together) Name() string {
	return "together.Together"
}

// Description returns a human-readable description.
func (g *Together) Description() string {
	return "Together.ai API generator for open-source models"
}
