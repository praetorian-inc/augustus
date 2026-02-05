package nim

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// NVMultimodal is a generator that wraps NVIDIA NIM multimodal endpoints.
// Supports text, image, and audio inputs.
type NVMultimodal struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
}

// NewNVMultimodal creates a new NVMultimodal generator from configuration.
func NewNVMultimodal(cfg registry.Config) (generators.Generator, error) {
	g := &NVMultimodal{
		temperature: 0.1, // Match Garak default
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("nim.NVMultimodal requires 'model' configuration")
	}
	g.model = model

	// API key: from config or env var
	apiKey, err := getAPIKey(cfg)
	if err != nil {
		return nil, err
	}

	// Create client config
	config := goopenai.DefaultConfig(apiKey)

	// Base URL: from config or use default NIM endpoint
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

	return g, nil
}

// Generate sends the conversation to NIM multimodal endpoint and returns responses.
func (g *NVMultimodal) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	// Convert conversation to OpenAI message format
	messages := conversationToMessages(conv)

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
		return nil, fmt.Errorf("nim multimodal: %w", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// conversationToMessages converts an Augustus Conversation to OpenAI messages.
// This is shared by chat-based generators.
func conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// ClearHistory is a no-op for NVMultimodal generator (stateless per call).
func (g *NVMultimodal) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *NVMultimodal) Name() string {
	return "nim.NVMultimodal"
}

// Description returns a human-readable description.
func (g *NVMultimodal) Description() string {
	return "NVIDIA NIM multimodal generator for text, image, and audio inputs"
}

// Vision is a generator that wraps NVIDIA NIM vision endpoints.
// This is a specialized version of NVMultimodal for text + image only.
type Vision struct {
	*NVMultimodal
}

// NewVision creates a new Vision generator from configuration.
func NewVision(cfg registry.Config) (generators.Generator, error) {
	// Vision is just a wrapper around NVMultimodal with a different name
	multimodal, err := NewNVMultimodal(cfg)
	if err != nil {
		return nil, err
	}

	return &Vision{
		NVMultimodal: multimodal.(*NVMultimodal),
	}, nil
}

// Name returns the generator's fully qualified name.
func (g *Vision) Name() string {
	return "nim.Vision"
}

// Description returns a human-readable description.
func (g *Vision) Description() string {
	return "NVIDIA NIM vision generator for text and image inputs"
}
