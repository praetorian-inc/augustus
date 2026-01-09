// Package openai provides an OpenAI generator for Augustus.
//
// This package implements the Generator interface for OpenAI's chat and
// completion APIs. It supports both chat models (GPT-4, GPT-3.5-turbo) and
// legacy completion models (gpt-3.5-turbo-instruct, davinci-002).
package openai

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

func init() {
	generators.Register("openai.OpenAI", NewOpenAI)
}

// chatModels is the set of models that use the chat completions API.
var chatModels = map[string]bool{
	"chatgpt-4o-latest":               true,
	"gpt-3.5-turbo":                   true,
	"gpt-3.5-turbo-0125":              true,
	"gpt-3.5-turbo-1106":              true,
	"gpt-3.5-turbo-16k":               true,
	"gpt-4":                           true,
	"gpt-4-0125-preview":              true,
	"gpt-4-0314":                      true,
	"gpt-4-0613":                      true,
	"gpt-4-1106-preview":              true,
	"gpt-4-1106-vision-preview":       true,
	"gpt-4-32k":                       true,
	"gpt-4-32k-0314":                  true,
	"gpt-4-32k-0613":                  true,
	"gpt-4-turbo":                     true,
	"gpt-4-turbo-2024-04-09":          true,
	"gpt-4-turbo-preview":             true,
	"gpt-4-vision-preview":            true,
	"gpt-4o":                          true,
	"gpt-4o-2024-05-13":               true,
	"gpt-4o-2024-08-06":               true,
	"gpt-4o-2024-11-20":               true,
	"gpt-4o-audio-preview":            true,
	"gpt-4o-audio-preview-2024-12-17": true,
	"gpt-4o-audio-preview-2024-10-01": true,
	"gpt-4o-mini":                     true,
	"gpt-4o-mini-2024-07-18":          true,
	"gpt-4o-mini-audio-preview":       true,
	"gpt-4o-mini-audio-preview-2024-12-17":   true,
	"gpt-4o-mini-realtime-preview":           true,
	"gpt-4o-mini-realtime-preview-2024-12-17": true,
	"gpt-4o-realtime-preview":                 true,
	"gpt-4o-realtime-preview-2024-12-17":      true,
	"gpt-4o-realtime-preview-2024-10-01":      true,
	"o1-mini":              true,
	"o1-mini-2024-09-12":   true,
	"o1-preview":           true,
	"o1-preview-2024-09-12": true,
	"o3-mini":              true,
	"o3-mini-2025-01-31":   true,
}

// completionModels is the set of models that use the legacy completions API.
var completionModels = map[string]bool{
	"gpt-3.5-turbo-instruct":  true,
	"davinci-002":             true,
	"babbage-002":             true,
	"davinci-instruct-beta":   true,
}

// OpenAI is a generator that wraps the OpenAI API.
type OpenAI struct {
	client *goopenai.Client
	model  string
	isChat bool

	// Configuration parameters
	temperature      float32
	maxTokens        int
	topP             float32
	frequencyPenalty float32
	presencePenalty  float32
	stop             []string
}

// NewOpenAI creates a new OpenAI generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewOpenAI(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewOpenAITyped(cfg)
}

// NewOpenAITyped creates a new OpenAI generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewOpenAITyped(cfg Config) (*OpenAI, error) {
	g := &OpenAI{
		model:            cfg.Model,
		temperature:      cfg.Temperature,
		maxTokens:        cfg.MaxTokens,
		topP:             cfg.TopP,
		frequencyPenalty: cfg.FrequencyPenalty,
		presencePenalty:  cfg.PresencePenalty,
		stop:             cfg.Stop,
	}

	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("openai generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("openai generator requires api_key")
	}

	// Determine if this is a chat or completion model
	g.isChat = chatModels[cfg.Model]
	if !g.isChat && !completionModels[cfg.Model] {
		g.isChat = true // Default to chat for unknown models
	}

	// Create client config
	clientCfg := goopenai.DefaultConfig(cfg.APIKey)
	if cfg.BaseURL != "" {
		clientCfg.BaseURL = cfg.BaseURL
	}
	g.client = goopenai.NewClientWithConfig(clientCfg)

	return g, nil
}

// NewOpenAIWithOptions creates a new OpenAI generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//   g, err := NewOpenAIWithOptions(
//       WithModel("gpt-4"),
//       WithAPIKey("sk-..."),
//       WithTemperature(0.5),
//   )
func NewOpenAIWithOptions(opts ...Option) (*OpenAI, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewOpenAITyped(cfg)
}

// Generate sends the conversation to OpenAI and returns responses.
func (g *OpenAI) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	if g.isChat {
		return g.generateChat(ctx, conv, n)
	}
	return g.generateCompletion(ctx, conv, n)
}

// generateChat handles chat completion requests.
func (g *OpenAI) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
	if g.frequencyPenalty != 0 {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 {
		req.Stop = g.stop
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

// generateCompletion handles legacy completion requests.
func (g *OpenAI) generateCompletion(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// For completion models, use the last prompt
	prompt := conv.LastPrompt()

	req := goopenai.CompletionRequest{
		Model:  g.model,
		Prompt: prompt,
		N:      n,
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
	if g.frequencyPenalty != 0 {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 {
		req.Stop = g.stop
	}

	resp, err := g.client.CreateCompletion(ctx, req)
	if err != nil {
		return nil, g.wrapError(err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Text))
	}

	return responses, nil
}

// conversationToMessages converts an Augustus Conversation to OpenAI messages.
func (g *OpenAI) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// wrapError wraps OpenAI API errors with more context.
func (g *OpenAI) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return fmt.Errorf("openai: rate limit exceeded: %w", err)
		case 400:
			return fmt.Errorf("openai: bad request: %w", err)
		case 401:
			return fmt.Errorf("openai: authentication error: %w", err)
		case 500, 502, 503, 504:
			return fmt.Errorf("openai: server error: %w", err)
		default:
			return fmt.Errorf("openai: API error: %w", err)
		}
	}

	return fmt.Errorf("openai: %w", err)
}

// ClearHistory is a no-op for OpenAI generator (stateless per call).
func (g *OpenAI) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *OpenAI) Name() string {
	return "openai.OpenAI"
}

// Description returns a human-readable description.
func (g *OpenAI) Description() string {
	return "OpenAI API generator for GPT models (chat and completion)"
}
