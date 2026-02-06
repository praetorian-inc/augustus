// Package openai provides an OpenAI generator for Augustus.
//
// This package implements the Generator interface for OpenAI's chat and
// completion APIs. It supports both chat models (GPT-4, GPT-3.5-turbo) and
// legacy completion models (gpt-3.5-turbo-instruct, davinci-002).
package openai

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

func init() {
	generators.Register("openai.OpenAI", NewOpenAI)
}

// chatModels references the shared set of models that use the chat completions API.
var chatModels = openaicompat.ChatModels

// completionModels references the shared set of models that use the legacy completions API.
var completionModels = openaicompat.CompletionModels

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
	messages := openaicompat.ConversationToMessages(conv)

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
		return nil, openaicompat.WrapError("openai", err)
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
		return nil, openaicompat.WrapError("openai", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Text))
	}

	return responses, nil
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
