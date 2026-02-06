// Package openai provides OpenAI generator implementations for Augustus.
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
	generators.Register("openai.OpenAIReasoning", NewOpenAIReasoning)
}

// reasoningModels is the set of models that use reasoning APIs (o1/o3 family).
var reasoningModels = map[string]bool{
	"o1-mini":              true,
	"o1-mini-2024-09-12":   true,
	"o1-preview":           true,
	"o1-preview-2024-09-12": true,
	"o3-mini":              true,
	"o3-mini-2025-01-31":   true,
}

// OpenAIReasoning is a generator for OpenAI reasoning models (o1/o3 family).
// These models have different API constraints:
// - Use max_completion_tokens instead of max_tokens
// - Do NOT support n>1 (multiple generations)
// - Do NOT support temperature parameter
type OpenAIReasoning struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	maxCompletionTokens int
	topP                 float32
	frequencyPenalty     float32
	presencePenalty      float32
	stop                 []string
}

// NewOpenAIReasoning creates a new OpenAI Reasoning generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewOpenAIReasoning(m registry.Config) (generators.Generator, error) {
	cfg, err := ReasoningConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewOpenAIReasoningTyped(cfg)
}

// NewOpenAIReasoningTyped creates a new OpenAI Reasoning generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewOpenAIReasoningTyped(cfg ReasoningConfig) (*OpenAIReasoning, error) {
	// Create client config
	clientCfg := goopenai.DefaultConfig(cfg.APIKey)
	if cfg.BaseURL != "" {
		clientCfg.BaseURL = cfg.BaseURL
	}

	return &OpenAIReasoning{
		client:               goopenai.NewClientWithConfig(clientCfg),
		model:                cfg.Model,
		maxCompletionTokens:  cfg.MaxCompletionTokens,
		topP:                 cfg.TopP,
		frequencyPenalty:     cfg.FrequencyPenalty,
		presencePenalty:      cfg.PresencePenalty,
		stop:                 cfg.Stop,
	}, nil
}

// Name returns the generator's registry name.
func (g *OpenAIReasoning) Name() string {
	return "openai.OpenAIReasoning"
}

// Description returns a human-readable description.
func (g *OpenAIReasoning) Description() string {
	return "OpenAI Reasoning API generator for o1/o3 models"
}

// ClearHistory is a no-op for OpenAI reasoning generator (stateless per call).
func (g *OpenAIReasoning) ClearHistory() {}

// Generate produces completions using OpenAI reasoning models.
// Note: Reasoning models do NOT support n>1, so this will return an error if count > 1.
func (g *OpenAIReasoning) Generate(ctx context.Context, conv *attempt.Conversation, count int) ([]attempt.Message, error) {
	// Reasoning models do not support multiple generations per call
	if count > 1 {
		return nil, fmt.Errorf("openai reasoning models do not support multiple generations (n>1)")
	}

	// Convert conversation to OpenAI messages
	messages := convToOpenAIMessages(conv)

	// Build request - reasoning models use max_completion_tokens, not max_tokens
	req := goopenai.ChatCompletionRequest{
		Model:    g.model,
		Messages: messages,
		TopP:     g.topP,
	}

	// Only set max_completion_tokens if configured
	if g.maxCompletionTokens > 0 {
		req.MaxCompletionTokens = g.maxCompletionTokens
	}

	// Add optional parameters
	if g.frequencyPenalty != 0 {
		req.FrequencyPenalty = g.frequencyPenalty
	}
	if g.presencePenalty != 0 {
		req.PresencePenalty = g.presencePenalty
	}
	if len(g.stop) > 0 {
		req.Stop = g.stop
	}

	// Call OpenAI API
	resp, err := g.client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, openaicompat.WrapError("openai", err)
	}

	// Extract responses
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("openai: reasoning API returned no choices")
	}

	result := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		result = append(result, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return result, nil
}

// convToOpenAIMessages converts an Augustus conversation to OpenAI messages format.
// This is shared logic between regular and reasoning generators.
func convToOpenAIMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
	augustusMessages := conv.ToMessages()
	messages := make([]goopenai.ChatCompletionMessage, 0, len(augustusMessages))

	for _, msg := range augustusMessages {
		var role string
		switch msg.Role {
		case attempt.RoleUser:
			role = goopenai.ChatMessageRoleUser
		case attempt.RoleAssistant:
			role = goopenai.ChatMessageRoleAssistant
		case attempt.RoleSystem:
			role = goopenai.ChatMessageRoleSystem
		default:
			role = string(msg.Role)
		}

		messages = append(messages, goopenai.ChatCompletionMessage{
			Role:    role,
			Content: msg.Content,
		})
	}

	return messages
}
