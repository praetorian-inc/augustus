// Package azure provides an Azure OpenAI generator for Augustus.
//
// This package implements the Generator interface for Azure OpenAI's chat and
// completion APIs. It supports Azure-specific configuration including custom
// endpoints and API versions.
//
// Azure OpenAI requires three key pieces of configuration:
//   - Model: The Azure OpenAI model name (may differ from OpenAI names)
//   - Endpoint: The Azure resource endpoint (e.g., https://your-resource.openai.azure.com)
//   - API Key: The Azure OpenAI API key
//
// Configuration can be provided via:
//   - Direct configuration (Config struct or functional options)
//   - Environment variables (AZURE_MODEL_NAME, AZURE_ENDPOINT, AZURE_API_KEY)
//   - Legacy registry.Config for backward compatibility
package azure

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
	generators.Register("azure.AzureOpenAI", NewAzure)
}

// openaiModelMapping maps Azure model names to OpenAI equivalents.
// Based on https://learn.microsoft.com/en-us/azure/ai-services/openai/concepts/models
var openaiModelMapping = map[string]string{
	"gpt-4":                   "gpt-4-turbo-2024-04-09",
	"gpt-35-turbo":            "gpt-3.5-turbo-0125",
	"gpt-35-turbo-16k":        "gpt-3.5-turbo-16k",
	"gpt-35-turbo-instruct":   "gpt-3.5-turbo-instruct",
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

// AzureOpenAI is a generator that wraps the Azure OpenAI API.
type AzureOpenAI struct {
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

// NewAzure creates a new Azure OpenAI generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewAzure(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewAzureTyped(cfg)
}

// NewAzureTyped creates a new Azure OpenAI generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewAzureTyped(cfg Config) (*AzureOpenAI, error) {
	// Load from environment if config is empty
	if cfg.Model == "" {
		cfg.Model = os.Getenv("AZURE_MODEL_NAME")
	}
	if cfg.APIKey == "" {
		cfg.APIKey = os.Getenv("AZURE_API_KEY")
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = os.Getenv("AZURE_ENDPOINT")
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	g := &AzureOpenAI{
		model:            cfg.Model,
		temperature:      cfg.Temperature,
		maxTokens:        cfg.MaxTokens,
		topP:             cfg.TopP,
		frequencyPenalty: cfg.FrequencyPenalty,
		presencePenalty:  cfg.PresencePenalty,
		stop:             cfg.Stop,
	}

	// Apply model mapping if necessary
	if mapped, ok := openaiModelMapping[cfg.Model]; ok {
		g.model = mapped
	}

	// Determine if this is a chat or completion model
	g.isChat = chatModels[g.model]
	if !g.isChat && !completionModels[g.model] {
		g.isChat = true // Default to chat for unknown models
	}

	// Create Azure OpenAI client
	clientCfg := goopenai.DefaultAzureConfig(cfg.APIKey, cfg.Endpoint)
	clientCfg.APIVersion = cfg.APIVersion
	g.client = goopenai.NewClientWithConfig(clientCfg)

	return g, nil
}

// NewAzureWithOptions creates a new Azure OpenAI generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//   g, err := NewAzureWithOptions(
//       WithModel("gpt-4"),
//       WithAPIKey("..."),
//       WithEndpoint("https://your-resource.openai.azure.com"),
//       WithTemperature(0.5),
//   )
func NewAzureWithOptions(opts ...Option) (*AzureOpenAI, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewAzureTyped(cfg)
}

// Generate sends the conversation to Azure OpenAI and returns responses.
func (g *AzureOpenAI) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	if g.isChat {
		return g.generateChat(ctx, conv, n)
	}
	return g.generateCompletion(ctx, conv, n)
}

// generateChat handles chat completion requests.
func (g *AzureOpenAI) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
func (g *AzureOpenAI) generateCompletion(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
func (g *AzureOpenAI) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// wrapError wraps Azure OpenAI API errors with more context.
func (g *AzureOpenAI) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return fmt.Errorf("azure openai: rate limit exceeded: %w", err)
		case 400:
			return fmt.Errorf("azure openai: bad request: %w", err)
		case 401:
			return fmt.Errorf("azure openai: authentication error: %w", err)
		case 500, 502, 503, 504:
			return fmt.Errorf("azure openai: server error: %w", err)
		default:
			return fmt.Errorf("azure openai: API error: %w", err)
		}
	}

	return fmt.Errorf("azure openai: %w", err)
}

// ClearHistory is a no-op for Azure OpenAI generator (stateless per call).
func (g *AzureOpenAI) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *AzureOpenAI) Name() string {
	return "azure.AzureOpenAI"
}

// Description returns a human-readable description.
func (g *AzureOpenAI) Description() string {
	return "Azure OpenAI API generator for GPT models (chat and completion)"
}
