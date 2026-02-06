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
	"os"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
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

// chatModels references the shared set of models that use the chat completions API.
var chatModels = openaicompat.ChatModels

// completionModels references the shared set of models that use the legacy completions API.
var completionModels = openaicompat.CompletionModels

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
		return nil, openaicompat.WrapError("azure openai", err)
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
		return nil, openaicompat.WrapError("azure openai", err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Text))
	}

	return responses, nil
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
