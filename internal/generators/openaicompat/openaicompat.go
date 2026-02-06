// Package openaicompat provides shared functions for OpenAI-compatible API generators.
//
// Many LLM providers (Groq, Mistral, Together, DeepInfra, Fireworks, Anyscale,
// NIM, NeMo, LiteLLM) offer OpenAI-compatible APIs. This package extracts the
// common logic so each generator can delegate to shared implementations rather
// than duplicating identical code.
package openaicompat

import (
	"context"
	"fmt"
	"os"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

// ChatModels is the set of models that use the chat completions API.
// This is shared between the openai and azure generators.
var ChatModels = map[string]bool{
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
	"gpt-4o-mini-audio-preview":                   true,
	"gpt-4o-mini-audio-preview-2024-12-17":        true,
	"gpt-4o-mini-realtime-preview":                true,
	"gpt-4o-mini-realtime-preview-2024-12-17":     true,
	"gpt-4o-realtime-preview":                     true,
	"gpt-4o-realtime-preview-2024-12-17":          true,
	"gpt-4o-realtime-preview-2024-10-01":          true,
	"o1-mini":              true,
	"o1-mini-2024-09-12":   true,
	"o1-preview":           true,
	"o1-preview-2024-09-12": true,
	"o3-mini":              true,
	"o3-mini-2025-01-31":   true,
}

// CompletionModels is the set of models that use the legacy completions API.
// This is shared between the openai and azure generators.
var CompletionModels = map[string]bool{
	"gpt-3.5-turbo-instruct": true,
	"davinci-002":            true,
	"babbage-002":            true,
	"davinci-instruct-beta":  true,
}

// ConversationToMessages converts an Augustus Conversation to OpenAI chat messages.
// This is the canonical implementation used by all OpenAI-compatible generators.
func ConversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// WrapError wraps OpenAI-compatible API errors with a provider-specific prefix.
// The providerName is used to prefix error messages (e.g., "openai", "groq", "azure openai").
// For rate limit errors (HTTP 429), it returns a *RateLimitError so callers can
// detect them with IsRateLimitError() for retry logic.
func WrapError(providerName string, err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return &RateLimitError{Err: fmt.Errorf("%s: rate limit exceeded: %w", providerName, err)}
		case 400:
			return fmt.Errorf("%s: bad request: %w", providerName, err)
		case 401:
			return fmt.Errorf("%s: authentication error: %w", providerName, err)
		case 500, 502, 503, 504:
			return fmt.Errorf("%s: server error: %w", providerName, err)
		default:
			return fmt.Errorf("%s: API error: %w", providerName, err)
		}
	}

	return fmt.Errorf("%s: %w", providerName, err)
}

// GenerateChat performs a standard OpenAI-compatible chat completion request.
// It converts the conversation, builds the request with the given parameters,
// calls the API, and extracts the response messages.
//
// This covers the common case used by deepinfra, fireworks, nim, nemo, and others.
// Generators with extra parameters (e.g., frequencyPenalty, stop) or special
// logic (e.g., retry, suppressed params) should build their own requests but
// can still use ConversationToMessages and WrapError.
func GenerateChat(
	ctx context.Context,
	client *goopenai.Client,
	providerName string,
	model string,
	conv *attempt.Conversation,
	n int,
	temperature float32,
	maxTokens int,
	topP float32,
) ([]attempt.Message, error) {
	messages := ConversationToMessages(conv)

	req := goopenai.ChatCompletionRequest{
		Model:    model,
		Messages: messages,
		N:        n,
	}

	// Add optional parameters if set
	if temperature != 0 {
		req.Temperature = temperature
	}
	if maxTokens > 0 {
		req.MaxTokens = maxTokens
	}
	if topP != 0 {
		req.TopP = topP
	}

	resp, err := client.CreateChatCompletion(ctx, req)
	if err != nil {
		return nil, WrapError(providerName, err)
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// ProviderConfig defines the static configuration for an OpenAI-compatible provider.
type ProviderConfig struct {
	// Name is the fully qualified generator name (e.g., "deepinfra.DeepInfra").
	Name string
	// Description is a human-readable description.
	Description string
	// Provider is the short provider name for error messages (e.g., "deepinfra").
	Provider string
	// DefaultBaseURL is the default API base URL.
	DefaultBaseURL string
	// EnvVar is the environment variable name for the API key.
	EnvVar string
	// DefaultTemperature is the default temperature (0 means 0.7).
	DefaultTemperature float32
}

// CompatGenerator is a ready-to-use generator for OpenAI-compatible providers.
// It implements the full Generator interface using shared openaicompat functions.
type CompatGenerator struct {
	client      *goopenai.Client
	provider    string
	name        string
	description string
	model       string
	temperature float32
	maxTokens   int
	topP        float32
}

// NewGenerator creates a new CompatGenerator from registry config and provider settings.
// This eliminates constructor duplication across OpenAI-compatible providers.
func NewGenerator(cfg registry.Config, pc ProviderConfig) (*CompatGenerator, error) {
	defaultTemp := pc.DefaultTemperature
	if defaultTemp == 0 {
		defaultTemp = 0.7
	}

	g := &CompatGenerator{
		provider:    pc.Provider,
		name:        pc.Name,
		description: pc.Description,
		temperature: defaultTemp,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("%s generator requires 'model' configuration", pc.Provider)
	}
	g.model = model

	// API key: from config or env var
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv(pc.EnvVar)
	}
	if apiKey == "" {
		return nil, fmt.Errorf("%s generator requires 'api_key' configuration or %s environment variable", pc.Provider, pc.EnvVar)
	}

	// Create client config
	config := goopenai.DefaultConfig(apiKey)
	if baseURL, ok := cfg["base_url"].(string); ok && baseURL != "" {
		config.BaseURL = baseURL
	} else {
		config.BaseURL = pc.DefaultBaseURL
	}
	g.client = goopenai.NewClientWithConfig(config)

	// Optional parameters
	if temp, ok := cfg["temperature"].(float64); ok {
		g.temperature = float32(temp)
	}
	if maxTokens, ok := cfg["max_tokens"].(int); ok {
		g.maxTokens = maxTokens
	} else if maxTokens, ok := cfg["max_tokens"].(float64); ok {
		g.maxTokens = int(maxTokens)
	}
	if topP, ok := cfg["top_p"].(float64); ok {
		g.topP = float32(topP)
	}

	return g, nil
}

// Generate sends the conversation to the provider and returns responses.
func (g *CompatGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}
	return GenerateChat(ctx, g.client, g.provider, g.model, conv, n, g.temperature, g.maxTokens, g.topP)
}

// ClearHistory is a no-op (stateless per call).
func (g *CompatGenerator) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *CompatGenerator) Name() string { return g.name }

// Description returns a human-readable description.
func (g *CompatGenerator) Description() string { return g.description }

// Client returns the underlying OpenAI client for advanced usage.
func (g *CompatGenerator) Client() *goopenai.Client { return g.client }

// Model returns the model name.
func (g *CompatGenerator) Model() string { return g.model }
