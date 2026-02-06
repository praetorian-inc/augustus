// Package anyscale provides an Anyscale generator for Augustus.
//
// This package implements the Generator interface for Anyscale's OpenAI-compatible API.
// Anyscale provides access to llama-2 and mistral models through an OpenAI-compatible interface.
package anyscale

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

const (
	// DefaultBaseURL is the Anyscale API base URL.
	DefaultBaseURL = "https://api.anyscale.com/v1"

	// DefaultMaxRetries is the default number of retries for rate limit errors.
	DefaultMaxRetries = 3

	// DefaultInitialBackoff is the initial backoff duration for retries.
	DefaultInitialBackoff = 1 * time.Second
)

func init() {
	generators.Register("anyscale.Anyscale", NewAnyscale)
}

// Anyscale is a generator that wraps the Anyscale API.
type Anyscale struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
	maxRetries  int
}

// NewAnyscale creates a new Anyscale generator from configuration.
func NewAnyscale(cfg registry.Config) (generators.Generator, error) {
	g := &Anyscale{
		temperature: 0.7,            // Default temperature
		maxRetries:  DefaultMaxRetries,
	}

	// Required: model name
	model, ok := cfg["model"].(string)
	if !ok || model == "" {
		return nil, fmt.Errorf("anyscale generator requires 'model' configuration")
	}
	g.model = model

	// API key: from config or env var
	apiKey := ""
	if key, ok := cfg["api_key"].(string); ok && key != "" {
		apiKey = key
	} else {
		apiKey = os.Getenv("ANYSCALE_API_KEY")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("anyscale generator requires 'api_key' configuration or ANYSCALE_API_KEY environment variable")
	}

	// Create client config
	config := goopenai.DefaultConfig(apiKey)

	// Base URL: from config or use default Anyscale endpoint
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

	// Optional: max_retries
	if maxRetries, ok := cfg["max_retries"].(int); ok {
		g.maxRetries = maxRetries
	} else if maxRetries, ok := cfg["max_retries"].(float64); ok {
		g.maxRetries = int(maxRetries)
	}

	return g, nil
}

// Generate sends the conversation to Anyscale and returns responses.
func (g *Anyscale) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	return g.generateWithRetry(ctx, conv, n)
}

// generateWithRetry implements retry logic with exponential backoff for rate limits.
func (g *Anyscale) generateWithRetry(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	var lastErr error
	backoff := DefaultInitialBackoff

	for attempt := 0; attempt <= g.maxRetries; attempt++ {
		if attempt > 0 {
			// Wait before retrying with exponential backoff
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
				// Continue to retry
			}
			// Exponential backoff: 1s, 2s, 4s, ...
			backoff = time.Duration(float64(backoff) * math.Pow(2, float64(attempt-1)))
		}

		responses, err := g.generateChat(ctx, conv, n)
		if err == nil {
			return responses, nil
		}

		lastErr = err

		// Check if it's a rate limit error that we should retry
		if !isRateLimitError(err) {
			// Not a rate limit error, don't retry
			return nil, err
		}

		// Rate limit error, will retry if attempts remaining
	}

	return nil, fmt.Errorf("anyscale: max retries exceeded: %w", lastErr)
}

// generateChat handles chat completion requests.
func (g *Anyscale) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
		// Check for rate limit before wrapping to preserve error type info
		isRateLimit := isRateLimitError(err)
		wrappedErr := g.wrapError(err)

		// Preserve rate limit status in wrapped error for retry logic
		if isRateLimit {
			return nil, &rateLimitError{err: wrappedErr}
		}
		return nil, wrappedErr
	}

	// Extract responses from choices
	responses := make([]attempt.Message, 0, len(resp.Choices))
	for _, choice := range resp.Choices {
		responses = append(responses, attempt.NewAssistantMessage(choice.Message.Content))
	}

	return responses, nil
}

// rateLimitError wraps an error to indicate it's a rate limit error.
type rateLimitError struct {
	err error
}

func (e *rateLimitError) Error() string {
	return e.err.Error()
}

func (e *rateLimitError) Unwrap() error {
	return e.err
}

// conversationToMessages converts an Augustus Conversation to OpenAI messages.
func (g *Anyscale) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// wrapError wraps Anyscale API errors with more context.
func (g *Anyscale) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return fmt.Errorf("anyscale: rate limit exceeded: %w", err)
		case 400:
			return fmt.Errorf("anyscale: bad request: %w", err)
		case 401:
			return fmt.Errorf("anyscale: authentication error: %w", err)
		case 500, 502, 503, 504:
			return fmt.Errorf("anyscale: server error: %w", err)
		default:
			return fmt.Errorf("anyscale: API error: %w", err)
		}
	}

	return fmt.Errorf("anyscale: %w", err)
}

// isRateLimitError checks if an error is a rate limit error.
func isRateLimitError(err error) bool {
	// Check for our wrapped rateLimitError type
	if _, ok := err.(*rateLimitError); ok {
		return true
	}

	// Check for OpenAI API error with 429 status
	if apiErr, ok := err.(*goopenai.APIError); ok {
		return apiErr.HTTPStatusCode == 429
	}
	return false
}

// ClearHistory is a no-op for Anyscale generator (stateless per call).
func (g *Anyscale) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Anyscale) Name() string {
	return "anyscale.Anyscale"
}

// Description returns a human-readable description.
func (g *Anyscale) Description() string {
	return "Anyscale Endpoints API generator supporting Llama-2, Mistral, and other open-source models"
}
