// Package groq provides a Groq generator for Augustus.
//
// This package implements the Generator interface for Groq's fast inference API.
// Groq uses an OpenAI-compatible chat completions API format.
package groq

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	goopenai "github.com/sashabaranov/go-openai"
)

const (
	// DefaultBaseURL is the Groq API base URL.
	DefaultBaseURL = "https://api.groq.com/openai/v1"

	// DefaultMaxRetries is the default number of retries for rate limit errors.
	DefaultMaxRetries = 3

	// DefaultInitialBackoff is the initial backoff duration for retries.
	DefaultInitialBackoff = 1 * time.Second
)

func init() {
	generators.Register("groq.Groq", NewGroq)
}

// Groq is a generator that wraps the Groq API.
type Groq struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
	maxRetries  int
}

// NewGroq creates a new Groq generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewGroq(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewGroqTyped(cfg)
}

// NewGroqTyped creates a new Groq generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewGroqTyped(cfg Config) (*Groq, error) {
	g := &Groq{
		model:       cfg.Model,
		temperature: cfg.Temperature,
		maxTokens:   cfg.MaxTokens,
		topP:        cfg.TopP,
		maxRetries:  cfg.MaxRetries,
	}

	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("groq generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("groq generator requires api_key")
	}

	// Create client config
	config := goopenai.DefaultConfig(cfg.APIKey)

	// Base URL: from config or use default Groq endpoint
	if cfg.BaseURL != "" {
		config.BaseURL = cfg.BaseURL
	} else {
		config.BaseURL = DefaultBaseURL
	}

	g.client = goopenai.NewClientWithConfig(config)

	return g, nil
}

// NewGroqWithOptions creates a new Groq generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//   g, err := NewGroqWithOptions(
//       WithModel("llama-3.1-70b-versatile"),
//       WithAPIKey("..."),
//       WithTemperature(0.5),
//   )
func NewGroqWithOptions(opts ...Option) (*Groq, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewGroqTyped(cfg)
}

// Generate sends the conversation to Groq and returns responses.
func (g *Groq) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	return g.generateWithRetry(ctx, conv, n)
}

// generateWithRetry implements retry logic with exponential backoff for rate limits.
func (g *Groq) generateWithRetry(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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

	return nil, fmt.Errorf("groq: max retries exceeded: %w", lastErr)
}

// generateChat handles chat completion requests.
func (g *Groq) generateChat(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
func (g *Groq) conversationToMessages(conv *attempt.Conversation) []goopenai.ChatCompletionMessage {
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

// wrapError wraps Groq API errors with more context.
func (g *Groq) wrapError(err error) error {
	if err == nil {
		return nil
	}

	// Check for specific error types
	if apiErr, ok := err.(*goopenai.APIError); ok {
		switch apiErr.HTTPStatusCode {
		case 429:
			return fmt.Errorf("groq: rate limit exceeded: %w", err)
		case 400:
			return fmt.Errorf("groq: bad request: %w", err)
		case 401:
			return fmt.Errorf("groq: authentication error: %w", err)
		case 500, 502, 503, 504:
			return fmt.Errorf("groq: server error: %w", err)
		default:
			return fmt.Errorf("groq: API error: %w", err)
		}
	}

	return fmt.Errorf("groq: %w", err)
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

// ClearHistory is a no-op for Groq generator (stateless per call).
func (g *Groq) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Groq) Name() string {
	return "groq.Groq"
}

// Description returns a human-readable description.
func (g *Groq) Description() string {
	return "Groq fast inference API generator for LLaMA, Mixtral, and Gemma models"
}
