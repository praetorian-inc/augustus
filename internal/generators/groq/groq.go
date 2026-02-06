// Package groq provides a Groq generator for Augustus.
//
// This package implements the Generator interface for Groq's fast inference API.
// Groq uses an OpenAI-compatible chat completions API format.
package groq

import (
	"context"
	"fmt"
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/openaicompat"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/retry"
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
// Rate limit errors (HTTP 429) are automatically retried with exponential backoff.
func (g *Groq) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	var responses []attempt.Message
	err := retry.Do(ctx, retry.Config{
		MaxAttempts:  g.maxRetries + 1, // maxRetries doesn't count the initial attempt
		InitialDelay: DefaultInitialBackoff,
		MaxDelay:     30 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.1,
		RetryableFunc: func(err error) bool {
			return openaicompat.IsRateLimitError(err)
		},
	}, func() error {
		var genErr error
		responses, genErr = openaicompat.GenerateChat(ctx, g.client, "groq", g.model, conv, n, g.temperature, g.maxTokens, g.topP)
		return genErr
	})
	if err != nil {
		return nil, fmt.Errorf("groq: %w", err)
	}
	return responses, nil
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
