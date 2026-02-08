// Package anyscale provides an Anyscale generator for Augustus.
//
// This package implements the Generator interface for Anyscale's OpenAI-compatible API.
// Anyscale provides access to llama-2 and mistral models through an OpenAI-compatible interface.
package anyscale

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

// NewAnyscale creates a new Anyscale generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewAnyscale(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewAnyscaleTyped(cfg)
}

// NewAnyscaleTyped creates a new Anyscale generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewAnyscaleTyped(cfg Config) (*Anyscale, error) {
	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("anyscale generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("anyscale generator requires api_key")
	}

	g := &Anyscale{
		model:       cfg.Model,
		temperature: cfg.Temperature,
		maxTokens:   cfg.MaxTokens,
		topP:        cfg.TopP,
		maxRetries:  cfg.MaxRetries,
	}

	// Create client config
	config := goopenai.DefaultConfig(cfg.APIKey)

	// Base URL: from config or use default Anyscale endpoint
	if cfg.BaseURL != "" {
		config.BaseURL = cfg.BaseURL
	} else {
		config.BaseURL = DefaultBaseURL
	}

	g.client = goopenai.NewClientWithConfig(config)

	return g, nil
}

// NewAnyscaleWithOptions creates a new Anyscale generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//
//	g, err := NewAnyscaleWithOptions(
//	    WithModel("meta-llama/Llama-2-7b-chat-hf"),
//	    WithAPIKey("..."),
//	    WithTemperature(0.5),
//	)
func NewAnyscaleWithOptions(opts ...Option) (*Anyscale, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewAnyscaleTyped(cfg)
}

// Generate sends the conversation to Anyscale and returns responses.
// Rate limit errors (HTTP 429) are automatically retried with exponential backoff.
func (g *Anyscale) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
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
		responses, genErr = openaicompat.GenerateChat(ctx, g.client, "anyscale", g.model, conv, n, g.temperature, g.maxTokens, g.topP)
		return genErr
	})
	if err != nil {
		return nil, fmt.Errorf("anyscale: %w", err)
	}
	return responses, nil
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
