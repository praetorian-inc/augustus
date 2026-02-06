// Package mistral provides a Mistral AI generator for Augustus.
//
// This package implements the Generator interface for Mistral's API.
// It supports Mistral models including Mistral-7B, Mistral-8x7B, etc.
package mistral

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
	generators.Register("mistral.Mistral", NewMistral)
}

// Mistral is a generator that wraps the Mistral API.
type Mistral struct {
	client *goopenai.Client
	model  string

	// Configuration parameters
	temperature float32
	maxTokens   int
	topP        float32
}

// NewMistral creates a new Mistral generator from legacy registry.Config.
// This is the backward-compatible entry point.
func NewMistral(m registry.Config) (generators.Generator, error) {
	cfg, err := ConfigFromMap(m)
	if err != nil {
		return nil, err
	}
	return NewMistralTyped(cfg)
}

// NewMistralTyped creates a new Mistral generator from typed configuration.
// This is the type-safe entry point for programmatic use.
func NewMistralTyped(cfg Config) (*Mistral, error) {
	g := &Mistral{
		model:       cfg.Model,
		temperature: cfg.Temperature,
		maxTokens:   cfg.MaxTokens,
		topP:        cfg.TopP,
	}

	// Validate required fields
	if cfg.Model == "" {
		return nil, fmt.Errorf("mistral generator requires model")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("mistral generator requires api_key")
	}

	// Create client config (Mistral uses OpenAI-compatible API)
	config := goopenai.DefaultConfig(cfg.APIKey)
	baseURL := "https://api.mistral.ai"

	// Optional: custom base URL
	if cfg.BaseURL != "" {
		baseURL = cfg.BaseURL
	}

	config.BaseURL = baseURL + "/v1"
	g.client = goopenai.NewClientWithConfig(config)

	return g, nil
}

// NewMistralWithOptions creates a new Mistral generator using functional options.
// This is the recommended entry point for Go code.
//
// Usage:
//   g, err := NewMistralWithOptions(
//       WithModel("mistral-large"),
//       WithAPIKey("..."),
//       WithTemperature(0.5),
//   )
func NewMistralWithOptions(opts ...Option) (*Mistral, error) {
	cfg := ApplyOptions(DefaultConfig(), opts...)
	return NewMistralTyped(cfg)
}

// Generate sends the conversation to Mistral and returns responses.
func (g *Mistral) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	return openaicompat.GenerateChat(ctx, g.client, "mistral", g.model, conv, n, g.temperature, g.maxTokens, g.topP)
}

// ClearHistory is a no-op for Mistral generator (stateless per call).
func (g *Mistral) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (g *Mistral) Name() string {
	return "mistral.Mistral"
}

// Description returns a human-readable description.
func (g *Mistral) Description() string {
	return "Mistral AI API generator for Mistral models"
}
