package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.BlankVision", NewBlankVision)
}

// BlankVision is a test generator that returns empty responses for text+image input.
// Useful for testing multimodal probe behavior without actual vision model access.
type BlankVision struct{}

// NewBlankVision creates a new BlankVision generator.
func NewBlankVision(_ registry.Config) (generators.Generator, error) {
	return &BlankVision{}, nil
}

// Generate returns n empty message responses.
// Supports text+image input modality but returns empty text output.
func (b *BlankVision) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, n)
	for i := range responses {
		responses[i] = attempt.NewAssistantMessage("")
	}

	return responses, nil
}

// ClearHistory is a no-op for BlankVision generator.
func (b *BlankVision) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (b *BlankVision) Name() string {
	return "test.BlankVision"
}

// Description returns a human-readable description.
func (b *BlankVision) Description() string {
	return "Returns empty responses for text+image input, testing multimodal probe handling"
}
