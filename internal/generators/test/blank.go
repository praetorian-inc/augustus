// Package test provides simple test generators for verification and examples.
package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.Blank", NewBlank)
}

// Blank is the simplest generator - always returns empty responses.
// Used for testing harness functionality without LLM access.
type Blank struct{}

// NewBlank creates a new Blank generator.
func NewBlank(_ registry.Config) (generators.Generator, error) {
	return &Blank{}, nil
}

// Generate returns n empty message responses.
func (b *Blank) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	responses := make([]attempt.Message, n)
	for i := range responses {
		responses[i] = attempt.NewAssistantMessage("")
	}

	return responses, nil
}

// ClearHistory is a no-op for Blank generator.
func (b *Blank) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (b *Blank) Name() string {
	return "test.Blank"
}

// Description returns a human-readable description.
func (b *Blank) Description() string {
	return "Returns empty responses for testing harness connectivity"
}
