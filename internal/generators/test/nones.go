package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.Nones", NewNones)
}

// Nones is a test generator that always returns empty messages.
// Supports multiple generations for testing probe handling of empty responses.
type Nones struct{}

// NewNones creates a new Nones generator.
func NewNones(_ registry.Config) (generators.Generator, error) {
	return &Nones{}, nil
}

// Generate returns n empty message responses.
func (n *Nones) Generate(_ context.Context, _ *attempt.Conversation, generations int) ([]attempt.Message, error) {
	if generations <= 0 {
		generations = 1
	}

	responses := make([]attempt.Message, generations)
	for i := range responses {
		responses[i] = attempt.NewAssistantMessage("")
	}

	return responses, nil
}

// ClearHistory is a no-op for Nones generator.
func (n *Nones) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (n *Nones) Name() string {
	return "test.Nones"
}

// Description returns a human-readable description.
func (n *Nones) Description() string {
	return "Returns empty messages for testing probe handling of missing responses"
}
