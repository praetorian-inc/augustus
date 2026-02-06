package test

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.Single", NewSingle)
}

// Single is a test generator that returns a fixed string and refuses multiple generations.
// Useful for testing that generation logic properly handles single-generation constraints.
type Single struct{}

// NewSingle creates a new Single generator.
func NewSingle(_ registry.Config) (generators.Generator, error) {
	return &Single{}, nil
}

// Generate returns the fixed string "ELIM" for single generations.
// Returns an error if n > 1 to test generation logic.
func (s *Single) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n > 1 {
		return nil, fmt.Errorf("test.Single refuses to generate multiple generations (requested %d)", n)
	}

	return []attempt.Message{attempt.NewAssistantMessage("ELIM")}, nil
}

// ClearHistory is a no-op for Single generator.
func (s *Single) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (s *Single) Name() string {
	return "test.Single"
}

// Description returns a human-readable description.
func (s *Single) Description() string {
	return "Returns fixed string 'ELIM' and refuses multiple generations for testing constraints"
}
