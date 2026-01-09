// Package types provides shared interfaces used across Augustus packages.
//
// This package eliminates interface duplication by providing canonical definitions
// that other packages import via type aliases for backward compatibility.
package types

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Generator is the interface that all generator implementations must satisfy.
// Generators wrap LLM APIs with a common interface for authentication, rate limiting,
// and conversation management.
type Generator interface {
	// Generate sends a conversation to the model and returns responses.
	// n specifies the number of completions to generate.
	Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error)
	// ClearHistory resets any conversation state in the generator.
	ClearHistory()
	// Name returns the fully qualified generator name (e.g., "openai.GPT4").
	Name() string
	// Description returns a human-readable description.
	Description() string
}
