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

// VisionCapable is an optional interface a Generator implements to declare that
// its request builder can transmit image attachments to the backing model.
//
// Multimodal image probes use this to skip generators whose wire layer cannot
// carry images, rather than silently sending a text-only request and
// mis-reporting the target as safe — a false negative is the worst outcome for
// a vulnerability scanner.
//
// SupportsVision reports STRUCTURAL capability (the generator emits image
// content blocks), not per-model support. An OpenAI-compatible generator
// returns true even though, say, gpt-3.5 ignores images, because choosing which
// model to point at is the operator's responsibility, not the harness's.
type VisionCapable interface {
	SupportsVision() bool
}
