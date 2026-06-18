// Package types provides shared interfaces used across Augustus packages.
//
// This package eliminates interface duplication by providing canonical definitions
// that other packages import via type aliases for backward compatibility.
package types

import (
	"context"
	"sync/atomic"

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

// DocumentCapable is an optional interface a Generator implements to declare
// that its request builder can transmit document attachments (Message.Documents)
// to the backing model — e.g. Anthropic's native PDF "document" content blocks.
//
// Document probes use this to skip generators whose wire layer cannot carry
// documents, rather than silently sending a doc-less request and mis-reporting
// the target as safe. Like SupportsVision, it reports STRUCTURAL capability
// (the generator emits document content blocks), not per-model support.
type DocumentCapable interface {
	SupportsDocuments() bool
}

// UsageReporter is an OPTIONAL interface a Generator (or a Generator decorator)
// may implement to expose the cumulative number of tokens it has consumed across
// all Generate calls since construction. Generators whose provider does not report
// usage simply embed UsageCounter and never Add, contributing 0 (honest coverage).
type UsageReporter interface {
	// AccumulatedTokens returns the running total of tokens consumed.
	// Safe to call concurrently and after concurrent Generate calls.
	AccumulatedTokens() int64
}

// UsageCounter is an embeddable, concurrency-safe token accumulator. Embed it in a
// generator struct to satisfy UsageReporter for free:
//
//	type Anthropic struct {
//	    types.UsageCounter   // embedded; provides AccumulatedTokens()
//	    // ... existing fields ...
//	}
//	// at each usage-parse site:
//	g.AddTokens(int64(resp.Usage.InputTokens + resp.Usage.OutputTokens))
//
// The zero value is ready to use. It MUST NOT be copied after first use
// (atomic.Int64 has noCopy); generators are always used as pointers, and go vet
// copylocks (run by the lint gate) enforces this.
type UsageCounter struct {
	tokens atomic.Int64
}

// AddTokens adds n to the cumulative total. Safe for concurrent use.
func (u *UsageCounter) AddTokens(n int64) { u.tokens.Add(n) }

// AccumulatedTokens returns the cumulative total. Satisfies UsageReporter.
func (u *UsageCounter) AccumulatedTokens() int64 { return u.tokens.Load() }
