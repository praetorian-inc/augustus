package types

import "context"

// Parser normalizes raw LLM response content before detection.
// Parsers transform raw/fragmented responses (e.g., SSE streams) into
// coherent text suitable for detector analysis.
type Parser interface {
	// Parse transforms raw response content into normalized text.
	// The contentType hint (e.g., "text/event-stream", "application/json")
	// helps parsers decide how to process the input.
	Parse(ctx context.Context, raw []byte, contentType string) (string, error)

	// Name returns the fully qualified parser name (e.g., "sse.Aggregate").
	Name() string

	// Description returns a human-readable description.
	Description() string
}
