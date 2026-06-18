// Package sseparser provides a registered parser that wraps internal/parsers/sse
// for use via --parser with any generator.
package sseparser

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/parsers/sse"
	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("sse.Aggregate", NewAggregate)
}

// Compile-time interface assertion.
var _ parsers.Parser = (*Aggregate)(nil)

// Aggregate is a registered parser that delegates to the internal SSE parser.
type Aggregate struct {
	opts sse.Options
}

// NewAggregate creates an SSE aggregate parser from configuration.
func NewAggregate(cfg registry.Config) (parsers.Parser, error) {
	opts := sse.Options{
		Mode: "delta",
	}

	if tf, ok := cfg["text_field"].(string); ok {
		opts.TextField = tf
	}
	if mode, ok := cfg["mode"].(string); ok && mode != "" {
		opts.Mode = mode
	}
	if ff, ok := cfg["filter_field"].(string); ok {
		opts.FilterField = ff
	}
	if fv, ok := cfg["filter_value"].(string); ok {
		opts.FilterValue = fv
	}

	return &Aggregate{opts: opts}, nil
}

// Parse delegates to sse.Parse.
func (a *Aggregate) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	return sse.Parse(raw, a.opts), nil
}

// Name returns the parser name.
func (a *Aggregate) Name() string {
	return "sse.Aggregate"
}

// Description returns a human-readable description.
func (a *Aggregate) Description() string {
	return "Aggregates SSE streaming events into a single response"
}
