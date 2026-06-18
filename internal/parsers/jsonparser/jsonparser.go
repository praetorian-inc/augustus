// Package jsonparser provides a registered parser that wraps internal/parsers/extract
// for use via --parser with any generator.
package jsonparser

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/parsers/extract"
	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("json.Extract", NewExtract)
}

// Compile-time interface assertion.
var _ parsers.Parser = (*Extract)(nil)

// Extract is a registered parser that extracts text from JSON responses
// using a JSONPath expression or simple field name.
type Extract struct {
	field string
}

// NewExtract creates a JSON extract parser from configuration.
func NewExtract(cfg registry.Config) (parsers.Parser, error) {
	field, _ := cfg["field"].(string)
	if field == "" {
		field, _ = cfg["response_json_field"].(string)
	}

	return &Extract{field: field}, nil
}

// Parse extracts text content from a JSON response body.
func (e *Extract) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	if e.field == "" {
		return string(raw), nil
	}
	return extract.Response(raw, true, e.field)
}

// Name returns the parser name.
func (e *Extract) Name() string {
	return "json.Extract"
}

// Description returns a human-readable description.
func (e *Extract) Description() string {
	return "Extracts text from JSON responses using JSONPath expressions"
}
