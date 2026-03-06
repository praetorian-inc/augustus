package parsers

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// Compile-time interface assertion.
var _ types.Generator = (*ParsedGenerator)(nil)

// ParsedGenerator wraps a Generator and applies a Parser to its output.
// This allows transparent parsing of LLM responses before they reach detectors.
type ParsedGenerator struct {
	inner  types.Generator
	parser Parser
}

// NewParsedGenerator creates a new parsed generator wrapper.
// The parser will be applied to each message returned by the inner generator.
func NewParsedGenerator(gen types.Generator, parser Parser) *ParsedGenerator {
	return &ParsedGenerator{inner: gen, parser: parser}
}

// Generate calls the inner generator and applies the parser to each message.
func (g *ParsedGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	// Call inner generator
	messages, err := g.inner.Generate(ctx, conv, n)
	if err != nil {
		return nil, err
	}

	// Default content type - parsers should handle format detection
	contentType := "text/plain"

	// Apply parser to each message
	for i := range messages {
		parsed, err := g.parser.Parse(ctx, []byte(messages[i].Content), contentType)
		if err != nil {
			return nil, err
		}
		messages[i].Content = parsed
	}

	return messages, nil
}

// ClearHistory delegates to the inner generator.
func (g *ParsedGenerator) ClearHistory() {
	g.inner.ClearHistory()
}

// Name returns the inner generator's name.
func (g *ParsedGenerator) Name() string {
	return g.inner.Name()
}

// Description returns the inner generator's description.
func (g *ParsedGenerator) Description() string {
	return g.inner.Description()
}

// Inner returns the wrapped generator.
// This can be used to access generator-specific functionality.
func (g *ParsedGenerator) Inner() types.Generator {
	return g.inner
}

// Parser returns the parser being applied.
func (g *ParsedGenerator) Parser() Parser {
	return g.parser
}
