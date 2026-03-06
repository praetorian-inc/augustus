// Package passthrough provides a no-op parser that returns content unchanged.
package passthrough

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/parsers"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	parsers.Register("passthrough.Passthrough", NewPassthrough)
}

// Compile-time interface assertion.
var _ parsers.Parser = (*Passthrough)(nil)

// Passthrough is a no-op parser that returns content unchanged.
// It serves as the default parser when no transformation is needed.
type Passthrough struct{}

// NewPassthrough creates a new passthrough parser.
func NewPassthrough(_ registry.Config) (parsers.Parser, error) {
	return &Passthrough{}, nil
}

// Parse returns the raw content unchanged.
func (p *Passthrough) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	return string(raw), nil
}

// Name returns the parser name.
func (p *Passthrough) Name() string {
	return "passthrough.Passthrough"
}

// Description returns a human-readable description.
func (p *Passthrough) Description() string {
	return "No-op parser that returns content unchanged"
}
