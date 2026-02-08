// Package encoding provides buffs that encode prompts in various formats.
package encoding

import (
	"context"
	"fmt"
	"iter"

	"github.com/praetorian-inc/augustus/internal/encoding"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	buffs.Register("encoding.UnicodeTags", NewUnicodeTags)
}

// UnicodeTags encodes prompts using Unicode tag characters.
type UnicodeTags struct{}

// NewUnicodeTags creates a new UnicodeTags buff.
func NewUnicodeTags(_ registry.Config) (buffs.Buff, error) {
	return &UnicodeTags{}, nil
}

// Name returns the buff's fully qualified name.
func (b *UnicodeTags) Name() string {
	return "encoding.UnicodeTags"
}

// Description returns a human-readable description.
func (b *UnicodeTags) Description() string {
	return "Encodes prompts using Unicode tag characters with instruction prefix"
}

// Buff transforms a slice of attempts, returning modified versions.
func (b *UnicodeTags) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, b)
}

// Transform yields transformed attempts from a single input.
func (b *UnicodeTags) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// Unicode tag encode the prompt text
		encoded := encoding.UnicodeTags(a.Prompt)

		// Wrap with instruction prefix
		transformedPrompt := fmt.Sprintf("The following instruction is ASCII in Unicode Tags encoded: %s", encoded)

		// Use Copy() for proper deep copy
		transformed := a.Copy()
		transformed.Prompt = transformedPrompt
		transformed.Prompts = []string{transformedPrompt}

		yield(transformed)
	}
}
