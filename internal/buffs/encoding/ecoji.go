// Package encoding provides buffs that encode prompts in various formats.
package encoding

import (
	"bytes"
	"context"
	"fmt"
	"iter"
	"log/slog"

	"github.com/keith-turner/ecoji/v2"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	buffs.Register("encoding.Ecoji", NewEcoji)
}

// Ecoji encodes prompts using Ecoji emoji encoding.
//
// This buff transforms the prompt text into emojis and wraps it with an
// instruction prefix. Ecoji encodes data as emojis - each 5 bytes of input
// is encoded as 4 emojis from a set of 1024 emojis (base1024 encoding).
type Ecoji struct{}

// NewEcoji creates a new Ecoji buff.
func NewEcoji(_ registry.Config) (buffs.Buff, error) {
	return &Ecoji{}, nil
}

// Name returns the buff's fully qualified name.
func (b *Ecoji) Name() string {
	return "encoding.Ecoji"
}

// Description returns a human-readable description.
func (b *Ecoji) Description() string {
	return "Encodes prompts using Ecoji emoji encoding with instruction prefix"
}

// Buff transforms a slice of attempts, returning modified versions.
func (b *Ecoji) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, b)
}

// Transform yields transformed attempts from a single input.
// Uses iter.Seq for lazy generation (Go 1.23+).
func (b *Ecoji) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// Ecoji encode the prompt text
		var out bytes.Buffer
		r := bytes.NewReader([]byte(a.Prompt))

		// Handle potential encoding errors gracefully
		if err := ecoji.EncodeV2(r, &out, 0); err != nil {
			slog.Warn("ecoji encoding failed, skipping attempt",
				"error", err,
				"prompt_length", len(a.Prompt),
			)
			return // Don't yield if encoding failed
		}

		encoded := out.String()

		// Wrap with instruction prefix
		transformedPrompt := fmt.Sprintf("The following instruction is Ecoji encoded: %s", encoded)

		// Use Copy() for proper deep copy
		transformed := a.Copy()
		transformed.Prompt = transformedPrompt
		transformed.Prompts = []string{transformedPrompt}

		yield(transformed)
	}
}
