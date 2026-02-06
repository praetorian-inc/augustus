// Package lowercase provides a buff that converts prompts to lowercase.
//
// This is a port of garak/buffs/lowercase.py to Go.
package lowercase

import (
	"context"
	"iter"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	buffs.Register("lowercase.Lowercase", NewLowercase)
}

// Lowercase is a buff that converts all prompt text to lowercase.
// Useful for testing model robustness to case variations.
type Lowercase struct{}

// NewLowercase creates a new Lowercase buff.
func NewLowercase(_ registry.Config) (buffs.Buff, error) {
	return &Lowercase{}, nil
}

// Buff transforms a slice of attempts, returning modified versions with
// lowercased prompts.
func (l *Lowercase) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	return buffs.DefaultBuff(ctx, attempts, l)
}

// Transform yields a single transformed attempt with lowercased prompts.
// Uses iter.Seq for lazy generation (Go 1.23+).
func (l *Lowercase) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		// Create a copy with lowercased prompts
		transformed := &attempt.Attempt{
			ID:              a.ID,
			Probe:           a.Probe,
			Generator:       a.Generator,
			Detector:        a.Detector,
			Prompt:          strings.ToLower(a.Prompt),
			Outputs:         a.Outputs,
			Conversations:   a.Conversations,
			Scores:          a.Scores,
			DetectorResults: a.DetectorResults,
			Status:          a.Status,
			Error:           a.Error,
			Timestamp:       a.Timestamp,
			Duration:        a.Duration,
			Metadata:        a.Metadata,
		}

		// Lowercase all prompts in the slice
		if len(a.Prompts) > 0 {
			transformed.Prompts = make([]string, len(a.Prompts))
			for i, p := range a.Prompts {
				transformed.Prompts[i] = strings.ToLower(p)
			}
		}

		yield(transformed)
	}
}

// Name returns the buff's fully qualified name.
func (l *Lowercase) Name() string {
	return "lowercase.Lowercase"
}

// Description returns a human-readable description.
func (l *Lowercase) Description() string {
	return "Converts all prompt text to lowercase"
}
