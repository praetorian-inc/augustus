// Package buffs provides the buff interface for prompt transformations.
//
// Buffs transform attempts by modifying prompts. They can add prefixes,
// encode text, translate languages, or apply other mutations to test
// LLM robustness against prompt variations.
package buffs

import (
	"context"
	"iter"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Buff transforms attempts by modifying their prompts.
type Buff interface {
	// Buff transforms a slice of attempts, returning modified versions.
	Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error)
	// Transform yields transformed attempts from a single input.
	// Uses iter.Seq for lazy generation (Go 1.23+).
	Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt]
	// Name returns the buff's fully qualified name.
	Name() string
	// Description returns a human-readable description.
	Description() string
}

// PostBuff is an optional interface for buffs that need to post-process
// generator outputs after generation but before detection.
type PostBuff interface {
	Buff
	// HasPostBuffHook returns true if this buff needs post-generation processing.
	HasPostBuffHook() bool
	// Untransform post-processes an attempt after generation.
	Untransform(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error)
}

// Registry is the global buff registry.
var Registry = registry.New[Buff]("buffs")

// Register adds a buff factory to the global registry.
func Register(name string, factory func(registry.Config) (Buff, error)) {
	Registry.Register(name, factory)
}

// List returns all registered buff names.
func List() []string {
	return Registry.List()
}

// Get retrieves a buff factory by name.
func Get(name string) (func(registry.Config) (Buff, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a buff by name.
func Create(name string, cfg registry.Config) (Buff, error) {
	return Registry.Create(name, cfg)
}
