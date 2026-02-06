package buffs

import (
	"context"
	"fmt"
	"iter"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// BuffChain composes multiple buffs into a sequential pipeline.
type BuffChain struct {
	buffs []Buff
}

// NewBuffChain creates a chain from the given buffs.
func NewBuffChain(buffs ...Buff) *BuffChain {
	return &BuffChain{buffs: buffs}
}

// Len returns the number of buffs in the chain.
func (c *BuffChain) Len() int {
	return len(c.buffs)
}

// IsEmpty returns true if the chain has no buffs.
func (c *BuffChain) IsEmpty() bool {
	return len(c.buffs) == 0
}

// Buffs returns the underlying buff slice.
func (c *BuffChain) Buffs() []Buff {
	return c.buffs
}

// Apply runs all buffs in sequence on the given attempts.
func (c *BuffChain) Apply(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
	if len(c.buffs) == 0 {
		return attempts, nil
	}

	current := attempts
	for _, b := range c.buffs {
		var err error
		current, err = b.Buff(ctx, current)
		if err != nil {
			return nil, fmt.Errorf("buff %s failed: %w", b.Name(), err)
		}
	}
	return current, nil
}

// Transform applies all buffs lazily using iter.Seq.
func (c *BuffChain) Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt] {
	if len(c.buffs) == 0 {
		return func(yield func(*attempt.Attempt) bool) {
			yield(a)
		}
	}

	current := c.buffs[0].Transform(a)
	for _, b := range c.buffs[1:] {
		current = chainTransforms(current, b)
	}
	return current
}

// chainTransforms feeds each attempt from prev into next's Transform.
func chainTransforms(prev iter.Seq[*attempt.Attempt], next Buff) iter.Seq[*attempt.Attempt] {
	return func(yield func(*attempt.Attempt) bool) {
		for a := range prev {
			for transformed := range next.Transform(a) {
				if !yield(transformed) {
					return
				}
			}
		}
	}
}

// ApplyPostBuffs runs any PostBuff.Untransform hooks on the attempt.
func (c *BuffChain) ApplyPostBuffs(ctx context.Context, a *attempt.Attempt) (*attempt.Attempt, error) {
	current := a
	for _, b := range c.buffs {
		if pb, ok := b.(PostBuff); ok && pb.HasPostBuffHook() {
			var err error
			current, err = pb.Untransform(ctx, current)
			if err != nil {
				return nil, fmt.Errorf("post-buff %s failed: %w", b.Name(), err)
			}
		}
	}
	return current, nil
}

// HasPostBuffHooks returns true if any buff implements PostBuff.
func (c *BuffChain) HasPostBuffHooks() bool {
	for _, b := range c.buffs {
		if pb, ok := b.(PostBuff); ok && pb.HasPostBuffHook() {
			return true
		}
	}
	return false
}
