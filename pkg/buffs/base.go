package buffs

import (
	"context"
	"iter"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Transformer is any type that can transform a single attempt into a sequence
// of attempts. All Buff implementations satisfy this interface via their
// Transform method.
type Transformer interface {
	Transform(a *attempt.Attempt) iter.Seq[*attempt.Attempt]
}

// DefaultBuff provides the standard Buff() loop: iterate over input attempts,
// check for context cancellation between each, collect all Transform() results.
//
// Most buff implementations have identical Buff() methods that follow this
// exact pattern. Using DefaultBuff eliminates that boilerplate.
//
// Usage in a buff implementation:
//
//	func (b *MyBuff) Buff(ctx context.Context, attempts []*attempt.Attempt) ([]*attempt.Attempt, error) {
//	    return buffs.DefaultBuff(ctx, attempts, b)
//	}
func DefaultBuff(ctx context.Context, attempts []*attempt.Attempt, t Transformer) ([]*attempt.Attempt, error) {
	var results []*attempt.Attempt

	for _, a := range attempts {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		for transformed := range t.Transform(a) {
			results = append(results, transformed)
		}
	}

	return results, nil
}
