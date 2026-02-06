package buffs

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// BuffedProber wraps a Prober and applies buff transformations.
type BuffedProber struct {
	inner types.Prober
	chain *BuffChain
	gen   types.Generator
}

// NewBuffedProber wraps a prober with buff transformations.
// If the chain is nil or empty, it returns the inner prober directly (zero overhead).
func NewBuffedProber(inner types.Prober, chain *BuffChain, gen types.Generator) types.Prober {
	if chain == nil || chain.IsEmpty() {
		return inner
	}
	return &BuffedProber{
		inner: inner,
		chain: chain,
		gen:   gen,
	}
}

// Probe executes the wrapped probe, applies buffs, re-generates, and returns.
func (bp *BuffedProber) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	// Get original attempts from inner probe
	originalAttempts, err := bp.inner.Probe(ctx, gen)
	if err != nil {
		return nil, err
	}

	// Apply buff chain to transform prompts
	var allAttempts []*attempt.Attempt
	for _, orig := range originalAttempts {
		transformed, err := bp.chain.Apply(ctx, []*attempt.Attempt{orig})
		if err != nil {
			return nil, fmt.Errorf("buff chain failed for probe %s: %w", bp.inner.Name(), err)
		}

		for _, ta := range transformed {
			// If prompt changed, re-generate
			if ta.Prompt != orig.Prompt {
				conv := attempt.NewConversation()
				conv.AddPrompt(ta.Prompt)

				messages, genErr := gen.Generate(ctx, conv, 1)
				if genErr != nil {
					// Set error on attempt but don't fail completely (partial failure)
					ta.SetError(genErr)
					allAttempts = append(allAttempts, ta)
					continue
				}

				// Replace outputs with new generation
				ta.Outputs = make([]string, len(messages))
				for i, msg := range messages {
					ta.Outputs[i] = msg.Content
				}

				// Apply post-buff hooks
				if bp.chain.HasPostBuffHooks() {
					ta, err = bp.chain.ApplyPostBuffs(ctx, ta)
					if err != nil {
						return nil, fmt.Errorf("post-buff failed for probe %s: %w", bp.inner.Name(), err)
					}
				}
			}

			allAttempts = append(allAttempts, ta)
		}
	}

	return allAttempts, nil
}

// Name returns the probe name (delegated to inner).
func (bp *BuffedProber) Name() string { return bp.inner.Name() }

// Description returns the probe description (delegated to inner).
func (bp *BuffedProber) Description() string { return bp.inner.Description() }

// Goal returns the probe goal (delegated to inner).
func (bp *BuffedProber) Goal() string { return bp.inner.Goal() }

// GetPrimaryDetector returns the primary detector (delegated to inner).
func (bp *BuffedProber) GetPrimaryDetector() string { return bp.inner.GetPrimaryDetector() }

// GetPrompts returns the probe prompts (delegated to inner).
func (bp *BuffedProber) GetPrompts() []string { return bp.inner.GetPrompts() }
