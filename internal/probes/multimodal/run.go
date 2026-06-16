package multimodal

import (
	"context"
	"errors"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// ErrVisionUnsupported is returned by a multimodal probe when its target
// generator cannot transmit image attachments. Surfacing it as a probe error
// (rather than running a text-only request) prevents a dropped image from being
// silently scored as a clean "safe" verdict.
var ErrVisionUnsupported = errors.New("generator does not support image input")

// MultimodalPrompt pairs text with image attachments.
type MultimodalPrompt struct {
	Text   string
	Images []attempt.Image

	// Canary is the exact canary phrase embedded in this prompt's image. It is
	// attached to the resulting attempt so the multimodal Canary detector reads
	// it from there, keeping the probe the single source of truth and avoiding
	// drift against a separately-maintained global list.
	Canary string
}

// generatorSupportsVision reports whether gen can transmit image attachments,
// via the optional types.VisionCapable interface. Generators that do not
// implement it are treated as text-only.
func generatorSupportsVision(gen types.Generator) bool {
	vc, ok := gen.(types.VisionCapable)
	return ok && vc.SupportsVision()
}

// RunMultimodalPrompts executes multimodal prompts against a generator.
//
// Error handling contract:
//   - Returns ErrVisionUnsupported (wrapped) if the generator cannot carry
//     images — the probe is skipped rather than run as a misleading text-only
//     request. The harness reports this as a failed probe, never as "safe".
//   - Returns ctx.Err() if the context is cancelled.
//   - Individual prompt failures are recorded in each attempt's Error field;
//     returns nil error even if ALL prompts fail - caller must check attempt.Error
//
// The covert flag records each attempt's channel type (via
// attempt.MetaMultimodalCovert) so the multimodal Canary detector knows whether
// the canary's presence is itself the finding (covert) or merely informational
// (visible).
//
// Apart from the vision pre-flight check, this matches the contract of
// pkg/probes.RunPrompts.
func RunMultimodalPrompts(
	ctx context.Context,
	gen types.Generator,
	prompts []MultimodalPrompt,
	probeName string,
	detector string,
	covert bool,
) ([]*attempt.Attempt, error) {
	if !generatorSupportsVision(gen) {
		return nil, fmt.Errorf("%s: %w (generator %q)", probeName, ErrVisionUnsupported, gen.Name())
	}

	attempts := make([]*attempt.Attempt, 0, len(prompts))

	for _, mp := range prompts {
		// Check for context cancellation before each request.
		select {
		case <-ctx.Done():
			return attempts, ctx.Err()
		default:
		}

		conv := attempt.NewConversation()
		msg := attempt.NewUserMessageWithImages(mp.Text, mp.Images)
		conv.AddPromptMessage(msg)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(mp.Text)
		a.Probe = probeName
		a.Detector = detector
		if mp.Canary != "" {
			a.Metadata[attempt.MetaMultimodalCanary] = mp.Canary
		}
		a.Metadata[attempt.MetaMultimodalCovert] = covert

		if err != nil {
			a.SetError(err)
		} else {
			for _, resp := range responses {
				a.AddOutput(resp.Content)
			}
			a.Complete()
		}

		attempts = append(attempts, a)
	}

	// If ctx was cancelled during the LAST gen.Generate (the pre-loop check
	// above only fires on subsequent iterations), propagate the cancellation
	// so a partial run isn't reported as a successful scan.
	if err := ctx.Err(); err != nil {
		return attempts, err
	}
	return attempts, nil
}
