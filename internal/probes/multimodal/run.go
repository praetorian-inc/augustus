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
// Apart from the vision pre-flight check, this matches the contract of
// pkg/probes.RunPrompts.
func RunMultimodalPrompts(
	ctx context.Context,
	gen types.Generator,
	prompts []MultimodalPrompt,
	probeName string,
	detector string,
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

	return attempts, nil
}
