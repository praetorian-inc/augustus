package probes

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// RunPrompts executes a standard probe loop: for each prompt it creates a
// conversation, sends it to the generator, and collects the result into an
// attempt. This is the shared core of SimpleProbe.Probe and
// templates.TemplateProbe.Probe.
//
// probeName and detector are stamped onto every attempt.  metadataFn is an
// optional callback invoked after an attempt is created but before outputs
// are added; pass nil when no per-attempt metadata is needed.
func RunPrompts(
	ctx context.Context,
	gen types.Generator,
	prompts []string,
	probeName string,
	detector string,
	metadataFn func(i int, prompt string, a *attempt.Attempt),
) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(prompts))

	for i, prompt := range prompts {
		// Check for context cancellation before each request.
		select {
		case <-ctx.Done():
			return attempts, ctx.Err()
		default:
		}

		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = probeName
		a.Detector = detector

		// Apply optional per-attempt metadata.
		if metadataFn != nil {
			metadataFn(i, prompt, a)
		}

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
