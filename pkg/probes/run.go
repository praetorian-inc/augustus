package probes

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// RunPrompts executes multiple prompts sequentially against a generator.
//
// For each prompt it creates a conversation, sends it to the generator, and
// collects the result into an attempt. This is the shared core of
// SimpleProbe.Probe and templates.TemplateProbe.Probe.
//
// Error handling contract:
//   - Returns error ONLY when context is cancelled (ctx.Err() != nil)
//   - Individual prompt failures are recorded in each attempt's Error field
//   - Returns nil error even if ALL prompts fail - caller must check attempt.Error
//
// This design allows partial success scenarios where some prompts succeed
// and others fail, which is common with rate limiting or transient API issues.
//
// Arguments:
//   - ctx: Context for cancellation support
//   - gen: Generator that produces responses to prompts
//   - prompts: Slice of prompts to execute
//   - probeName: Name stamped onto every attempt
//   - detector: Detector name stamped onto every attempt
//   - metadataFn: Optional callback invoked after attempt creation but before
//     outputs are added; pass nil when no per-attempt metadata is needed
//
// Example:
//
//	attempts, err := RunPrompts(ctx, gen, prompts, "probe", "detector", nil)
//	if err != nil {
//	    // Context was cancelled
//	    return err
//	}
//	for _, a := range attempts {
//	    if a.Error != "" {
//	        // This specific prompt failed
//	        log.Printf("prompt %s failed: %s", a.Prompt, a.Error)
//	    }
//	}
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
