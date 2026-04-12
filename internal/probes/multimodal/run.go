package multimodal

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// MultimodalPrompt pairs text with image attachments.
type MultimodalPrompt struct {
	Text   string
	Images []attempt.Image
}

// RunMultimodalPrompts executes multimodal prompts against a generator.
//
// Error handling contract:
//   - Returns error ONLY when context is cancelled (ctx.Err() != nil)
//   - Individual prompt failures are recorded in each attempt's Error field
//   - Returns nil error even if ALL prompts fail - caller must check attempt.Error
//
// This matches the contract of pkg/probes.RunPrompts.
func RunMultimodalPrompts(
	ctx context.Context,
	gen types.Generator,
	prompts []MultimodalPrompt,
	probeName string,
	detector string,
) ([]*attempt.Attempt, error) {
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
