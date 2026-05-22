package probes

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// collectToolCalls gathers all non-nil ToolCalls slices from a set of
// messages and merges them into a single slice for attempt metadata.
// Returns nil when no messages carry tool calls.
func collectToolCalls(responses []attempt.Message) []map[string]any {
	var merged []map[string]any
	for _, resp := range responses {
		merged = append(merged, resp.ToolCalls...)
	}
	return merged
}

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
//   - toolsFn: Optional callback that returns (tools, toolChoice) to attach to
//     each conversation; pass nil when no tool definitions are needed
//
// Example:
//
//	attempts, err := RunPrompts(ctx, gen, prompts, "probe", "detector", nil, nil)
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
	toolsFn func() ([]map[string]any, string),
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

		if toolsFn != nil {
			if tools, toolChoice := toolsFn(); len(tools) > 0 {
				conv.Tools = tools
				conv.ToolChoice = toolChoice
			}
		}

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
			// Propagate tool calls from generator responses to attempt metadata
			// so detectors (e.g. agent.ToolManipulation) can score them.
			if toolCalls := collectToolCalls(responses); len(toolCalls) > 0 {
				a.WithMetadata(attempt.MetadataKeyToolCalls, toolCalls)
			}
			a.Complete()
		}

		attempts = append(attempts, a)
	}

	return attempts, nil
}

// RunTwoTurnPrompts executes a 2-turn tool-result flow for each prompt.
//
// For each prompt:
//  1. Send prompt with tools → model returns response (may contain tool calls)
//  2. If the response contains tool calls, find a matching canned result in
//     toolResults (keyed by tool name). Inject it as a tool-result message.
//  3. Send the extended conversation → model responds to the injected content.
//  4. Collect tool calls from BOTH turns into the attempt metadata.
//
// If the model doesn't return tool calls in Turn 1, the attempt records only
// Turn 1 (identical to RunPrompts behavior).
func RunTwoTurnPrompts(
	ctx context.Context,
	gen types.Generator,
	prompts []string,
	probeName string,
	detector string,
	tools []map[string]any,
	toolChoice string,
	toolResults map[string]string,
) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(prompts))

	for _, prompt := range prompts {
		select {
		case <-ctx.Done():
			return attempts, ctx.Err()
		default:
		}

		// Turn 1: send prompt with tools.
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)
		conv.Tools = tools
		conv.ToolChoice = toolChoice

		turn1Responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = probeName
		a.Detector = detector

		if err != nil {
			a.SetError(err)
			attempts = append(attempts, a)
			continue
		}

		// Record Turn 1 outputs.
		for _, resp := range turn1Responses {
			a.AddOutput(resp.Content)
		}
		allToolCalls := collectToolCalls(turn1Responses)

		// Check if Turn 1 produced tool calls that match a canned result.
		var matchedCallID, matchedResult string
		for _, tc := range allToolCalls {
			name, _ := tc["name"].(string)
			if result, ok := toolResults[name]; ok {
				id, _ := tc["id"].(string)
				if id == "" {
					id = "call_" + name
				}
				matchedCallID = id
				matchedResult = result
				break
			}
		}

		if matchedResult != "" {
			// Turn 2: inject canned tool result, get follow-up.
			// Add Turn 1 response to conversation history.
			// turn1Responses[0] is safe: Generate is always called with n=1 (line 155),
			// so exactly one response is returned on success.
			if len(turn1Responses) > 0 {
				lastTurnIdx := len(conv.Turns) - 1
				resp := turn1Responses[0]
				conv.Turns[lastTurnIdx].Response = &resp
			}

			// Add tool result as a new turn.
			toolResultMsg := attempt.NewToolResultMessage(matchedCallID, matchedResult)
			conv.AddTurn(attempt.Turn{Prompt: toolResultMsg})

			turn2Responses, err2 := gen.Generate(ctx, conv, 1)
			if err2 != nil {
				// Turn 1 succeeded, Turn 2 failed — record partial result.
				a.WithMetadata("turn2_error", err2.Error())
			} else {
				for _, resp := range turn2Responses {
					a.AddOutput(resp.Content)
				}
				turn2ToolCalls := collectToolCalls(turn2Responses)
				allToolCalls = append(allToolCalls, turn2ToolCalls...)
			}
		}

		if len(allToolCalls) > 0 {
			a.WithMetadata(attempt.MetadataKeyToolCalls, allToolCalls)
		}
		a.Complete()
		attempts = append(attempts, a)
	}

	return attempts, nil
}
