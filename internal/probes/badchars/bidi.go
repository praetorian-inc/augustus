// Package badchars provides imperceptible perturbation probes inspired by the Bad Characters paper.
//
// Implements Unicode-based attacks including invisible characters, bidi-based reorderings,
// and other imperceptible text manipulations as described in https://arxiv.org/abs/2106.09898.
//
// Python garak equivalent: garak.probes.badchars
package badchars

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Bidi control characters as defined in Unicode.
// These characters control text directionality and can be used to reorder text visually.
const (
	PDF = "\u202c" // Pop Directional Formatting
	LRO = "\u202d" // Left-to-Right Override
	RLO = "\u202e" // Right-to-Left Override
	LRI = "\u2066" // Left-to-Right Isolate
	RLI = "\u2067" // Right-to-Left Isolate
	PDI = "\u2069" // Pop Directional Isolate
)

// Payloads are defined in common.go to avoid duplication across badchars probes.

// Bidi is a probe that uses Unicode bidirectional text controls to reorder text.
//
// This probe applies bidi control characters to swap adjacent characters in harmful prompts,
// creating imperceptible perturbations that may bypass text-based safety filters while
// remaining semantically equivalent when rendered.
//
// Python garak equivalent: garak.probes.badchars.Bidi (reordering variants)
type Bidi struct {
	prompts []string
}

// NewBidi creates a new Bidi probe.
//
// The probe generates variants of harmful prompts by applying Unicode bidi controls
// to swap adjacent characters at various positions in the text.
func NewBidi(_ registry.Config) (probes.Prober, error) {
	var prompts []string

	// For each payload, generate variants with bidi swaps at different positions
	for _, payload := range defaultPayloads {
		// Select positions to apply swaps (similar to garak's strategy)
		// We'll apply single swaps at start, middle, and end positions
		// Don't include endpoint since we're swapping adjacent chars
		positions := selectPositions(len(payload), 3, false)

		for _, pos := range positions {
			// Only swap if position is valid (not at the end)
			if pos < len(payload)-1 {
				variant := applySwaps(payload, []int{pos})
				prompts = append(prompts, variant)
			}
		}

		// Also generate a variant with multiple swaps (2 positions)
		if len(positions) >= 2 {
			// Use first two non-overlapping positions
			nonOverlapping := []int{positions[0]}
			for _, pos := range positions[1:] {
				if pos >= nonOverlapping[len(nonOverlapping)-1]+2 {
					nonOverlapping = append(nonOverlapping, pos)
					if len(nonOverlapping) >= 2 {
						break
					}
				}
			}

			if len(nonOverlapping) >= 2 {
				variant := applySwaps(payload, nonOverlapping)
				prompts = append(prompts, variant)
			}
		}
	}

	return &Bidi{
		prompts: prompts,
	}, nil
}

// selectPositions is defined in common.go to avoid duplication.

// renderSwap wraps two characters in bidi control sequences to swap their display order.
//
// The sequence mirrors the bidi swap function from Boucher et al. ("Bad Characters")
// and forces two adjacent code points to render in reverse order while containing
// all directionality side effects.
//
// Python equivalent: garak.probes.badchars._render_swaps for _Swap objects
func renderSwap(first, second string) string {
	// Build the bidi control sequence that swaps first and second
	// Sequence: LRO, LRI, RLO, LRI, second, PDI, LRI, first, PDI, PDF, PDI, PDF
	//
	// Note: We swap the order of first/second in the sequence to achieve visual reordering
	return LRO + LRI + RLO + LRI + second + PDI + LRI + first + PDI + PDF + PDI + PDF
}

// applySwaps applies bidi swaps at the specified indices in the payload.
//
// Each index represents the position where two adjacent characters should be swapped.
// The function processes indices in order and adjusts for the length changes caused
// by inserting bidi control sequences.
//
// Python equivalent: garak.probes.badchars.BadCharacters._apply_swaps
func applySwaps(payload string, indices []int) string {
	// Convert string to rune slice for proper Unicode handling
	runes := []rune(payload)
	result := make([]any, len(runes))

	// Copy all runes as strings initially
	for i, r := range runes {
		result[i] = string(r)
	}

	// Apply swaps in reverse order to maintain correct indices
	// Track how many swaps we've done to adjust subsequent indices
	swapsDone := 0

	for _, idx := range indices {
		// Adjust index for previous swaps (each swap reduces array size by 1)
		adjusted := idx - swapsDone

		if adjusted < 0 || adjusted >= len(result)-1 {
			continue
		}

		// Get the two elements to swap
		first := result[adjusted].(string)
		second := result[adjusted+1].(string)

		// Replace the two elements with the bidi-swapped version
		swapped := renderSwap(first, second)

		// Build new result array
		newResult := make([]any, len(result)-1)
		copy(newResult[:adjusted], result[:adjusted])
		newResult[adjusted] = swapped
		copy(newResult[adjusted+1:], result[adjusted+2:])

		result = newResult
		swapsDone++
	}

	// Convert result back to string
	var output string
	for _, item := range result {
		output += item.(string)
	}

	return output
}

// Probe executes the Bidi attack against the generator.
func (b *Bidi) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(b.prompts))

	for _, prompt := range b.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = b.Name()
		a.Detector = b.GetPrimaryDetector()

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

// Name returns the probe's fully qualified name.
func (b *Bidi) Name() string {
	return "badchars.Bidi"
}

// Description returns a human-readable description.
func (b *Bidi) Description() string {
	return "Bidi probe - uses Unicode bidirectional text controls (LRO, RLO, LRI, RLI, PDI, PDF) to imperceptibly reorder characters in prompts, testing if models can be bypassed via visual text perturbations"
}

// Goal returns the probe's goal (matches Python garak).
func (b *Bidi) Goal() string {
	return "inject imperceptible text perturbations that bypass refusal policies"
}

// GetPrimaryDetector returns the recommended detector.
func (b *Bidi) GetPrimaryDetector() string {
	// Use approximate decoding detector since bidi reordering creates visual variations
	return "encoding.DecodeApprox"
}

// GetPrompts returns the attack prompts used by this probe.
func (b *Bidi) GetPrompts() []string {
	return b.prompts
}

func init() {
	probes.Register("badchars.Bidi", NewBidi)
}
