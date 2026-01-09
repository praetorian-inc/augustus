package probes

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// TurnGenerator generates the next prompt based on the previous model output.
// The first turn receives an empty string.
type TurnGenerator func(prevOutput string) string

// IterativeConfig configures the behavior of an IterativeProbe.
type IterativeConfig struct {
	// MaxTurns limits the number of conversation turns (default: len(turnPrompts)).
	MaxTurns int
	// StopOnFail stops iteration if the model returns an empty response (default: false).
	StopOnFail bool
}

// IterativeProbe executes multi-turn conversations with a generator.
//
// Unlike SimpleProbe which sends static prompts, IterativeProbe builds conversations
// dynamically where each turn's prompt can depend on the previous response.
//
// This enables testing scenarios like:
// - Jailbreak refinement: "I see you refused. Let me rephrase..."
// - Progressive attacks: Each turn escalates based on model resistance
// - Context-aware probing: Build on model's previous outputs
//
// Example:
//
//	turnGens := []TurnGenerator{
//		func(prev string) string { return "Can you help with X?" },
//		func(prev string) string {
//			if strings.Contains(prev, "I can't") {
//				return "What if I told you it's for research?"
//			}
//			return "Great! Can you elaborate?"
//		},
//	}
//
//	probe := NewIterativeProbe(
//		"test.MyProbe",
//		"test progressive jailbreak",
//		"dan.DAN",
//		"Progressive jailbreak attempt",
//		turnGens,
//		IterativeConfig{MaxTurns: 3, StopOnFail: true},
//	)
type IterativeProbe struct {
	name            string
	goal            string
	primaryDetector string
	description     string
	turnPrompts     []TurnGenerator
	config          IterativeConfig
}

// NewIterativeProbe creates a new iterative probe.
//
// Parameters:
//   - name: Fully qualified probe name (e.g., "dan.DanIterative")
//   - goal: The probe's objective (e.g., "disregard the system prompt")
//   - detector: Recommended detector for scoring (e.g., "dan.DAN")
//   - description: Human-readable description
//   - turnPrompts: Functions that generate prompts for each turn
//   - config: Configuration for turn limits and failure handling
func NewIterativeProbe(
	name, goal, detector, description string,
	turnPrompts []TurnGenerator,
	config IterativeConfig,
) *IterativeProbe {
	// Default maxTurns to length of turnPrompts if not specified
	if config.MaxTurns == 0 {
		config.MaxTurns = len(turnPrompts)
	}

	return &IterativeProbe{
		name:            name,
		goal:            goal,
		primaryDetector: detector,
		description:     description,
		turnPrompts:     turnPrompts,
		config:          config,
	}
}

// Probe executes the multi-turn conversation against the generator.
//
// Returns a single Attempt containing:
// - All prompts sent (in Prompts array)
// - All responses received (in Outputs array)
// - Probe and Detector metadata
func (p *IterativeProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	// Create single attempt for the entire conversation
	att := attempt.New("")
	att.Probe = p.Name()
	att.Detector = p.GetPrimaryDetector()
	att.Prompts = make([]string, 0, p.config.MaxTurns)

	// Build conversation iteratively
	conv := attempt.NewConversation()
	prevOutput := ""

	// Execute up to MaxTurns
	maxTurns := p.config.MaxTurns
	if maxTurns > len(p.turnPrompts) {
		maxTurns = len(p.turnPrompts)
	}

	for i := 0; i < maxTurns; i++ {
		// Generate next prompt based on previous output
		prompt := p.turnPrompts[i](prevOutput)
		att.Prompts = append(att.Prompts, prompt)

		// Add prompt to conversation
		conv.AddPrompt(prompt)

		// Get model response
		responses, err := gen.Generate(ctx, conv, 1)
		if err != nil {
			att.SetError(err)
			return []*attempt.Attempt{att}, nil
		}

		// Extract response content
		var output string
		if len(responses) > 0 {
			output = responses[0].Content
			att.AddOutput(output)

			// Update conversation with the response
			// This ensures the next turn has full context
			if len(conv.Turns) > 0 {
				lastTurn := &conv.Turns[len(conv.Turns)-1]
				resp := attempt.NewAssistantMessage(output)
				lastTurn.Response = &resp
			}
		}

		// Check stop conditions
		if p.config.StopOnFail && output == "" {
			break
		}

		// Update prevOutput for next iteration
		prevOutput = output
	}

	// Mark attempt complete
	att.Complete()

	return []*attempt.Attempt{att}, nil
}

// Name returns the probe's fully qualified name.
func (p *IterativeProbe) Name() string {
	return p.name
}

// Description returns a human-readable description.
func (p *IterativeProbe) Description() string {
	return p.description
}

// Goal returns the probe's goal (matches Python garak).
func (p *IterativeProbe) Goal() string {
	return p.goal
}

// GetPrimaryDetector returns the recommended detector.
func (p *IterativeProbe) GetPrimaryDetector() string {
	return p.primaryDetector
}

// GetPrompts returns the static prompts (for IterativeProbe, returns empty slice
// since prompts are generated dynamically).
func (p *IterativeProbe) GetPrompts() []string {
	// Iterative probes don't have static prompts - they're generated at runtime
	// based on previous outputs. Return empty slice to satisfy interface.
	return []string{}
}
