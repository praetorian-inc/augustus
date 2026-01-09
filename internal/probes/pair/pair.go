// Package pair provides PAIR (Prompt Automatic Iterative Refinement) probe for LLM testing.
//
// PAIR implements an iterative prompt refinement attack that:
// 1. Starts with an initial adversarial prompt
// 2. Uses an attacker model to refine the prompt based on target model responses
// 3. Iteratively improves the attack until successful or max iterations reached
//
// This is based on the PAIR methodology for automated jailbreak discovery.
package pair

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// Note: PAIR probes are now registered via YAML templates in templates.go
// The init() function that registered hardcoded probes has been removed.

// SimpleProbe provides shared infrastructure for simple PAIR jailbreak probes.
type SimpleProbe struct {
	name            string
	goal            string
	primaryDetector string
	description     string
	prompts         []string
}

// NewSimpleProbe creates a new simple probe with the given configuration.
func NewSimpleProbe(name, goal, detector, description string, prompts []string) *SimpleProbe {
	return &SimpleProbe{
		name:            name,
		goal:            goal,
		primaryDetector: detector,
		description:     description,
		prompts:         prompts,
	}
}

// Probe executes the probe against the generator.
func (s *SimpleProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(s.prompts))

	for _, prompt := range s.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = s.Name()
		a.Detector = s.GetPrimaryDetector()

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
func (s *SimpleProbe) Name() string {
	return s.name
}

// Description returns a human-readable description.
func (s *SimpleProbe) Description() string {
	return s.description
}

// Goal returns the probe's goal.
func (s *SimpleProbe) Goal() string {
	return s.goal
}

// GetPrimaryDetector returns the recommended detector.
func (s *SimpleProbe) GetPrimaryDetector() string {
	return s.primaryDetector
}

// GetPrompts returns the prompts used by this probe.
func (s *SimpleProbe) GetPrompts() []string {
	return s.prompts
}

// Note: Hardcoded PAIR probes (NewPAIR, NewPAIRBasic) have been removed.
// PAIR probes are now defined as YAML templates in data/*.yaml and loaded via templates.go.
