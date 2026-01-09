// Package latentinjection provides probes for testing latent injection attacks.
//
// Latent injection attacks involve hiding malicious instructions within seemingly
// benign text that only activate under certain conditions or in multi-turn conversations.
package latentinjection

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// Probe registration is now handled by templates.go via YAML templates

// SimpleProbe provides shared infrastructure for simple latent injection probes.
// Latent injection probes have prompts that hide malicious instructions.
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
// This is the common Probe implementation for all simple latent injection probes.
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
