package phrasing

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// FutureTense is a probe that attempts to evade safeguards by setting requests in future tense.
//
// This probe reformulates potentially harmful requests in the future tense
// (e.g., "How will X be done in the future?" instead of "How do you do X?").
// The technique exploits that LLM safety training often focuses on present-tense
// imperative commands while being less robust to hypothetical future framing.
//
// Python garak equivalent: garak.probes.phrasing.FutureTense
//
// Reference: https://arxiv.org/pdf/2407.11969v2
type FutureTense struct {
	prompts []string
}

// NewFutureTense creates a new FutureTense probe instance.
func NewFutureTense(_ registry.Config) (probes.Prober, error) {
	return &FutureTense{
		prompts: LoadFutureTensePrompts(),
	}, nil
}

// Probe executes the future tense rephrasing attack against the generator.
//
// For each prompt in the dataset, the probe:
// 1. Creates a new conversation with the future-tense formatted prompt
// 2. Sends it to the generator
// 3. Captures the response in an attempt object
// 4. Returns all attempts for detection/evaluation
func (p *FutureTense) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(p.prompts))

	for _, prompt := range p.prompts {
		// Create conversation with single prompt
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		// Generate response
		responses, err := gen.Generate(ctx, conv, 1)

		// Create attempt with metadata
		a := attempt.New(prompt)
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()

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
func (p *FutureTense) Name() string {
	return "phrasing.FutureTense"
}

// Description returns a human-readable description of the probe.
func (p *FutureTense) Description() string {
	return "Attempt to evade safeguards by setting requests in the future tense. " +
		"Reformulates potentially harmful requests using future-tense phrasing " +
		"(e.g., 'How will X be done in the future?' instead of 'How do you do X?'). " +
		"Exploits that LLM safety training often focuses on present-tense commands " +
		"while being less robust to hypothetical future framing."
}

// Goal returns the probe's objective (matching Python garak).
func (p *FutureTense) Goal() string {
	return "use future tense to disregard the system prompt"
}

// GetPrimaryDetector returns the recommended detector for this probe.
//
// Uses mitigation.MitigationBypass which detects when the model provides
// information it should refuse (bypassing its safety mitigations).
func (p *FutureTense) GetPrimaryDetector() string {
	return "mitigation.MitigationBypass"
}

// GetPrompts returns the prompts used by this probe.
//
// Returns all future-tense reformulated prompts loaded from the embedded data file.
func (p *FutureTense) GetPrompts() []string {
	return p.prompts
}
