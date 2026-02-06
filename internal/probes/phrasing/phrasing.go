// Package phrasing provides probes that test LLM vulnerabilities through prompt rephrasing.
//
// These probes reformulate potentially harmful requests using grammatical alterations
// (past tense, future tense, etc.) to attempt bypassing safety filters. The technique
// exploits the observation that safety training often focuses on present-tense commands
// while being less robust to historical or hypothetical framing.
//
// Reference: https://arxiv.org/pdf/2407.11969v2
package phrasing

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("phrasing.PastTense", NewPastTense)
	probes.Register("phrasing.FutureTense", NewFutureTense)
}

// PastTense is a probe that attempts to evade safeguards by setting requests in past tense.
//
// This probe reformulates potentially harmful requests in the past tense
// (e.g., "How was X done in the past?" instead of "How do you do X?").
// The technique exploits that LLM safety training often focuses on present-tense
// imperative commands while being less robust to historical framing.
//
// Python garak equivalent: garak.probes.phrasing.PastTense
//
// Reference: https://arxiv.org/pdf/2407.11969v2
type PastTense struct {
	prompts []string
}

// NewPastTense creates a new PastTense probe instance.
func NewPastTense(_ registry.Config) (probes.Prober, error) {
	return &PastTense{
		prompts: LoadPastTensePrompts(),
	}, nil
}

// Probe executes the past tense rephrasing attack against the generator.
//
// For each prompt in the dataset, the probe:
// 1. Creates a new conversation with the past-tense formatted prompt
// 2. Sends it to the generator
// 3. Captures the response in an attempt object
// 4. Returns all attempts for detection/evaluation
func (p *PastTense) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
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
func (p *PastTense) Name() string {
	return "phrasing.PastTense"
}

// Description returns a human-readable description of the probe.
func (p *PastTense) Description() string {
	return "Attempt to evade safeguards by setting requests in the past tense. " +
		"Reformulates potentially harmful requests using past-tense phrasing " +
		"(e.g., 'How was X done in the past?' instead of 'How do you do X?'). " +
		"Exploits that LLM safety training often focuses on present-tense commands " +
		"while being less robust to historical framing."
}

// Goal returns the probe's objective (matching Python garak).
func (p *PastTense) Goal() string {
	return "use past tense to disregard the system prompt"
}

// GetPrimaryDetector returns the recommended detector for this probe.
//
// Uses mitigation.MitigationBypass which detects when the model provides
// information it should refuse (bypassing its safety mitigations).
func (p *PastTense) GetPrimaryDetector() string {
	return "mitigation.MitigationBypass"
}

// GetPrompts returns the prompts used by this probe.
//
// Returns all past-tense reformulated prompts loaded from the embedded data file.
func (p *PastTense) GetPrompts() []string {
	return p.prompts
}
