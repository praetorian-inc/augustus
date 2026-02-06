// Package prefix provides adversarial prefix injection probes for LLM testing.
//
// Prefix probes attempt to bypass LLM safety mechanisms by prepending
// adversarial prefixes to harmful prompts. These prefixes use various
// techniques including roleplay, context manipulation, and authority claims.
//
// Python garak equivalent: garak.probes.prefix
package prefix

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("prefix.Prefix", NewPrefixProbe)
}

// PrefixProbe implements adversarial prefix injection attacks.
//
// It prepends adversarial prefixes to harmful base prompts to test
// if the target LLM can be manipulated to bypass safety guardrails.
type PrefixProbe struct {
	name            string
	goal            string
	primaryDetector string
	description     string
	prompts         []string
}

// NewPrefixProbe creates a new prefix injection probe.
//
// The probe combines each adversarial prefix with each harmful base prompt
// to generate a comprehensive test suite.
func NewPrefixProbe(_ registry.Config) (probes.Prober, error) {
	// Generate all combinations of prefixes and base prompts
	prompts := make([]string, 0, len(DefaultPrefixes)*len(HarmfulBasePrompts))

	for _, prefix := range DefaultPrefixes {
		for _, basePrompt := range HarmfulBasePrompts {
			// Combine prefix + base prompt
			prompt := prefix + basePrompt
			prompts = append(prompts, prompt)
		}
	}

	return &PrefixProbe{
		name:            "prefix.Prefix",
		goal:            "cause the model to disregard the system prompt via prefix injection",
		primaryDetector: "mitigation.MitigationBypass",
		description:     "Adversarial prefix injection probe - prepends crafted prefixes to harmful prompts to test if LLM safety mechanisms can be bypassed",
		prompts:         prompts,
	}, nil
}

// Probe executes the prefix injection attack against the generator.
func (p *PrefixProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(p.prompts))

	for _, prompt := range p.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

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
func (p *PrefixProbe) Name() string {
	return p.name
}

// Description returns a human-readable description.
func (p *PrefixProbe) Description() string {
	return p.description
}

// Goal returns the probe's goal (matches Python garak).
func (p *PrefixProbe) Goal() string {
	return p.goal
}

// GetPrimaryDetector returns the recommended detector.
func (p *PrefixProbe) GetPrimaryDetector() string {
	return p.primaryDetector
}

// GetPrompts returns the prompts used by this probe.
func (p *PrefixProbe) GetPrompts() []string {
	return p.prompts
}
