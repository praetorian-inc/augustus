// Package prefix provides adversarial prefix injection probes for LLM testing.
//
// Prefix probes attempt to bypass LLM safety mechanisms by prepending
// adversarial prefixes to harmful prompts. These prefixes use various
// techniques including roleplay, context manipulation, and authority claims.
//
// Python garak equivalent: garak.probes.prefix
package prefix

import (
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
	*probes.SimpleProbe
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
		SimpleProbe: probes.NewSimpleProbe(
			"prefix.Prefix",
			"cause the model to disregard the system prompt via prefix injection",
			"mitigation.MitigationBypass",
			"Adversarial prefix injection probe - prepends crafted prefixes to harmful prompts to test if LLM safety mechanisms can be bypassed",
			prompts,
		),
	}, nil
}
