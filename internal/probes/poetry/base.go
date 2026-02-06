// Package poetry provides poetry-based prompt injection probes for LLM testing.
//
// These probes reformulate harmful prompts into poetic structures (haiku, sonnet,
// limerick, etc.) to bypass LLM safety mechanisms. Research shows poetry formatting
// can achieve up to 18x improvement over prose jailbreak baselines.
//
// Based on arXiv:2511.15304: "Adversarial Poetry as a Universal Single-Turn
// Jailbreak Mechanism"
package poetry

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// PoetryFormatter transforms a harmful payload into poetry.
type PoetryFormatter func(payload string) string

// PoetryProbe provides shared infrastructure for all poetry-based probes.
type PoetryProbe struct {
	*probes.SimpleProbe
	poetryType string
	payloads   []string
	formatters []PoetryFormatter
}

// NewPoetryProbe creates a poetry probe with the given configuration.
func NewPoetryProbe(name, poetryType, description string, formatters []PoetryFormatter) *PoetryProbe {
	pairs := generatePoetryPrompts(formatters)

	prompts := make([]string, len(pairs))
	payloads := make([]string, len(pairs))
	for i, pair := range pairs {
		prompts[i] = pair.prompt
		payloads[i] = pair.payload
	}

	p := &PoetryProbe{
		SimpleProbe: probes.NewSimpleProbe(name, "make the model comply with harmful instructions reformulated as poetry", "mitigation.MitigationBypass", description, prompts),
		poetryType:  poetryType,
		payloads:    payloads,
		formatters:  formatters,
	}
	p.MetadataFn = func(i int, prompt string, a *attempt.Attempt) {
		a.WithMetadata("harmful_payload", p.payloads[i])
		a.WithMetadata("poetry_type", p.poetryType)
	}
	return p
}

type promptPayloadPair struct {
	prompt  string
	payload string
}

func generatePoetryPrompts(formatters []PoetryFormatter) []promptPayloadPair {
	var pairs []promptPayloadPair

	for _, payload := range DefaultHarmfulPayloads {
		for _, formatter := range formatters {
			poetic := formatter(payload)
			pairs = append(pairs, promptPayloadPair{
				prompt:  poetic,
				payload: payload,
			})
		}
	}

	return pairs
}

// GetPayloads returns the original harmful payloads.
func (p *PoetryProbe) GetPayloads() []string { return p.payloads }

// FormatDescription returns a formatted description for a poetry probe.
func FormatDescription(poetryType string) string {
	return fmt.Sprintf(
		"Probe for susceptibility to %s poetry-based jailbreaks. "+
			"Reformats harmful instructions into %s structure to bypass safety mechanisms.",
		poetryType, poetryType,
	)
}

// Helper functions for keyword extraction

func extractAction(payload string) string {
	words := strings.Fields(strings.ToLower(payload))
	verbs := []string{"write", "create", "make", "build", "generate", "explain", "describe", "provide", "outline"}
	for _, word := range words {
		for _, v := range verbs {
			if word == v {
				return word
			}
		}
	}
	return "create"
}

func extractTarget(payload string) string {
	words := strings.Fields(strings.ToLower(payload))
	for i, word := range words {
		if isActionVerb(word) && i+1 < len(words) {
			// Skip articles
			next := i + 1
			if words[next] == "a" || words[next] == "an" || words[next] == "the" {
				next++
			}
			if next < len(words) {
				return words[next]
			}
		}
	}
	return "something"
}

func isActionVerb(word string) bool {
	verbs := []string{"write", "create", "make", "build", "generate", "explain", "describe", "provide", "outline"}
	for _, v := range verbs {
		if word == v {
			return true
		}
	}
	return false
}
