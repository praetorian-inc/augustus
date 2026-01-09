// Package misleading provides probes for testing LLM responses to false claims.
//
// These probes pose targets with false claims and check if they successfully
// debunk or reject them. Will a model refute false claims, or will it go along
// with false information and perform tasks based on them?
//
// This checks for a subset of hallucination types, where false information is
// present that the system is expected to deny, refute, or contradict.
//
// Based on research: https://arxiv.org/abs/2304.13734
// Python garak equivalent: garak.probes.misleading
package misleading

import (
	"context"
	_ "embed"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/truefalse_falseclaims_50.txt
var falseClaimsData []byte

func init() {
	probes.Register("misleading.FalseAssertion", NewFalseAssertion)
}

// baseProbe provides common functionality for all misleading probes.
type baseProbe struct {
	name            string
	description     string
	goal            string
	primaryDetector string
	prompts         []string
}

func (b *baseProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(b.prompts))

	for _, prompt := range b.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = b.name
		a.Detector = b.primaryDetector

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

func (b *baseProbe) Name() string                { return b.name }
func (b *baseProbe) Description() string         { return b.description }
func (b *baseProbe) Goal() string                { return b.goal }
func (b *baseProbe) GetPrimaryDetector() string  { return b.primaryDetector }
func (b *baseProbe) GetPrompts() []string        { return b.prompts }

// FalseAssertion checks if the model rejects questions based on false claims.
//
// Poses a number of false statements to the model and checks to see if the model
// refutes the statement, contradicts the statement, or issues a safety mitigation
// message.
type FalseAssertion struct {
	baseProbe
}

// NewFalseAssertion creates a probe that tests false claim rejection.
// Generates 150 prompts: 50 false claims × 3 prefixes.
func NewFalseAssertion(_ registry.Config) (probes.Prober, error) {
	// Load false claims from embedded data
	lines := strings.Split(string(falseClaimsData), "\n")

	// Define prefixes
	prefixes := []string{"", "Why is it that", "Explain why"}

	// Generate prompts: 3 prefixes × 50 claims = 150 prompts
	prompts := make([]string, 0, len(lines)*len(prefixes))

	for _, prefix := range prefixes {
		for _, claim := range lines {
			claim = strings.TrimSpace(claim)
			if claim == "" {
				continue
			}

			if prefix == "" {
				// Empty prefix: use claim as-is
				prompts = append(prompts, claim)
			} else {
				// Non-empty prefix: lowercase first "The" if present
				if strings.HasPrefix(claim, "The ") {
					claim = "t" + claim[1:]
				}
				prompts = append(prompts, prefix+" "+claim)
			}
		}
	}

	return &FalseAssertion{
		baseProbe: baseProbe{
			name:            "misleading.FalseAssertion",
			description:     "Does the model reject questions based on false claims?",
			goal:            "make the model expand on a false assertion",
			primaryDetector: "mitigation.MitigationBypass",
			prompts:         prompts,
		},
	}, nil
}
