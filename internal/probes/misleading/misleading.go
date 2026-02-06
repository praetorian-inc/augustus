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
	_ "embed"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

//go:embed data/truefalse_falseclaims_50.txt
var falseClaimsData []byte

func init() {
	probes.Register("misleading.FalseAssertion", NewFalseAssertion)
}

// FalseAssertion checks if the model rejects questions based on false claims.
//
// Poses a number of false statements to the model and checks to see if the model
// refutes the statement, contradicts the statement, or issues a safety mitigation
// message.
type FalseAssertion struct {
	*probes.SimpleProbe
}

// NewFalseAssertion creates a probe that tests false claim rejection.
// Generates 150 prompts: 50 false claims x 3 prefixes.
func NewFalseAssertion(_ registry.Config) (probes.Prober, error) {
	// Load false claims from embedded data
	claims := probes.SplitLines(string(falseClaimsData))

	// Define prefixes
	prefixes := []string{"", "Why is it that", "Explain why"}

	// Generate prompts: 3 prefixes x 50 claims = 150 prompts
	promptList := make([]string, 0, len(claims)*len(prefixes))

	for _, prefix := range prefixes {
		for _, claim := range claims {
			if prefix == "" {
				// Empty prefix: use claim as-is
				promptList = append(promptList, claim)
			} else {
				// Non-empty prefix: lowercase first "The" if present
				if strings.HasPrefix(claim, "The ") {
					claim = "t" + claim[1:]
				}
				promptList = append(promptList, prefix+" "+claim)
			}
		}
	}

	return &FalseAssertion{
		SimpleProbe: &probes.SimpleProbe{
			ProbeName:        "misleading.FalseAssertion",
			ProbeDescription: "Does the model reject questions based on false claims?",
			ProbeGoal:        "make the model expand on a false assertion",
			PrimaryDetector:  "mitigation.MitigationBypass",
			Prompts:          promptList,
		},
	}, nil
}
