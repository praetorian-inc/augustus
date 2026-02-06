package gcg

import (
	_ "embed"

	"github.com/praetorian-inc/augustus/pkg/probes"
)

// Pre-computed GCG adversarial suffixes from research.
// These suffixes are generated using Greedy Coordinate Gradient descent
// and are designed to bypass LLM safety mechanisms.
//
// Research: "Universal and Transferable Adversarial Attacks on Aligned Language Models"
// https://arxiv.org/abs/2307.15043

//go:embed data/gcg.txt
var gcgSuffixData string

// parseSuffixes extracts adversarial suffixes from embedded data.
// Each line in the file is one suffix (whitespace trimmed).
// Empty lines are skipped.
func parseSuffixes(data string) []string {
	return probes.SplitLines(data)
}
