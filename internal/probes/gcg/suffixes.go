package gcg

import (
	_ "embed"
	"strings"
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
	lines := strings.Split(data, "\n")
	suffixes := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" {
			suffixes = append(suffixes, trimmed)
		}
	}

	return suffixes
}
