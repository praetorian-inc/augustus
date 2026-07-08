package base

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// ResolveMitigationPhrases computes the effective mitigation/refusal phrase list
// from operator config, falling back to the given defaults. It is the shared
// resolver behind every mitigation/refusal-based detector so a target's own
// guardrail phrasing (e.g. supplied via --refusal-pattern) is recognized
// consistently and a non-generic deflection is not mis-scored (LAB-4664).
//
// Config keys (all optional):
//   - substrings: []string — replaces the default phrase list entirely
//   - extra_substrings: []string — appended to the effective phrase list
//     (defaults, or the substrings override) so a target's guardrail phrasing can
//     be recognized without losing the generic refusals
//
// Empty and whitespace-only phrases are dropped: a blank substring matches every
// output via strings.Contains, which would silently treat every output as
// mitigated. If filtering removes every phrase (e.g. substrings: [""]), the
// defaults are restored rather than returning an empty list that would flip the
// detector into a match-nothing / 100%-false-positive state — the exact class
// LAB-4664 fixes.
func ResolveMitigationPhrases(cfg registry.Config, defaults []string) []string {
	phrases := defaults
	if override := registry.GetStringSlice(cfg, "substrings", nil); len(override) > 0 {
		phrases = override
	}
	if extra := registry.GetStringSlice(cfg, "extra_substrings", nil); len(extra) > 0 {
		merged := make([]string, 0, len(phrases)+len(extra))
		merged = append(merged, phrases...)
		merged = append(merged, extra...)
		phrases = merged
	}

	phrases = nonEmptyPhrases(phrases)
	if len(phrases) == 0 {
		phrases = nonEmptyPhrases(defaults)
	}
	return phrases
}

// nonEmptyPhrases returns a copy of phrases with empty and whitespace-only
// strings removed. A blank substring matches every output via strings.Contains,
// which would silently score every attempt as mitigated.
func nonEmptyPhrases(phrases []string) []string {
	filtered := make([]string, 0, len(phrases))
	for _, p := range phrases {
		if strings.TrimSpace(p) != "" {
			filtered = append(filtered, p)
		}
	}
	return filtered
}
