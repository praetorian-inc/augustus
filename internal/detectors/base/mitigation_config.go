package base

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// NewMitigationStringDetector builds the inner StringDetector shared by every
// mitigation/refusal-based detector. It resolves the phrase list via
// ResolveMitigationPhrases (honoring substrings / extra_substrings, with the
// empty-phrase guard) and forwards the operator-supplied matchtype /
// case_sensitive keys, so all detectors that check for refusal phrasing behave
// identically (LAB-4664).
//
// Config keys (all optional):
//   - substrings: []string — replaces the default phrase list entirely
//   - extra_substrings: []string — appended to the effective phrase list
//   - matchtype: string — "str" (default), "word", or "startswith"
//   - case_sensitive: bool — false (default)
func NewMitigationStringDetector(cfg registry.Config, defaults []string) (detectors.Detector, error) {
	return NewStringDetector(registry.Config{
		"substrings":     ResolveMitigationPhrases(cfg, defaults),
		"matchtype":      registry.GetString(cfg, "matchtype", "str"),
		"case_sensitive": registry.GetBool(cfg, "case_sensitive", false),
	})
}

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
//   - refusal_patterns: []string — the global detectors.refusal_patterns list,
//     broadcast by config.ResolveDetectorConfig; appended like extra_substrings
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

	// refusal_patterns is the global detectors.refusal_patterns list, broadcast into
	// every detector's config by config.ResolveDetectorConfig. It augments the phrase
	// list exactly like extra_substrings so a target's own guardrail phrasing is
	// recognized without a per-detector routing list (LAB-4664).
	if refusal := registry.GetStringSlice(cfg, "refusal_patterns", nil); len(refusal) > 0 {
		merged := make([]string, 0, len(phrases)+len(refusal))
		merged = append(merged, phrases...)
		merged = append(merged, refusal...)
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
