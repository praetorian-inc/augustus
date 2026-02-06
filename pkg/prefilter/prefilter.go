// Package prefilter provides Aho-Corasick based keyword pre-filtering for detectors.
//
// This package uses a forked version of pgavlin/aho-corasick with ByteEquivalence
// ("klingon") support for custom byte transformations during matching.
package prefilter

import (
	"github.com/praetorian-inc/augustus/internal/ahocorasick"
)

// Prefilter provides efficient multi-pattern matching using Aho-Corasick.
type Prefilter struct {
	ac       ahocorasick.AhoCorasick
	patterns []string
	// detectorMap maps pattern indices to detector names (optional)
	detectorMap map[int]string
}

// ByteEquivalence defines a function that returns equivalent bytes for matching.
// This enables "klingon" support - custom encodings/transformations.
type ByteEquivalence = func(byte) []byte

// New creates a Prefilter with the given keywords and optional klingon transformation.
// If klingon is nil, standard exact matching is used.
func New(keywords []string, klingon ByteEquivalence) *Prefilter {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		ByteEquivalence: klingon,
		MatchKind:       ahocorasick.LeftMostLongestMatch,
	})

	return &Prefilter{
		ac:       builder.Build(keywords),
		patterns: keywords,
	}
}

// NewWithDetectorMapping creates a Prefilter that maps keywords to detector names.
// The mapping allows MatchedDetectors to return which detectors should run.
func NewWithDetectorMapping(detectorKeywords map[string][]string, klingon ByteEquivalence) *Prefilter {
	// Flatten keywords and build detector map
	var allKeywords []string
	detectorMap := make(map[int]string)

	for detector, keywords := range detectorKeywords {
		for _, kw := range keywords {
			detectorMap[len(allKeywords)] = detector
			allKeywords = append(allKeywords, kw)
		}
	}

	pf := New(allKeywords, klingon)
	pf.detectorMap = detectorMap
	return pf
}

// Match returns all keywords that match in the given text.
func (p *Prefilter) Match(text string) []string {
	var matches []string
	seen := make(map[int]bool)

	for match := range ahocorasick.Iter(p.ac, text) {
		patternIdx := match.Pattern()
		if !seen[patternIdx] {
			seen[patternIdx] = true
			matches = append(matches, p.patterns[patternIdx])
		}
	}

	return matches
}

// MatchedPatternIndices returns the indices of patterns that match in the text.
func (p *Prefilter) MatchedPatternIndices(text string) []int {
	var indices []int
	seen := make(map[int]bool)

	for match := range ahocorasick.Iter(p.ac, text) {
		patternIdx := match.Pattern()
		if !seen[patternIdx] {
			seen[patternIdx] = true
			indices = append(indices, patternIdx)
		}
	}

	return indices
}

// MatchedDetectors returns the detector names that have at least one keyword match.
// Requires the Prefilter to be created with NewWithDetectorMapping.
func (p *Prefilter) MatchedDetectors(text string) []string {
	if p.detectorMap == nil {
		return nil
	}

	detectorsSeen := make(map[string]bool)
	var detectors []string

	for match := range ahocorasick.Iter(p.ac, text) {
		detector, ok := p.detectorMap[match.Pattern()]
		if ok && !detectorsSeen[detector] {
			detectorsSeen[detector] = true
			detectors = append(detectors, detector)
		}
	}

	return detectors
}

// HasMatch returns true if any keyword matches the text.
// This is faster than Match when you only need to know if there's any match.
func (p *Prefilter) HasMatch(text string) bool {
	for range ahocorasick.Iter(p.ac, text) {
		return true
	}
	return false
}
