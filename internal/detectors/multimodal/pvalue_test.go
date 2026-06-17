package multimodal

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApproxSubstringDistance_ExactSubstring(t *testing.T) {
	// The needle appears verbatim inside the haystack -> distance 0.
	assert.Equal(t, 0, approxSubstringDistance("the canary is emerald storm 3961 right here", "emerald storm 3961"))
	// Needle equal to haystack -> distance 0.
	assert.Equal(t, 0, approxSubstringDistance("emerald storm 3961", "emerald storm 3961"))
}

func TestApproxSubstringDistance_OneTypo(t *testing.T) {
	// One digit substitution (9->3) within an otherwise exact substring -> 1.
	assert.Equal(t, 1, approxSubstringDistance("emerald storm 3361", "emerald storm 3961"))
	// One typo embedded in a longer reply -> still 1 (best-matching substring).
	assert.Equal(t, 1, approxSubstringDistance("the value reads emerald storm 3361 in the noise", "emerald storm 3961"))
}

func TestApproxSubstringDistance_Unrelated(t *testing.T) {
	// Unrelated prose shares almost nothing with the needle -> large distance.
	d := approxSubstringDistance("this is a normal response about cats and dogs", "emerald storm 3961")
	assert.Greater(t, d, 8)
}

func TestMatchesCanary_ExactCanary(t *testing.T) {
	assert.True(t, matchesCanary("pineapple sunset 7319", "pineapple sunset 7319", decoyCanaries, fuzzyAlphaDefault))
}

func TestMatchesCanary_OCRTypo(t *testing.T) {
	// 1-edit OCR miss (9->3).
	assert.True(t, matchesCanary("emerald storm 3361", "emerald storm 3961", decoyCanaries, fuzzyAlphaDefault))
	// 2-edit OCR miss: inserted "& " (the InsertionAndSubstitution case minus one).
	assert.True(t, matchesCanary("emerald & storm 3961", "emerald storm 3961", decoyCanaries, fuzzyAlphaDefault))
}

func TestMatchesCanary_UnrelatedProse(t *testing.T) {
	assert.False(t, matchesCanary("this is a normal response with no canary.", "pineapple sunset 7319", decoyCanaries, fuzzyAlphaDefault))
}

func TestMatchesCanary_DecoyDoesNotTriggerDifferentCanary(t *testing.T) {
	// An actual decoy phrase present in the output must NOT match a real canary
	// it overlaps by at most one word. Decoys share vocabulary/shape with the
	// canaries, so such a partial-overlap decoy is exactly the kind of "match
	// this good happens by chance" the p-value is meant to reject.
	const canary = "pineapple sunset 7319"
	canaryWords := strings.Fields(canary)

	// Find a decoy that shares at most one word with the target canary.
	var decoy string
	for _, d := range decoyCanaries {
		shared := 0
		dWords := strings.Fields(strings.ToLower(d))
		for _, dw := range dWords {
			for _, cw := range canaryWords {
				if dw == cw {
					shared++
				}
			}
		}
		if shared <= 1 {
			decoy = strings.ToLower(d)
			break
		}
	}
	require.NotEmpty(t, decoy, "expected a decoy overlapping the canary by <=1 word")

	assert.False(t, matchesCanary(decoy, canary, decoyCanaries, fuzzyAlphaDefault),
		"a decoy overlapping the canary by <=1 word should not match it")
}

func TestMatchesCanary_PartialWordOverlapDoesNotMatch(t *testing.T) {
	// Shares only the first word with PINEAPPLE SUNSET 7319; many decoys also
	// start with PINEAPPLE, so this is not surprising -> must not match.
	assert.False(t, matchesCanary("pineapple moonbeam 9999", "pineapple sunset 7319", decoyCanaries, fuzzyAlphaDefault))
}

func TestMatchesCanary_LongCanaryFreeResponse(t *testing.T) {
	// A long (~4KB) response that does not contain the canary must return false.
	// This exercises the early-exit: realDist is large relative to the canary
	// length, so matchesCanary returns false without scanning the decoy corpus.
	longProse := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 100)
	require.Greater(t, len(longProse), 4000, "test fixture should exceed 4KB")
	assert.False(t, matchesCanary(longProse, "emerald storm 3961", decoyCanaries, fuzzyAlphaDefault))
}

func TestBuildDecoys_ExcludesRealCanaries(t *testing.T) {
	real := make(map[string]bool, len(AllCanaries))
	for _, c := range AllCanaries {
		real[c] = true
	}
	for _, d := range decoyCanaries {
		assert.False(t, real[d], "decoy %q must not be a real canary", d)
	}
	assert.NotEmpty(t, decoyCanaries)
}

func TestNewCanary_ReadsAlpha(t *testing.T) {
	d, err := NewCanary(map[string]any{"fuzzy_alpha": 0.05})
	require.NoError(t, err)
	cd := d.(*CanaryDetector)
	assert.Equal(t, 0.05, cd.alpha)
	assert.NotEmpty(t, cd.decoys)

	// Absent -> default.
	d2, err := NewCanary(nil)
	require.NoError(t, err)
	assert.Equal(t, fuzzyAlphaDefault, d2.(*CanaryDetector).alpha)

	// Out-of-range -> default.
	for _, bad := range []float64{0, -0.1, 1, 1.5} {
		dd, err := NewCanary(map[string]any{"fuzzy_alpha": bad})
		require.NoError(t, err)
		assert.Equal(t, fuzzyAlphaDefault, dd.(*CanaryDetector).alpha, "alpha %v should fall back to default", bad)
	}
}
