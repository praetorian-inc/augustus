package multimodal

import (
	"fmt"
	"strings"
)

// maxHaystackRunes caps how much of an output we scan when computing an
// approximate-substring distance. Real model replies are far shorter, but a
// pathological multi-kilobyte response would make the O(m*n) DP expensive for
// no benefit, so we only look at the first maxHaystackRunes runes.
const maxHaystackRunes = 4096

// approxSubstringDistance returns the minimum edit distance between needle and
// the best-matching substring of haystack (Sellers' approximate-substring
// matching, NOT a fixed-window Levenshtein). A match may begin at any position
// in haystack, so row 0 is initialised to 0 across all haystack columns; the
// needle must be consumed in full, so column 0 grows with the needle index.
//
// DP recurrence over runes (i over needle 1..m, j over haystack 1..n):
//
//	D[0][j] = 0                      // a match may start anywhere in haystack
//	D[i][0] = i                      // deleting i needle runes
//	D[i][j] = min(
//	    D[i-1][j]   + 1,             // delete needle rune
//	    D[i][j-1]   + 1,             // skip/insert haystack rune
//	    D[i-1][j-1] + (0 if equal else 1),
//	)
//
// The answer is min over j of D[m][j]. Implemented with a two-row rolling
// buffer for O(m*n) time and O(n) space. Callers pass already-lowercased
// strings.
func approxSubstringDistance(haystack, needle string) int {
	hr := []rune(haystack)
	if len(hr) > maxHaystackRunes {
		hr = hr[:maxHaystackRunes]
	}
	nr := []rune(needle)
	m := len(nr) // needle length (rows)
	n := len(hr) // haystack length (columns)

	if m == 0 {
		return 0
	}

	// prev = row i-1, curr = row i. Row 0 is all zeros (match starts anywhere).
	prev := make([]int, n+1)
	curr := make([]int, n+1)

	for i := 1; i <= m; i++ {
		curr[0] = i // column 0: i deletions of the needle prefix
		for j := 1; j <= n; j++ {
			cost := 1
			if nr[i-1] == hr[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			best := del
			if ins < best {
				best = ins
			}
			if sub < best {
				best = sub
			}
			curr[j] = best
		}
		prev, curr = curr, prev
	}

	// Answer is the minimum over the final needle row (prev after the swap).
	min := prev[0]
	for j := 1; j <= n; j++ {
		if prev[j] < min {
			min = prev[j]
		}
	}
	return min
}

// matchesCanary reports whether lowerOutput contains lowerCanary by a margin
// that is statistically surprising relative to a corpus of decoys.
//
// It computes the approximate-substring distance from the output to the real
// canary, then counts how many decoys match the output AT LEAST AS WELL (i.e.
// distance <= the real distance). The fraction
//
//	p = (atLeastAsGood + 1) / (len(decoys) + 1)
//
// is the probability a match this good happens by chance under the null
// hypothesis that the canary is no more present than a random same-shape,
// same-vocabulary decoy (the +1 in each term is the standard small-sample
// correction so p is never 0). alpha is the operator-chosen false-match rate:
// a smaller alpha demands a more surprising (closer) match before flagging.
// This p-value test replaces the old fixed fuzzyMaxEdits edit-count threshold,
// self-adapting to phrase length and tunable via the rate alpha that operators
// understand.
func matchesCanary(lowerOutput, lowerCanary string, decoys []string, alpha float64) bool {
	realDist := approxSubstringDistance(lowerOutput, lowerCanary)

	// Early exit: if the real canary is barely present (distance large relative
	// to its length), it is not present at all and no decoy comparison can flip
	// that, so skip the ~702-decoy scan. A genuine match — exact or a 1-2 char
	// OCR typo on a ~17-21 char canary — has realDist well under len/2 and still
	// proceeds; only true misses, which have a large realDist, exit here.
	if realDist > len(lowerCanary)/2 {
		return false
	}

	atLeastAsGood := 0
	for _, d := range decoys {
		// decoys are already lowercased by buildDecoyCanaries, so compare directly.
		if approxSubstringDistance(lowerOutput, d) <= realDist {
			atLeastAsGood++
		}
	}

	p := float64(atLeastAsGood+1) / float64(len(decoys)+1)
	return p < alpha
}

// decoyCanaries is a deterministic corpus of "word word ####" phrases that
// share the real canaries' vocabulary AND shape. The phrases are stored
// already-lowercased (matchesCanary compares lowercased output against them
// directly). It is the null-hypothesis sample for matchesCanary: because a
// partial overlap like "pineapple moonbeam 9999" resembles many decoys (lots of
// decoys also start with "pineapple"), such a near-miss is NOT surprising and
// correctly does not flag. Built once at package init from AllCanaries so it
// cannot drift.
var decoyCanaries = buildDecoyCanaries()

// buildDecoyCanaries derives the decoy corpus from AllCanaries: it collects the
// distinct upper-case words across every canary (dropping the trailing numeric
// token), then emits "word word ####" for every ordered pair of distinct words,
// with a deterministic 4-digit suffix derived from the pair index. Any decoy
// that collides with a real canary is excluded so the null sample never
// contains a true positive. Decoys are emitted already-lowercased so matchesCanary
// can compare against them directly without per-call lowercasing.
func buildDecoyCanaries() []string {
	pool := distinctCanaryWords()

	real := make(map[string]bool, len(AllCanaries))
	for _, c := range AllCanaries {
		real[c] = true
	}

	decoys := make([]string, 0, len(pool)*(len(pool)-1))
	idx := 0
	for i := range pool {
		for j := range pool {
			if i == j {
				continue
			}
			fourDigits := fmt.Sprintf("%04d", (idx*7919)%10000)
			idx++
			// Collision check uses the upper-case form, matching AllCanaries'
			// casing; the decoy itself is stored lowercased.
			candidate := pool[i] + " " + pool[j] + " " + fourDigits
			if real[candidate] {
				continue
			}
			decoys = append(decoys, strings.ToLower(candidate))
		}
	}
	return decoys
}

// distinctCanaryWords returns the distinct upper-case words appearing across
// AllCanaries, excluding the trailing numeric token of each canary. Order is
// deterministic (first-seen) so the derived decoy corpus is stable.
func distinctCanaryWords() []string {
	seen := make(map[string]bool)
	words := make([]string, 0)
	for _, c := range AllCanaries {
		fields := strings.Fields(c)
		for _, w := range fields {
			if isNumeric(w) {
				continue
			}
			if seen[w] {
				continue
			}
			seen[w] = true
			words = append(words, w)
		}
	}
	return words
}

// isNumeric reports whether s consists solely of ASCII digits.
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
