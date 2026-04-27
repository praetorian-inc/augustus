package multimodal

import "strings"

// fuzzyMaxEdits is the maximum Levenshtein distance tolerated when matching a
// canary inside a model response. OCR on low-contrast / stego payloads commonly
// introduces 1-2 character errors (e.g. digit confusions: 9↔3, 6↔8, 0↔O);
// a distance of 3 catches these without creating false-positive collisions
// against normal prose (canaries are 19-char unique strings).
const fuzzyMaxEdits = 3

// fuzzyContains reports whether any substring of haystack is within maxDist
// edit operations (insertion/deletion/substitution, Levenshtein) of needle.
//
// Both inputs should already be lowercased by the caller. Empty needle always
// matches. O((2*maxDist+1) * len(haystack) * len(needle)) in the worst case;
// fast enough for ~20-char canaries × ~500-char responses.
func fuzzyContains(haystack, needle string, maxDist int) bool {
	if needle == "" {
		return true
	}
	// Fast path: exact substring wins without any allocation.
	if strings.Contains(haystack, needle) {
		return true
	}

	hr := []rune(haystack)
	nr := []rune(needle)
	hlen := len(hr)
	nlen := len(nr)

	// If haystack can't contain a window close enough to needle, bail.
	if hlen+maxDist < nlen {
		return false
	}

	// Slide windows of length nlen-maxDist .. nlen+maxDist across haystack.
	minWin := nlen - maxDist
	if minWin < 1 {
		minWin = 1
	}
	maxWin := nlen + maxDist
	if maxWin > hlen {
		maxWin = hlen
	}

	for winLen := minWin; winLen <= maxWin; winLen++ {
		for i := 0; i+winLen <= hlen; i++ {
			if levenshtein(hr[i:i+winLen], nr) <= maxDist {
				return true
			}
		}
	}
	return false
}

// levenshtein computes the classic edit distance between two rune slices.
// Two-row dynamic programming; O(len(a)*len(b)) time, O(len(b)) space.
func levenshtein(a, b []rune) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}
