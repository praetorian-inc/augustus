package mcpprobe

import (
	"fmt"
	"strconv"
	"strings"
)

// Relations between two independently issued credentials, most to least obvious.
const (
	// RelationIdentical — the surface hands every caller the same value.
	RelationIdentical = "identical"
	// RelationSequential — a shared prefix with numeric tails one apart.
	RelationSequential = "sequential"
	// RelationNearIdentical — a long shared prefix with a trivially small tail.
	RelationNearIdentical = "near-identical"
	// RelationUnrelated — no derivable relationship.
	RelationUnrelated = "unrelated"
)

// minRelatableLength is the shortest pair the near-identical test will consider.
//
// The proportional prefix test is meaningless on very short values: two unrelated
// three-character identifiers sharing two leading characters score a 0.67 ratio
// with a one-character tail, which is an incidental collision rather than a
// derivable relationship. Identical and sequential values are still reported at
// any length, because those relationships hold regardless of size.
const minRelatableLength = 8

// IssuedRelation classifies how two independently issued credentials relate,
// deciding whether a holder of one could derive the other.
//
// Structural only: no format is assumed and no wordlist consulted. A properly
// random pair trips none of the tests.
//
// This lives in the shared kit rather than in the detector because the PROBE must
// perform the comparison. Both values are live credentials the target just issued,
// so storing them for a detector to compare later would put working credentials in
// the scan report, the JSONL and every downstream consumer. The probe compares them
// in memory and records only the relation plus redacted evidence — the same
// division of labour the BOLA controls use, for a different reason.
func IssuedRelation(first, second string) string {
	first, second = strings.TrimSpace(first), strings.TrimSpace(second)
	if first == "" || second == "" {
		return RelationUnrelated
	}
	if first == second {
		return RelationIdentical
	}
	shared := commonPrefixLen(first, second)
	tail1, tail2 := first[shared:], second[shared:]

	// Sequential counters: identical prefix, numeric tails differing by one.
	if n1, ok1 := wholeNumber(tail1); ok1 {
		if n2, ok2 := wholeNumber(tail2); ok2 {
			if n1+1 == n2 || n2+1 == n1 {
				return RelationSequential
			}
		}
	}

	longer := max(len(first), len(second))
	if longer < minRelatableLength {
		return RelationUnrelated
	}
	longestTail := max(len(tail1), len(tail2))
	if float64(shared)/float64(longer) >= 0.75 && longestTail <= 2 {
		return RelationNearIdentical
	}
	return RelationUnrelated
}

// IssuedRelationIsDerivable reports whether a relation means one credential could
// be derived from the other.
func IssuedRelationIsDerivable(relation string) bool {
	switch relation {
	case RelationIdentical, RelationSequential, RelationNearIdentical:
		return true
	default:
		return false
	}
}

// RedactCredential renders a credential as evidence a reviewer can act on without
// reproducing the credential itself: its length and a short leading fragment, so
// two values can be told apart in a report and matched against server logs.
//
// Deliberately lossy. The verdict travels as IssuedRelation, so nothing downstream
// needs the full value, and a scan report should never be a credential store.
func RedactCredential(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "<empty>"
	}
	const keep = 4
	if len(v) <= keep {
		return fmt.Sprintf("<redacted %d chars>", len(v))
	}
	return fmt.Sprintf("%s… <redacted, %d chars total>", v[:keep], len(v))
}

// commonPrefixLen returns the length of the shared leading substring.
func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// wholeNumber parses an entirely numeric string into an int, reporting failure for
// anything else — including a digit run that overflows int on this platform.
func wholeNumber(s string) (int, bool) {
	if s == "" || len(s) > 15 {
		return 0, false
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, false
	}
	return n, true
}
