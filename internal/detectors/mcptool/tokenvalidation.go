package mcptool

import (
	"context"
	"strings"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.TokenValidation", NewTokenValidationDetector)
}

// TokenValidationDetector adjudicates the two token-validation weaknesses the
// mcptool.TokenValidation probe gathers evidence for:
//
//   - FORMAT-ONLY VALIDATION: a verification surface whose answer depends on a
//     value's SHAPE rather than on whether it was ever ISSUED. Adjudicated by
//     response differential (see differentialVerdict), never by matching a
//     success string, so it carries no assumption about a particular server's
//     wording or token format.
//
//   - PREDICTABLE ISSUANCE: two tokens issued in close succession that are
//     related, so one holder can derive another's. Adjudicated structurally from
//     the two values.
type TokenValidationDetector struct{}

// NewTokenValidationDetector constructs the detector.
func NewTokenValidationDetector(_ registry.Config) (detectors.Detector, error) {
	return &TokenValidationDetector{}, nil
}

func (d *TokenValidationDetector) Name() string { return "mcptool.TokenValidation" }

func (d *TokenValidationDetector) Description() string {
	return "Flags a token verification surface that accepts a well-formed but never-issued value (validating shape instead of issuance), and an issuing surface whose tokens are predictable across closely-spaced requests"
}

// Detect returns one score per output.
func (d *TokenValidationDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class := metaString(a, mcpprobe.MetaAuthClass)
	if class == mcpprobe.AuthClassTokenPredictable {
		return scoresFor(a, predictabilityVerdict(a)), nil
	}
	return scoresFor(a, differentialVerdict(a)), nil
}

// predictabilityVerdict adjudicates whether two independently issued tokens are
// related. It is structural — no format is assumed and no wordlist consulted.
func predictabilityVerdict(a *attempt.Attempt) float64 {
	if a.Error != "" {
		return 0.0
	}
	first := strings.TrimSpace(metaString(a, mcpprobe.MetaAuthProbeValue))
	second := strings.TrimSpace(metaString(a, mcpprobe.MetaAuthReplicaValue))
	if first == "" || second == "" {
		return InconclusiveScore // could not obtain two samples
	}
	if tokensAreRelated(first, second) {
		return 1.0
	}
	return 0.0
}

// tokensAreRelated reports whether two issued values are close enough that a
// holder of one could derive the other.
//
// Three structural relationships, in increasing subtlety:
//
//  1. IDENTICAL — the surface hands every caller the same value. The strongest
//     form of predictability, and not rare: a hardcoded or module-level constant.
//  2. SEQUENTIAL — a shared prefix with numeric tails one apart (a counter).
//  3. NEAR-IDENTICAL — a long shared prefix with only a tiny differing tail, so
//     the derivable search space is trivial.
//
// A properly random pair shares no meaningful prefix and trips none of these. The
// prefix test is proportional (most of the value must match) rather than a fixed
// length, so it does not fire on two random values that happen to share a few
// leading characters.
func tokensAreRelated(first, second string) bool {
	if first == second {
		return true
	}
	shared := commonPrefixLen(first, second)
	tail1, tail2 := first[shared:], second[shared:]

	// Sequential counters: identical prefix, numeric tails differing by one.
	if n1, ok1 := trailingNumber(tail1); ok1 {
		if n2, ok2 := trailingNumber(tail2); ok2 {
			if n1+1 == n2 || n2+1 == n1 {
				return true
			}
		}
	}

	// Near-identical: the shared prefix dominates both values and only a very
	// short tail differs. Requiring BOTH a proportional majority and a short
	// absolute tail keeps short random values from qualifying.
	longer := len(first)
	if len(second) > longer {
		longer = len(second)
	}
	if longer == 0 {
		return false
	}
	prefixRatio := float64(shared) / float64(longer)
	longestTail := len(tail1)
	if len(tail2) > longestTail {
		longestTail = len(tail2)
	}
	return prefixRatio >= 0.75 && longestTail <= 2
}

// commonPrefixLen returns the length of the shared leading substring.
func commonPrefixLen(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}

// trailingNumber parses a purely numeric string into an int, reporting failure
// for anything else. Bounded in length so a very long digit run cannot overflow.
func trailingNumber(s string) (int, bool) {
	if s == "" || len(s) > 15 {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, true
}
