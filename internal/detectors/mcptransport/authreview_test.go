package mcptransport

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// TestUnauthenticated_DeclaredOpenClass covers the branch with no test at all — and
// it is the one that scores 1.0 most aggressively, bypassing both the
// configured-credentials precondition and the host-class softening every other
// class gets.
func TestUnauthenticated_DeclaredOpenClass(t *testing.T) {
	// No credentials configured anywhere below: the target's own published metadata
	// is the evidence of intent, which is what makes this class independent of the
	// operator's configuration.
	t.Run("anonymous refused after declaring authorization", func(t *testing.T) {
		a := unauthAttempt(mcpprobe.AuthClassOAuthDeclaredOpen, "public", false, false, false)
		if got := detectUnauth(t, a); got != 0.0 {
			t.Errorf("scored %v, want 0.0; the target declared authorization and enforced it", got)
		}
	})

	t.Run("anonymous succeeded against its own declaration", func(t *testing.T) {
		a := unauthAttempt(mcpprobe.AuthClassOAuthDeclaredOpen, "public", false, true, false)
		if got := detectUnauth(t, a); got != 1.0 {
			t.Errorf("scored %v, want 1.0; the server contradicted its own published metadata", got)
		}
	})

	t.Run("loopback is NOT softened for this class", func(t *testing.T) {
		// Deliberate asymmetry with the credentials path: a loopback server with no
		// authentication is unremarkable, but one that ADVERTISES OAuth protection
		// and then ignores it is misconfigured wherever it runs.
		a := unauthAttempt(mcpprobe.AuthClassOAuthDeclaredOpen, "loopback", false, true, false)
		if got := detectUnauth(t, a); got != 1.0 {
			t.Errorf("scored %v, want 1.0; the declaration is the evidence, not the reachability", got)
		}
	})

	t.Run("inconclusive wins over the class verdict", func(t *testing.T) {
		// Pins the ordering fix. The declared-open branch returns 1.0
		// unconditionally, so evaluating the class before the inconclusive flag
		// reported an attempt the probe could not measure as a confirmed finding.
		a := unauthAttempt(mcpprobe.AuthClassOAuthDeclaredOpen, "public", false, true, false)
		a.Metadata[attempt.MetadataKeyInconclusive] = true
		if got := detectUnauth(t, a); got != InconclusiveScore {
			t.Errorf("scored %v, want %v; an unmeasured attempt is not a finding", got, InconclusiveScore)
		}
	})
}

// TestUnauthenticated_ReachabilityTiers exercises the lan/public scoring tiers on
// the credentials path, which the live-target tests cannot reach: every server
// available to them classifies as loopback, where the verdict is deliberately
// softened to inconclusive.
func TestUnauthenticated_ReachabilityTiers(t *testing.T) {
	cases := []struct {
		targetClass string
		class       string
		want        float64
	}{
		{"public", mcpprobe.AuthClassAnonEnumeration, EnumerationScore},
		{"lan", mcpprobe.AuthClassAnonEnumeration, EnumerationScore},
		{"public", mcpprobe.AuthClassAnonInvocation, 1.0},
		{"lan", mcpprobe.AuthClassAnonInvocation, 1.0},
		// A development server with no authentication is expected, not defective.
		{"loopback", mcpprobe.AuthClassAnonInvocation, InconclusiveScore},
		{"unresolvable", mcpprobe.AuthClassAnonInvocation, InconclusiveScore},
	}
	for _, tc := range cases {
		t.Run(tc.targetClass+"/"+tc.class, func(t *testing.T) {
			a := unauthAttempt(tc.class, tc.targetClass, true, true, true)
			if got := detectUnauth(t, a); got != tc.want {
				t.Errorf("scored %v, want %v", got, tc.want)
			}
		})
	}
}
