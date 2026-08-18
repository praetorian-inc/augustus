package mcptransport

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// unauthAttempt builds an attempt carrying the metadata the probe records.
func unauthAttempt(class, targetClass string, credsConfigured, anonOK, authOK bool) *attempt.Attempt {
	a := attempt.New("probe")
	a.AddOutput("response")
	a.Complete()
	a.Metadata[mcpprobe.MetaAuthClass] = class
	a.Metadata[mcpprobe.MetaAuthTargetClass] = targetClass
	a.Metadata[mcpprobe.MetaAuthCredentialsConfigured] = credsConfigured
	a.Metadata[mcpprobe.MetaAuthAnonymousSucceeded] = anonOK
	a.Metadata[mcpprobe.MetaAuthAuthenticatedSucceeded] = authOK
	return a
}

func detectUnauth(t *testing.T, a *attempt.Attempt) float64 {
	t.Helper()
	d, err := NewUnauthenticatedAccessDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewUnauthenticatedAccessDetector: %v", err)
	}
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	max := 0.0
	for _, s := range scores {
		if s > max {
			max = s
		}
	}
	return max
}

// TestUnauthDetector_NoCredentialsNeverFires is THE design constraint. With no
// credentials configured, "the anonymous session worked" is trivially true and
// says nothing about the target. Scoring it would make the probe a
// false-positive generator that discredits the family on first contact.
func TestUnauthDetector_NoCredentialsNeverFires(t *testing.T) {
	for _, class := range []string{mcpprobe.AuthClassAnonEnumeration, mcpprobe.AuthClassAnonInvocation} {
		for _, tc := range []string{"public", "lan", "loopback", "unresolvable"} {
			a := unauthAttempt(class, tc, false /* no creds */, true /* anon worked */, true)
			if got := detectUnauth(t, a); got != 0.0 {
				t.Errorf("class=%s target=%s with NO credentials configured scored %v, want 0.0", class, tc, got)
			}
		}
	}
}

// TestUnauthDetector_AnonymousRefusedIsSafe: a target that refuses the anonymous
// session is enforcing its boundary. Never a finding.
func TestUnauthDetector_AnonymousRefusedIsSafe(t *testing.T) {
	for _, tc := range []string{"public", "lan", "loopback"} {
		a := unauthAttempt(mcpprobe.AuthClassAnonEnumeration, tc, true, false /* anon refused */, true)
		if got := detectUnauth(t, a); got != 0.0 {
			t.Errorf("target=%s with anonymous refused scored %v, want 0.0", tc, got)
		}
	}
}

// TestUnauthDetector_AnonRefusedWithFailedAuthBaselineIsInconclusive: an anonymous
// refusal only means "boundary enforced" if we know the target was reachable in the
// first place. When the operator's own authenticated control ALSO failed, the target
// may simply be down/unreachable and refusing every caller identically — nothing was
// measured, so this must be inconclusive rather than a clean 0.0. The paired
// TestUnauthDetector_AnonymousRefusedIsSafe above keeps the authOK=true case at 0.0.
func TestUnauthDetector_AnonRefusedWithFailedAuthBaselineIsInconclusive(t *testing.T) {
	for _, tc := range []string{"public", "lan", "loopback", "unresolvable"} {
		a := unauthAttempt(mcpprobe.AuthClassAnonEnumeration, tc, true, false /* anon refused */, false /* auth also failed */)
		if got := detectUnauth(t, a); got != InconclusiveScore {
			t.Errorf("target=%s anon refused AND auth baseline failed scored %v, want %v (unassessable, not a clean SAFE)", tc, got, InconclusiveScore)
		}
	}
}

// TestUnauthDetector_SeverityTiering: anonymous enumeration is serious,
// anonymous invocation is the critical proof. They must not score the same —
// enumeration discloses the surface, invocation proves the server ACTS for an
// unauthenticated caller.
func TestUnauthDetector_SeverityTiering(t *testing.T) {
	enum := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonEnumeration, "public", true, true, true))
	invoke := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonInvocation, "public", true, true, true))

	if invoke != 1.0 {
		t.Errorf("anonymous invocation on a public target scored %v, want 1.0 (critical)", invoke)
	}
	if enum < 0.5 {
		t.Errorf("anonymous enumeration scored %v, want >= 0.5 (must be reported as a finding)", enum)
	}
	if !(enum < invoke) {
		t.Errorf("enumeration (%v) must score BELOW invocation (%v): severity tiering", enum, invoke)
	}
}

// TestUnauthDetector_LoopbackIsInconclusive: a loopback development server with
// no effective auth is expected, not a vulnerability. It stays visible (a
// reviewer must look) without asserting the target is vulnerable.
func TestUnauthDetector_LoopbackIsInconclusive(t *testing.T) {
	for _, class := range []string{mcpprobe.AuthClassAnonEnumeration, mcpprobe.AuthClassAnonInvocation} {
		got := detectUnauth(t, unauthAttempt(class, "loopback", true, true, true))
		if got != InconclusiveScore {
			t.Errorf("class=%s on loopback scored %v, want %v (inconclusive, not vulnerable)", class, got, InconclusiveScore)
		}
	}
}

// TestUnauthDetector_LANIsAFinding: an RFC1918 server with a decorative auth
// boundary is reachable by anyone on the corporate network — a real finding, not
// a dev-box artifact.
func TestUnauthDetector_LANIsAFinding(t *testing.T) {
	got := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonInvocation, "lan", true, true, true))
	if got != 1.0 {
		t.Errorf("anonymous invocation on a LAN target scored %v, want 1.0", got)
	}
}

// TestUnauthDetector_UnresolvableIsInconclusive: reachability unknown means
// severity unknown.
func TestUnauthDetector_UnresolvableIsInconclusive(t *testing.T) {
	got := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonInvocation, "unresolvable", true, true, true))
	if got != InconclusiveScore {
		t.Errorf("unresolvable target scored %v, want %v", got, InconclusiveScore)
	}
}

// TestUnauthDetector_AuthBaselineNeverFires: the authenticated control is
// evidence, not a finding. Scoring it would drown the real results.
func TestUnauthDetector_AuthBaselineNeverFires(t *testing.T) {
	got := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAuthBaseline, "public", true, true, true))
	if got != 0.0 {
		t.Errorf("auth-baseline scored %v, want 0.0 (informational)", got)
	}
}

// TestUnauthDetector_AnonWithoutAuthBaselineIsInconclusive: if the operator's own
// authenticated session could not exercise the target, an anonymous "success" is
// unreliable — the endpoint may be answering everything the same way. Report
// uncertainty rather than a confident verdict in either direction.
func TestUnauthDetector_AnonWithoutAuthBaselineIsInconclusive(t *testing.T) {
	got := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonInvocation, "public", true, true, false /* auth failed */))
	if got != InconclusiveScore {
		t.Errorf("anonymous success without an authenticated baseline scored %v, want %v", got, InconclusiveScore)
	}
}

// TestUnauthDetector_ExplicitInconclusiveHonoured: a probe that could not make a
// confident determination must never surface as a clean SAFE.
func TestUnauthDetector_ExplicitInconclusiveHonoured(t *testing.T) {
	a := unauthAttempt(mcpprobe.AuthClassAnonEnumeration, "public", true, false, true)
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = "transport error mid-sweep"
	if got := detectUnauth(t, a); got != InconclusiveScore {
		t.Errorf("explicitly inconclusive attempt scored %v, want %v", got, InconclusiveScore)
	}
}

// TestUnauthDetector_MissingTargetClassIsInconclusive: an unstamped target class
// means the probe could not judge reachability. Default to caution rather than
// to the maximum score.
func TestUnauthDetector_MissingTargetClassIsInconclusive(t *testing.T) {
	got := detectUnauth(t, unauthAttempt(mcpprobe.AuthClassAnonInvocation, "", true, true, true))
	if got != InconclusiveScore {
		t.Errorf("missing target class scored %v, want %v", got, InconclusiveScore)
	}
}
