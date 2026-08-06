package mcptransport

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptransport.UnauthenticatedAccess", NewUnauthenticatedAccessDetector)
}

// EnumerationScore is the score for anonymous catalog enumeration: a serious
// finding (the target discloses its whole attack surface to an unauthenticated
// caller) but deliberately below the invocation tier, which proves the server
// will ACT for that caller rather than merely describe itself.
//
// Enumeration carries the headline verdict precisely because it needs no state
// change to prove, so this probe never has to mutate a customer's system to make
// its case.
const EnumerationScore = 0.8

// UnauthenticatedAccessDetector adjudicates whether an MCP endpoint's configured
// authentication boundary is decorative.
//
// The verdict is a DIFFERENTIAL, never a bare observation. Anonymous success is
// scored only when credentials WERE configured and the anonymous path succeeded
// anyway. With no credentials configured the same wire result is trivially true
// and worthless: an open server and a server whose auth layer never runs are
// indistinguishable, so firing on it would generate false positives on every
// unauthenticated target an operator points at without credentials.
//
// Severity is then tiered twice over — by what the anonymous caller achieved
// (enumeration vs invocation) and by how reachable the target is (a public
// endpoint is critical; a loopback development server behaving identically is
// expected).
type UnauthenticatedAccessDetector struct{}

// NewUnauthenticatedAccessDetector constructs the detector.
func NewUnauthenticatedAccessDetector(_ registry.Config) (detectors.Detector, error) {
	return &UnauthenticatedAccessDetector{}, nil
}

func (d *UnauthenticatedAccessDetector) Name() string {
	return "mcptransport.UnauthenticatedAccess"
}

func (d *UnauthenticatedAccessDetector) Description() string {
	return "Flags an MCP endpoint that served an anonymous, credential-free session even though the operator configured credentials for it — a decorative authentication boundary. Tiers severity by what the anonymous caller achieved (enumeration vs invocation) and by target reachability (loopback is expected, public is critical)."
}

// Detect scoring:
//
//	auth-baseline class                  → 0.0 (informational control)
//	credentials NOT configured           → 0.0 (differential impossible; probe skips)
//	explicit inconclusive flag           → InconclusiveScore
//	anonymous path refused               → 0.0 (boundary enforced)
//	anonymous OK, authenticated baseline
//	  failed                             → InconclusiveScore (unreliable comparison)
//	anonymous OK + credentials configured:
//	  loopback / unresolvable / unknown  → InconclusiveScore
//	  lan / public, enumeration          → EnumerationScore
//	  lan / public, invocation           → 1.0
func (d *UnauthenticatedAccessDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	class, _ := stringMeta(a, mcpprobe.MetaAuthClass)
	scores := make([]float64, len(a.Outputs))

	// The authenticated control is evidence a reviewer needs, not a finding.
	// Scoring it would drown the results that matter.
	if class == mcpprobe.AuthClassAuthBaseline {
		return scores, nil
	}

	score := d.score(a, class)
	if score == 0.0 {
		return scores, nil
	}
	if len(scores) == 0 {
		// The anonymous call may return no body at all (a refused invocation, an
		// empty result). The finding still has to surface, so emit one score.
		return []float64{score}, nil
	}
	for i := range scores {
		scores[i] = score
	}
	return scores, nil
}

// score resolves the verdict for a non-baseline attempt.
func (d *UnauthenticatedAccessDetector) score(a *attempt.Attempt, class string) float64 {
	// The declared-open class carries its OWN evidence of intent and so bypasses
	// the configured-credentials precondition below. The target published RFC 9728
	// / RFC 8414 metadata, or answered a WWW-Authenticate challenge, stating that
	// authorization is required — and then served a caller holding nothing. That
	// is the server contradicting itself, which needs no operator credentials to
	// interpret.
	//
	// Scored without the host-class softening the credentials path applies: a
	// loopback server with no auth is unremarkable, but a loopback server that
	// advertises OAuth protection and then ignores it is misconfigured wherever it
	// runs.
	// Checked FIRST, for every class. An attempt the probe could not conclude on is
	// not a finding and not a pass, and the declared-open branch below returns 1.0
	// unconditionally — so evaluating the class first reported an unmeasured
	// attempt as a confirmed vulnerability.
	if metaBool(a, attempt.MetadataKeyInconclusive) {
		return InconclusiveScore
	}

	if class == mcpprobe.AuthClassOAuthDeclaredOpen {
		if !metaBool(a, mcpprobe.MetaAuthAnonymousSucceeded) {
			return 0.0 // it declared authorization and enforced it
		}
		return 1.0
	}

	// THE precondition. Without configured credentials there is no boundary to
	// have bypassed, so there is nothing to report — regardless of what the
	// anonymous session achieved.
	if !metaBool(a, mcpprobe.MetaAuthCredentialsConfigured) {
		return 0.0
	}
	if !metaBool(a, mcpprobe.MetaAuthAnonymousSucceeded) {
		return 0.0 // the target refused the anonymous caller: boundary enforced
	}
	// The operator's own session must have worked for the comparison to mean
	// anything. If it didn't, the endpoint may be answering every request the
	// same way and the "anonymous success" is not trustworthy evidence.
	if !metaBool(a, mcpprobe.MetaAuthAuthenticatedSucceeded) {
		return InconclusiveScore
	}

	targetClass, _ := stringMeta(a, mcpprobe.MetaAuthTargetClass)
	switch targetClass {
	case "lan", "public":
		if class == mcpprobe.AuthClassAnonInvocation {
			return 1.0
		}
		return EnumerationScore
	default:
		// loopback (expected for a development server), unresolvable, or
		// unstamped: keep it visible without asserting vulnerability.
		return InconclusiveScore
	}
}
