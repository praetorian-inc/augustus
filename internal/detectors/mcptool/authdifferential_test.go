package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// diffAttempt builds an attempt in the shape the authorization probes record:
// a probe call, an optional same-shape replica, and a control call.
type diffAttempt struct {
	class        string
	probeValue   string
	probeResp    string
	replicaValue string
	replicaResp  string
	controlValue string
	controlResp  string
}

func (d diffAttempt) build() *attempt.Attempt {
	a := attempt.New(d.probeValue)
	a.AddOutput(d.probeResp)
	a.Complete()
	a.Metadata[mcpprobe.MetaAuthClass] = d.class
	a.Metadata[mcpprobe.MetaAuthProbeValue] = d.probeValue
	a.Metadata[mcpprobe.MetaAuthControlValue] = d.controlValue
	a.Metadata[mcpprobe.MetaAuthControl] = d.controlResp
	if d.replicaValue != "" {
		a.Metadata[mcpprobe.MetaAuthReplicaValue] = d.replicaValue
		a.Metadata[mcpprobe.MetaAuthReplicaResponse] = d.replicaResp
	}
	return a
}

func detectTokenValidation(t *testing.T, a *attempt.Attempt) float64 {
	t.Helper()
	d, err := NewTokenValidationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewTokenValidationDetector: %v", err)
	}
	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	best := 0.0
	for _, s := range scores {
		if s > best {
			best = s
		}
	}
	return best
}

// TestAuthDifferential_FormatOnlyValidationDetected is the DVMCP-challenge-7
// class, expressed generically. Two independent random values of one shape are
// both accepted while a malformed value is refused. Both random values were
// certainly never issued, so a verifier doing a real issuance lookup could not
// answer them differently from any other unissued value. Note the adjudication
// never matches on "appears to be valid": it compares response classes.
func TestAuthDifferential_FormatOnlyValidationDetected(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "0123456789abcdef0123456789abcdef",
		probeResp:    "Token 0123456789abcdef0123456789abcdef appears to be valid",
		replicaValue: "fedcba9876543210fedcba9876543210",
		replicaResp:  "Token fedcba9876543210fedcba9876543210 appears to be valid",
		controlValue: "!!",
		controlResp:  "Token !! is invalid (incorrect format)",
	}.build()

	if got := detectTokenValidation(t, a); got != 1.0 {
		t.Errorf("format-only validation scored %v, want 1.0", got)
	}
}

// TestAuthDifferential_RealTokenStoreIsSafe is the mandatory control: a server
// that validates against a real store answers a well-formed-but-unissued value
// the same way it answers garbage. Must NOT fire.
func TestAuthDifferential_RealTokenStoreIsSafe(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "0123456789abcdef0123456789abcdef",
		probeResp:    "Token 0123456789abcdef0123456789abcdef is invalid",
		replicaValue: "fedcba9876543210fedcba9876543210",
		replicaResp:  "Token fedcba9876543210fedcba9876543210 is invalid",
		controlValue: "!!",
		controlResp:  "Token !! is invalid",
	}.build()

	if got := detectTokenValidation(t, a); got != 0.0 {
		t.Errorf("real token store scored %v, want 0.0 (must not fire)", got)
	}
}

// TestAuthDifferential_EchoOnlyDifferenceIsSafe: servers routinely echo the
// submitted value. Without masking it out, every response would differ and the
// comparison would fire on every target — a total false-positive machine.
func TestAuthDifferential_EchoOnlyDifferenceIsSafe(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "aaaabbbbccccdddd",
		probeResp:    "no such token: aaaabbbbccccdddd",
		replicaValue: "1111222233334444",
		replicaResp:  "no such token: 1111222233334444",
		controlValue: "!!",
		controlResp:  "no such token: !!",
	}.build()

	if got := detectTokenValidation(t, a); got != 0.0 {
		t.Errorf("responses differing only by the echoed value scored %v, want 0.0", got)
	}
}

// TestAuthDifferential_UnstableResponsesAreInconclusive: if two identical-shape
// values get different answers, the target is not partitioning on shape and the
// comparison cannot be trusted. Report uncertainty, never a silent clean pass.
func TestAuthDifferential_UnstableResponsesAreInconclusive(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "0123456789abcdef0123456789abcdef",
		probeResp:    "session established for user alice",
		replicaValue: "fedcba9876543210fedcba9876543210",
		replicaResp:  "quota exceeded, try later",
		controlValue: "!!",
		controlResp:  "bad format",
	}.build()

	if got := detectTokenValidation(t, a); got != InconclusiveScore {
		t.Errorf("unstable responses scored %v, want %v", got, InconclusiveScore)
	}
}

// TestAuthDifferential_DenialWordedDifferentlyIsSafe is the key false-positive
// guard. A correct server may word its two rejections differently ("bad format"
// vs "token not found"). That partitions responses by shape, so a naive
// class-comparison would flag it — but the never-issued value was REFUSED, which
// is precisely the desired behaviour. Differing refusal wording is a better error
// message, not a weakness, so this must be SAFE rather than a finding.
func TestAuthDifferential_DenialWordedDifferentlyIsSafe(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "0123456789abcdef0123456789abcdef",
		probeResp:    "token not found",
		replicaValue: "fedcba9876543210fedcba9876543210",
		replicaResp:  "token not found",
		controlValue: "!!",
		controlResp:  "malformed token: incorrect format",
	}.build()

	if got := detectTokenValidation(t, a); got != 0.0 {
		t.Errorf("differently-worded denial scored %v, want 0.0 (the unissued value was refused: safe)", got)
	}
}

// TestAuthDifferential_SecondControlIsolatesPrivilege: where the control is a
// SUCCESSFUL lower-privilege call, "control was refused" cannot be the signal. Two
// unprivileged controls that agree, with the probe differing from both, isolate
// the privilege as the cause of the difference.
func TestAuthDifferential_SecondControlIsolatesPrivilege(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassPrivilegeDiscriminator,
		probeValue:   "admin",
		probeResp:    "root shell attached to admin plane",
		controlValue: "database",
		controlResp:  "connected to database with standard privileges",
	}.build()
	a.Metadata[mcpprobe.MetaAuthControl2Value] = "augff00ff00ff00"
	a.Metadata[mcpprobe.MetaAuthControl2Response] = "connected to augff00ff00ff00 with standard privileges"

	if got := detectTokenValidation(t, a); got != 1.0 {
		t.Errorf("privilege isolated by two agreeing controls scored %v, want 1.0", got)
	}
}

// TestAuthDifferential_DisagreeingControlsAreInconclusive: when two equally
// unprivileged values get different answers, the target's responses vary by value
// and no privilege conclusion can be drawn.
func TestAuthDifferential_DisagreeingControlsAreInconclusive(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassPrivilegeDiscriminator,
		probeValue:   "admin",
		probeResp:    "attached to plane C",
		controlValue: "database",
		controlResp:  "attached to plane A",
	}.build()
	a.Metadata[mcpprobe.MetaAuthControl2Value] = "augff00ff00ff00"
	a.Metadata[mcpprobe.MetaAuthControl2Response] = "attached to plane B"

	if got := detectTokenValidation(t, a); got != InconclusiveScore {
		t.Errorf("disagreeing unprivileged controls scored %v, want %v", got, InconclusiveScore)
	}
}

// TestAuthDifferential_RefusedSecondControlConfirmsAllowList: when the second
// control is REFUSED the target maintains an allow-list. The probe value being
// served by that allow-list AND reaching behaviour the ordinary declared value did
// not isolates the escalation, even though the two controls cannot agree here (one
// served, one refused).
func TestAuthDifferential_RefusedSecondControlConfirmsAllowList(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassPrivilegeDiscriminator,
		probeValue:   "admin-console",
		probeResp:    "root shell attached to the control plane",
		controlValue: "database",
		controlResp:  "connected to database with standard privileges",
	}.build()
	a.Metadata[mcpprobe.MetaAuthControl2Value] = "aug0011223344"
	a.Metadata[mcpprobe.MetaAuthControl2Response] = "Error: System 'aug0011223344' not found."

	if got := detectTokenValidation(t, a); got != 1.0 {
		t.Errorf("allow-list-confirmed escalation scored %v, want 1.0", got)
	}
}

// TestAuthDifferential_RefusedProbeIsAlwaysSafe: whatever the control said, a
// probe value the target refused reached nothing.
func TestAuthDifferential_RefusedProbeIsAlwaysSafe(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassPrivilegeDiscriminator,
		probeValue:   "admin",
		probeResp:    "error: unknown system requested",
		controlValue: "database",
		controlResp:  "connected to database",
	}.build()

	if got := detectTokenValidation(t, a); got != 0.0 {
		t.Errorf("refused probe value scored %v, want 0.0", got)
	}
}

// TestAuthDifferential_MissingControlIsInconclusive: with no baseline there is
// nothing to compare against.
func TestAuthDifferential_MissingControlIsInconclusive(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "0123456789abcdef0123456789abcdef",
		probeResp:    "welcome",
		replicaValue: "fedcba9876543210fedcba9876543210",
		replicaResp:  "welcome",
		controlValue: "!!",
		controlResp:  "", // control call failed
	}.build()

	if got := detectTokenValidation(t, a); got != InconclusiveScore {
		t.Errorf("missing control scored %v, want %v", got, InconclusiveScore)
	}
}

// TestAuthDifferential_ErroredAttemptIsNotAFinding: a transport failure is not
// evidence of anything.
func TestAuthDifferential_ErroredAttemptIsNotAFinding(t *testing.T) {
	a := attempt.New("x")
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenFormatOnly
	a.SetError(context.DeadlineExceeded)
	if got := detectTokenValidation(t, a); got != 0.0 {
		t.Errorf("errored attempt scored %v, want 0.0", got)
	}
}

// ---------------------------------------------------------------------------
// Token predictability
// ---------------------------------------------------------------------------

func detectPredictable(t *testing.T, first, second string) float64 {
	t.Helper()
	a := attempt.New("issued tokens")
	a.AddOutput(first)
	a.Complete()
	a.Metadata[mcpprobe.MetaAuthClass] = mcpprobe.AuthClassTokenPredictable
	// The PROBE classifies and the detector reads the verdict, so the two live
	// credentials never enter metadata. Going through the real IssuedRelation keeps
	// these cases exercising the classification rather than a hand-set answer.
	a.Metadata[mcpprobe.MetaAuthIssuedRelation] = mcpprobe.IssuedRelation(first, second)
	a.Metadata[mcpprobe.MetaAuthIssuedEvidence] = "first " + mcpprobe.RedactCredential(first) +
		"; second " + mcpprobe.RedactCredential(second)
	return detectTokenValidation(t, a)
}

// TestAuthDifferential_IdenticalIssuedTokensArePredictable: a surface that hands
// the same value to every caller is the strongest form of predictability.
func TestAuthDifferential_IdenticalIssuedTokensArePredictable(t *testing.T) {
	if got := detectPredictable(t, "abc123def456", "abc123def456"); got != 1.0 {
		t.Errorf("identical issued tokens scored %v, want 1.0", got)
	}
}

// TestAuthDifferential_SequentialIssuedTokensArePredictable: a counter suffix
// lets one holder derive another's token.
func TestAuthDifferential_SequentialIssuedTokensArePredictable(t *testing.T) {
	if got := detectPredictable(t, "session_1041", "session_1042"); got != 1.0 {
		t.Errorf("sequential issued tokens scored %v, want 1.0", got)
	}
}

// TestAuthDifferential_RandomIssuedTokensAreSafe: the mandatory control for the
// predictability check — properly random tokens must NOT fire.
func TestAuthDifferential_RandomIssuedTokensAreSafe(t *testing.T) {
	pairs := [][2]string{
		{"9f2b7c1de4a05836bb17c9e2f4d80a51", "3c8e15af90b762d4e5fa2c0817bd936e"},
		{"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc", "MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG0"},
		{"3f2504e0-4f89-11d3-9a0c-0305e82c3301", "b7e11d6a-0c2f-4e5b-8a19-7d3f4c210985"},
	}
	for _, p := range pairs {
		if got := detectPredictable(t, p[0], p[1]); got != 0.0 {
			t.Errorf("random tokens %q / %q scored %v, want 0.0", p[0], p[1], got)
		}
	}
}

// TestAuthDifferential_SharedPrefixWithTinyDeltaIsPredictable: a long common
// prefix with a one-character tail is a derivable token.
func TestAuthDifferential_SharedPrefixWithTinyDeltaIsPredictable(t *testing.T) {
	got := detectPredictable(t, "tok_2024_prod_useast_00000001", "tok_2024_prod_useast_00000002")
	if got != 1.0 {
		t.Errorf("shared-prefix tokens scored %v, want 1.0", got)
	}
}
