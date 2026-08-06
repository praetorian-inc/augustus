package mcptool

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// detectFunctionAuthorization scores an attempt with the PRODUCTION
// FunctionAuthorization detector.
//
// The privilege-discriminator cases all ran through detectTokenValidation, so the
// detector that actually consumes those attempts in production was never exercised.
// Two detectors sharing a differential implementation is exactly the situation where
// testing only one lets them drift apart unnoticed.
func detectFunctionAuthorization(t *testing.T, a *attempt.Attempt) float64 {
	t.Helper()
	d, err := NewFunctionAuthorizationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewFunctionAuthorizationDetector: %v", err)
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

// TestFunctionAuthorizationDetector_AgreesOnPrivilegeIsolation pins the two
// detectors to the same verdict on the class FunctionAuthorization owns.
func TestFunctionAuthorizationDetector_AgreesOnPrivilegeIsolation(t *testing.T) {
	build := func() *attempt.Attempt {
		a := diffAttempt{
			class:        mcpprobe.AuthClassPrivilegeDiscriminator,
			probeValue:   "admin",
			probeResp:    "root shell attached to admin plane",
			controlValue: "database",
			controlResp:  "connected to database with standard privileges",
		}.build()
		a.Metadata[mcpprobe.MetaAuthControl2Value] = "augff00ff00ff00"
		a.Metadata[mcpprobe.MetaAuthControl2Response] = "connected to augff00ff00ff00 with standard privileges"
		return a
	}
	viaToken := detectTokenValidation(t, build())
	viaAuthz := detectFunctionAuthorization(t, build())
	if viaAuthz != viaToken {
		t.Errorf("FunctionAuthorization scored %v but TokenValidation scored %v on the same attempt; the shared differential has drifted", viaAuthz, viaToken)
	}
	if viaAuthz != 1.0 {
		t.Errorf("privilege isolation scored %v, want 1.0", viaAuthz)
	}
}

// TestIssuedRelation_ShortValuesAreNotRelated covers the near-identical heuristic on
// very short values. Two unrelated three-character identifiers sharing two leading
// characters produce a 0.67 prefix ratio with a one-character tail — an incidental
// collision, not a derivable relationship.
func TestIssuedRelation_ShortValuesAreNotRelated(t *testing.T) {
	for _, p := range [][2]string{{"ab1", "ab2"}, {"x9", "x8"}, {"tok1", "tok7"}} {
		if got := mcpprobe.IssuedRelation(p[0], p[1]); got == mcpprobe.RelationNearIdentical {
			t.Errorf("IssuedRelation(%q,%q) = %q; short values must not qualify as near-identical", p[0], p[1], got)
		}
	}
	// Identical and sequential still hold at any length: those relationships do
	// not depend on size.
	if got := mcpprobe.IssuedRelation("ab", "ab"); got != mcpprobe.RelationIdentical {
		t.Errorf("identical short values = %q, want %q", got, mcpprobe.RelationIdentical)
	}
	if got := mcpprobe.IssuedRelation("s1", "s2"); got != mcpprobe.RelationSequential {
		t.Errorf("sequential short values = %q, want %q", got, mcpprobe.RelationSequential)
	}
	// And a genuinely long near-identical pair must still fire.
	if got := mcpprobe.IssuedRelation("tok_2024_prod_useast_00000001", "tok_2024_prod_useast_00000002"); !mcpprobe.IssuedRelationIsDerivable(got) {
		t.Errorf("long shared-prefix pair = %q, want a derivable relation", got)
	}
}

// TestAuthDifferential_HonorsExplicitInconclusiveMark covers a FALSE POSITIVE with
// the strongest possible verdict: 1.0 on an attempt the probe had already declared
// unmeasurable.
//
// The probes mark an attempt inconclusive when a leg of the differential cannot be
// obtained. This shared detector never read the flag, so a missing replica response
// normalised to the same class as the probe response and the logic fell through to
// the control-refusal branch. Adding inconclusive marking to the probes made the
// path MORE reachable, so both halves have to agree.
func TestAuthDifferential_HonorsExplicitInconclusiveMark(t *testing.T) {
	a := diffAttempt{
		class:        mcpprobe.AuthClassTokenFormatOnly,
		probeValue:   "aaaa1111",
		probeResp:    "accepted",
		controlValue: "!!",
		controlResp:  "invalid token",
	}.build()
	// The replica leg was never obtained.
	a.Metadata[mcpprobe.MetaAuthReplicaValue] = ""
	a.Metadata[mcpprobe.MetaAuthReplicaResponse] = ""
	a.Metadata[attempt.MetadataKeyInconclusive] = true

	if got := detectTokenValidation(t, a); got != InconclusiveScore {
		t.Errorf("scored %v, want %v; an attempt the probe could not measure is not a finding", got, InconclusiveScore)
	}
}

// TestMaskID_IsCaseInsensitive covers the second, unfixed copy of a defect. The
// caller lowercases only AFTER masking, so a server that canonicalises what it
// echoes — upper-casing a token, capitalising a role — left that text in the
// compared class, and two responses differing only by the echoed value read as
// different behaviour.
func TestMaskID_IsCaseInsensitive(t *testing.T) {
	const submitted = "Ab12-Cd34"
	lower := maskID("value "+strings.ToLower(submitted)+" accepted", submitted)
	upper := maskID("value "+strings.ToUpper(submitted)+" accepted", submitted)
	if lower != upper {
		t.Errorf("masking is case-sensitive:\n lower = %q\n upper = %q", lower, upper)
	}
	if !strings.Contains(lower, "<id>") {
		t.Errorf("value was not masked at all: %q", lower)
	}
}
