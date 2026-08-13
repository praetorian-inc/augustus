package mcptransport

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newOriginValidationDetector(t *testing.T) *OriginValidationDetector {
	t.Helper()
	d, err := NewOriginValidationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewOriginValidationDetector: %v", err)
	}
	return d.(*OriginValidationDetector)
}

func originValidationAttempt(class string, accepted bool, output string) *attempt.Attempt {
	a := attempt.New("Origin=...")
	a.Metadata[attempt.MetadataKeyOriginValidationClass] = class
	a.Metadata[attempt.MetadataKeyOriginValidationAccepted] = accepted
	if output != "" {
		a.AddOutput(output)
	}
	return a
}

func TestOriginValidationDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want []float64
	}{
		// The sweep is the probe's aggregated bypass attempt: one output
		// carrying every accepted variant as evidence, so it scores exactly
		// one 1.0 — one finding for the endpoint, not one per variant
		// (LAB-5584).
		{"sweep accepted -> one vuln score", originValidationAttempt("origin-validation-sweep", true, "7 of 9 accepted"), []float64{1.0}},
		{"sweep rejected -> safe", originValidationAttempt("origin-validation-sweep", false, "0 of 9 accepted"), []float64{0.0}},
		{"cors-reflect-creds accepted -> vuln", originValidationAttempt("cors-reflect-creds", true, "HTTP 204"), []float64{1.0}},
		{"baseline accepted -> not a finding", originValidationAttempt("baseline", true, "HTTP 200"), []float64{0.0}},
		{"blind acceptance (no output) still flagged", originValidationAttempt("origin-validation-sweep", true, ""), []float64{1.0}},
	}

	d := newOriginValidationDetector(t)

	// Target-class scoring: an accepted finding on a PUBLIC endpoint is
	// spec-violation-only (CSRF-class, not rebinding), so score is
	// InconclusiveScore rather than 1.0. Verified via table-driven cases
	// with the target-class metadata set explicitly.
	targetTests := []struct {
		name        string
		targetClass string
		wantScore   float64
	}{
		{"loopback → 1.0", "loopback", 1.0},
		{"lan → 1.0", "lan", 1.0},
		{"public → InconclusiveScore", "public", InconclusiveScore},
		{"unresolvable → InconclusiveScore", "unresolvable", InconclusiveScore},
	}
	for _, tt := range targetTests {
		t.Run(tt.name, func(t *testing.T) {
			a := originValidationAttempt("origin-validation-sweep", true, "7 of 9 accepted")
			a.Metadata[attempt.MetadataKeyOriginValidationTargetClass] = tt.targetClass
			got, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != 1 || got[0] != tt.wantScore {
				t.Errorf("Detect = %v, want [%v]", got, tt.wantScore)
			}
		})
	}

	// Baseline-served is what makes a refusal interpretable. A sweep that
	// accepted nothing is only "safe" when the endpoint actually answered the
	// unauthenticated baseline; if it refused that too, it refused the CALLER
	// and the sweep assessed nothing. Scoring both 0.0 would report an
	// untested endpoint as clean.
	baselineTests := []struct {
		name             string
		baselineAccepted any
		wantScore        float64
	}{
		{"baseline served → refusals are real, safe", true, 0.0},
		{"baseline refused → nothing was assessed, inconclusive", false, InconclusiveScore},
	}
	for _, tt := range baselineTests {
		t.Run(tt.name, func(t *testing.T) {
			a := originValidationAttempt("origin-validation-sweep", false, "0 of 9 accepted")
			a.Metadata[attempt.MetadataKeyOriginValidationTargetClass] = "loopback"
			a.Metadata[attempt.MetadataKeyOriginValidationBaselineAccepted] = tt.baselineAccepted
			got, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != 1 || got[0] != tt.wantScore {
				t.Errorf("Detect = %v, want [%v]", got, tt.wantScore)
			}
		})
	}

	// An attempt that does not carry the baseline fact (the CORS preflight, or
	// a run predating it) keeps its previous scoring rather than being
	// silently reclassified as inconclusive.
	t.Run("no baseline fact → unchanged", func(t *testing.T) {
		a := originValidationAttempt("cors-reflect-creds", false, "HTTP 204")
		got, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect: %v", err)
		}
		if len(got) != 1 || got[0] != 0.0 {
			t.Errorf("Detect = %v, want [0]", got)
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := d.Detect(context.Background(), tt.a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Detect = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("Detect[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
