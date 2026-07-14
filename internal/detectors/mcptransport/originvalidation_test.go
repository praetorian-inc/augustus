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
		{"external-origin accepted -> vuln", originValidationAttempt("external-origin", true, "HTTP 200"), []float64{1.0}},
		{"null-origin accepted -> vuln", originValidationAttempt("null-origin", true, "HTTP 200"), []float64{1.0}},
		{"extension-origin accepted -> vuln", originValidationAttempt("extension-origin", true, "HTTP 200"), []float64{1.0}},
		{"localhost-lookalike accepted -> vuln", originValidationAttempt("localhost-lookalike", true, "HTTP 200"), []float64{1.0}},
		{"case-variant accepted -> vuln", originValidationAttempt("case-variant", true, "HTTP 200"), []float64{1.0}},
		{"unexpected-host accepted -> vuln", originValidationAttempt("unexpected-host", true, "HTTP 200"), []float64{1.0}},
		{"cors-reflect-creds accepted -> vuln", originValidationAttempt("cors-reflect-creds", true, "HTTP 204"), []float64{1.0}},
		{"baseline accepted -> not a finding", originValidationAttempt("baseline", true, "HTTP 200"), []float64{0.0}},
		{"external-origin rejected -> safe", originValidationAttempt("external-origin", false, "HTTP 403"), []float64{0.0}},
		{"blind acceptance (no output) still flagged", originValidationAttempt("external-origin", true, ""), []float64{1.0}},
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
			a := originValidationAttempt("external-origin", true, "HTTP 200")
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
