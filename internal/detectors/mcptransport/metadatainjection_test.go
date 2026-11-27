package mcptransport

import (
	"context"
	"fmt"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newMetadataInjectionDetector(t *testing.T) *MetadataInjectionDetector {
	t.Helper()
	d, err := NewMetadataInjectionDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewMetadataInjectionDetector: %v", err)
	}
	return d.(*MetadataInjectionDetector)
}

func newCapabilityEscalationDetector(t *testing.T) *CapabilityEscalationDetector {
	t.Helper()
	d, err := NewCapabilityEscalationDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewCapabilityEscalationDetector: %v", err)
	}
	return d.(*CapabilityEscalationDetector)
}

func metadataAttempt(class string, differential bool, newTools int, output string) *attempt.Attempt {
	a := attempt.New("attempt")
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = differential
	a.Metadata[attempt.MetadataKeyMetadataInjectionNewTools] = newTools
	if output != "" {
		a.AddOutput(output)
	}
	a.Complete()
	return a
}

func metadataAttemptErrored(class string) *attempt.Attempt {
	a := attempt.New("attempt")
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.SetError(fmt.Errorf("transport failure"))
	return a
}

func TestMetadataInjectionDetector(t *testing.T) {
	tests := []struct {
		name                string
		a                   *attempt.Attempt
		want                []float64
		wantPartialEvidence bool
	}{
		{
			name: "differential variant -> 1.0",
			a:    metadataAttempt("client-identity-spoof", true, 2, "different tools"),
			want: []float64{1.0},
		},
		{
			name: "non-differential variant -> 0.0",
			a:    metadataAttempt("client-identity-spoof", false, 0, "same tools"),
			want: []float64{0.0},
		},
		{
			name: "baseline -> 0.0 (informational)",
			a:    metadataAttempt("baseline", false, 0, "baseline tools"),
			want: []float64{0.0},
		},
		{
			name: "errored variant -> inconclusive",
			a:    metadataAttemptErrored("protocol-version-upgrade"),
			want: []float64{InconclusiveScore},
		},
		{
			name: "errored baseline -> inconclusive (not safe)",
			a:    metadataAttemptErrored("baseline"),
			want: []float64{InconclusiveScore},
		},
		{
			name: "header-mismatch differential -> 1.0",
			a:    metadataAttempt("header-mismatch", true, 2, "different tools"),
			want: []float64{1.0},
		},
		{
			name:                "header-version-mismatch differential -> review (0.5)",
			a:                   metadataAttempt("header-version-mismatch", true, 2, "different tools"),
			want:                []float64{InconclusiveScore},
			wantPartialEvidence: true,
		},
		{
			name:                "capability-escalation differential -> review (0.5)",
			a:                   metadataAttempt("capability-escalation", true, 2, "different tools"),
			want:                []float64{InconclusiveScore},
			wantPartialEvidence: true,
		},
		{
			name: "capability-bogus non-differential -> 0.0",
			a:    metadataAttempt("capability-bogus", false, 0, "same tools"),
			want: []float64{0.0},
		},
		{
			name:                "protocol-version-downgrade differential -> review (0.5)",
			a:                   metadataAttempt("protocol-version-downgrade", true, 1, "different tools"),
			want:                []float64{InconclusiveScore},
			wantPartialEvidence: true,
		},
		{
			name: "identity-spoof differential subset (newTools=0) -> 0.0",
			a: func() *attempt.Attempt {
				a := attempt.New("attempt")
				a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "client-identity-spoof"
				a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = true
				a.Metadata[attempt.MetadataKeyMetadataInjectionNewTools] = 0
				a.AddOutput("fewer tools")
				a.Complete()
				return a
			}(),
			want: []float64{0.0},
		},
		{
			name: "capability-bogus differential superset -> 1.0",
			a:    metadataAttempt("capability-bogus", true, 2, "extra tools"),
			want: []float64{1.0},
		},
		{
			name: "inconclusive flag -> 0.5",
			a: func() *attempt.Attempt {
				a := attempt.New("attempt")
				a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "client-identity-spoof"
				a.Metadata[attempt.MetadataKeyInconclusive] = true
				a.AddOutput("inconclusive")
				a.Complete()
				return a
			}(),
			want: []float64{InconclusiveScore},
		},
	}

	d := newMetadataInjectionDetector(t)
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
			pe, _ := tt.a.GetMetadata(attempt.MetadataKeyPartialEvidence)
			gotPE, _ := pe.(bool)
			if gotPE != tt.wantPartialEvidence {
				t.Errorf("PartialEvidence = %v, want %v", gotPE, tt.wantPartialEvidence)
			}
		})
	}
}

func TestCapabilityEscalationDetector(t *testing.T) {
	tests := []struct {
		name                string
		a                   *attempt.Attempt
		want                []float64
		wantPartialEvidence bool
	}{
		{
			name:                "escalation differential -> review (0.5)",
			a:                   metadataAttempt("capability-escalation", true, 2, "extra tools"),
			want:                []float64{InconclusiveScore},
			wantPartialEvidence: true,
		},
		{
			name: "escalation non-differential -> 0.0",
			a:    metadataAttempt("capability-escalation", false, 0, "same tools"),
			want: []float64{0.0},
		},
		{
			name: "baseline -> 0.0",
			a:    metadataAttempt("baseline", false, 0, "baseline tools"),
			want: []float64{0.0},
		},
		{
			name: "errored -> inconclusive",
			a:    metadataAttemptErrored("capability-all"),
			want: []float64{InconclusiveScore},
		},
	}

	d := newCapabilityEscalationDetector(t)
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
			pe, _ := tt.a.GetMetadata(attempt.MetadataKeyPartialEvidence)
			gotPE, _ := pe.(bool)
			if gotPE != tt.wantPartialEvidence {
				t.Errorf("PartialEvidence = %v, want %v", gotPE, tt.wantPartialEvidence)
			}
		})
	}
}
