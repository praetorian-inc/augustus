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
		name string
		a    *attempt.Attempt
		want []float64
	}{
		{
			"differential variant -> 1.0",
			metadataAttempt("client-identity-spoof", true, 2, "different tools"),
			[]float64{1.0},
		},
		{
			"non-differential variant -> 0.0",
			metadataAttempt("client-identity-spoof", false, 0, "same tools"),
			[]float64{0.0},
		},
		{
			"baseline -> 0.0 (informational)",
			metadataAttempt("baseline", false, 0, "baseline tools"),
			[]float64{0.0},
		},
		{
			"errored variant -> inconclusive",
			metadataAttemptErrored("protocol-version-upgrade"),
			[]float64{InconclusiveScore},
		},
		{
			"errored baseline -> inconclusive (not safe)",
			metadataAttemptErrored("baseline"),
			[]float64{InconclusiveScore},
		},
		{
			"header-mismatch differential -> 1.0",
			metadataAttempt("header-mismatch", true, 2, "different tools"),
			[]float64{1.0},
		},
		{
			"capability-escalation differential -> review (0.5)",
			metadataAttempt("capability-escalation", true, 2, "different tools"),
			[]float64{InconclusiveScore},
		},
		{
			"capability-bogus non-differential -> 0.0",
			metadataAttempt("capability-bogus", false, 0, "same tools"),
			[]float64{0.0},
		},
		{
			"protocol-version-downgrade differential -> review (0.5)",
			metadataAttempt("protocol-version-downgrade", true, 1, "different tools"),
			[]float64{InconclusiveScore},
		},
		{
			"identity-spoof differential subset (newTools=0) -> 0.0",
			func() *attempt.Attempt {
				a := attempt.New("attempt")
				a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "client-identity-spoof"
				a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = true
				a.Metadata[attempt.MetadataKeyMetadataInjectionNewTools] = 0
				a.AddOutput("fewer tools")
				a.Complete()
				return a
			}(),
			[]float64{0.0},
		},
		{
			"capability-bogus differential superset -> 1.0",
			metadataAttempt("capability-bogus", true, 2, "extra tools"),
			[]float64{1.0},
		},
		{
			"inconclusive flag -> 0.5",
			func() *attempt.Attempt {
				a := attempt.New("attempt")
				a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = "client-identity-spoof"
				a.Metadata[attempt.MetadataKeyInconclusive] = true
				a.AddOutput("inconclusive")
				a.Complete()
				return a
			}(),
			[]float64{InconclusiveScore},
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
		})
	}
}

func TestCapabilityEscalationDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want []float64
	}{
		{
			"escalation differential -> review (0.5)",
			metadataAttempt("capability-escalation", true, 2, "extra tools"),
			[]float64{InconclusiveScore},
		},
		{
			"escalation non-differential -> 0.0",
			metadataAttempt("capability-escalation", false, 0, "same tools"),
			[]float64{0.0},
		},
		{
			"baseline -> 0.0",
			metadataAttempt("baseline", false, 0, "baseline tools"),
			[]float64{0.0},
		},
		{
			"errored -> inconclusive",
			metadataAttemptErrored("capability-all"),
			[]float64{InconclusiveScore},
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
		})
	}
}
