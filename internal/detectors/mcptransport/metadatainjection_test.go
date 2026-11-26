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

func metadataAttempt(class string, differential bool, output string) *attempt.Attempt {
	a := attempt.New("attempt")
	a.Metadata[attempt.MetadataKeyMetadataInjectionClass] = class
	a.Metadata[attempt.MetadataKeyMetadataInjectionDifferential] = differential
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
			metadataAttempt("client-identity-spoof", true, "different tools"),
			[]float64{1.0},
		},
		{
			"non-differential variant -> 0.0",
			metadataAttempt("client-identity-spoof", false, "same tools"),
			[]float64{0.0},
		},
		{
			"baseline -> 0.0 (informational)",
			metadataAttempt("baseline", false, "baseline tools"),
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
			metadataAttempt("header-mismatch", true, "different tools"),
			[]float64{1.0},
		},
		{
			"capability-escalation differential -> 1.0",
			metadataAttempt("capability-escalation", true, "different tools"),
			[]float64{1.0},
		},
		{
			"capability-bogus non-differential -> 0.0",
			metadataAttempt("capability-bogus", false, "same tools"),
			[]float64{0.0},
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
			"escalation differential -> 1.0",
			metadataAttempt("capability-escalation", true, "extra tools"),
			[]float64{1.0},
		},
		{
			"escalation non-differential -> 0.0",
			metadataAttempt("capability-escalation", false, "same tools"),
			[]float64{0.0},
		},
		{
			"baseline -> 0.0",
			metadataAttempt("baseline", false, "baseline tools"),
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
