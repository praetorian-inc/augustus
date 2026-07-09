package toolsec

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newDNSRebindDetector(t *testing.T) *DNSRebindingDetector {
	t.Helper()
	d, err := NewDNSRebindingDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewDNSRebindingDetector: %v", err)
	}
	return d.(*DNSRebindingDetector)
}

func dnsRebindAttempt(class string, accepted bool, output string) *attempt.Attempt {
	a := attempt.New("Origin=...")
	a.Metadata[attempt.MetadataKeyDNSRebindClass] = class
	a.Metadata[attempt.MetadataKeyDNSRebindAccepted] = accepted
	if output != "" {
		a.AddOutput(output)
	}
	return a
}

func TestDNSRebindingDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want []float64
	}{
		{"external-origin accepted -> vuln", dnsRebindAttempt("external-origin", true, "HTTP 200"), []float64{1.0}},
		{"null-origin accepted -> vuln", dnsRebindAttempt("null-origin", true, "HTTP 200"), []float64{1.0}},
		{"extension-origin accepted -> vuln", dnsRebindAttempt("extension-origin", true, "HTTP 200"), []float64{1.0}},
		{"localhost-lookalike accepted -> vuln", dnsRebindAttempt("localhost-lookalike", true, "HTTP 200"), []float64{1.0}},
		{"case-variant accepted -> vuln", dnsRebindAttempt("case-variant", true, "HTTP 200"), []float64{1.0}},
		{"unexpected-host accepted -> vuln", dnsRebindAttempt("unexpected-host", true, "HTTP 200"), []float64{1.0}},
		{"cors-reflect-creds accepted -> vuln", dnsRebindAttempt("cors-reflect-creds", true, "HTTP 204"), []float64{1.0}},
		{"baseline accepted -> not a finding", dnsRebindAttempt("baseline", true, "HTTP 200"), []float64{0.0}},
		{"external-origin rejected -> safe", dnsRebindAttempt("external-origin", false, "HTTP 403"), []float64{0.0}},
		{"blind acceptance (no output) still flagged", dnsRebindAttempt("external-origin", true, ""), []float64{1.0}},
	}

	d := newDNSRebindDetector(t)
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
