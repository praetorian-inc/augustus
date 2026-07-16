package mcptransport

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newSSESessionDetector(t *testing.T) *SSESessionHijackDetector {
	t.Helper()
	d, err := NewSSESessionHijackDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewSSESessionHijackDetector: %v", err)
	}
	return d.(*SSESessionHijackDetector)
}

func sseAttempt(class string, accepted bool, output string) *attempt.Attempt {
	a := attempt.New("attempt")
	a.Metadata[attempt.MetadataKeySSESessionClass] = class
	a.Metadata[attempt.MetadataKeySSESessionAccepted] = accepted
	if output != "" {
		a.AddOutput(output)
	}
	return a
}

func sseAttemptInconclusive(class, output string) *attempt.Attempt {
	a := sseAttempt(class, true, output)
	a.Metadata[attempt.MetadataKeyInconclusive] = true
	a.Metadata[attempt.MetadataKeyInconclusiveReason] = "test"
	return a
}

func TestSSESessionDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want []float64
	}{
		{"session-id-collision accepted -> vuln", sseAttempt("session-id-collision", true, "dup"), []float64{1.0}},
		{"session-not-tcp-bound accepted -> vuln", sseAttempt("session-not-tcp-bound", true, "HTTP 200"), []float64{1.0}},
		{"session-post-close-alive accepted -> vuln", sseAttempt("session-post-close-alive", true, "HTTP 200"), []float64{1.0}},
		{"baseline accepted -> not a finding", sseAttempt("baseline", true, "sampled"), []float64{0.0}},
		{"unknown-id-rejects accepted -> not a finding (control)", sseAttempt("unknown-id-rejects", true, "server accepts any"), []float64{0.0}},
		{"class rejected -> safe", sseAttempt("session-not-tcp-bound", false, "HTTP 401"), []float64{0.0}},
		{"inconclusive under proxy -> 0.5", sseAttemptInconclusive("session-not-tcp-bound", "HTTP 202 (proxy-suppressed)"), []float64{InconclusiveScore}},
	}
	d := newSSESessionDetector(t)
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
