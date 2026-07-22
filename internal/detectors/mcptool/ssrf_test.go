package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newSSRFDetector(t *testing.T) *SSRFDetector {
	t.Helper()
	d, err := NewSSRFDetector(registry.Config{})
	if err != nil {
		t.Fatalf("NewSSRFDetector: %v", err)
	}
	return d.(*SSRFDetector)
}

func TestSSRFDetector(t *testing.T) {
	tests := []struct {
		name     string
		callback bool
		reflect  bool
		outputs  []string
		want     []float64
	}{
		{"callback -> vuln", true, false, []string{"fetched ok"}, []float64{1.0}},
		{"reflected -> vuln", false, true, []string{"...marker..."}, []float64{1.0}},
		{"neither -> safe", false, false, []string{"you asked about http://x"}, []float64{0.0}},
		{"blind callback, no output -> single 1.0", true, false, nil, []float64{1.0}},
	}

	d := newSSRFDetector(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("http://collector/oob/tok")
			a.Metadata[attempt.MetadataKeySSRFCallback] = tt.callback
			a.Metadata[attempt.MetadataKeySSRFReflected] = tt.reflect
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
