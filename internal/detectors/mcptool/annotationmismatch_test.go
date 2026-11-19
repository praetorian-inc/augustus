package mcptool

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestAnnotationMismatch_Verdicts(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]any
		want float64
	}{
		{"mismatch", map[string]any{mcpprobe.MetaAnnotationMismatch: true}, 1.0},
		{"held", map[string]any{}, 0.0},
		{"inconclusive wins", map[string]any{mcpprobe.MetaAnnotationMismatch: true, attempt.MetadataKeyInconclusive: true}, InconclusiveScore},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := attempt.New("p")
			a.AddOutput("evidence")
			for k, v := range tc.meta {
				a.Metadata[k] = v
			}
			scores, err := (&AnnotationMismatchDetector{}).Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(scores) != 1 || scores[0] != tc.want {
				t.Errorf("scores = %v, want [%v]", scores, tc.want)
			}
		})
	}
}
