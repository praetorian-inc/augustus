package detectors_test

import (
	"context"
	"testing"

	_ "github.com/praetorian-inc/augustus/internal/detectors/advpatch"
	_ "github.com/praetorian-inc/augustus/internal/detectors/pair"
	_ "github.com/praetorian-inc/augustus/internal/detectors/packagehallucination"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewDetectorsRegistered(t *testing.T) {
	tests := []struct {
		name          string
		expectedScore float64
	}{
		{"advpatch.Universal", 0.0},
		{"advpatch.Targeted", 0.0},
		{"advpatch.Transfer", 0.0},
		{"pair.PAIR", 1.0}, // Should return 1.0 for output with no refusal
		{"packagehallucination.GoMod", 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create detector
			d, err := detectors.Create(tt.name, registry.Config{})
			if err != nil {
				t.Fatalf("failed to create detector %s: %v", tt.name, err)
			}

			// Test with simple output
			a := &attempt.Attempt{
				Outputs: []string{"test output without refusal"},
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("detection failed for %s: %v", tt.name, err)
			}

			if len(scores) != 1 {
				t.Fatalf("expected 1 score, got %d", len(scores))
			}

			if scores[0] != tt.expectedScore {
				t.Errorf("%s: expected score %.1f, got %.1f", tt.name, tt.expectedScore, scores[0])
			}

			t.Logf("✅ %s: detector works (score: %.1f)", tt.name, scores[0])
		})
	}
}

func TestPAIRDetectorWithRefusal(t *testing.T) {
	// Test pair.PAIR with refusal message (should return 0.0)
	d, err := detectors.Create("pair.PAIR", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create pair.PAIR detector: %v", err)
	}

	a := &attempt.Attempt{
		Outputs: []string{"I'm sorry, I cannot help with that request."},
	}

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("detection failed: %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("expected 1 score, got %d", len(scores))
	}

	if scores[0] != 0.0 {
		t.Errorf("expected score 0.0 (refusal detected), got %.1f", scores[0])
	}

	t.Logf("✅ pair.PAIR with refusal: score %.1f (correct)", scores[0])
}
