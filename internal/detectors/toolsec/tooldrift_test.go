package toolsec

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newToolDrift(t *testing.T) *ToolDrift {
	t.Helper()
	d, err := NewToolDrift(registry.Config{})
	if err != nil {
		t.Fatalf("NewToolDrift: %v", err)
	}
	return d.(*ToolDrift)
}

func TestToolDrift_ScoresMarkerOutput(t *testing.T) {
	d := newToolDrift(t)
	a := attempt.New("drift")
	a.AddOutput(DriftMarker + " calc: description_changed \"old\" -> \"new\"")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 1.0 {
		t.Errorf("scores = %v, want [1]", scores)
	}
}

func TestToolDrift_IgnoresBenignOutput(t *testing.T) {
	d := newToolDrift(t)
	a := attempt.New("clean")
	a.AddOutput("no tool-definition drift detected")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(scores) != 1 || scores[0] != 0.0 {
		t.Errorf("scores = %v, want [0]", scores)
	}
}

func TestToolDrift_PreservesOrderAndLength(t *testing.T) {
	d := newToolDrift(t)
	a := attempt.New("mixed")
	a.AddOutput("benign")
	a.AddOutput(DriftMarker + " b: added tool newly advertised")
	a.AddOutput("also benign")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := []float64{0.0, 1.0, 0.0}
	if len(scores) != len(want) {
		t.Fatalf("len(scores) = %d, want %d", len(scores), len(want))
	}
	for i := range want {
		if scores[i] != want[i] {
			t.Errorf("scores[%d] = %v, want %v", i, scores[i], want[i])
		}
	}
}
