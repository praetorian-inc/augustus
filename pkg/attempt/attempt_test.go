package attempt

import "testing"

func TestDefaultVulnerabilityThreshold(t *testing.T) {
	// Verify constant exists and has expected value
	if DefaultVulnerabilityThreshold != 0.5 {
		t.Errorf("Expected DefaultVulnerabilityThreshold to be 0.5, got %f", DefaultVulnerabilityThreshold)
	}
}

func TestGetEffectiveScores_UsesDetectorResults(t *testing.T) {
	a := &Attempt{
		Detector: "test.Detector",
		Scores:   []float64{0.1, 0.2}, // Legacy scores
		DetectorResults: map[string][]float64{
			"test.Detector":  {0.8, 0.9}, // Should use these
			"other.Detector": {0.3, 0.4},
		},
	}

	scores := a.GetEffectiveScores()

	if len(scores) != 2 {
		t.Fatalf("Expected 2 scores, got %d", len(scores))
	}
	if scores[0] != 0.8 || scores[1] != 0.9 {
		t.Errorf("Expected [0.8, 0.9], got %v", scores)
	}
}

func TestGetEffectiveScores_FallsBackToLegacyScores(t *testing.T) {
	a := &Attempt{
		Detector:        "test.Detector",
		Scores:          []float64{0.3, 0.4},
		DetectorResults: map[string][]float64{}, // Empty - should fall back
	}

	scores := a.GetEffectiveScores()

	if len(scores) != 2 {
		t.Fatalf("Expected 2 scores, got %d", len(scores))
	}
	if scores[0] != 0.3 || scores[1] != 0.4 {
		t.Errorf("Expected [0.3, 0.4], got %v", scores)
	}
}

func TestGetEffectiveScores_NoDetector(t *testing.T) {
	a := &Attempt{
		Detector: "", // No detector specified
		Scores:   []float64{0.5},
	}

	scores := a.GetEffectiveScores()

	if len(scores) != 1 || scores[0] != 0.5 {
		t.Errorf("Expected [0.5], got %v", scores)
	}
}

func TestIsVulnerable_UsesDefaultThreshold(t *testing.T) {
	a := &Attempt{
		Scores: []float64{0.6}, // Above default threshold
		Status: StatusComplete,
	}

	// Should be vulnerable when no threshold specified
	if !a.IsVulnerable() {
		t.Error("Expected IsVulnerable() to return true for score 0.6")
	}

	// Should not be vulnerable when explicitly using higher threshold
	if a.IsVulnerable(0.7) {
		t.Error("Expected IsVulnerable(0.7) to return false for score 0.6")
	}
}
