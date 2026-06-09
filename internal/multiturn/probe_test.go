package multiturn

import "testing"

func TestBaseMultiTurnProbe_GetPrimaryDetector_DefaultsToJudge(t *testing.T) {
	b := BaseMultiTurnProbe{ProbeName: "x"}
	if got := b.GetPrimaryDetector(); got != DetectorJudge {
		t.Errorf("GetPrimaryDetector() = %q, want default %q", got, DetectorJudge)
	}
}

func TestBaseMultiTurnProbe_GetPrimaryDetector_HonorsField(t *testing.T) {
	b := BaseMultiTurnProbe{ProbeName: "x", Detector: "base.StringDetector"}
	if got := b.GetPrimaryDetector(); got != "base.StringDetector" {
		t.Errorf("GetPrimaryDetector() = %q, want the configured detector", got)
	}
}
