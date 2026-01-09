package always

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestPassDetector_Name(t *testing.T) {
	d := &Pass{}
	if got := d.Name(); got != "always.Pass" {
		t.Errorf("Name() = %q, want %q", got, "always.Pass")
	}
}

func TestPassDetector_Description(t *testing.T) {
	d := &Pass{}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestPassDetector_Detect(t *testing.T) {
	tests := []struct {
		name        string
		outputs     []string
		wantScores  []float64
		wantNumScores int
	}{
		{
			name:          "single output",
			outputs:       []string{"some output"},
			wantScores:    []float64{0.0},
			wantNumScores: 1,
		},
		{
			name:          "multiple outputs",
			outputs:       []string{"output1", "output2", "output3"},
			wantScores:    []float64{0.0, 0.0, 0.0},
			wantNumScores: 3,
		},
		{
			name:          "empty output",
			outputs:       []string{""},
			wantScores:    []float64{0.0},
			wantNumScores: 1,
		},
		{
			name:          "no outputs",
			outputs:       []string{},
			wantScores:    []float64{},
			wantNumScores: 0,
		},
		{
			name:          "many outputs",
			outputs:       []string{"1", "2", "3", "4", "5", "6", "7", "8", "9", "10"},
			wantScores:    []float64{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0},
			wantNumScores: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &Pass{}
			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}

			if len(scores) != tt.wantNumScores {
				t.Fatalf("Detect() returned %d scores, want %d", len(scores), tt.wantNumScores)
			}

			for i, score := range scores {
				if score != 0.0 {
					t.Errorf("scores[%d] = %f, want 0.0", i, score)
				}
			}
		})
	}
}

func TestPassDetector_Detect_AlwaysZero(t *testing.T) {
	// Test that Pass always returns 0.0 regardless of content
	d := &Pass{}

	testCases := []string{
		"safe content",
		"potentially unsafe content",
		"malicious content",
		"SQL injection attempt",
		"XSS attack",
		"",
		"very long content " + string(make([]byte, 10000)),
	}

	for _, content := range testCases {
		a := attempt.New("test")
		a.AddOutput(content)

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() with content %q error = %v, want nil", content[:min(len(content), 20)], err)
		}

		if len(scores) != 1 {
			t.Fatalf("Detect() returned %d scores, want 1", len(scores))
		}

		if scores[0] != 0.0 {
			t.Errorf("Detect() with content %q = %f, want 0.0", content[:min(len(content), 20)], scores[0])
		}
	}
}

func TestPassDetector_Detect_ScoreCountMatchesOutputCount(t *testing.T) {
	d := &Pass{}

	// Test various output counts
	for numOutputs := 0; numOutputs <= 10; numOutputs++ {
		a := attempt.New("test")
		for i := 0; i < numOutputs; i++ {
			a.AddOutput("output")
		}

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() with %d outputs error = %v, want nil", numOutputs, err)
		}

		if len(scores) != numOutputs {
			t.Errorf("Detect() with %d outputs returned %d scores, want %d", numOutputs, len(scores), numOutputs)
		}
	}
}

func TestPassDetector_Detect_WithCompleteAttempt(t *testing.T) {
	d := &Pass{}

	// Create a realistic attempt
	a := attempt.New("test prompt")
	a.Probe = "test.Blank"
	a.Detector = "always.Pass"
	a.AddOutput("response 1")
	a.AddOutput("response 2")
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v, want nil", err)
	}

	if len(scores) != 2 {
		t.Fatalf("Detect() returned %d scores, want 2", len(scores))
	}

	for i, score := range scores {
		if score != 0.0 {
			t.Errorf("scores[%d] = %f, want 0.0", i, score)
		}
	}
}

func TestPassDetector_Registration(t *testing.T) {
	// Test that the detector is registered via init()
	factory, ok := detectors.Get("always.Pass")
	if !ok {
		t.Fatal("always.Pass not registered in detectors registry")
	}

	// Test factory creates valid detector
	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if d.Name() != "always.Pass" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "always.Pass")
	}
}

func TestNewPass(t *testing.T) {
	tests := []struct {
		name   string
		config registry.Config
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: registry.Config{},
		},
		{
			name: "config with data",
			config: registry.Config{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewPass(tt.config)
			if err != nil {
				t.Fatalf("NewPass() error = %v, want nil", err)
			}
			if d == nil {
				t.Fatal("NewPass() returned nil detector")
			}
			if d.Name() != "always.Pass" {
				t.Errorf("detector.Name() = %q, want %q", d.Name(), "always.Pass")
			}
		})
	}
}

func TestPassDetector_ContextCancellation(t *testing.T) {
	d := &Pass{}
	a := attempt.New("test")
	a.AddOutput("output")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Pass detector ignores context, should still work
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() with cancelled context error = %v, want nil", err)
	}
	if len(scores) != 1 {
		t.Errorf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() = %f, want 0.0", scores[0])
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
