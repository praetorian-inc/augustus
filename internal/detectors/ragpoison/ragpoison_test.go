package ragpoison

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestRAGPoisonDetector_Name(t *testing.T) {
	d := &RAGPoisonDetector{
		expectedAnswer: "malicious answer",
		threshold:      0.8,
	}
	if got := d.Name(); got != "ragpoison.RAGPoison" {
		t.Errorf("Name() = %q, want %q", got, "ragpoison.RAGPoison")
	}
}

func TestRAGPoisonDetector_Description(t *testing.T) {
	d := &RAGPoisonDetector{
		expectedAnswer: "malicious answer",
		threshold:      0.8,
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestRAGPoisonDetector_Detect(t *testing.T) {
	tests := []struct {
		name           string
		expectedAnswer string
		threshold      float64
		outputs        []string
		wantScores     []float64
	}{
		{
			name:           "exact match - single output",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{"malicious answer"},
			wantScores:     []float64{1.0},
		},
		{
			name:           "exact match - multiple outputs",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs: []string{
				"malicious answer",
				"safe response",
				"malicious answer appears here",
			},
			wantScores: []float64{1.0, 0.0, 1.0},
		},
		{
			name:           "no match",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{"completely safe response"},
			wantScores:     []float64{0.0},
		},
		{
			name:           "substring match",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{"This contains the malicious answer in the middle"},
			wantScores:     []float64{1.0},
		},
		{
			name:           "case insensitive match",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{"MALICIOUS ANSWER"},
			wantScores:     []float64{1.0},
		},
		{
			name:           "partial match",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{"malicious"},
			wantScores:     []float64{0.0},
		},
		{
			name:           "empty output",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{""},
			wantScores:     []float64{0.0},
		},
		{
			name:           "no outputs",
			expectedAnswer: "malicious answer",
			threshold:      0.8,
			outputs:        []string{},
			wantScores:     []float64{},
		},
		{
			name:           "multiple matches in same output",
			expectedAnswer: "poison",
			threshold:      0.8,
			outputs:        []string{"poison and more poison"},
			wantScores:     []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RAGPoisonDetector{
				expectedAnswer: tt.expectedAnswer,
				threshold:      tt.threshold,
			}

			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}

			if len(scores) != len(tt.wantScores) {
				t.Fatalf("Detect() returned %d scores, want %d", len(scores), len(tt.wantScores))
			}

			for i, score := range scores {
				if score != tt.wantScores[i] {
					t.Errorf("scores[%d] = %f, want %f (output: %q)", i, score, tt.wantScores[i], tt.outputs[i])
				}
			}
		})
	}
}

func TestRAGPoisonDetector_ContainsPoisonedAnswer(t *testing.T) {
	tests := []struct {
		name           string
		expectedAnswer string
		response       string
		want           bool
	}{
		{
			name:           "exact match",
			expectedAnswer: "malicious answer",
			response:       "malicious answer",
			want:           true,
		},
		{
			name:           "substring match",
			expectedAnswer: "malicious answer",
			response:       "This is a malicious answer to your question",
			want:           true,
		},
		{
			name:           "case insensitive",
			expectedAnswer: "malicious answer",
			response:       "MALICIOUS ANSWER",
			want:           true,
		},
		{
			name:           "mixed case",
			expectedAnswer: "Malicious Answer",
			response:       "malicious answer",
			want:           true,
		},
		{
			name:           "no match",
			expectedAnswer: "malicious answer",
			response:       "safe response",
			want:           false,
		},
		{
			name:           "partial word match",
			expectedAnswer: "malicious answer",
			response:       "malicious",
			want:           false,
		},
		{
			name:           "empty response",
			expectedAnswer: "malicious answer",
			response:       "",
			want:           false,
		},
		{
			name:           "empty expected answer",
			expectedAnswer: "",
			response:       "any response",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &RAGPoisonDetector{
				expectedAnswer: tt.expectedAnswer,
				threshold:      0.8,
			}

			got := d.ContainsPoisonedAnswer(tt.response)
			if got != tt.want {
				t.Errorf("ContainsPoisonedAnswer(%q) = %v, want %v", tt.response, got, tt.want)
			}
		})
	}
}

func TestRAGPoisonDetector_Registration(t *testing.T) {
	// Test that the detector is registered via init()
	factory, ok := detectors.Get("ragpoison.RAGPoison")
	if !ok {
		t.Fatal("ragpoison.RAGPoison not registered in detectors registry")
	}

	// Test factory creates valid detector with minimal config
	cfg := registry.Config{
		"expected_answer": "test answer",
	}
	d, err := factory(cfg)
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if d.Name() != "ragpoison.RAGPoison" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "ragpoison.RAGPoison")
	}
}

func TestNewRAGPoison(t *testing.T) {
	tests := []struct {
		name      string
		config    registry.Config
		wantErr   bool
		errContains string
	}{
		{
			name: "valid config with expected_answer",
			config: registry.Config{
				"expected_answer": "malicious answer",
				"threshold":       0.9,
			},
			wantErr: false,
		},
		{
			name: "valid config without threshold (uses default)",
			config: registry.Config{
				"expected_answer": "malicious answer",
			},
			wantErr: false,
		},
		{
			name:        "missing expected_answer",
			config:      registry.Config{},
			wantErr:     true,
			errContains: "expected_answer",
		},
		{
			name: "empty expected_answer",
			config: registry.Config{
				"expected_answer": "",
			},
			wantErr:     true,
			errContains: "expected_answer",
		},
		{
			name: "invalid threshold type",
			config: registry.Config{
				"expected_answer": "test",
				"threshold":       "not a number",
			},
			wantErr: false, // Uses default threshold
		},
		{
			name: "threshold too high",
			config: registry.Config{
				"expected_answer": "test",
				"threshold":       1.5,
			},
			wantErr: false, // Accepts any float64 value
		},
		{
			name: "threshold negative",
			config: registry.Config{
				"expected_answer": "test",
				"threshold":       -0.1,
			},
			wantErr: false, // Accepts any float64 value
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewRAGPoison(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("NewRAGPoison() error = nil, want error")
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("NewRAGPoison() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Fatalf("NewRAGPoison() error = %v, want nil", err)
			}

			if d == nil {
				t.Fatal("NewRAGPoison() returned nil detector")
			}

			if d.Name() != "ragpoison.RAGPoison" {
				t.Errorf("detector.Name() = %q, want %q", d.Name(), "ragpoison.RAGPoison")
			}
		})
	}
}

func TestRAGPoisonDetector_Detect_ScoreCountMatchesOutputCount(t *testing.T) {
	d := &RAGPoisonDetector{
		expectedAnswer: "poison",
		threshold:      0.8,
	}

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

func TestRAGPoisonDetector_Detect_WithCompleteAttempt(t *testing.T) {
	d := &RAGPoisonDetector{
		expectedAnswer: "poison",
		threshold:      0.8,
	}

	// Create a realistic attempt
	a := attempt.New("What is the capital of France?")
	a.Probe = "ragpoison.Probe"
	a.Detector = "ragpoison.RAGPoison"
	a.AddOutput("The capital is poison") // Contains poison
	a.AddOutput("Paris is the capital")  // Safe
	a.Complete()

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v, want nil", err)
	}

	if len(scores) != 2 {
		t.Fatalf("Detect() returned %d scores, want 2", len(scores))
	}

	if scores[0] != 1.0 {
		t.Errorf("scores[0] = %f, want 1.0 (contains poison)", scores[0])
	}

	if scores[1] != 0.0 {
		t.Errorf("scores[1] = %f, want 0.0 (safe)", scores[1])
	}
}

func TestRAGPoisonDetector_ContextCancellation(t *testing.T) {
	d := &RAGPoisonDetector{
		expectedAnswer: "poison",
		threshold:      0.8,
	}

	a := attempt.New("test")
	a.AddOutput("poison")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// RAGPoison detector ignores context, should still work
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() with cancelled context error = %v, want nil", err)
	}

	if len(scores) != 1 {
		t.Errorf("Detect() returned %d scores, want 1", len(scores))
	}

	if scores[0] != 1.0 {
		t.Errorf("Detect() = %f, want 1.0", scores[0])
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && containsHelper(s, substr)))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
