package patterns

import (
	"context"
	"regexp"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestPatternsDetector_Name(t *testing.T) {
	d := &PatternsDetector{}
	if got := d.Name(); got != "patterns.Patterns" {
		t.Errorf("Name() = %q, want %q", got, "patterns.Patterns")
	}
}

func TestPatternsDetector_Description(t *testing.T) {
	d := &PatternsDetector{}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestPatternsDetector_Detect_NoPatterns(t *testing.T) {
	// Test with no patterns - should return 0.0 for all outputs
	d := &PatternsDetector{
		patterns: []Pattern{},
		mode:     ModeAny,
	}

	a := attempt.New("test prompt")
	a.AddOutput("some output")
	a.AddOutput("another output")

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

func TestPatternsDetector_Detect_SingleRegexPattern_ModeAny(t *testing.T) {
	tests := []struct {
		name       string
		pattern    string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "match in first output",
			pattern:    "password",
			outputs:    []string{"my password is secret", "normal output"},
			wantScores: []float64{1.0, 0.0},
		},
		{
			name:       "match in second output",
			pattern:    "password",
			outputs:    []string{"normal output", "my password is secret"},
			wantScores: []float64{0.0, 1.0},
		},
		{
			name:       "match in all outputs",
			pattern:    "password",
			outputs:    []string{"password here", "password there"},
			wantScores: []float64{1.0, 1.0},
		},
		{
			name:       "no match in any output",
			pattern:    "password",
			outputs:    []string{"safe output", "another safe output"},
			wantScores: []float64{0.0, 0.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &PatternsDetector{
				patterns: []Pattern{
					{
						Name:     "password_pattern",
						Regex:    regexp.MustCompile(tt.pattern),
						Severity: 1.0,
					},
				},
				mode:      ModeAny,
				threshold: 0.5,
			}

			a := attempt.New("test")
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
					t.Errorf("scores[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestPatternsDetector_Detect_MultiplePatterns_ModeAny(t *testing.T) {
	// ModeAny: If ANY pattern matches, return severity score
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "password",
				Regex:    regexp.MustCompile("password"),
				Severity: 1.0,
			},
			{
				Name:     "secret",
				Regex:    regexp.MustCompile("secret"),
				Severity: 0.8,
			},
			{
				Name:     "token",
				Regex:    regexp.MustCompile("token"),
				Severity: 0.6,
			},
		},
		mode:      ModeAny,
		threshold: 0.5,
	}

	tests := []struct {
		name      string
		output    string
		wantScore float64
	}{
		{
			name:      "matches highest severity pattern",
			output:    "my password is here",
			wantScore: 1.0,
		},
		{
			name:      "matches medium severity pattern",
			output:    "the secret key",
			wantScore: 0.8,
		},
		{
			name:      "matches lowest severity pattern",
			output:    "bearer token",
			wantScore: 0.6,
		},
		{
			name:      "matches multiple patterns - returns highest",
			output:    "password and secret and token",
			wantScore: 1.0,
		},
		{
			name:      "no matches",
			output:    "safe content",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			if scores[0] != tt.wantScore {
				t.Errorf("Detect() score = %f, want %f", scores[0], tt.wantScore)
			}
		})
	}
}

func TestPatternsDetector_Detect_MultiplePatterns_ModeAll(t *testing.T) {
	// ModeAll: ALL patterns must match for positive detection
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "password",
				Regex:    regexp.MustCompile("password"),
				Severity: 1.0,
			},
			{
				Name:     "secret",
				Regex:    regexp.MustCompile("secret"),
				Severity: 1.0,
			},
		},
		mode:      ModeAll,
		threshold: 0.5,
	}

	tests := []struct {
		name      string
		output    string
		wantScore float64
	}{
		{
			name:      "matches all patterns",
			output:    "password and secret",
			wantScore: 1.0,
		},
		{
			name:      "matches only first pattern",
			output:    "password only",
			wantScore: 0.0,
		},
		{
			name:      "matches only second pattern",
			output:    "secret only",
			wantScore: 0.0,
		},
		{
			name:      "matches no patterns",
			output:    "safe content",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			if scores[0] != tt.wantScore {
				t.Errorf("Detect() score = %f, want %f", scores[0], tt.wantScore)
			}
		})
	}
}

func TestPatternsDetector_Detect_MultiplePatterns_ModeWeighted(t *testing.T) {
	// ModeWeighted: Average severity of all matching patterns
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "password",
				Regex:    regexp.MustCompile("password"),
				Severity: 1.0,
			},
			{
				Name:     "secret",
				Regex:    regexp.MustCompile("secret"),
				Severity: 0.6,
			},
			{
				Name:     "token",
				Regex:    regexp.MustCompile("token"),
				Severity: 0.8,
			},
		},
		mode:      ModeWeighted,
		threshold: 0.5,
	}

	tests := []struct {
		name      string
		output    string
		wantScore float64
	}{
		{
			name:      "matches one pattern",
			output:    "password only",
			wantScore: 1.0,
		},
		{
			name:      "matches two patterns - average",
			output:    "password and secret",
			wantScore: 0.8, // (1.0 + 0.6) / 2
		},
		{
			name:      "matches all three patterns - average",
			output:    "password secret token",
			wantScore: 0.8, // (1.0 + 0.6 + 0.8) / 3
		},
		{
			name:      "no matches",
			output:    "safe content",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v, want nil", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			// Allow small floating point differences
			if diff := abs(scores[0] - tt.wantScore); diff > 0.01 {
				t.Errorf("Detect() score = %f, want %f (diff: %f)", scores[0], tt.wantScore, diff)
			}
		})
	}
}

func TestPatternsDetector_Detect_ScoreCountMatchesOutputCount(t *testing.T) {
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "test",
				Regex:    regexp.MustCompile("test"),
				Severity: 1.0,
			},
		},
		mode: ModeAny,
	}

	// Test various output counts
	for numOutputs := 0; numOutputs <= 5; numOutputs++ {
		t.Run("outputs="+string(rune(numOutputs+'0')), func(t *testing.T) {
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
		})
	}
}

func TestPatternsDetector_Registration(t *testing.T) {
	// Test that the detector is registered via init()
	factory, ok := detectors.Get("patterns.Patterns")
	if !ok {
		t.Fatal("patterns.Patterns not registered in detectors registry")
	}

	// Test factory creates valid detector
	cfg := registry.Config{
		"patterns": []map[string]any{
			{
				"name":     "test",
				"regex":    "test",
				"severity": 1.0,
			},
		},
		"mode": "any",
	}

	d, err := factory(cfg)
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if d.Name() != "patterns.Patterns" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "patterns.Patterns")
	}
}

func TestNewPatterns_WithConfig(t *testing.T) {
	tests := []struct {
		name      string
		config    registry.Config
		wantError bool
	}{
		{
			name: "valid config with patterns",
			config: registry.Config{
				"patterns": []map[string]any{
					{
						"name":     "password",
						"regex":    "password",
						"severity": 1.0,
					},
					{
						"name":     "secret",
						"regex":    "secret",
						"severity": 0.8,
					},
				},
				"mode":      "any",
				"threshold": 0.5,
			},
			wantError: false,
		},
		{
			name: "valid config with mode all",
			config: registry.Config{
				"patterns": []map[string]any{
					{
						"name":  "test",
						"regex": "test",
					},
				},
				"mode": "all",
			},
			wantError: false,
		},
		{
			name: "valid config with mode weighted",
			config: registry.Config{
				"patterns": []map[string]any{
					{
						"name":  "test",
						"regex": "test",
					},
				},
				"mode": "weighted",
			},
			wantError: false,
		},
		{
			name:      "empty config - should use defaults",
			config:    registry.Config{},
			wantError: false,
		},
		{
			name: "invalid regex pattern",
			config: registry.Config{
				"patterns": []map[string]any{
					{
						"name":  "bad",
						"regex": "[invalid(regex",
					},
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewPatterns(tt.config)

			if tt.wantError {
				if err == nil {
					t.Fatalf("NewPatterns() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("NewPatterns() error = %v, want nil", err)
			}

			if d == nil {
				t.Fatal("NewPatterns() returned nil detector")
			}

			if d.Name() != "patterns.Patterns" {
				t.Errorf("detector.Name() = %q, want %q", d.Name(), "patterns.Patterns")
			}
		})
	}
}

func TestPatternsDetector_CaseInsensitive(t *testing.T) {
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "password",
				Regex:    regexp.MustCompile("(?i)password"), // Case insensitive
				Severity: 1.0,
			},
		},
		mode: ModeAny,
	}

	tests := []struct {
		output    string
		wantScore float64
	}{
		{"password", 1.0},
		{"PASSWORD", 1.0},
		{"PaSsWoRd", 1.0},
		{"safe", 0.0},
	}

	for _, tt := range tests {
		a := attempt.New("test")
		a.AddOutput(tt.output)

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() error = %v, want nil", err)
		}

		if scores[0] != tt.wantScore {
			t.Errorf("Detect(%q) = %f, want %f", tt.output, scores[0], tt.wantScore)
		}
	}
}

func TestPatternsDetector_ContextCancellation(t *testing.T) {
	d := &PatternsDetector{
		patterns: []Pattern{
			{
				Name:     "test",
				Regex:    regexp.MustCompile("test"),
				Severity: 1.0,
			},
		},
		mode: ModeAny,
	}

	a := attempt.New("test")
	a.AddOutput("test output")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should still work (doesn't do async work that respects context)
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() with cancelled context error = %v, want nil", err)
	}

	if len(scores) != 1 {
		t.Errorf("Detect() returned %d scores, want 1", len(scores))
	}
}

// Helper function for floating point comparison
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
