package base

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestStringDetector_Name(t *testing.T) {
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"test"},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
	}
	if got := d.Name(); got != "base.StringDetector" {
		t.Errorf("Name() = %q, want %q", got, "base.StringDetector")
	}
}

func TestStringDetector_Description(t *testing.T) {
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"test"},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestStringDetector_Detect_SubstringMatch(t *testing.T) {
	tests := []struct {
		name       string
		substrings []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "single match",
			substrings: []string{"hello"},
			outputs:    []string{"hello world"},
			wantScores: []float64{1.0},
		},
		{
			name:       "no match",
			substrings: []string{"hello"},
			outputs:    []string{"goodbye world"},
			wantScores: []float64{0.0},
		},
		{
			name:       "multiple outputs mixed",
			substrings: []string{"hello"},
			outputs:    []string{"hello world", "goodbye world", "say hello again"},
			wantScores: []float64{1.0, 0.0, 1.0},
		},
		{
			name:       "multiple substrings any match",
			substrings: []string{"hello", "world"},
			outputs:    []string{"just world here"},
			wantScores: []float64{1.0},
		},
		{
			name:       "empty outputs",
			substrings: []string{"hello"},
			outputs:    []string{},
			wantScores: []float64{},
		},
		{
			name:       "empty string output",
			substrings: []string{"hello"},
			outputs:    []string{""},
			wantScores: []float64{0.0},
		},
		{
			name:       "case insensitive by default",
			substrings: []string{"HELLO"},
			outputs:    []string{"hello world"},
			wantScores: []float64{1.0},
		},
		{
			name:       "substring in middle",
			substrings: []string{"needle"},
			outputs:    []string{"haystack needle haystack"},
			wantScores: []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewStringDetector(registry.Config{
				"substrings": tt.substrings,
				"matchtype":  "str",
			})
			if err != nil {
				t.Fatalf("NewStringDetector() error = %v", err)
			}

			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
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

func TestStringDetector_Detect_CaseSensitive(t *testing.T) {
	tests := []struct {
		name          string
		substrings    []string
		caseSensitive bool
		outputs       []string
		wantScores    []float64
	}{
		{
			name:          "case sensitive match",
			substrings:    []string{"Hello"},
			caseSensitive: true,
			outputs:       []string{"Hello world"},
			wantScores:    []float64{1.0},
		},
		{
			name:          "case sensitive no match",
			substrings:    []string{"Hello"},
			caseSensitive: true,
			outputs:       []string{"hello world"},
			wantScores:    []float64{0.0},
		},
		{
			name:          "case insensitive match",
			substrings:    []string{"Hello"},
			caseSensitive: false,
			outputs:       []string{"hello world"},
			wantScores:    []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewStringDetector(registry.Config{
				"substrings":     tt.substrings,
				"case_sensitive": tt.caseSensitive,
			})
			if err != nil {
				t.Fatalf("NewStringDetector() error = %v", err)
			}

			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			for i, score := range scores {
				if score != tt.wantScores[i] {
					t.Errorf("scores[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestStringDetector_Detect_WordMatch(t *testing.T) {
	tests := []struct {
		name       string
		substrings []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "word match standalone",
			substrings: []string{"hello"},
			outputs:    []string{"say hello please"},
			wantScores: []float64{1.0},
		},
		{
			name:       "word no match embedded",
			substrings: []string{"hello"},
			outputs:    []string{"helloworld"},
			wantScores: []float64{0.0},
		},
		{
			name:       "word match at start",
			substrings: []string{"hello"},
			outputs:    []string{"hello there"},
			wantScores: []float64{1.0},
		},
		{
			name:       "word match at end",
			substrings: []string{"hello"},
			outputs:    []string{"say hello"},
			wantScores: []float64{1.0},
		},
		{
			name:       "word with punctuation boundary",
			substrings: []string{"hello"},
			outputs:    []string{"hello, world!"},
			wantScores: []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewStringDetector(registry.Config{
				"substrings": tt.substrings,
				"matchtype":  "word",
			})
			if err != nil {
				t.Fatalf("NewStringDetector() error = %v", err)
			}

			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			for i, score := range scores {
				if score != tt.wantScores[i] {
					t.Errorf("scores[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestStringDetector_Detect_StartsWithMatch(t *testing.T) {
	tests := []struct {
		name       string
		substrings []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "startswith match",
			substrings: []string{"hello"},
			outputs:    []string{"hello world"},
			wantScores: []float64{1.0},
		},
		{
			name:       "startswith no match - in middle",
			substrings: []string{"hello"},
			outputs:    []string{"say hello"},
			wantScores: []float64{0.0},
		},
		{
			name:       "startswith case insensitive",
			substrings: []string{"HELLO"},
			outputs:    []string{"hello world"},
			wantScores: []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewStringDetector(registry.Config{
				"substrings": tt.substrings,
				"matchtype":  "startswith",
			})
			if err != nil {
				t.Fatalf("NewStringDetector() error = %v", err)
			}

			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			for i, score := range scores {
				if score != tt.wantScores[i] {
					t.Errorf("scores[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestStringDetector_Detect_InvalidMatchtype(t *testing.T) {
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"test"},
		"matchtype":  "invalid",
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("test output")

	_, err = d.Detect(context.Background(), a)
	if err == nil {
		t.Error("Detect() with invalid matchtype should return error")
	}
}

func TestStringDetector_Registration(t *testing.T) {
	// Test that the detector is registered via init()
	factory, ok := detectors.Get("base.StringDetector")
	if !ok {
		t.Fatal("base.StringDetector not registered in detectors registry")
	}

	// Test factory creates valid detector with substrings config
	d, err := factory(registry.Config{
		"substrings": []string{"test"},
	})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if d.Name() != "base.StringDetector" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "base.StringDetector")
	}
}

func TestNewStringDetector_RequiresSubstrings(t *testing.T) {
	// Missing substrings should error
	_, err := NewStringDetector(registry.Config{})
	if err == nil {
		t.Error("NewStringDetector() without substrings should return error")
	}

	// Empty substrings should work (matches nothing)
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() with empty substrings error = %v", err)
	}

	a := attempt.New("test")
	a.AddOutput("any output")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if scores[0] != 0.0 {
		t.Errorf("Detect() with no substrings = %f, want 0.0", scores[0])
	}
}

func TestNewStringDetector_SubstringsFromConfig(t *testing.T) {
	tests := []struct {
		name       string
		config     registry.Config
		wantError  bool
	}{
		{
			name: "slice of strings",
			config: registry.Config{
				"substrings": []string{"a", "b"},
			},
			wantError: false,
		},
		{
			name: "slice of any (strings)",
			config: registry.Config{
				"substrings": []any{"a", "b"},
			},
			wantError: false,
		},
		{
			name: "invalid type",
			config: registry.Config{
				"substrings": "not a slice",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewStringDetector(tt.config)
			if tt.wantError && err == nil {
				t.Error("NewStringDetector() should have returned error")
			}
			if !tt.wantError && err != nil {
				t.Errorf("NewStringDetector() error = %v, want nil", err)
			}
		})
	}
}

func TestStringDetector_DefaultMatchtype(t *testing.T) {
	// When matchtype is not specified, should default to "str"
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"hello"},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
	}

	a := attempt.New("test")
	a.AddOutput("helloworld") // embedded substring

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// With "str" matchtype, "hello" should match inside "helloworld"
	if scores[0] != 1.0 {
		t.Errorf("Detect() with default matchtype = %f, want 1.0 (substring match)", scores[0])
	}
}

func TestStringDetector_ContextCancellation(t *testing.T) {
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"test"},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
	}

	a := attempt.New("test")
	a.AddOutput("test output")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// StringDetector ignores context (no I/O), should still work
	scores, err := d.Detect(ctx, a)
	if err != nil {
		t.Fatalf("Detect() with cancelled context error = %v", err)
	}
	if len(scores) != 1 {
		t.Errorf("Detect() returned %d scores, want 1", len(scores))
	}
	if scores[0] != 1.0 {
		t.Errorf("Detect() = %f, want 1.0", scores[0])
	}
}

func TestStringDetector_Detect_ScoreCountMatchesOutputCount(t *testing.T) {
	d, err := NewStringDetector(registry.Config{
		"substrings": []string{"test"},
	})
	if err != nil {
		t.Fatalf("NewStringDetector() error = %v", err)
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
