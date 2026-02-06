package any

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestAnyOutput tests the AnyOutput detector
func TestAnyOutput(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantScore float64
	}{
		{
			name:      "detects non-empty output",
			output:    "Hello world",
			wantScore: 1.0,
		},
		{
			name:      "detects single character",
			output:    "x",
			wantScore: 1.0,
		},
		{
			name:      "detects whitespace only",
			output:    "   ",
			wantScore: 1.0,
		},
		{
			name:      "detects newline only",
			output:    "\n",
			wantScore: 1.0,
		},
		{
			name:      "no detection for empty string",
			output:    "",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewAnyOutput(registry.Config{})
			if err != nil {
				t.Fatalf("NewAnyOutput() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			if scores[0] != tt.wantScore {
				t.Errorf("Detect() = %f, want %f", scores[0], tt.wantScore)
			}
		})
	}
}

func TestAnyOutput_MultipleOutputs(t *testing.T) {
	d, err := NewAnyOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyOutput() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("Hello")
	a.AddOutput("")
	a.AddOutput("World")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 3 {
		t.Fatalf("Detect() returned %d scores, want 3", len(scores))
	}

	want := []float64{1.0, 0.0, 1.0}
	for i, wantScore := range want {
		if scores[i] != wantScore {
			t.Errorf("Detect() scores[%d] = %f, want %f", i, scores[i], wantScore)
		}
	}
}

func TestAnyOutput_Name(t *testing.T) {
	d, err := NewAnyOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyOutput() error = %v", err)
	}
	if got := d.Name(); got != "any.AnyOutput" {
		t.Errorf("Name() = %q, want %q", got, "any.AnyOutput")
	}
}

func TestAnyOutput_Description(t *testing.T) {
	d, err := NewAnyOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyOutput() error = %v", err)
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestAnyOutput_Registration(t *testing.T) {
	factory, ok := detectors.Get("any.AnyOutput")
	if !ok {
		t.Fatal("any.AnyOutput not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "any.AnyOutput" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "any.AnyOutput")
	}
}

// TestAnyNonspaceOutput tests the AnyNonspaceOutput detector
func TestAnyNonspaceOutput(t *testing.T) {
	tests := []struct {
		name      string
		output    string
		wantScore float64
	}{
		{
			name:      "detects non-empty output",
			output:    "Hello world",
			wantScore: 1.0,
		},
		{
			name:      "detects single character",
			output:    "x",
			wantScore: 1.0,
		},
		{
			name:      "detects output with leading/trailing whitespace",
			output:    "  hello  ",
			wantScore: 1.0,
		},
		{
			name:      "no detection for whitespace only",
			output:    "   ",
			wantScore: 0.0,
		},
		{
			name:      "no detection for newline only",
			output:    "\n",
			wantScore: 0.0,
		},
		{
			name:      "no detection for tabs only",
			output:    "\t\t",
			wantScore: 0.0,
		},
		{
			name:      "no detection for empty string",
			output:    "",
			wantScore: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewAnyNonspaceOutput(registry.Config{})
			if err != nil {
				t.Fatalf("NewAnyNonspaceOutput() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}

			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}

			if scores[0] != tt.wantScore {
				t.Errorf("Detect() = %f, want %f", scores[0], tt.wantScore)
			}
		})
	}
}

func TestAnyNonspaceOutput_MultipleOutputs(t *testing.T) {
	d, err := NewAnyNonspaceOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyNonspaceOutput() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("Hello")
	a.AddOutput("   ")
	a.AddOutput("World")
	a.AddOutput("")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 4 {
		t.Fatalf("Detect() returned %d scores, want 4", len(scores))
	}

	want := []float64{1.0, 0.0, 1.0, 0.0}
	for i, wantScore := range want {
		if scores[i] != wantScore {
			t.Errorf("Detect() scores[%d] = %f, want %f", i, scores[i], wantScore)
		}
	}
}

func TestAnyNonspaceOutput_Name(t *testing.T) {
	d, err := NewAnyNonspaceOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyNonspaceOutput() error = %v", err)
	}
	if got := d.Name(); got != "any.AnyNonspaceOutput" {
		t.Errorf("Name() = %q, want %q", got, "any.AnyNonspaceOutput")
	}
}

func TestAnyNonspaceOutput_Description(t *testing.T) {
	d, err := NewAnyNonspaceOutput(registry.Config{})
	if err != nil {
		t.Fatalf("NewAnyNonspaceOutput() error = %v", err)
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestAnyNonspaceOutput_Registration(t *testing.T) {
	factory, ok := detectors.Get("any.AnyNonspaceOutput")
	if !ok {
		t.Fatal("any.AnyNonspaceOutput not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "any.AnyNonspaceOutput" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "any.AnyNonspaceOutput")
	}
}

// TestAllDetectorsRegistered verifies both detectors are registered
func TestAllDetectorsRegistered(t *testing.T) {
	expectedDetectors := []string{
		"any.AnyOutput",
		"any.AnyNonspaceOutput",
	}

	for _, name := range expectedDetectors {
		t.Run(name, func(t *testing.T) {
			factory, ok := detectors.Get(name)
			if !ok {
				t.Fatalf("%s not registered in detectors registry", name)
			}

			// Verify factory creates valid detector
			d, err := factory(registry.Config{})
			if err != nil {
				t.Fatalf("factory() error = %v", err)
			}

			if d.Name() != name {
				t.Errorf("factory created detector with name %q, want %q", d.Name(), name)
			}
		})
	}
}
