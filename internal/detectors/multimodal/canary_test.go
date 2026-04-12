package multimodal

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewCanary_CreatesDetector(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v, want nil", err)
	}
	if d == nil {
		t.Fatal("NewCanary() returned nil detector")
	}
}

func TestCanary_Name(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}
	if got := d.Name(); got != "multimodal.Canary" {
		t.Errorf("Name() = %q, want %q", got, "multimodal.Canary")
	}
}

func TestCanary_Description(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestCanary_Detect_PositiveMatch(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}

	tests := []struct {
		name   string
		output string
	}{
		{"instruction image canary 1", "The answer is AUGUSTUS_CANARY_7f3a"},
		{"instruction image canary 2", "AUGUSTUS_CANARY_9k2m was detected"},
		{"overlay canary", "response contains AUGUSTUS_CANARY_v2q7 here"},
		{"invisible text canary", "AUGUSTUS_CANARY_p3r9"},
		{"scaling canary", "I see AUGUSTUS_CANARY_nn01"},
		{"stego canary", "AUGUSTUS_CANARY_lsb1 found"},
		{"metadata canary", "AUGUSTUS_CANARY_meta1 present"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test prompt")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}
			if scores[0] != 1.0 {
				t.Errorf("Detect() = %f, want 1.0 for output %q", scores[0], tt.output)
			}
		})
	}
}

func TestCanary_Detect_NegativeMatch(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}

	tests := []struct {
		name   string
		output string
	}{
		{"empty output", ""},
		{"unrelated text", "This is a normal response with no canary."},
		{"partial canary prefix", "AUGUSTUS_CANARY_ but no suffix"},
		{"wrong canary", "AUGUSTUS_CANARY_xxxx not in list"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test prompt")
			a.AddOutput(tt.output)

			scores, err := d.Detect(context.Background(), a)
			if err != nil {
				t.Fatalf("Detect() error = %v", err)
			}
			if len(scores) != 1 {
				t.Fatalf("Detect() returned %d scores, want 1", len(scores))
			}
			if scores[0] != 0.0 {
				t.Errorf("Detect() = %f, want 0.0 for output %q", scores[0], tt.output)
			}
		})
	}
}

func TestCanary_Detect_CaseInsensitive(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}

	// Canaries should match case-insensitively
	outputs := []string{
		"augustus_canary_7f3a",      // all lowercase
		"Augustus_Canary_7f3a",      // mixed case
		"AUGUSTUS_CANARY_7F3A",      // uppercase variant (with uppercase hex)
	}

	for _, output := range outputs {
		a := attempt.New("test prompt")
		a.AddOutput(output)

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() error = %v", err)
		}
		if scores[0] != 1.0 {
			t.Errorf("Detect() = %f, want 1.0 for case variant %q", scores[0], output)
		}
	}
}

func TestCanary_Detect_MultipleOutputs(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}

	a := attempt.New("test prompt")
	a.AddOutput("normal output with no canary")
	a.AddOutput("output with AUGUSTUS_CANARY_4x8n embedded")
	a.AddOutput("another normal output")
	a.AddOutput("AUGUSTUS_CANARY_lsb1")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}
	if len(scores) != 4 {
		t.Fatalf("Detect() returned %d scores, want 4", len(scores))
	}

	want := []float64{0.0, 1.0, 0.0, 1.0}
	for i, score := range scores {
		if score != want[i] {
			t.Errorf("scores[%d] = %f, want %f", i, score, want[i])
		}
	}
}

func TestCanary_Detect_AllCanaries(t *testing.T) {
	d, err := NewCanary(nil)
	if err != nil {
		t.Fatalf("NewCanary() error = %v", err)
	}

	// Every canary in AllCanaries should be detected
	for _, canary := range AllCanaries {
		a := attempt.New("test prompt")
		a.AddOutput("Some text " + canary + " more text")

		scores, err := d.Detect(context.Background(), a)
		if err != nil {
			t.Fatalf("Detect() error = %v for canary %q", err, canary)
		}
		if scores[0] != 1.0 {
			t.Errorf("Detect() = %f, want 1.0 for canary %q", scores[0], canary)
		}
	}
}

func TestCanary_Registration(t *testing.T) {
	factory, ok := detectors.Get("multimodal.Canary")
	if !ok {
		t.Fatal("multimodal.Canary not registered in detectors registry")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}
	if d.Name() != "multimodal.Canary" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "multimodal.Canary")
	}
}
