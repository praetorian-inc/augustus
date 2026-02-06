package promptinject

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestAttackRogueString tests the AttackRogueString detector
func TestAttackRogueString(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "detects single trigger in output",
			triggers:   []string{"TRIGGER_STRING"},
			outputs:    []string{"Hello TRIGGER_STRING world"},
			wantScores: []float64{1.0},
		},
		{
			name:       "case insensitive by default",
			triggers:   []string{"TRIGGER"},
			outputs:    []string{"output with trigger in lowercase"},
			wantScores: []float64{1.0},
		},
		{
			name:       "no trigger match returns 0.0",
			triggers:   []string{"TRIGGER"},
			outputs:    []string{"normal output without match"},
			wantScores: []float64{0.0},
		},
		{
			name:       "multiple triggers, any match returns 1.0",
			triggers:   []string{"ALPHA", "BETA", "GAMMA"},
			outputs:    []string{"output contains BETA trigger"},
			wantScores: []float64{1.0},
		},
		{
			name:       "multiple outputs, mixed results",
			triggers:   []string{"SECRET"},
			outputs:    []string{"no match", "has SECRET here", "also no match"},
			wantScores: []float64{0.0, 1.0, 0.0},
		},
		{
			name:       "empty triggers returns empty results",
			triggers:   []string{},
			outputs:    []string{"any output"},
			wantScores: []float64{},
		},
		{
			name:       "empty output string still scored",
			triggers:   []string{"TRIGGER"},
			outputs:    []string{""},
			wantScores: []float64{0.0},
		},
		{
			name:       "trigger at start of output",
			triggers:   []string{"START"},
			outputs:    []string{"START of the output"},
			wantScores: []float64{1.0},
		},
		{
			name:       "trigger at end of output",
			triggers:   []string{"END"},
			outputs:    []string{"output at the END"},
			wantScores: []float64{1.0},
		},
		{
			name:       "partial trigger match succeeds (substring)",
			triggers:   []string{"inject"},
			outputs:    []string{"this is an injection attack"},
			wantScores: []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewAttackRogueString(registry.Config{})
			if err != nil {
				t.Fatalf("NewAttackRogueString() error = %v", err)
			}

			a := attempt.New("test prompt")
			// Set triggers in metadata
			a.Metadata["triggers"] = tt.triggers
			// Add outputs
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
					t.Errorf("Detect() score[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

// TestAttackRogueString_NoTriggersInMetadata tests behavior when triggers key is missing
func TestAttackRogueString_NoTriggersInMetadata(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}

	a := attempt.New("test prompt")
	// Don't set triggers in metadata at all
	a.AddOutput("some output")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should return empty results when no triggers defined
	if len(scores) != 0 {
		t.Errorf("Detect() returned %d scores, want 0 (empty)", len(scores))
	}
}

// TestAttackRogueString_InvalidTriggersType tests handling of invalid triggers type
func TestAttackRogueString_InvalidTriggersType(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}

	a := attempt.New("test prompt")
	// Set triggers to truly invalid type (not string, []string, or []any)
	a.Metadata["triggers"] = 123
	a.AddOutput("some output")

	_, err = d.Detect(context.Background(), a)
	if err == nil {
		t.Errorf("Detect() expected error for invalid triggers type, got nil")
	}
}

// TestAttackRogueString_SingleStringTrigger tests handling of single string trigger
func TestAttackRogueString_SingleStringTrigger(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}

	a := attempt.New("test prompt")
	// Set triggers to a single string (now supported)
	a.Metadata["triggers"] = "some output"
	a.AddOutput("some output")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	// Should detect the single string trigger
	if len(scores) != 1 {
		t.Errorf("Detect() returned %d scores, want 1", len(scores))
	}
	if len(scores) > 0 && scores[0] != 1.0 {
		t.Errorf("Detect() scores[0] = %v, want 1.0", scores[0])
	}
}

// TestAttackRogueString_TriggersAsAnySlice tests handling of []any (from JSON unmarshaling)
func TestAttackRogueString_TriggersAsAnySlice(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}

	a := attempt.New("test prompt")
	// Set triggers as []any (common from JSON)
	a.Metadata["triggers"] = []any{"ALPHA", "BETA"}
	a.AddOutput("output with BETA present")

	scores, err := d.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect() error = %v", err)
	}

	if len(scores) != 1 {
		t.Fatalf("Detect() returned %d scores, want 1", len(scores))
	}

	if scores[0] != 1.0 {
		t.Errorf("Detect() = %f, want 1.0", scores[0])
	}
}

func TestAttackRogueString_Name(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}
	if got := d.Name(); got != "promptinject.AttackRogueString" {
		t.Errorf("Name() = %q, want %q", got, "promptinject.AttackRogueString")
	}
}

func TestAttackRogueString_Description(t *testing.T) {
	d, err := NewAttackRogueString(registry.Config{})
	if err != nil {
		t.Fatalf("NewAttackRogueString() error = %v", err)
	}
	desc := d.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestAttackRogueString_Registration(t *testing.T) {
	factory, ok := detectors.Get("promptinject.AttackRogueString")
	if !ok {
		t.Fatal("promptinject.AttackRogueString not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "promptinject.AttackRogueString" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "promptinject.AttackRogueString")
	}
}

// TestDirectInjection tests the DirectInjection detector
func TestDirectInjection(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "detects direct injection trigger",
			triggers:   []string{"DIRECT_INJECT"},
			outputs:    []string{"Output with DIRECT_INJECT pattern"},
			wantScores: []float64{1.0},
		},
		{
			name:       "case insensitive by default",
			triggers:   []string{"OVERRIDE"},
			outputs:    []string{"system override detected"},
			wantScores: []float64{1.0},
		},
		{
			name:       "no trigger match returns 0.0",
			triggers:   []string{"INJECT"},
			outputs:    []string{"normal safe output"},
			wantScores: []float64{0.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewDirectInjection(registry.Config{})
			if err != nil {
				t.Fatalf("NewDirectInjection() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.Metadata["triggers"] = tt.triggers
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
					t.Errorf("Detect() score[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestDirectInjection_Registration(t *testing.T) {
	factory, ok := detectors.Get("promptinjection.DirectInjection")
	if !ok {
		t.Fatal("promptinjection.DirectInjection not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "promptinjection.DirectInjection" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "promptinjection.DirectInjection")
	}
}

// TestContextManipulation tests the ContextManipulation detector
func TestContextManipulation(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "detects context manipulation trigger",
			triggers:   []string{"CONTEXT_INJECT"},
			outputs:    []string{"Previous conversation with CONTEXT_INJECT"},
			wantScores: []float64{1.0},
		},
		{
			name:       "case insensitive by default",
			triggers:   []string{"PREVIOUS"},
			outputs:    []string{"based on previous discussion"},
			wantScores: []float64{1.0},
		},
		{
			name:       "no trigger match returns 0.0",
			triggers:   []string{"CONTEXT"},
			outputs:    []string{"unrelated output"},
			wantScores: []float64{0.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewContextManipulation(registry.Config{})
			if err != nil {
				t.Fatalf("NewContextManipulation() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.Metadata["triggers"] = tt.triggers
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
					t.Errorf("Detect() score[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestContextManipulation_Registration(t *testing.T) {
	factory, ok := detectors.Get("promptinjection.ContextManipulation")
	if !ok {
		t.Fatal("promptinjection.ContextManipulation not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "promptinjection.ContextManipulation" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "promptinjection.ContextManipulation")
	}
}

// TestRoleManipulation tests the RoleManipulation detector
func TestRoleManipulation(t *testing.T) {
	tests := []struct {
		name       string
		triggers   []string
		outputs    []string
		wantScores []float64
	}{
		{
			name:       "detects role manipulation trigger",
			triggers:   []string{"ROLE_CHANGE"},
			outputs:    []string{"Assuming ROLE_CHANGE for testing"},
			wantScores: []float64{1.0},
		},
		{
			name:       "case insensitive by default",
			triggers:   []string{"ROLE"},
			outputs:    []string{"you are now in role mode"},
			wantScores: []float64{1.0},
		},
		{
			name:       "no trigger match returns 0.0",
			triggers:   []string{"IDENTITY"},
			outputs:    []string{"normal response"},
			wantScores: []float64{0.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := NewRoleManipulation(registry.Config{})
			if err != nil {
				t.Fatalf("NewRoleManipulation() error = %v", err)
			}

			a := attempt.New("test prompt")
			a.Metadata["triggers"] = tt.triggers
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
					t.Errorf("Detect() score[%d] = %f, want %f", i, score, tt.wantScores[i])
				}
			}
		})
	}
}

func TestRoleManipulation_Registration(t *testing.T) {
	factory, ok := detectors.Get("promptinjection.RoleManipulation")
	if !ok {
		t.Fatal("promptinjection.RoleManipulation not registered")
	}

	d, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v", err)
	}

	if d.Name() != "promptinjection.RoleManipulation" {
		t.Errorf("factory created detector with name %q, want %q", d.Name(), "promptinjection.RoleManipulation")
	}
}
