package badchars

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewBidi(t *testing.T) {
	// Test probe creation
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	if p == nil {
		t.Fatal("NewBidi() returned nil probe")
	}

	// Verify it implements Prober interface
	var _ probes.Prober = p
}

func TestBidi_Name(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	name := p.Name()
	expected := "badchars.Bidi"
	if name != expected {
		t.Errorf("Name() = %q, want %q", name, expected)
	}
}

func TestBidi_Description(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	desc := p.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}

	// Should mention bidi or reordering
	lowerDesc := strings.ToLower(desc)
	if !strings.Contains(lowerDesc, "bidi") && !strings.Contains(lowerDesc, "reorder") {
		t.Errorf("Description() = %q, should mention 'bidi' or 'reorder'", desc)
	}
}

func TestBidi_Goal(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	goal := p.Goal()
	if goal == "" {
		t.Error("Goal() returned empty string")
	}

	// Should mention perturbation or bypass
	lowerGoal := strings.ToLower(goal)
	if !strings.Contains(lowerGoal, "perturbation") && !strings.Contains(lowerGoal, "bypass") {
		t.Errorf("Goal() = %q, should mention 'perturbation' or 'bypass'", goal)
	}
}

func TestBidi_GetPrimaryDetector(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	detector := p.GetPrimaryDetector()
	// Should use a detector for approximate decoding
	if detector == "" {
		t.Error("GetPrimaryDetector() returned empty string")
	}
}

func TestBidi_GetPrompts(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	prompts := p.GetPrompts()
	if len(prompts) == 0 {
		t.Error("GetPrompts() returned empty slice")
	}

	// Each prompt should contain at least one bidi control character
	bidiControls := []string{
		"\u202c", // PDF
		"\u202d", // LRO
		"\u202e", // RLO
		"\u2066", // LRI
		"\u2067", // RLI
		"\u2069", // PDI
	}

	for i, prompt := range prompts {
		hasBidi := false
		for _, control := range bidiControls {
			if strings.Contains(prompt, control) {
				hasBidi = true
				break
			}
		}
		if !hasBidi {
			t.Errorf("Prompt %d does not contain any bidi control characters: %q", i, prompt)
		}
	}
}

func TestBidi_Probe(t *testing.T) {
	p, err := NewBidi(registry.Config{})
	if err != nil {
		t.Fatalf("NewBidi() error = %v", err)
	}

	gen := testutil.NewMockGenerator("I'm a helpful assistant.")

	attempts, err := p.Probe(context.Background(), gen)
	if err != nil {
		t.Fatalf("Probe() error = %v", err)
	}

	if len(attempts) == 0 {
		t.Fatal("Probe() returned no attempts")
	}

	// Verify each attempt has expected fields
	for i, a := range attempts {
		if a.Prompt == "" {
			t.Errorf("Attempt %d has empty prompt", i)
		}

		if a.Probe != "badchars.Bidi" {
			t.Errorf("Attempt %d probe = %q, want %q", i, a.Probe, "badchars.Bidi")
		}

		if len(a.Outputs) == 0 {
			t.Errorf("Attempt %d has no outputs", i)
		}

		if a.Status != "complete" {
			t.Errorf("Attempt %d status = %q, want %q", i, a.Status, "complete")
		}
	}

	// Verify generator was called for each prompt
	expectedCalls := len(p.GetPrompts())
	if gen.Calls != expectedCalls {
		t.Errorf("Generator called %d times, expected %d", gen.Calls, expectedCalls)
	}
}

func TestRenderSwap(t *testing.T) {
	tests := []struct {
		name   string
		first  string
		second string
		want   []string // Substrings that should be present
	}{
		{
			name:   "simple ASCII swap",
			first:  "a",
			second: "b",
			want: []string{
				"\u202d", // LRO
				"\u202e", // RLO
				"\u2066", // LRI
				"\u2069", // PDI
				"\u202c", // PDF
			},
		},
		{
			name:   "multi-char swap",
			first:  "ab",
			second: "cd",
			want: []string{
				"\u202d", // LRO
				"\u202e", // RLO
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := renderSwap(tt.first, tt.second)

			// Verify result contains the characters
			if !strings.Contains(result, tt.first) {
				t.Errorf("renderSwap() result does not contain first char %q", tt.first)
			}
			if !strings.Contains(result, tt.second) {
				t.Errorf("renderSwap() result does not contain second char %q", tt.second)
			}

			// Verify result contains expected bidi controls
			for _, control := range tt.want {
				if !strings.Contains(result, control) {
					t.Errorf("renderSwap() result does not contain expected control %q (U+%04X)", control, []rune(control)[0])
				}
			}
		})
	}
}

func TestBidiRegistration(t *testing.T) {
	// Verify probe is registered
	factory, ok := probes.Get("badchars.Bidi")
	if !ok {
		t.Fatal("badchars.Bidi not registered")
	}

	// Verify factory works
	p, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("Factory function error = %v", err)
	}

	if p.Name() != "badchars.Bidi" {
		t.Errorf("Factory returned probe with name %q, want %q", p.Name(), "badchars.Bidi")
	}
}

func TestApplySwaps(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		indices []int
		wantLen int // Expected that result has more chars than input (due to bidi controls)
	}{
		{
			name:    "single swap at start",
			payload: "abcd",
			indices: []int{0},
			wantLen: 10, // Much longer due to bidi controls
		},
		{
			name:    "single swap at end",
			payload: "abcd",
			indices: []int{2},
			wantLen: 10,
		},
		{
			name:    "multiple non-overlapping swaps",
			payload: "abcdef",
			indices: []int{0, 3},
			wantLen: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applySwaps(tt.payload, tt.indices)

			if len(result) < tt.wantLen {
				t.Errorf("applySwaps() result length = %d, want >= %d", len(result), tt.wantLen)
			}

			// Result should contain bidi controls
			hasBidi := false
			bidiControls := []string{"\u202c", "\u202d", "\u202e", "\u2066", "\u2067", "\u2069"}
			for _, control := range bidiControls {
				if strings.Contains(result, control) {
					hasBidi = true
					break
				}
			}
			if !hasBidi {
				t.Error("applySwaps() result does not contain any bidi controls")
			}
		})
	}
}
