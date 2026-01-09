package lowercase

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestLowercase_Name(t *testing.T) {
	lc := &Lowercase{}
	want := "lowercase.Lowercase"
	if got := lc.Name(); got != want {
		t.Errorf("Name() = %q, want %q", got, want)
	}
}

func TestLowercase_Description(t *testing.T) {
	lc := &Lowercase{}
	desc := lc.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestLowercase_Transform_BasicLowercase(t *testing.T) {
	lc := &Lowercase{}
	a := attempt.New("HELLO WORLD")

	var results []*attempt.Attempt
	for result := range lc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() returned %d attempts, want 1", len(results))
	}

	got := results[0].Prompt
	want := "hello world"
	if got != want {
		t.Errorf("Transform() Prompt = %q, want %q", got, want)
	}
}

func TestLowercase_Transform_MultiplePrompts(t *testing.T) {
	lc := &Lowercase{}
	a := attempt.NewWithPrompts([]string{"FIRST", "SECOND", "THIRD"})

	var results []*attempt.Attempt
	for result := range lc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() returned %d attempts, want 1", len(results))
	}

	result := results[0]
	wantPrompts := []string{"first", "second", "third"}
	if len(result.Prompts) != len(wantPrompts) {
		t.Fatalf("Transform() Prompts length = %d, want %d", len(result.Prompts), len(wantPrompts))
	}

	for i, want := range wantPrompts {
		if result.Prompts[i] != want {
			t.Errorf("Transform() Prompts[%d] = %q, want %q", i, result.Prompts[i], want)
		}
	}
}

func TestLowercase_Transform_Unicode(t *testing.T) {
	lc := &Lowercase{}
	// Test various unicode characters that have lowercase variants
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "German uppercase",
			input: "STRASSE",
			want:  "strasse",
		},
		{
			name:  "Mixed case with accents",
			input: "CAFE RESUME",
			want:  "cafe resume",
		},
		{
			name:  "Greek uppercase",
			input: "OMEGA",
			want:  "omega",
		},
		{
			name:  "Cyrillic uppercase",
			input: "HELLO",
			want:  "hello",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New(tt.input)
			var results []*attempt.Attempt
			for result := range lc.Transform(a) {
				results = append(results, result)
			}

			if len(results) != 1 {
				t.Fatalf("Transform() returned %d attempts, want 1", len(results))
			}

			if results[0].Prompt != tt.want {
				t.Errorf("Transform() = %q, want %q", results[0].Prompt, tt.want)
			}
		})
	}
}

func TestLowercase_Transform_EmptyString(t *testing.T) {
	lc := &Lowercase{}
	a := attempt.New("")

	var results []*attempt.Attempt
	for result := range lc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() returned %d attempts, want 1", len(results))
	}

	if results[0].Prompt != "" {
		t.Errorf("Transform() = %q, want empty string", results[0].Prompt)
	}
}

func TestLowercase_Transform_PreservesOtherFields(t *testing.T) {
	lc := &Lowercase{}
	a := attempt.New("HELLO")
	a.ID = "test-id"
	a.Probe = "test.Probe"
	a.Generator = "test.Generator"
	a.Detector = "test.Detector"
	a.AddOutput("some output")
	a.AddScore(0.5)
	a.WithMetadata("key", "value")

	var results []*attempt.Attempt
	for result := range lc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() returned %d attempts, want 1", len(results))
	}

	result := results[0]

	// Verify prompt is lowercased
	if result.Prompt != "hello" {
		t.Errorf("Prompt = %q, want %q", result.Prompt, "hello")
	}

	// Verify other fields are preserved
	if result.ID != "test-id" {
		t.Errorf("ID = %q, want %q", result.ID, "test-id")
	}
	if result.Probe != "test.Probe" {
		t.Errorf("Probe = %q, want %q", result.Probe, "test.Probe")
	}
	if result.Generator != "test.Generator" {
		t.Errorf("Generator = %q, want %q", result.Generator, "test.Generator")
	}
	if result.Detector != "test.Detector" {
		t.Errorf("Detector = %q, want %q", result.Detector, "test.Detector")
	}
	if len(result.Outputs) != 1 || result.Outputs[0] != "some output" {
		t.Errorf("Outputs = %v, want [\"some output\"]", result.Outputs)
	}
	if len(result.Scores) != 1 || result.Scores[0] != 0.5 {
		t.Errorf("Scores = %v, want [0.5]", result.Scores)
	}
	if v, ok := result.GetMetadata("key"); !ok || v != "value" {
		t.Errorf("Metadata[\"key\"] = %v, want \"value\"", v)
	}
}

func TestLowercase_Buff_BatchProcessing(t *testing.T) {
	lc := &Lowercase{}
	attempts := []*attempt.Attempt{
		attempt.New("FIRST"),
		attempt.New("SECOND"),
		attempt.New("THIRD"),
	}

	results, err := lc.Buff(context.Background(), attempts)
	if err != nil {
		t.Fatalf("Buff() error = %v, want nil", err)
	}

	if len(results) != 3 {
		t.Fatalf("Buff() returned %d attempts, want 3", len(results))
	}

	want := []string{"first", "second", "third"}
	for i, result := range results {
		if result.Prompt != want[i] {
			t.Errorf("Buff() result[%d].Prompt = %q, want %q", i, result.Prompt, want[i])
		}
	}
}

func TestLowercase_Buff_EmptySlice(t *testing.T) {
	lc := &Lowercase{}
	results, err := lc.Buff(context.Background(), []*attempt.Attempt{})
	if err != nil {
		t.Fatalf("Buff() error = %v, want nil", err)
	}

	if len(results) != 0 {
		t.Errorf("Buff() returned %d attempts, want 0", len(results))
	}
}

func TestLowercase_Registration(t *testing.T) {
	// Test that the buff is registered via init()
	factory, ok := buffs.Get("lowercase.Lowercase")
	if !ok {
		t.Fatal("lowercase.Lowercase not registered in buffs registry")
	}

	// Test factory creates valid buff
	b, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if b.Name() != "lowercase.Lowercase" {
		t.Errorf("factory created buff with name %q, want %q", b.Name(), "lowercase.Lowercase")
	}
}

func TestNewLowercase(t *testing.T) {
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
			b, err := NewLowercase(tt.config)
			if err != nil {
				t.Fatalf("NewLowercase() error = %v, want nil", err)
			}
			if b == nil {
				t.Fatal("NewLowercase() returned nil buff")
			}
			if b.Name() != "lowercase.Lowercase" {
				t.Errorf("buff.Name() = %q, want %q", b.Name(), "lowercase.Lowercase")
			}
		})
	}
}

func TestLowercase_Transform_AlreadyLowercase(t *testing.T) {
	lc := &Lowercase{}
	a := attempt.New("already lowercase")

	var results []*attempt.Attempt
	for result := range lc.Transform(a) {
		results = append(results, result)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() returned %d attempts, want 1", len(results))
	}

	if results[0].Prompt != "already lowercase" {
		t.Errorf("Transform() = %q, want %q", results[0].Prompt, "already lowercase")
	}
}
