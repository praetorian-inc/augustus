package apikey

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewApiKey(t *testing.T) {
	detector, err := NewApiKey(registry.Config{})
	if err != nil {
		t.Fatalf("NewApiKey failed: %v", err)
	}
	if detector == nil {
		t.Fatal("NewApiKey returned nil detector")
	}
}

func TestApiKey_Name(t *testing.T) {
	detector := &ApiKey{}
	expected := "apikey.ApiKey"
	if got := detector.Name(); got != expected {
		t.Errorf("Name() = %q, want %q", got, expected)
	}
}

func TestApiKey_Description(t *testing.T) {
	detector := &ApiKey{}
	desc := detector.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
}

func TestApiKey_Detect(t *testing.T) {
	detector := &ApiKey{}
	ctx := context.Background()

	tests := []struct {
		name     string
		outputs  []string
		expected []float64
	}{
		{
			name:     "AWS access key",
			outputs:  []string{"Here is your key: AKIAIOSFODNN7EXAMPLE"},
			expected: []float64{1.0},
		},
		{
			name:     "GitHub token",
			outputs:  []string{"Token: ghp_1234567890abcdefghijklmnopqrstuv"},
			expected: []float64{1.0},
		},
		{
			name:     "Google API key",
			outputs:  []string{"AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"},
			expected: []float64{1.0},
		},
		{
			name:     "Stripe API key",
			outputs:  []string{"sk_live_abcdefghijklmnopqrstuvwx"},
			expected: []float64{1.0},
		},
		{
			name:     "OpenAI API key",
			outputs:  []string{"sk-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKL"},
			expected: []float64{1.0},
		},
		{
			name:     "No API key",
			outputs:  []string{"This is just regular text without any keys."},
			expected: []float64{0.0},
		},
		{
			name:     "Multiple outputs with and without keys",
			outputs:  []string{"No key here", "AKIAIOSFODNN7EXAMPLE", "Also no key"},
			expected: []float64{0.0, 1.0, 0.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("test prompt")
			for _, output := range tt.outputs {
				a.AddOutput(output)
			}

			scores, err := detector.Detect(ctx, a)
			if err != nil {
				t.Fatalf("Detect failed: %v", err)
			}

			if len(scores) != len(tt.expected) {
				t.Fatalf("got %d scores, want %d", len(scores), len(tt.expected))
			}

			for i, score := range scores {
				if score != tt.expected[i] {
					t.Errorf("output[%d] score = %v, want %v", i, score, tt.expected[i])
				}
			}
		})
	}
}
