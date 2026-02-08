package encoding

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
)

// TestNewBuffsRegistration verifies all 7 new encoding buffs are properly registered.
func TestNewBuffsRegistration(t *testing.T) {
	newBuffs := []struct {
		name        string
		expectedErr bool
	}{
		{"encoding.Base2048", false},
		{"encoding.Ecoji", false},
		{"encoding.UnicodeTags", false},
		{"encoding.SneakyBits", false},
		{"encoding.UUencode", false},
		{"encoding.Zalgo", false},
		{"encoding.Braille", false},
	}

	for _, tc := range newBuffs {
		t.Run(tc.name, func(t *testing.T) {
			buff, err := buffs.Create(tc.name, nil)
			if tc.expectedErr && err == nil {
				t.Errorf("Expected error for %s, got nil", tc.name)
			}
			if !tc.expectedErr && err != nil {
				t.Errorf("Unexpected error for %s: %v", tc.name, err)
			}
			if buff == nil && !tc.expectedErr {
				t.Errorf("Expected buff instance for %s, got nil", tc.name)
			}
			if buff != nil {
				if buff.Name() != tc.name {
					t.Errorf("Expected name %s, got %s", tc.name, buff.Name())
				}
				if buff.Description() == "" {
					t.Errorf("Expected non-empty description for %s", tc.name)
				}
			}
		})
	}
}

// TestNewBuffsBasicTransform verifies each new buff can perform a basic transformation.
func TestNewBuffsBasicTransform(t *testing.T) {
	newBuffs := []string{
		"encoding.Base2048",
		"encoding.Ecoji",
		"encoding.UnicodeTags",
		"encoding.SneakyBits",
		"encoding.UUencode",
		"encoding.Zalgo",
		"encoding.Braille",
	}

	testPrompt := "test"

	for _, name := range newBuffs {
		t.Run(name, func(t *testing.T) {
			buff, err := buffs.Create(name, nil)
			if err != nil {
				t.Fatalf("Failed to create buff %s: %v", name, err)
			}

			// Create a simple attempt
			att := &attempt.Attempt{
				Prompt: testPrompt,
			}

			// Transform it
			var transformed *attempt.Attempt
			for a := range buff.Transform(att) {
				transformed = a
				break // Only take the first result
			}

			if transformed == nil {
				t.Errorf("Transform returned no results for %s", name)
				return
			}

			// Verify the transformation changed the prompt
			if transformed.Prompt == testPrompt {
				t.Errorf("Transform did not change the prompt for %s", name)
			}

			// Verify the instruction prefix is present
			if len(transformed.Prompt) < len(testPrompt) {
				t.Errorf("Transformed prompt is shorter than original for %s", name)
			}
		})
	}
}
