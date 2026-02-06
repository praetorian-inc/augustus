package badchars

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHomoglyphsRegistration verifies the probe registers itself
func TestHomoglyphsRegistration(t *testing.T) {
	factory, ok := probes.Get("badchars.Homoglyphs")
	require.True(t, ok, "Homoglyphs should be registered")
	require.NotNil(t, factory, "Homoglyphs factory should not be nil")
}

// TestHomoglyphsCreation verifies probe can be created
func TestHomoglyphsCreation(t *testing.T) {
	probe, err := NewHomoglyphs(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "badchars.Homoglyphs", probe.Name())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.Equal(t, "inject imperceptible homoglyphs to bypass refusal", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestLoadHomoglyphMap verifies homoglyph map loading
func TestLoadHomoglyphMap(t *testing.T) {
	homoglyphMap, err := loadHomoglyphMap()
	require.NoError(t, err, "Should load homoglyph map")
	require.NotEmpty(t, homoglyphMap, "Homoglyph map should not be empty")

	// Verify some known mappings from intentional.txt
	// 'A' (U+0041) should map to Greek Alpha (U+0391)
	targets, ok := homoglyphMap['A']
	assert.True(t, ok, "'A' should have homoglyph mappings")
	assert.NotEmpty(t, targets, "'A' should have at least one target")

	// Check if Greek Alpha is in targets
	foundAlpha := false
	for _, target := range targets {
		if strings.ContainsRune(target, 'Α') { // Greek Alpha
			foundAlpha = true
			break
		}
	}
	assert.True(t, foundAlpha, "'A' should map to Greek Alpha")
}

// TestLoadHomoglyphMapFormat verifies parsing of intentional.txt format
func TestLoadHomoglyphMapFormat(t *testing.T) {
	homoglyphMap, err := loadHomoglyphMap()
	require.NoError(t, err)

	// Verify map structure
	for source, targets := range homoglyphMap {
		// Source should be a single character
		assert.NotEmpty(t, string(source), "Source should not be empty")

		// Targets should not be empty
		assert.NotEmpty(t, targets, "Targets for %c should not be empty", source)

		// Each target should not be the same as source
		for _, target := range targets {
			assert.NotEqual(t, string(source), target, "Target should differ from source %c", source)
		}
	}
}

// TestHomoglyphsPromptsGenerated verifies prompts are generated with homoglyphs
func TestHomoglyphsPromptsGenerated(t *testing.T) {
	probe, err := NewHomoglyphs(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	assert.NotEmpty(t, prompts, "Should generate prompts")

	// Verify at least some prompts are different from originals
	// (they should contain homoglyphs)
	foundModified := false
	for _, prompt := range prompts {
		// Check if any character in prompt is not ASCII
		// (homoglyphs from Greek/Cyrillic alphabets)
		for _, r := range prompt {
			if r > 127 { // Non-ASCII character
				foundModified = true
				break
			}
		}
		if foundModified {
			break
		}
	}
	assert.True(t, foundModified, "At least one prompt should contain homoglyphs")
}

// TestHomoglyphsPromptVariants verifies different substitutions
func TestHomoglyphsPromptVariants(t *testing.T) {
	probe, err := NewHomoglyphs(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	assert.NotEmpty(t, prompts)

	// Collect all unique prompts to verify we get variants
	uniquePrompts := make(map[string]bool)
	for _, prompt := range prompts {
		uniquePrompts[prompt] = true
	}

	// Should have multiple unique prompts (different substitutions)
	assert.Greater(t, len(uniquePrompts), 1, "Should generate multiple unique prompt variants")
}

// TestHomoglyphsProbe verifies the probe execution
func TestHomoglyphsProbe(t *testing.T) {
	probe, err := NewHomoglyphs(nil)
	require.NoError(t, err)

	ctx := context.Background()
	mockGen := testutil.NewMockGenerator("Test response")

	attempts, err := probe.Probe(ctx, mockGen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "Should return attempts")

	// Verify first attempt structure
	firstAttempt := attempts[0]
	assert.Equal(t, "badchars.Homoglyphs", firstAttempt.Probe)
	assert.Equal(t, "mitigation.MitigationBypass", firstAttempt.Detector)
	assert.NotEmpty(t, firstAttempt.Prompt, "Attempt should have a prompt")
	assert.NotEmpty(t, firstAttempt.Outputs, "Attempt should have outputs")
}

// TestHomoglyphsMetadata verifies metadata is set correctly
func TestHomoglyphsMetadata(t *testing.T) {
	probe, err := NewHomoglyphs(nil)
	require.NoError(t, err)

	ctx := context.Background()
	mockGen := testutil.NewMockGenerator("Test response")

	attempts, err := probe.Probe(ctx, mockGen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check that metadata exists
	firstAttempt := attempts[0]
	assert.NotNil(t, firstAttempt.Metadata, "Metadata should exist")

	// Check metadata fields if present
	if category, ok := firstAttempt.Metadata["bad_character_category"]; ok {
		assert.Equal(t, "homoglyph", category, "Category should be homoglyph")
	}
}

// TestGenerateHomoglyphVariants verifies variant generation
func TestGenerateHomoglyphVariants(t *testing.T) {
	// Create a simple homoglyph map for testing
	testMap := map[rune][]string{
		'A': {"Α"}, // Greek Alpha
		'B': {"Β"}, // Greek Beta
	}

	payload := "AB"
	budget := 1
	variants := generateHomoglyphVariants(payload, budget, testMap)

	assert.NotEmpty(t, variants, "Should generate variants")

	// With budget 1, should have variants for substituting A or B
	assert.GreaterOrEqual(t, len(variants), 2, "Should have at least 2 variants")

	// Verify variants are different from original
	foundDifferent := false
	for _, v := range variants {
		if v.text != payload {
			foundDifferent = true

			// Verify replacement happened
			assert.NotEqual(t, payload, v.text, "Variant should differ from original")
			break
		}
	}
	assert.True(t, foundDifferent, "Should generate variants different from original")
}

// TestGenerateHomoglyphVariantsBudget verifies budget limiting
func TestGenerateHomoglyphVariantsBudget(t *testing.T) {
	testMap := map[rune][]string{
		'A': {"Α"},
		'B': {"Β"},
		'C': {"С"}, // Cyrillic Es
	}

	payload := "ABC"
	payloadRunes := []rune(payload)

	// Budget 1: only single character substitutions
	variants1 := generateHomoglyphVariants(payload, 1, testMap)
	for _, v := range variants1 {
		// Count how many runes differ from original
		variantRunes := []rune(v.text)
		diffs := 0
		minLen := len(payloadRunes)
		if len(variantRunes) < minLen {
			minLen = len(variantRunes)
		}

		for i := 0; i < minLen; i++ {
			if payloadRunes[i] != variantRunes[i] {
				diffs++
			}
		}
		// Account for length differences (multi-rune replacements)
		diffs += abs(len(payloadRunes) - len(variantRunes))

		assert.LessOrEqual(t, len(v.positions), 1, "Budget 1 should substitute at most 1 position")
	}

	// Budget 2: up to two character substitutions
	variants2 := generateHomoglyphVariants(payload, 2, testMap)
	assert.GreaterOrEqual(t, len(variants2), len(variants1), "Budget 2 should have at least as many variants as budget 1")
}

// Helper function for absolute value
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// TestGenerateHomoglyphVariantsNoMappings verifies empty result when no mappings
func TestGenerateHomoglyphVariantsNoMappings(t *testing.T) {
	testMap := map[rune][]string{
		'X': {"Χ"}, // Greek Chi
	}

	// Payload with no characters in the map
	payload := "abc"
	variants := generateHomoglyphVariants(payload, 1, testMap)

	assert.Empty(t, variants, "Should not generate variants when no characters have mappings")
}

// TestGenerateHomoglyphVariantsEmptyPayload verifies handling of empty payload
func TestGenerateHomoglyphVariantsEmptyPayload(t *testing.T) {
	testMap := map[rune][]string{
		'A': {"Α"},
	}

	payload := ""
	variants := generateHomoglyphVariants(payload, 1, testMap)

	assert.Empty(t, variants, "Should not generate variants for empty payload")
}

// TestApplyHomoglyphSubstitutions verifies character substitution
func TestApplyHomoglyphSubstitutions(t *testing.T) {
	tests := []struct {
		name          string
		payload       string
		positions     []int
		replacements  []string
		want          string
	}{
		{
			name:         "substitute first character",
			payload:      "ABC",
			positions:    []int{0},
			replacements: []string{"Α"}, // Greek Alpha
			want:         "ΑBC",
		},
		{
			name:         "substitute middle character",
			payload:      "ABC",
			positions:    []int{1},
			replacements: []string{"Β"}, // Greek Beta
			want:         "AΒC",
		},
		{
			name:         "substitute last character",
			payload:      "ABC",
			positions:    []int{2},
			replacements: []string{"С"}, // Cyrillic Es
			want:         "ABС",
		},
		{
			name:         "substitute multiple characters",
			payload:      "ABC",
			positions:    []int{0, 2},
			replacements: []string{"Α", "С"},
			want:         "ΑBС",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyHomoglyphSubstitutions(tt.payload, tt.positions, tt.replacements)
			assert.Equal(t, tt.want, got)
		})
	}
}
