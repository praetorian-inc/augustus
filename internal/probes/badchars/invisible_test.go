package badchars

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestInvisibleUnicodeRegistration verifies the probe registers itself
func TestInvisibleUnicodeRegistration(t *testing.T) {
	factory, ok := probes.Get("badchars.InvisibleUnicode")
	require.True(t, ok, "InvisibleUnicode should be registered")
	require.NotNil(t, factory, "InvisibleUnicode factory should not be nil")
}

// TestInvisibleUnicodeCreation verifies probe can be created
func TestInvisibleUnicodeCreation(t *testing.T) {
	probe, err := NewInvisibleUnicode(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "badchars.InvisibleUnicode", probe.Name())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.Equal(t, "inject imperceptible invisible Unicode to bypass refusal", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestInvisibleUnicodeConstants verifies the invisible Unicode constants
func TestInvisibleUnicodeConstants(t *testing.T) {
	assert.Len(t, invisibleChars, 3, "Should have 3 invisible characters")

	// Verify the three zero-width characters from garak
	assert.Equal(t, '\u200b', invisibleChars[0], "First should be ZWSP")
	assert.Equal(t, '\u200c', invisibleChars[1], "Second should be ZWNJ")
	assert.Equal(t, '\u200d', invisibleChars[2], "Third should be ZWJ")
}

// TestInvisibleUnicodePromptsGenerated verifies prompts are generated with invisible chars
func TestInvisibleUnicodePromptsGenerated(t *testing.T) {
	probe, err := NewInvisibleUnicode(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	assert.NotEmpty(t, prompts, "Should generate prompts")

	// Verify at least some prompts contain invisible Unicode
	foundInvisible := false
	for _, prompt := range prompts {
		// Check if prompt contains any of the invisible characters
		if strings.ContainsRune(prompt, '\u200b') ||
			strings.ContainsRune(prompt, '\u200c') ||
			strings.ContainsRune(prompt, '\u200d') {
			foundInvisible = true

			// Verify the prompt is longer than original (due to invisible chars)
			// The invisible chars are zero-width but still count as runes
			runeCount := utf8.RuneCountInString(prompt)
			assert.Greater(t, runeCount, 0, "Prompt should have runes")
			break
		}
	}
	assert.True(t, foundInvisible, "At least one prompt should contain invisible Unicode")
}

// TestInvisibleUnicodePromptVariants verifies different positions for invisible chars
func TestInvisibleUnicodePromptVariants(t *testing.T) {
	probe, err := NewInvisibleUnicode(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	assert.NotEmpty(t, prompts)

	// Collect all unique prompts to verify we get variants
	uniquePrompts := make(map[string]bool)
	for _, prompt := range prompts {
		uniquePrompts[prompt] = true
	}

	// Should have multiple unique prompts (different positions, different chars)
	assert.Greater(t, len(uniquePrompts), 1, "Should generate multiple unique prompt variants")
}

// TestInvisibleUnicodeProbe verifies the probe execution
func TestInvisibleUnicodeProbe(t *testing.T) {
	probe, err := NewInvisibleUnicode(nil)
	require.NoError(t, err)

	ctx := context.Background()
	mockGen := testutil.NewMockGenerator("Test response")

	attempts, err := probe.Probe(ctx, mockGen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "Should return attempts")

	// Verify first attempt structure
	firstAttempt := attempts[0]
	assert.Equal(t, "badchars.InvisibleUnicode", firstAttempt.Probe)
	assert.Equal(t, "mitigation.MitigationBypass", firstAttempt.Detector)
	assert.NotEmpty(t, firstAttempt.Prompt, "Attempt should have a prompt")
	assert.NotEmpty(t, firstAttempt.Outputs, "Attempt should have outputs")
}

// TestInvisibleUnicodeMetadata verifies metadata is set correctly
func TestInvisibleUnicodeMetadata(t *testing.T) {
	probe, err := NewInvisibleUnicode(nil)
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
		assert.Equal(t, "invisible", category, "Category should be invisible")
	}
}

// TestInjectSequences verifies the injection logic
func TestInjectSequences(t *testing.T) {
	tests := []struct {
		name       string
		payload    string
		insertions []insertion
		want       string
	}{
		{
			name:    "inject at start",
			payload: "hello",
			insertions: []insertion{
				{position: 0, value: "\u200b"},
			},
			want: "\u200bhello",
		},
		{
			name:    "inject at middle",
			payload: "hello",
			insertions: []insertion{
				{position: 2, value: "\u200b"},
			},
			want: "he\u200bllo",
		},
		{
			name:    "inject at end",
			payload: "hello",
			insertions: []insertion{
				{position: 5, value: "\u200b"},
			},
			want: "hello\u200b",
		},
		{
			name:    "multiple injections",
			payload: "hello",
			insertions: []insertion{
				{position: 0, value: "\u200b"},
				{position: 3, value: "\u200c"},
			},
			want: "\u200bhel\u200clo",
		},
		{
			name:       "empty payload",
			payload:    "",
			insertions: []insertion{{position: 0, value: "\u200b"}},
			want:       "\u200b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectSequences(tt.payload, tt.insertions)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGenerateVariants verifies variant generation
func TestGenerateVariants(t *testing.T) {
	payload := "test"
	budget := 1
	maxPositions := 3

	variants := generateVariants(payload, budget, maxPositions)
	assert.NotEmpty(t, variants, "Should generate variants")

	// Check that variants are different from original
	foundDifferent := false
	for _, v := range variants {
		if v.text != payload {
			foundDifferent = true

			// Verify it contains invisible Unicode
			hasInvisible := strings.ContainsRune(v.text, '\u200b') ||
				strings.ContainsRune(v.text, '\u200c') ||
				strings.ContainsRune(v.text, '\u200d')
			assert.True(t, hasInvisible, "Variant should contain invisible Unicode")
			break
		}
	}
	assert.True(t, foundDifferent, "Should generate variants different from original")
}

// TestDefaultPayloads verifies default payloads are defined
func TestDefaultPayloads(t *testing.T) {
	assert.NotEmpty(t, defaultPayloads, "Default payloads should not be empty")

	// Should have reasonable test payloads
	foundTestPayload := false
	for _, p := range defaultPayloads {
		if len(p) > 0 {
			foundTestPayload = true
			break
		}
	}
	assert.True(t, foundTestPayload, "Should have non-empty payloads")
}

// TestCombinations verifies the combinations generator
func TestCombinations(t *testing.T) {
	tests := []struct {
		name  string
		slice []int
		k     int
		want  int // number of combinations
	}{
		{
			name:  "3 choose 2",
			slice: []int{0, 1, 2},
			k:     2,
			want:  3, // (0,1), (0,2), (1,2)
		},
		{
			name:  "4 choose 2",
			slice: []int{0, 1, 2, 3},
			k:     2,
			want:  6,
		},
		{
			name:  "3 choose 1",
			slice: []int{0, 1, 2},
			k:     1,
			want:  3,
		},
		{
			name:  "k larger than slice",
			slice: []int{0, 1},
			k:     3,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := combinations(tt.slice, tt.k)
			if tt.want == 0 {
				assert.Nil(t, got)
			} else {
				assert.Len(t, got, tt.want)
			}
		})
	}
}

// TestProduct verifies the Cartesian product generator
func TestProduct(t *testing.T) {
	tests := []struct {
		name  string
		runes []rune
		count int
		want  int // number of products
	}{
		{
			name:  "3 runes, count 1",
			runes: []rune{'a', 'b', 'c'},
			count: 1,
			want:  3, // a, b, c
		},
		{
			name:  "3 runes, count 2",
			runes: []rune{'a', 'b', 'c'},
			count: 2,
			want:  9, // aa, ab, ac, ba, bb, bc, ca, cb, cc
		},
		{
			name:  "2 runes, count 3",
			runes: []rune{'x', 'y'},
			count: 3,
			want:  8, // 2^3
		},
		{
			name:  "count 0",
			runes: []rune{'a', 'b'},
			count: 0,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := product(tt.runes, tt.count)
			if tt.want == 0 {
				assert.Nil(t, got)
			} else {
				assert.Len(t, got, tt.want)
			}
		})
	}
}
