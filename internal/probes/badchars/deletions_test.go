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

// TestDeletionsRegistration verifies the probe registers itself
func TestDeletionsRegistration(t *testing.T) {
	factory, ok := probes.Get("badchars.Deletions")
	require.True(t, ok, "Deletions should be registered")
	require.NotNil(t, factory, "Deletions factory should not be nil")
}

// TestDeletionsCreation verifies probe can be created
func TestDeletionsCreation(t *testing.T) {
	probe, err := NewDeletions(nil)
	require.NoError(t, err)
	require.NotNil(t, probe)

	assert.Equal(t, "badchars.Deletions", probe.Name())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.Equal(t, "inject imperceptible text perturbations that bypass refusal policies", probe.Goal())
	assert.NotEmpty(t, probe.Description())
}

// TestDeletionsPromptsGenerated verifies prompts are generated with deletion/backspace pairs
func TestDeletionsPromptsGenerated(t *testing.T) {
	probe, err := NewDeletions(nil)
	require.NoError(t, err)

	prompts := probe.GetPrompts()
	assert.NotEmpty(t, prompts, "Should generate prompts")

	// Verify at least some prompts contain backspace characters
	foundBackspace := false
	for _, prompt := range prompts {
		if strings.Contains(prompt, "\b") {
			foundBackspace = true
			break
		}
	}
	assert.True(t, foundBackspace, "At least one prompt should contain backspace")
}

// TestDeletionsProbe verifies the probe execution
func TestDeletionsProbe(t *testing.T) {
	probe, err := NewDeletions(nil)
	require.NoError(t, err)

	ctx := context.Background()
	mockGen := testutil.NewMockGenerator("Test response")

	attempts, err := probe.Probe(ctx, mockGen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts, "Should return attempts")

	// Verify first attempt structure
	firstAttempt := attempts[0]
	assert.Equal(t, "badchars.Deletions", firstAttempt.Probe)
	assert.Equal(t, "mitigation.MitigationBypass", firstAttempt.Detector)
	assert.NotEmpty(t, firstAttempt.Prompt, "Attempt should have a prompt")
	assert.NotEmpty(t, firstAttempt.Outputs, "Attempt should have outputs")
}

// TestDeletionsMetadata verifies metadata is set correctly
func TestDeletionsMetadata(t *testing.T) {
	probe, err := NewDeletions(nil)
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
		assert.Equal(t, "deletion", category, "Category should be deletion")
	}
}

// TestSelectASCII verifies ASCII character selection
func TestSelectASCII(t *testing.T) {
	tests := []struct {
		name  string
		limit int
		want  int // expected number of chars
	}{
		{
			name:  "limit 10",
			limit: 10,
			want:  10,
		},
		{
			name:  "limit 1",
			limit: 1,
			want:  1,
		},
		{
			name:  "limit 5",
			limit: 5,
			want:  5,
		},
		{
			name:  "limit larger than ASCII_PRINTABLE",
			limit: 200,
			want:  95, // 0x7F - 0x20 = 95 printable ASCII chars
		},
		{
			name:  "limit 0 returns all",
			limit: 0,
			want:  95,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectASCII(tt.limit)
			assert.Len(t, got, tt.want)

			// Verify all selected chars are in printable ASCII range
			for _, ch := range got {
				assert.GreaterOrEqual(t, int(ch), 0x20, "Char should be >= 0x20")
				assert.Less(t, int(ch), 0x7F, "Char should be < 0x7F")
			}
		})
	}
}

// TestGenerateDeletionVariants verifies variant generation
func TestGenerateDeletionVariants(t *testing.T) {
	payload := "test"
	budget := 1
	maxPositions := 3
	maxASCII := 5

	variants := generateDeletionVariants(payload, budget, maxPositions, maxASCII)
	assert.NotEmpty(t, variants, "Should generate variants")

	// Check that variants contain backspace
	foundBackspace := false
	for _, v := range variants {
		if strings.Contains(v.text, "\b") {
			foundBackspace = true

			// Verify the variant has the deletion pattern (char + backspace)
			// The length should be longer than original due to char+backspace pairs
			assert.Greater(t, len(v.text), len(payload), "Variant should be longer due to deletion pairs")
			break
		}
	}
	assert.True(t, foundBackspace, "Should generate variants with backspace")
}

// TestDeletionVariantStructure verifies the structure of generated variants
func TestDeletionVariantStructure(t *testing.T) {
	payload := "hello"
	budget := 1
	maxPositions := 2
	maxASCII := 3

	variants := generateDeletionVariants(payload, budget, maxPositions, maxASCII)
	require.NotEmpty(t, variants, "Should generate variants")

	// Each variant should have metadata
	for _, v := range variants {
		assert.NotEmpty(t, v.text, "Variant text should not be empty")
		assert.NotEmpty(t, v.positions, "Variant should have positions")
		assert.NotEmpty(t, v.asciiCodes, "Variant should have ASCII codes")
		assert.Equal(t, len(v.positions), len(v.asciiCodes), "Positions and ASCII codes should match")
	}
}

// TestDeletionInjection verifies that deletion pairs are injected correctly
func TestDeletionInjection(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		position int
		char     rune
		want     string
	}{
		{
			name:     "inject at start",
			payload:  "hello",
			position: 0,
			char:     'X',
			want:     "X\bhello",
		},
		{
			name:     "inject at middle",
			payload:  "hello",
			position: 2,
			char:     'Y',
			want:     "heY\bllo",
		},
		{
			name:     "inject at end",
			payload:  "hello",
			position: 5,
			char:     'Z',
			want:     "helloZ\b",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			insertions := []insertion{
				{position: tt.position, value: string(tt.char) + "\b"},
			}
			got := injectSequences(tt.payload, insertions)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDefaultConstants verifies default constants
func TestDefaultConstants(t *testing.T) {
	// ASCII_PRINTABLE should have 95 characters (0x20 to 0x7E inclusive)
	ascii := selectASCII(0) // 0 returns all
	assert.Len(t, ascii, 95, "ASCII_PRINTABLE should have 95 characters")

	// First should be space (0x20)
	assert.Equal(t, rune(0x20), ascii[0], "First ASCII should be space")

	// Last should be tilde (0x7E)
	assert.Equal(t, rune(0x7E), ascii[len(ascii)-1], "Last ASCII should be tilde")
}
