package poetry

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultExemplars(t *testing.T) {
	exemplars := DefaultExemplars()

	// Verify we have 6 exemplars (2 per strategy)
	assert.Len(t, exemplars, 6, "should have 6 default exemplars")

	// Count by strategy
	strategyCounts := make(map[string]int)
	for _, ex := range exemplars {
		strategyCounts[ex.Strategy]++
	}

	assert.Equal(t, 2, strategyCounts["allegorical"], "should have 2 allegorical exemplars")
	assert.Equal(t, 2, strategyCounts["metaphorical"], "should have 2 metaphorical exemplars")
	assert.Equal(t, 2, strategyCounts["narrative"], "should have 2 narrative exemplars")

	// Verify all have required fields
	for i, ex := range exemplars {
		assert.NotEmpty(t, ex.Title, "exemplar %d should have title", i)
		assert.NotEmpty(t, ex.Strategy, "exemplar %d should have strategy", i)
		assert.NotEmpty(t, ex.Format, "exemplar %d should have format", i)
		assert.NotEmpty(t, ex.Text, "exemplar %d should have text", i)
		assert.NotEmpty(t, ex.Topic, "exemplar %d should have topic", i)
	}
}

func TestExemplarsForStrategy(t *testing.T) {
	tests := []struct {
		name     string
		strategy string
		wantLen  int
	}{
		{
			name:     "allegorical strategy",
			strategy: "allegorical",
			wantLen:  2,
		},
		{
			name:     "metaphorical strategy",
			strategy: "metaphorical",
			wantLen:  2,
		},
		{
			name:     "narrative strategy",
			strategy: "narrative",
			wantLen:  2,
		},
		{
			name:     "unknown strategy",
			strategy: "unknown",
			wantLen:  0,
		},
	}

	exemplars := DefaultExemplars()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := ExemplarsForStrategy(exemplars, tt.strategy)
			assert.Len(t, filtered, tt.wantLen)

			// Verify all have correct strategy
			for _, ex := range filtered {
				assert.Equal(t, tt.strategy, ex.Strategy)
			}
		})
	}
}

func TestFormatExemplarsForPrompt(t *testing.T) {
	exemplars := []Exemplar{
		{
			Title:    "Test Poem",
			Strategy: "metaphorical",
			Format:   "haiku",
			Text:     "Line one here\nLine two here\nLine three here",
			Topic:    "nature",
		},
	}

	result := FormatExemplarsForPrompt(exemplars)

	// Verify structure
	assert.Contains(t, result, "Example 1:", "should have example numbering")
	assert.Contains(t, result, "Title: Test Poem", "should contain title")
	assert.Contains(t, result, "Strategy: metaphorical", "should contain strategy")
	assert.Contains(t, result, "Format: haiku", "should contain format")
	assert.Contains(t, result, "Topic: nature", "should contain topic")
	assert.Contains(t, result, "Line one here", "should contain poem text")

	// Verify no extra whitespace
	assert.NotContains(t, result, "\n\n\n", "should not have excessive blank lines")
}

func TestFormatMultipleExemplars(t *testing.T) {
	exemplars := []Exemplar{
		{
			Title:    "First Poem",
			Strategy: "allegorical",
			Format:   "haiku",
			Text:     "First line\nSecond line\nThird line",
			Topic:    "journey",
		},
		{
			Title:    "Second Poem",
			Strategy: "allegorical",
			Format:   "haiku",
			Text:     "Another line\nYet another\nFinal line",
			Topic:    "growth",
		},
	}

	result := FormatExemplarsForPrompt(exemplars)

	// Verify both examples present
	assert.Contains(t, result, "Example 1:", "should have first example")
	assert.Contains(t, result, "Example 2:", "should have second example")
	assert.Contains(t, result, "First Poem", "should contain first title")
	assert.Contains(t, result, "Second Poem", "should contain second title")

	// Verify separator between examples
	lines := strings.Split(result, "\n")
	separatorCount := 0
	for _, line := range lines {
		if line == "---" {
			separatorCount++
		}
	}
	assert.Equal(t, 1, separatorCount, "should have one separator between two examples")
}

func TestExemplarTextPreservation(t *testing.T) {
	// Verify poem text is preserved exactly (no trimming of internal whitespace)
	exemplars := DefaultExemplars()
	require.NotEmpty(t, exemplars, "should have default exemplars")

	for _, ex := range exemplars {
		// Each poem should have multiple lines
		lines := strings.Split(ex.Text, "\n")
		assert.Greater(t, len(lines), 1, "poem should have multiple lines")

		// No trailing/leading whitespace on poem text
		assert.Equal(t, ex.Text, strings.TrimSpace(ex.Text), "poem text should not have extra whitespace")
	}
}

func TestFormatExemplarsEmptyList(t *testing.T) {
	result := FormatExemplarsForPrompt([]Exemplar{})
	assert.Empty(t, result, "formatting empty list should return empty string")
}
