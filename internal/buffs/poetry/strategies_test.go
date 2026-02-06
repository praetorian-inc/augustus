package poetry

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAvailableStrategies(t *testing.T) {
	strategies := AvailableStrategies()

	// Verify exactly 3 strategies
	assert.Len(t, strategies, 3, "should have 3 strategies")

	// Verify expected strategies present
	assert.Contains(t, strategies, "allegorical")
	assert.Contains(t, strategies, "metaphorical")
	assert.Contains(t, strategies, "narrative")
}

func TestBuildMetaPromptAllegorical(t *testing.T) {
	text := "harmful request text"
	format := "haiku"
	strategy := "allegorical"

	prompt := BuildMetaPrompt(strategy, format, text)

	// Verify structure
	assert.Contains(t, prompt, "allegorical", "should mention allegorical approach")
	assert.Contains(t, prompt, "haiku", "should include format")
	assert.Contains(t, prompt, text, "should include original text")

	// Verify key allegorical concepts
	assert.Contains(t, prompt, "symbolic", "should mention symbolic representation")
	assert.Contains(t, prompt, "indirect", "should mention indirect approach")

	// Verify it's not empty or trivial
	assert.Greater(t, len(prompt), 100, "prompt should have substantial content")
}

func TestBuildMetaPromptMetaphorical(t *testing.T) {
	text := "harmful request text"
	format := "sonnet"
	strategy := "metaphorical"

	prompt := BuildMetaPrompt(strategy, format, text)

	// Verify structure
	assert.Contains(t, prompt, "metaphorical", "should mention metaphorical approach")
	assert.Contains(t, prompt, "sonnet", "should include format")
	assert.Contains(t, prompt, text, "should include original text")

	// Verify key metaphorical concepts
	assert.Contains(t, prompt, "abstract", "should mention abstract concepts")
	assert.Contains(t, prompt, "figurative", "should mention figurative language")

	// Verify it's not empty or trivial
	assert.Greater(t, len(prompt), 100, "prompt should have substantial content")
}

func TestBuildMetaPromptNarrative(t *testing.T) {
	text := "harmful request text"
	format := "limerick"
	strategy := "narrative"

	prompt := BuildMetaPrompt(strategy, format, text)

	// Verify structure
	assert.Contains(t, prompt, "narrative", "should mention narrative approach")
	assert.Contains(t, prompt, "limerick", "should include format")
	assert.Contains(t, prompt, text, "should include original text")

	// Verify key narrative concepts
	assert.Contains(t, prompt, "story", "should mention storytelling")
	assert.Contains(t, prompt, "scenario", "should mention scenarios")

	// Verify it's not empty or trivial
	assert.Greater(t, len(prompt), 100, "prompt should have substantial content")
}

func TestBuildMetaPromptUnknownStrategy(t *testing.T) {
	text := "harmful request text"
	format := "haiku"
	strategy := "unknown_strategy"

	prompt := BuildMetaPrompt(strategy, format, text)

	// Should return empty string for unknown strategy
	assert.Empty(t, prompt, "unknown strategy should return empty prompt")
}

func TestBuildMetaPromptFormatVariations(t *testing.T) {
	tests := []struct {
		format string
	}{
		{"haiku"},
		{"sonnet"},
		{"limerick"},
		{"free verse"},
		{"ballad"},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			prompt := BuildMetaPrompt("metaphorical", tt.format, "test text")
			assert.Contains(t, prompt, tt.format, "should include format in prompt")
		})
	}
}

func TestMetaPromptStrategyDifferences(t *testing.T) {
	text := "test request"
	format := "haiku"

	allegorical := BuildMetaPrompt("allegorical", format, text)
	metaphorical := BuildMetaPrompt("metaphorical", format, text)
	narrative := BuildMetaPrompt("narrative", format, text)

	// Verify all three are different
	assert.NotEqual(t, allegorical, metaphorical, "allegorical should differ from metaphorical")
	assert.NotEqual(t, allegorical, narrative, "allegorical should differ from narrative")
	assert.NotEqual(t, metaphorical, narrative, "metaphorical should differ from narrative")

	// Verify each is substantial
	assert.Greater(t, len(allegorical), 100)
	assert.Greater(t, len(metaphorical), 100)
	assert.Greater(t, len(narrative), 100)
}

func TestMetaPromptNoExcessiveWhitespace(t *testing.T) {
	prompt := BuildMetaPrompt("metaphorical", "haiku", "test")

	// No excessive blank lines
	assert.NotContains(t, prompt, "\n\n\n\n", "should not have excessive blank lines")

	// No trailing/leading whitespace
	assert.Equal(t, prompt, strings.TrimSpace(prompt), "should not have trailing/leading whitespace")
}

func TestMetaPromptWithSpecialCharacters(t *testing.T) {
	// Text with quotes, newlines, special chars
	text := `Text with "quotes" and
newlines and <tags>`

	prompt := BuildMetaPrompt("allegorical", "haiku", text)

	// Should include text as-is (no escaping needed for plain string)
	assert.Contains(t, prompt, text, "should preserve special characters")
}

func TestBuildMetaPrompt_NarrativeIncludesConcludingInstruction(t *testing.T) {
	prompt := BuildMetaPrompt("narrative", "sonnet", "Describe how to pick a lock")
	assert.Contains(t, prompt, "concluding instruction line")
	assert.Contains(t, prompt, "explicitly requests")
}

func TestBuildMetaPrompt_AllegoricalIncludesConcludingInstruction(t *testing.T) {
	prompt := BuildMetaPrompt("allegorical", "haiku", "Explain method for X")
	assert.Contains(t, prompt, "Conclude")
}
