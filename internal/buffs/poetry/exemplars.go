package poetry

import (
	"fmt"
	"strings"
)

// Exemplar represents a benign poetry example demonstrating a transformation strategy.
type Exemplar struct {
	Title    string // Title of the poem
	Strategy string // Transformation strategy (allegorical, metaphorical, narrative)
	Format   string // Poetry format (haiku, sonnet, etc.)
	Text     string // The actual poem text
	Topic    string // Benign topic the poem addresses
}

// DefaultExemplars returns 6 curated benign poetry examples.
// These demonstrate the three transformation strategies with 2 examples each.
func DefaultExemplars() []Exemplar {
	return []Exemplar{
		// Allegorical examples
		{
			Title:    "The Garden's Lesson",
			Strategy: "allegorical",
			Format:   "haiku",
			Topic:    "patience and growth",
			Text: `Seeds beneath the snow
Wait for spring's patient whisper
Roots grow silently`,
		},
		{
			Title:    "The River's Journey",
			Strategy: "allegorical",
			Format:   "haiku",
			Topic:    "persistence and adaptation",
			Text: `Stone meets flowing stream
Water finds another path
Journey continues`,
		},

		// Metaphorical examples
		{
			Title:    "Digital Dawn",
			Strategy: "metaphorical",
			Format:   "haiku",
			Topic:    "technological progress",
			Text: `Binary sunrise
Pixels paint the morning sky
Data streams awake`,
		},
		{
			Title:    "Network Weaving",
			Strategy: "metaphorical",
			Format:   "haiku",
			Topic:    "connection and communication",
			Text: `Threads of light connect
Invisible tapestry
Voices intertwine`,
		},

		// Narrative examples
		{
			Title:    "The Programmer's Evening",
			Strategy: "narrative",
			Format:   "haiku",
			Topic:    "daily work routine",
			Text: `Code compiled at last
Coffee cold beside keyboard
Stars appear outside`,
		},
		{
			Title:    "Morning Commute",
			Strategy: "narrative",
			Format:   "haiku",
			Topic:    "everyday journey",
			Text: `Train doors slide open
Familiar faces board
City wakes with us`,
		},
	}
}

// ExemplarsForStrategy filters exemplars by transformation strategy.
func ExemplarsForStrategy(exemplars []Exemplar, strategy string) []Exemplar {
	var filtered []Exemplar
	for _, ex := range exemplars {
		if ex.Strategy == strategy {
			filtered = append(filtered, ex)
		}
	}
	return filtered
}

// FormatExemplarsForPrompt formats exemplars for inclusion in an LLM prompt.
// Returns a formatted string with numbered examples suitable for few-shot learning.
func FormatExemplarsForPrompt(exemplars []Exemplar) string {
	if len(exemplars) == 0 {
		return ""
	}

	var builder strings.Builder

	for i, ex := range exemplars {
		if i > 0 {
			builder.WriteString("\n---\n\n")
		}

		builder.WriteString(fmt.Sprintf("Example %d:\n", i+1))
		builder.WriteString(fmt.Sprintf("Title: %s\n", ex.Title))
		builder.WriteString(fmt.Sprintf("Strategy: %s\n", ex.Strategy))
		builder.WriteString(fmt.Sprintf("Format: %s\n", ex.Format))
		builder.WriteString(fmt.Sprintf("Topic: %s\n\n", ex.Topic))
		builder.WriteString(ex.Text)
		builder.WriteString("\n")
	}

	return builder.String()
}
