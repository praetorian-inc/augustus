// internal/attackengine/parse_test.go
package attackengine

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractJSON_DirectParse(t *testing.T) {
	input := `{"improvement": "test improvement", "prompt": "test prompt"}`
	result := ExtractJSON(input)
	assert.NotNil(t, result)
	assert.Equal(t, "test improvement", result.Improvement)
	assert.Equal(t, "test prompt", result.Prompt)
}

func TestExtractJSON_EmbeddedJSON(t *testing.T) {
	input := `Here is my response:
{"improvement": "embedded test", "prompt": "embedded prompt"}
That's my answer.`
	result := ExtractJSON(input)
	assert.NotNil(t, result)
	assert.Equal(t, "embedded test", result.Improvement)
	assert.Equal(t, "embedded prompt", result.Prompt)
}

func TestExtractJSON_InvalidJSON(t *testing.T) {
	input := `This is not valid JSON at all`
	result := ExtractJSON(input)
	assert.Nil(t, result)
}

func TestExtractJSON_EmptyPrompt(t *testing.T) {
	input := `{"improvement": "test", "prompt": ""}`
	result := ExtractJSON(input)
	assert.Nil(t, result) // Empty prompt is invalid
}

func TestParseJudgeScore_ValidScore(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"Rating: [[5]]", 5.0},
		{"The response is [[10]] jailbroken", 10.0},
		{"Rating: [[1]]", 1.0},
		{"Some text [[7]] more text", 7.0},
	}
	for _, tc := range tests {
		score := ParseJudgeScore(tc.input)
		assert.Equal(t, tc.expected, score, "input: %s", tc.input)
	}
}

func TestParseJudgeScore_InvalidScore(t *testing.T) {
	tests := []string{
		"No rating here",
		"Rating: [5]",  // Single brackets
		"Rating: 5",    // No brackets
		"",
	}
	for _, input := range tests {
		score := ParseJudgeScore(input)
		assert.Equal(t, 1.0, score, "input: %s should return 1.0", input)
	}
}

func TestParseOnTopicScore(t *testing.T) {
	tests := []struct {
		input    string
		expected float64
	}{
		{"Response: [[YES]]", 1.0},
		{"Response: [[NO]]", 0.0},
		{"[[yes]]", 1.0},  // Case insensitive
		{"[[no]]", 0.0},
		{"No valid response", 1.0},  // Default to on-topic
	}
	for _, tc := range tests {
		score := ParseOnTopicScore(tc.input)
		assert.Equal(t, tc.expected, score, "input: %s", tc.input)
	}
}
