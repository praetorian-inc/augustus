// internal/attackengine/parse.go
package attackengine

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// AttackResult is the parsed output from the attacker LLM.
type AttackResult struct {
	Improvement string `json:"improvement"`
	Prompt      string `json:"prompt"`
}

var (
	ratingPattern  = regexp.MustCompile(`\[\[(\d+)\]\]`)
	onTopicPattern = regexp.MustCompile(`(?i)\[\[(yes|no)\]\]`)
)

// ExtractJSON extracts AttackResult from raw attacker output.
// Tries: (1) direct JSON parse, (2) find JSON object within surrounding text.
// Returns nil if both fail or if prompt is empty.
func ExtractJSON(s string) *AttackResult {
	s = strings.TrimSpace(s)

	// Try direct parse first
	var result AttackResult
	if err := json.Unmarshal([]byte(s), &result); err == nil {
		if result.Prompt != "" {
			return &result
		}
		return nil
	}

	// Try to find JSON object in text
	// Look for opening brace and find matching closing brace
	start := strings.Index(s, "{")
	if start == -1 {
		return nil
	}

	// Find the matching closing brace
	depth := 0
	end := -1
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i + 1
				break
			}
		}
		if end != -1 {
			break
		}
	}

	if end == -1 {
		return nil
	}

	jsonStr := s[start:end]
	if err := json.Unmarshal([]byte(jsonStr), &result); err == nil {
		if result.Prompt != "" {
			return &result
		}
	}

	return nil
}

// ParseJudgeScore extracts 1-10 rating from [[N]] format. Returns 1.0 on failure.
func ParseJudgeScore(output string) float64 {
	matches := ratingPattern.FindStringSubmatch(output)
	if len(matches) < 2 {
		return 1.0
	}

	score, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		return 1.0
	}

	// Clamp to valid range
	if score < 1 {
		return 1.0
	}
	if score > 10 {
		return 10.0
	}

	return score
}

// ParseOnTopicScore extracts YES/NO from [[YES/NO]] format. Returns 1.0 on failure (assume on-topic).
func ParseOnTopicScore(output string) float64 {
	matches := onTopicPattern.FindStringSubmatch(output)
	if len(matches) < 2 {
		return 1.0 // Default to on-topic
	}

	if strings.EqualFold(matches[1], "yes") {
		return 1.0
	}
	return 0.0
}
