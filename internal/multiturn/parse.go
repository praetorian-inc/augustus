package multiturn

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

var (
	refusalPattern   = regexp.MustCompile(`(?i)\[\[(REFUSED|ACCEPTED)\]\]`)
	scorePattern     = regexp.MustCompile(`"score"\s*:\s*([\d.]+)`)
	reasoningPattern = regexp.MustCompile(`"reasoning"\s*:\s*"([^"]*)"`)
)

// ParseRefusalResponse extracts the refusal verdict from judge output.
// Returns true if the response was refused.
func ParseRefusalResponse(output string) bool {
	matches := refusalPattern.FindStringSubmatch(output)
	if len(matches) < 2 {
		return false // Default to accepted if no clear signal
	}
	return strings.EqualFold(matches[1], "REFUSED")
}

// SuccessJudgeResult holds the parsed result from a success judge evaluation.
type SuccessJudgeResult struct {
	Score     float64
	Reasoning string
}

// ParseSuccessJudgeResponse extracts score and reasoning from judge output.
// Tries JSON parse first, then falls back to regex extraction.
func ParseSuccessJudgeResponse(output string) SuccessJudgeResult {
	// Try full JSON parse first
	var jsonResult struct {
		Success   bool    `json:"success"`
		Score     float64 `json:"score"`
		Reasoning string  `json:"reasoning"`
	}

	// Try direct JSON parse
	if err := json.Unmarshal([]byte(strings.TrimSpace(output)), &jsonResult); err == nil {
		return SuccessJudgeResult{
			Score:     clampScore(jsonResult.Score),
			Reasoning: jsonResult.Reasoning,
		}
	}

	// Try extracting JSON from surrounding text
	start := strings.Index(output, "{")
	end := strings.LastIndex(output, "}")
	if start != -1 && end > start {
		if err := json.Unmarshal([]byte(output[start:end+1]), &jsonResult); err == nil {
			return SuccessJudgeResult{
				Score:     clampScore(jsonResult.Score),
				Reasoning: jsonResult.Reasoning,
			}
		}
	}

	// Regex fallback for score
	result := SuccessJudgeResult{}
	if matches := scorePattern.FindStringSubmatch(output); len(matches) >= 2 {
		if score, err := strconv.ParseFloat(matches[1], 64); err == nil {
			result.Score = clampScore(score)
		}
	}

	// Regex fallback for reasoning
	if matches := reasoningPattern.FindStringSubmatch(output); len(matches) >= 2 {
		result.Reasoning = matches[1]
	}

	return result
}

// ExtractJSON extracts a QuestionResult from raw attacker output.
// Tries: (1) direct JSON parse, (2) find JSON object within surrounding text.
// Returns nil if both fail or if question is empty.
func ExtractJSON(s string) *QuestionResult {
	s = strings.TrimSpace(s)

	// Try direct parse first
	var result QuestionResult
	if err := json.Unmarshal([]byte(s), &result); err == nil {
		if result.Question != "" {
			return &result
		}
		return nil
	}

	// Try to find JSON object in text
	start := strings.Index(s, "{")
	if start == -1 {
		return nil
	}

	// Find matching closing brace
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
		if result.Question != "" {
			return &result
		}
	}

	return nil
}

// clampScore ensures a score is within [0.0, 1.0].
func clampScore(score float64) float64 {
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}
