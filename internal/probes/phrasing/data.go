// Package phrasing provides probes that test LLM vulnerabilities through prompt rephrasing.
//
// These probes reformulate potentially harmful requests using grammatical alterations
// (past tense, future tense, etc.) to attempt bypassing safety filters.
package phrasing

import (
	_ "embed"
	"strings"
)

//go:embed data/past_tense_en.txt
var pastTenseData string

//go:embed data/future_tense_en.txt
var futureTenseData string

// parseLinesFromData extracts non-empty, non-comment lines from embedded data.
func parseLinesFromData(data string) []string {
	lines := strings.Split(data, "\n")
	result := make([]string, 0, len(lines))

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip empty lines and comments
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			result = append(result, trimmed)
		}
	}

	return result
}

// LoadPastTensePrompts returns all embedded past tense prompts.
func LoadPastTensePrompts() []string {
	return parseLinesFromData(pastTenseData)
}

// LoadFutureTensePrompts returns all embedded future tense prompts.
func LoadFutureTensePrompts() []string {
	return parseLinesFromData(futureTenseData)
}
