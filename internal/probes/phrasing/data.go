// Package phrasing provides probes that test LLM vulnerabilities through prompt rephrasing.
//
// These probes reformulate potentially harmful requests using grammatical alterations
// (past tense, future tense, etc.) to attempt bypassing safety filters.
package phrasing

import (
	_ "embed"

	"github.com/praetorian-inc/augustus/pkg/probes"
)

//go:embed data/past_tense_en.txt
var pastTenseData string

//go:embed data/future_tense_en.txt
var futureTenseData string

// LoadPastTensePrompts returns all embedded past tense prompts.
func LoadPastTensePrompts() []string {
	return probes.SplitLinesSkipComments(pastTenseData)
}

// LoadFutureTensePrompts returns all embedded future tense prompts.
func LoadFutureTensePrompts() []string {
	return probes.SplitLinesSkipComments(futureTenseData)
}
