// Package hydra implements the Hydra single-path multi-turn attack strategy
// with turn-level backtracking on refusal.
//
// Reference: PromptFoo Hydra (https://www.promptfoo.dev/docs/red-team/strategies/hydra/)
package hydra

import (
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements a single-path multi-turn attack with turn-level
// backtracking on refusal.
type Strategy struct {
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "hydra" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the Hydra-specific system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking the attacker for the next question.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.MaxTurns)
}

// RephrasePrompt builds a prompt asking the attacker to rephrase a refused question.
// For Hydra, this is the backtrack prompt — fundamentally different approach, not just rephrase.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return backtrackPrompt(rejectedQuestion, refusalResponse)
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *Strategy) FeedbackPrompt(response string, score float64, goal string) string {
	return feedbackPrompt(response, score, goal)
}

// ParseAttackerResponse extracts the question, strategy, observation, and thought from Hydra attacker output.
func (s *Strategy) ParseAttackerResponse(output string) *multiturn.QuestionResult {
	output = strings.TrimSpace(output)

	var hydraResult struct {
		Observation string `json:"observation"`
		Thought     string `json:"thought"`
		Strategy    string `json:"strategy"`
		Question    string `json:"question"`
	}

	// Try direct parse first
	if err := json.Unmarshal([]byte(output), &hydraResult); err == nil && hydraResult.Question != "" {
		return &multiturn.QuestionResult{
			Question:    hydraResult.Question,
			Strategy:    hydraResult.Strategy,
			Observation: hydraResult.Observation,
			Thought:     hydraResult.Thought,
		}
	}

	// Try to find JSON object within surrounding text
	start := strings.Index(output, "{")
	if start != -1 {
		end := strings.LastIndex(output, "}")
		if end > start {
			jsonStr := output[start : end+1]
			if err := json.Unmarshal([]byte(jsonStr), &hydraResult); err == nil && hydraResult.Question != "" {
				return &multiturn.QuestionResult{
					Question:    hydraResult.Question,
					Strategy:    hydraResult.Strategy,
					Observation: hydraResult.Observation,
					Thought:     hydraResult.Thought,
				}
			}
		}
	}

	// Fall back to standard ExtractJSON for simpler question/strategy format
	return multiturn.ExtractJSON(output)
}
