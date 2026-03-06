// Package mischievous implements a subtle multi-turn attack that simulates an
// innocent, curious user who gradually probes AI agent boundaries through
// natural-sounding conversation.
//
// Inspired by Tau-bench (https://github.com/sierra-research/tau-bench) and
// promptfoo's mischievous-user strategy.
//
// Reference: https://www.promptfoo.dev/docs/red-team/strategies/mischievous-user/
package mischievous

import (
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements the mischievous user multi-turn attack.
type Strategy struct {
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "mischievous_user" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the mischievous user system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking the attacker for the next question.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.MaxTurns)
}

// RephrasePrompt builds a prompt asking the attacker to rephrase a refused question.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return rephrasePrompt(rejectedQuestion, refusalResponse)
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *Strategy) FeedbackPrompt(response string, score float64, goal string) string {
	return feedbackPrompt(response, score, goal)
}

// ParseAttackerResponse extracts the question and strategy from attacker output.
func (s *Strategy) ParseAttackerResponse(output string) *multiturn.QuestionResult {
	output = strings.TrimSpace(output)
	var result struct {
		Thought  string `json:"thought"`
		Strategy string `json:"strategy"`
		Question string `json:"question"`
		Summary  string `json:"summary"`
	}
	if err := json.Unmarshal([]byte(output), &result); err == nil && result.Question != "" {
		return &multiturn.QuestionResult{
			Question: result.Question,
			Strategy: result.Strategy,
			Thought:  result.Thought,
			Summary:  result.Summary,
		}
	}
	start := strings.Index(output, "{")
	if start != -1 {
		end := strings.LastIndex(output, "}")
		if end > start {
			jsonStr := output[start : end+1]
			if err := json.Unmarshal([]byte(jsonStr), &result); err == nil && result.Question != "" {
				return &multiturn.QuestionResult{
					Question: result.Question,
					Strategy: result.Strategy,
					Thought:  result.Thought,
					Summary:  result.Summary,
				}
			}
		}
	}
	return multiturn.ExtractJSON(output)
}
