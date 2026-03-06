// Package goat implements the GOAT (Generative Offensive Agent Tester) multi-turn attack strategy.
//
// GOAT uses 7 adversarial techniques with Chain-of-Attack-Thought reasoning
// to dynamically adapt its conversational attack strategy across turns.
//
// Paper: Pavlova et al., 2024 (https://arxiv.org/abs/2410.01606)
package goat

import (
	"encoding/json"
	"strings"

	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements the GOAT multi-turn attack.
type Strategy struct {
	// AttackerModel is the attacker model name, used to derive context-aware
	// truncation limits for response text in prompts.
	AttackerModel string

	// MaxTurns is used for turn-count awareness in prompts.
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "goat" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the GOAT-specific system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking for the next attack turn.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.maxTurns(), s.charBudget())
}

// RephrasePrompt builds a prompt to rephrase a refused question using a different technique.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return rephrasePrompt(rejectedQuestion, refusalResponse, s.charBudget())
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *Strategy) FeedbackPrompt(response string, score float64, goal string) string {
	return feedbackPrompt(response, score, goal, s.charBudget())
}

// charBudget returns the per-response character budget based on attacker model.
func (s *Strategy) charBudget() int {
	return multiturn.ResponseCharBudget(s.AttackerModel)
}

// maxTurns returns MaxTurns with a default fallback.
func (s *Strategy) maxTurns() int {
	if s.MaxTurns > 0 {
		return s.MaxTurns
	}
	return 5 // GOAT paper default: k=5
}

// ParseAttackerResponse extracts the question and strategy from GOAT attacker output.
// GOAT outputs include observation, thought, strategy, and question fields.
// Falls back to ExtractJSON for simpler formats.
func (s *Strategy) ParseAttackerResponse(output string) *multiturn.QuestionResult {
	output = strings.TrimSpace(output)

	// Try parsing the full GOAT JSON format with observation/thought/strategy/question
	var goatResult struct {
		Observation string `json:"observation"`
		Thought     string `json:"thought"`
		Strategy    string `json:"strategy"`
		Question    string `json:"question"`
		Summary     string `json:"summary"`
	}

	// Try direct parse first
	if err := json.Unmarshal([]byte(output), &goatResult); err == nil && goatResult.Question != "" {
		return &multiturn.QuestionResult{
			Question:    goatResult.Question,
			Strategy:    goatResult.Strategy,
			Observation: goatResult.Observation,
			Thought:     goatResult.Thought,
			Summary:     goatResult.Summary,
		}
	}

	// Try to find JSON object within surrounding text
	start := strings.Index(output, "{")
	if start != -1 {
		end := strings.LastIndex(output, "}")
		if end > start {
			jsonStr := output[start : end+1]
			if err := json.Unmarshal([]byte(jsonStr), &goatResult); err == nil && goatResult.Question != "" {
				return &multiturn.QuestionResult{
					Question:    goatResult.Question,
					Strategy:    goatResult.Strategy,
					Observation: goatResult.Observation,
					Thought:     goatResult.Thought,
					Summary:     goatResult.Summary,
				}
			}
		}
	}

	// Fall back to standard ExtractJSON for simpler question/strategy format
	return multiturn.ExtractJSON(output)
}
