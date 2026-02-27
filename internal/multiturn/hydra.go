package multiturn

import (
	"encoding/json"
	"strings"
)

// HydraStrategy implements a single-path multi-turn attack with turn-level
// backtracking on refusal.
// Hydra maintains a single conversation path and rolls back entire turns
// when the target refuses, asking the attacker for a completely different approach.
//
// Reference: PromptFoo Hydra (https://www.promptfoo.dev/docs/red-team/strategies/hydra/)
type HydraStrategy struct {
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *HydraStrategy) Name() string { return "hydra" }

// AttackerSystemPrompt returns the Hydra-specific system prompt.
func (s *HydraStrategy) AttackerSystemPrompt(goal string) string {
	return hydraAttackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking the attacker for the next question.
func (s *HydraStrategy) GenerateTurnPrompt(goal string, turnHistory []TurnRecord, turnNum int) string {
	return hydraTurnPrompt(goal, turnHistory, turnNum, s.MaxTurns)
}

// RephrasePrompt builds a prompt asking the attacker to rephrase a refused question.
// For Hydra, this is the backtrack prompt — fundamentally different approach, not just rephrase.
func (s *HydraStrategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return hydraBacktrackPrompt(rejectedQuestion, refusalResponse)
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *HydraStrategy) FeedbackPrompt(response string, score float64, goal string) string {
	return hydraFeedbackPrompt(response, score, goal)
}

// ParseAttackerResponse extracts the question, strategy, observation, and thought from Hydra attacker output.
// Hydra uses standard observation/thought/strategy/question JSON (no branch_id).
func (s *HydraStrategy) ParseAttackerResponse(output string) *QuestionResult {
	output = strings.TrimSpace(output)

	var hydraResult struct {
		Observation string `json:"observation"`
		Thought     string `json:"thought"`
		Strategy    string `json:"strategy"`
		Question    string `json:"question"`
	}

	// Try direct parse first
	if err := json.Unmarshal([]byte(output), &hydraResult); err == nil && hydraResult.Question != "" {
		return &QuestionResult{
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
				return &QuestionResult{
					Question:    hydraResult.Question,
					Strategy:    hydraResult.Strategy,
					Observation: hydraResult.Observation,
					Thought:     hydraResult.Thought,
				}
			}
		}
	}

	// Fall back to standard ExtractJSON for simpler question/strategy format
	return ExtractJSON(output)
}
