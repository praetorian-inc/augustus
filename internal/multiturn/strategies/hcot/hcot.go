// Package hcot implements the H-CoT (Hijacking Chain-of-Thought) multi-turn
// attack strategy.
//
// Unlike the static H-CoT template probe (which pastes generic <thinking>
// blocks), this adaptive strategy elicits the target's own reasoning style
// in Phase 1, then has the attacker LLM synthesize an execution-phase CoT
// prefix in that style for Phase 2.
//
// Paper: Ma et al., 2025 (https://arxiv.org/abs/2502.12893)
package hcot

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements the adaptive H-CoT multi-turn attack.
type Strategy struct {
	AttackerModel string
	MaxTurns      int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "h-cot" }

// SetMaxTurns configures the maximum turn count.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the H-CoT-specific system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt for the next H-CoT attack turn.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.maxTurns(), s.charBudget())
}

// RephrasePrompt builds a prompt to rephrase a refused question.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return rephrasePrompt(rejectedQuestion, refusalResponse, s.charBudget())
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *Strategy) FeedbackPrompt(response string, score float64, goal string) string {
	return feedbackPrompt(response, score, goal, s.charBudget())
}

// ParseAttackerResponse extracts the question and strategy from attacker output.
func (s *Strategy) ParseAttackerResponse(output string) *multiturn.QuestionResult {
	return multiturn.ExtractJSON(output)
}

func (s *Strategy) charBudget() int {
	return multiturn.ResponseCharBudget(s.AttackerModel)
}

func (s *Strategy) maxTurns() int {
	if s.MaxTurns > 0 {
		return s.MaxTurns
	}
	return 5
}
