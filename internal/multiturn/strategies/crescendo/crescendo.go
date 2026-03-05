// Package crescendo implements the Crescendo multi-turn attack strategy.
//
// Crescendo starts with benign questions and gradually escalates toward
// a prohibited objective using the foot-in-the-door technique.
//
// Paper: Russinovich et al., 2024 (https://arxiv.org/abs/2404.01833)
package crescendo

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements the Crescendo multi-turn attack.
type Strategy struct {
	// AttackerModel is the attacker model name, used to derive context-aware
	// truncation limits for response text in prompts.
	AttackerModel string

	// MaxTurns is used for turn-count urgency in prompts.
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "crescendo" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the Crescendo-specific system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking for the next escalating question.
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

// charBudget returns the per-response character budget based on attacker model.
func (s *Strategy) charBudget() int {
	return multiturn.ResponseCharBudget(s.AttackerModel)
}

// maxTurns returns MaxTurns with a default fallback.
func (s *Strategy) maxTurns() int {
	if s.MaxTurns > 0 {
		return s.MaxTurns
	}
	return 10
}
