// Package html implements a multi-turn escalation strategy that probes for
// improper output handling (OWASP LLM05): coaxing a target assistant into
// returning raw, unescaped HTML containing web-executable markup.
//
// It plugs into the shared multi-turn engine via the multiturn.Strategy
// interface, exactly like the crescendo/goat/hydra strategies. The engine owns
// conversation management, refusal detection, judge evaluation, backtracking,
// and attempt building; this strategy only supplies the attacker prompts that
// drive the escalation ladder (benign formatting -> stop escaping -> render raw
// -> seed payload).
package html

import (
	"github.com/praetorian-inc/augustus/internal/multiturn"
)

// Strategy implements the HTML output-handling escalation attack.
type Strategy struct {
	// AttackerModel is the attacker model name, used to derive context-aware
	// truncation limits for response text in prompts.
	AttackerModel string

	// MaxTurns is used for rung pacing in prompts.
	MaxTurns int
}

// Name returns the strategy identifier.
func (s *Strategy) Name() string { return "html_escalation" }

// SetMaxTurns configures the maximum turn count for prompt generation.
func (s *Strategy) SetMaxTurns(n int) { s.MaxTurns = n }

// AttackerSystemPrompt returns the output-handling escalation system prompt.
func (s *Strategy) AttackerSystemPrompt(goal string) string {
	return attackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking for the next escalation message.
func (s *Strategy) GenerateTurnPrompt(goal string, turnHistory []multiturn.TurnRecord, turnNum int) string {
	return turnPrompt(goal, turnHistory, turnNum, s.maxTurns(), s.charBudget())
}

// RephrasePrompt builds a prompt to rephrase a refused message.
func (s *Strategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return rephrasePrompt(rejectedQuestion, refusalResponse, s.charBudget())
}

// FeedbackPrompt feeds the target response + score back to the attacker.
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
