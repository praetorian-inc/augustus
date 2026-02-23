package multiturn

// Strategy defines how a multi-turn attack generates and adapts questions.
// Each attack type (Crescendo, GOAT, Hydra) implements this interface.
// The engine handles shared infrastructure (conversation management, refusal
// detection, judge evaluation, turn recording, attempt building).
type Strategy interface {
	// Name returns the strategy identifier (e.g., "crescendo").
	Name() string

	// AttackerSystemPrompt returns the system prompt for the attacker LLM.
	AttackerSystemPrompt(goal string) string

	// GenerateTurnPrompt builds the prompt asking the attacker for the next question.
	// turnHistory contains all prior turns, turnNum is the current turn index (1-based).
	GenerateTurnPrompt(goal string, turnHistory []TurnRecord, turnNum int) string

	// RephrasePrompt builds a prompt asking the attacker to rephrase a refused question.
	RephrasePrompt(rejectedQuestion, refusalResponse string) string

	// FeedbackPrompt builds the prompt feeding target response + score back to attacker.
	FeedbackPrompt(response string, score float64, goal string) string

	// ParseAttackerResponse extracts the question and strategy from attacker output.
	ParseAttackerResponse(output string) *QuestionResult
}
