package multiturn

// CrescendoStrategy implements the Crescendo multi-turn attack.
// Crescendo starts with benign questions and gradually escalates toward
// a prohibited objective using the foot-in-the-door technique.
//
// Paper: Russinovich et al., 2024 (https://arxiv.org/abs/2404.01833)
type CrescendoStrategy struct{}

// Name returns the strategy identifier.
func (s *CrescendoStrategy) Name() string { return "crescendo" }

// AttackerSystemPrompt returns the Crescendo-specific system prompt.
func (s *CrescendoStrategy) AttackerSystemPrompt(goal string) string {
	return crescendoAttackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking for the next escalating question.
func (s *CrescendoStrategy) GenerateTurnPrompt(goal string, turnHistory []TurnRecord, turnNum int) string {
	return crescendoTurnPrompt(goal, turnHistory, turnNum)
}

// RephrasePrompt builds a prompt to rephrase a refused question.
func (s *CrescendoStrategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return crescendoRephrasePrompt(rejectedQuestion, refusalResponse)
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *CrescendoStrategy) FeedbackPrompt(response string, score float64, goal string) string {
	return crescendoFeedbackPrompt(response, score, goal)
}

// ParseAttackerResponse extracts the question and strategy from attacker output.
func (s *CrescendoStrategy) ParseAttackerResponse(output string) *QuestionResult {
	return ExtractJSON(output)
}
