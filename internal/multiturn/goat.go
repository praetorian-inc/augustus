package multiturn

import (
	"encoding/json"
	"strings"
)

// GoatStrategy implements the GOAT (Generative Offensive Agent Tester) multi-turn attack.
// GOAT uses a more aggressive conversational approach than Crescendo, employing 7 adversarial
// techniques with Chain-of-Attack-Thought reasoning to dynamically adapt its strategy.
//
// Paper: Pavlova et al., 2024 (https://arxiv.org/abs/2410.01606)
type GoatStrategy struct{}

// Name returns the strategy identifier.
func (s *GoatStrategy) Name() string { return "goat" }

// AttackerSystemPrompt returns the GOAT-specific system prompt.
func (s *GoatStrategy) AttackerSystemPrompt(goal string) string {
	return goatAttackerSystemPrompt
}

// GenerateTurnPrompt builds the prompt asking for the next attack turn.
func (s *GoatStrategy) GenerateTurnPrompt(goal string, turnHistory []TurnRecord, turnNum int) string {
	return goatTurnPrompt(goal, turnHistory, turnNum)
}

// RephrasePrompt builds a prompt to rephrase a refused question using a different technique.
func (s *GoatStrategy) RephrasePrompt(rejectedQuestion, refusalResponse string) string {
	return goatRephrasePrompt(rejectedQuestion, refusalResponse)
}

// FeedbackPrompt feeds target response + score back to the attacker.
func (s *GoatStrategy) FeedbackPrompt(response string, score float64, goal string) string {
	return goatFeedbackPrompt(response, score, goal)
}

// ParseAttackerResponse extracts the question and strategy from GOAT attacker output.
// GOAT outputs include observation, thought, strategy, and question fields.
// Falls back to ExtractJSON for simpler formats.
func (s *GoatStrategy) ParseAttackerResponse(output string) *QuestionResult {
	output = strings.TrimSpace(output)

	// Try parsing the full GOAT JSON format with observation/thought/strategy/question
	var goatResult struct {
		Observation string `json:"observation"`
		Thought     string `json:"thought"`
		Strategy    string `json:"strategy"`
		Question    string `json:"question"`
	}

	// Try direct parse first
	if err := json.Unmarshal([]byte(output), &goatResult); err == nil && goatResult.Question != "" {
		return &QuestionResult{
			Question: goatResult.Question,
			Strategy: goatResult.Strategy,
		}
	}

	// Try to find JSON object within surrounding text
	start := strings.Index(output, "{")
	if start != -1 {
		end := strings.LastIndex(output, "}")
		if end > start {
			jsonStr := output[start : end+1]
			if err := json.Unmarshal([]byte(jsonStr), &goatResult); err == nil && goatResult.Question != "" {
				return &QuestionResult{
					Question: goatResult.Question,
					Strategy: goatResult.Strategy,
				}
			}
		}
	}

	// Fall back to standard ExtractJSON for simpler question/strategy format
	return ExtractJSON(output)
}
