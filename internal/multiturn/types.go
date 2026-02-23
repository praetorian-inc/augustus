// Package multiturn implements a generic multi-turn attack engine.
//
// Unlike the single-turn attack engine in internal/attackengine (used by PAIR/TAP),
// multi-turn attacks maintain full conversation history with the target across all
// turns. The engine is strategy-agnostic: Crescendo, GOAT, and Hydra each implement
// the Strategy interface while the engine handles shared infrastructure.
package multiturn

// TurnRecord captures one turn of a multi-turn attack for reporting and visualization.
type TurnRecord struct {
	TurnNumber     int     `json:"turn_number"`
	Question       string  `json:"question"`
	Response       string  `json:"response"`
	WasRefused     bool    `json:"was_refused"`
	JudgeScore     float64 `json:"judge_score"` // 0.0-1.0
	JudgeReasoning string  `json:"judge_reasoning"`
	Strategy       string  `json:"strategy"` // Attacker's stated strategy for this turn
}

// QuestionResult is the parsed output from an attacker LLM.
type QuestionResult struct {
	Question string `json:"question"`
	Strategy string `json:"strategy"`
}
