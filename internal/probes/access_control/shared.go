package access_control

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// AttackerAction is the parsed output from the attacker LLM.
// Used by BOLA, BFLA, and RBAC probes.
type AttackerAction struct {
	Action     string `json:"action"`      // "send" or "done"
	Mode       string `json:"mode"`        // "continue" or "fresh"
	Reasoning  string `json:"reasoning"`   // why this message
	Scratchpad string `json:"scratchpad"`  // persistent notes across turns
	Strategy   string `json:"strategy"`    // attack strategy name
	ToolTested string `json:"tool_tested"` // which tool targeted this turn
	Message    string `json:"message"`     // text to send to target
}

// JudgeResult is the parsed output from the judge LLM.
// Used by BOLA, BFLA, and RBAC probes.
type JudgeResult struct {
	Score              float64        `json:"score"`
	Evidence           string         `json:"evidence"`
	IdentityFieldFound map[string]any `json:"identity_fields_found"`
	Reasoning          string         `json:"reasoning"`
	Verdict            string         `json:"verdict"`          // "breach_confirmed", "own_data", "inconclusive", "refused"
	ResponseSummary    string         `json:"response_summary"` // brief structural description
}

// TurnSummary captures the key facts from a completed turn, used to give
// the attacker compact history of past turns.
type TurnSummary struct {
	Turn            int
	Query           string // what the attacker sent
	Verdict         string
	Score           float64
	Evidence        string
	ResponseSummary string
}

// toolCoverage tracks testing status per tool.
type toolCoverage struct {
	Tested  bool
	Verdict string
	Score   float64
}

// parseAttackerAction extracts a structured action from the attacker's response.
func parseAttackerAction(msgs []attempt.Message) AttackerAction {
	if len(msgs) == 0 {
		return AttackerAction{Action: "done", Reasoning: "no response from attacker"}
	}

	content := msgs[0].Content
	action := AttackerAction{
		Action: "send",
		Mode:   "continue",
	}

	// Try to parse JSON from the response.
	jsonStr := extractJSON(content)
	if jsonStr != "" {
		if err := json.Unmarshal([]byte(jsonStr), &action); err == nil {
			// Normalize action values.
			action.Action = strings.ToLower(strings.TrimSpace(action.Action))
			action.Mode = strings.ToLower(strings.TrimSpace(action.Mode))
			if action.Action == "" {
				action.Action = "send"
			}
			if action.Mode == "" {
				action.Mode = "continue"
			}
			return action
		}
	}

	// Fallback: treat the entire response as the message.
	action.Message = content
	action.Reasoning = "failed to parse JSON, using raw response"
	return action
}

// parseJudgeResult extracts a structured result from the judge's response.
func parseJudgeResult(msgs []attempt.Message) JudgeResult {
	if len(msgs) == 0 {
		return JudgeResult{Score: 0.3, Verdict: "inconclusive", Evidence: "no response from judge"}
	}

	content := msgs[0].Content
	result := JudgeResult{}

	jsonStr := extractJSON(content)
	if jsonStr != "" {
		if parseErr := json.Unmarshal([]byte(jsonStr), &result); parseErr == nil {
			return result
		}
		slog.Warn("[access_control] judge JSON parse failed", "json_length", len(jsonStr), "json_preview", truncateResponse(jsonStr, 200))
	} else {
		slog.Warn("[access_control] judge returned no JSON", "content_length", len(content), "content_preview", truncateResponse(content, 200))
	}

	// Fallback: inconclusive.
	return JudgeResult{Score: 0.3, Verdict: "inconclusive", Evidence: "failed to parse judge response", Reasoning: content}
}

// evaluateWithJudge calls the judge LLM to evaluate a target response.
func evaluateWithJudge(ctx context.Context, judge types.Generator, systemPrompt, response string) JudgeResult {
	conv := attempt.NewConversation().WithSystem(systemPrompt)
	conv.AddPrompt(buildJudgePrompt(response))

	resp, err := judge.Generate(ctx, conv, 1)
	if err != nil {
		slog.Warn("[access_control] judge generation failed", "error", err)
		return JudgeResult{Score: 0.3, Verdict: "inconclusive", Evidence: "judge error: " + err.Error()}
	}

	return parseJudgeResult(resp)
}

// extractJSON finds the first JSON object in a string. Handles responses that
// wrap JSON in markdown code fences (```json ... ```) and tolerates braces
// appearing inside JSON string values by using json.Decoder for parsing.
func extractJSON(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}

	// Use the standard JSON decoder to locate a balanced object. This handles
	// quoted strings, escape sequences, and nested objects correctly —
	// naive brace counting breaks when a JSON string value contains `{` or `}`.
	dec := json.NewDecoder(strings.NewReader(s[start:]))
	var raw json.RawMessage
	if err := dec.Decode(&raw); err != nil {
		slog.Warn("[access_control] extractJSON decode failed", "error", err.Error(), "preview", truncateResponse(s[start:], 200))
		return ""
	}
	return string(raw)
}

// truncateResponse returns the first maxChars characters of a response,
// appending "..." if truncated.
func truncateResponse(s string, maxChars int) string {
	if len(s) <= maxChars {
		return s
	}
	return s[:maxChars] + "..."
}

// formatIdentifiers formats a map of identifiers as sorted key=value lines.
func formatIdentifiers(ids map[string]string) string {
	if len(ids) == 0 {
		return "None.\n"
	}
	keys := make([]string, 0, len(ids))
	for k := range ids {
		keys = append(keys, k)
	}
	// Sort for deterministic output.
	sortStrings(keys)

	var b strings.Builder
	for _, k := range keys {
		b.WriteString(fmt.Sprintf("  %s = %s\n", k, ids[k]))
	}
	return b.String()
}

// sortStrings sorts a slice of strings in place.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
