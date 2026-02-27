package results

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// turnData is the internal representation of a turn record used during HTML rendering.
type turnData struct {
	TurnNumber     int
	Question       string
	Response       string
	WasRefused     bool
	WasBacktracked bool
	JudgeScore     float64
	Strategy       string
	RefusalType    string
	Observation    string
	Thought        string
	JudgeReasoning string
}

// strategyColor returns a CSS color for a strategy category.
func strategyColor(strategy string) string {
	palette := []string{
		"#3498db", "#9b59b6", "#27ae60", "#e67e22",
		"#16a085", "#795548", "#e91e63", "#c0392b",
		"#607d8b", "#ff9800",
	}
	h := 0
	for _, c := range strategy {
		h = h*31 + int(c)
	}
	if h < 0 {
		h = -h
	}
	return palette[h%len(palette)]
}

// scoreColor returns a CSS color for a judge score.
func scoreColor(score float64) string {
	if score >= 0.8 {
		return "#dc3545"
	}
	if score >= 0.5 {
		return "#fd7e14"
	}
	if score >= 0.3 {
		return "#ffc107"
	}
	return "#28a745"
}

// WriteHTML generates a self-contained HTML report from scan attempts.
func WriteHTML(outputPath string, attempts []*attempt.Attempt) error {
	summary := ComputeSummary(attempts)

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directories: %w", err)
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	var sb strings.Builder

	sb.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n    <meta charset=\"UTF-8\">\n    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n    <title>Augustus Scan Report</title>\n    <style>\n")
	writeCSS(&sb)
	sb.WriteString("    </style>\n</head>\n<body>\n    <div class=\"container\">\n")
	sb.WriteString("        <h1>Augustus Scan Report</h1>\n")
	sb.WriteString("        <div class=\"timestamp\">Generated: " + time.Now().Format(time.RFC3339) + "</div>\n")

	// Summary section
	sb.WriteString(fmt.Sprintf(`        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card total"><h3>Total Attempts</h3><div class="value">%d</div></div>
            <div class="summary-card passed"><h3>Passed</h3><div class="value">%d</div></div>
            <div class="summary-card failed"><h3>Failed</h3><div class="value">%d</div></div>
        </div>
`, summary.TotalAttempts, summary.Passed, summary.Failed))

	if len(attempts) == 0 {
		sb.WriteString("        <div class=\"no-attempts\"><h2>No attempts recorded</h2><p>Run a scan to generate results</p></div>\n")
	} else {
		probeAttempts := make(map[string][]*attempt.Attempt)
		for _, a := range attempts {
			probeAttempts[a.Probe] = append(probeAttempts[a.Probe], a)
		}

		for probeName, probeAtts := range probeAttempts {
			stats := summary.ByProbe[probeName]
			sb.WriteString(fmt.Sprintf("        <div class=\"probe-section\">\n            <div class=\"probe-header\">\n                <h2>%s</h2>\n                <div class=\"probe-stats\">%d/%d passed</div>\n            </div>\n            <div class=\"probe-content\">\n",
				html.EscapeString(probeName), stats.Passed, stats.Total))

			for _, att := range probeAtts {
				writeAttemptHTML(&sb, att)
			}

			sb.WriteString("            </div>\n        </div>\n")
		}
	}

	sb.WriteString("    </div>\n</body>\n</html>")

	if _, err := file.WriteString(sb.String()); err != nil {
		return fmt.Errorf("failed to write HTML content: %w", err)
	}
	return nil
}

func writeCSS(sb *strings.Builder) {
	sb.WriteString(`        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; margin-bottom: 10px; font-size: 2em; }
        h2 { color: #2c3e50; margin-bottom: 15px; font-size: 1.5em; margin-top: 20px; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; margin-bottom: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 40px; }
        .summary-card { background: #ecf0f1; padding: 20px; border-radius: 6px; text-align: center; }
        .summary-card.passed { background: #d4edda; border-left: 4px solid #28a745; }
        .summary-card.failed { background: #f8d7da; border-left: 4px solid #dc3545; }
        .summary-card.total { background: #d1ecf1; border-left: 4px solid #17a2b8; }
        .summary-card h3 { font-size: 0.9em; color: #6c757d; margin-bottom: 10px; text-transform: uppercase; letter-spacing: 1px; }
        .summary-card .value { font-size: 2.5em; font-weight: bold; color: #2c3e50; }
        .probe-section { margin-bottom: 30px; }
        .probe-header { background: #343a40; color: white; padding: 15px 20px; border-radius: 6px 6px 0 0; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .probe-header:hover { background: #23272b; }
        .probe-header h2 { font-size: 1.2em; margin: 0; }
        .probe-stats { font-size: 0.9em; color: #adb5bd; }
        .probe-content { border: 1px solid #dee2e6; border-top: none; border-radius: 0 0 6px 6px; overflow: hidden; }
        .attempt { padding: 15px 20px; border-bottom: 1px solid #dee2e6; }
        .attempt:last-child { border-bottom: none; }
        .attempt-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .status-badge { padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600; text-transform: uppercase; }
        .status-badge.pass { background: #d4edda; color: #155724; }
        .status-badge.fail { background: #f8d7da; color: #721c24; }
        .attempt-detail { margin: 10px 0; }
        .attempt-detail strong { display: inline-block; min-width: 100px; color: #495057; }
        .prompt, .response { background: #f8f9fa; padding: 10px; border-radius: 4px; margin-top: 5px; font-family: 'Courier New', monospace; font-size: 0.9em; white-space: pre-wrap; word-wrap: break-word; }
        .scores { display: inline-block; padding: 2px 8px; background: #e9ecef; border-radius: 4px; font-family: monospace; }
        .no-attempts { text-align: center; padding: 60px 20px; color: #6c757d; }
        .no-attempts h2 { margin-bottom: 10px; font-size: 1.5em; }
        .conversation-flow { margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 6px; }
        .conversation-header { font-weight: 600; margin-bottom: 15px; padding-bottom: 10px; border-bottom: 2px solid #dee2e6; }
        .turn { margin-bottom: 15px; padding: 12px; border-radius: 6px; border-left: 4px solid #dee2e6; }
        .turn-header { display: flex; justify-content: space-between; margin-bottom: 8px; font-weight: 600; }
        .turn-score { font-family: monospace; }
        .turn-success { border-left-color: #dc3545; background: #fff5f5; }
        .turn-low { border-left-color: #28a745; }
        .turn-medium { border-left-color: #ffc107; }
        .turn-high { border-left-color: #fd7e14; }
        .turn-refused { border-left-color: #6c757d; background: #f0f0f0; opacity: 0.7; }
        .turn-question, .turn-response { margin: 5px 0; padding: 8px; border-radius: 4px; font-size: 0.9em; white-space: pre-wrap; word-wrap: break-word; }
        .turn-question { background: #e3f2fd; }
        .turn-response { background: #f5f5f5; }
        .score-bar { height: 4px; background: #e9ecef; border-radius: 2px; margin-top: 8px; }
        .score-bar-fill { height: 100%; border-radius: 2px; transition: width 0.3s; }
        /* Hydra */
        .hydra-attack { margin: 15px 0; padding: 20px; background: #fafbfc; border-radius: 8px; border: 1px solid #e1e4e8; }
        .hydra-header { font-weight: 700; font-size: 1.1em; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
        .hydra-result-tag { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.75em; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
        .hydra-result-tag.achieved { background: #ffdce0; color: #86181d; }
        .hydra-result-tag.not-achieved { background: #dcffe4; color: #165c26; }
        .hydra-goal { color: #586069; font-size: 0.9em; margin-bottom: 16px; }
        .hydra-stats-bar { display: flex; gap: 20px; flex-wrap: wrap; margin-bottom: 20px; padding: 12px 16px; background: #f1f3f5; border-radius: 6px; font-size: 0.85em; color: #586069; }
        .hydra-stat-label { margin-right: 4px; }
        .hydra-stat-value { font-weight: 700; font-family: monospace; color: #24292e; }
        .hydra-chart-section { margin-bottom: 20px; }
        .hydra-chart-label { font-size: 0.8em; color: #6a737d; margin-bottom: 6px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .hydra-chart-box { padding: 12px; background: white; border-radius: 6px; border: 1px solid #e1e4e8; }
        .hydra-chart-box svg { width: 100%; height: 80px; display: block; }
        .hydra-chart-legend { display: flex; gap: 16px; margin-top: 8px; font-size: 0.75em; color: #6a737d; }
        .hydra-chart-legend-item { display: flex; align-items: center; gap: 4px; }
        .hydra-chart-legend-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
        .hydra-chart-legend-x { color: #cb2431; font-weight: 700; font-size: 1.1em; line-height: 1; }
        .hydra-timeline-label { font-size: 0.8em; color: #6a737d; margin-bottom: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; }
        .hydra-timeline { position: relative; padding-left: 36px; }
        .hydra-timeline::before { content: ''; position: absolute; left: 15px; top: 12px; bottom: 12px; width: 2px; background: #d1d5da; }
        .hydra-event { position: relative; margin-bottom: 12px; }
        .hydra-event:last-child { margin-bottom: 0; }
        .hydra-dot { position: absolute; left: -36px; top: 6px; width: 22px; height: 22px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.7em; font-weight: 700; color: white; z-index: 1; box-shadow: 0 1px 3px rgba(0,0,0,0.15); }
        .hydra-accepted .hydra-dot { background: #0366d6; }
        .hydra-backtracked { padding-left: 20px; }
        .hydra-backtracked .hydra-dot { background: #cb2431; left: -56px; }
        .hydra-backtracked::before { content: ''; position: absolute; left: -22px; top: 16px; width: 20px; height: 2px; background: #cb2431; opacity: 0.5; }
        .hydra-card { background: white; border: 1px solid #e1e4e8; border-radius: 6px; padding: 10px 14px; }
        .hydra-backtracked .hydra-card { background: #ffeef0; border-color: #fdaeb7; }
        .hydra-card-header { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .hydra-strategy-badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.7em; font-weight: 600; color: white; text-transform: uppercase; letter-spacing: 0.5px; white-space: normal; vertical-align: middle; }
        .hydra-score-pill { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.75em; font-weight: 700; font-family: monospace; }
        .hydra-badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 0.7em; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px; white-space: nowrap; }
        .hydra-badge-backtrack { background: #ffdce0; color: #86181d; }
        .hydra-badge-refused { background: #ffdce0; color: #86181d; }
        .hydra-badge-deflected { background: #fff5b1; color: #735c0f; }
        .hydra-badge-partial { background: #dbedff; color: #0366d6; }
        .hydra-badge-engaged { background: #dcffe4; color: #165c26; }
        .hydra-badge-success { background: #ffdce0; color: #86181d; font-weight: 700; }
        .hydra-details { margin-top: 6px; }
        .hydra-details summary { cursor: pointer; color: #0366d6; font-size: 0.8em; padding: 2px 0; user-select: none; list-style: none; }
        .hydra-details summary::-webkit-details-marker { display: none; }
        .hydra-details summary::before { content: '\25B6\00a0'; font-size: 0.7em; transition: transform 0.15s; display: inline-block; }
        .hydra-details[open] summary::before { transform: rotate(90deg); }
        .hydra-details summary:hover { text-decoration: underline; }
        .hydra-reasoning { margin: 8px 0; padding: 8px 12px; background: #f6f8fa; border-radius: 4px; font-size: 0.82em; color: #586069; border-left: 3px solid #d1d5da; }
        .hydra-reasoning strong { color: #24292e; display: inline-block; min-width: 85px; }
        .hydra-reasoning-line { margin: 3px 0; }
        .hydra-conv { margin-top: 8px; }
        .hydra-q, .hydra-a { padding: 8px 12px; border-radius: 4px; font-size: 0.82em; white-space: pre-wrap; word-wrap: break-word; margin: 4px 0; max-height: 300px; overflow-y: auto; }
        .hydra-q { background: #e3f2fd; border-left: 3px solid #0366d6; }
        .hydra-a { background: #f6f8fa; border-left: 3px solid #d1d5da; }
        .hydra-backtracked .hydra-a { background: #ffeef0; border-left-color: #cb2431; }
        .hydra-judge-reasoning { margin-top: 6px; padding: 6px 10px; background: #f1f3f5; border-radius: 4px; font-size: 0.78em; color: #6a737d; }
`)
}

func writeAttemptHTML(sb *strings.Builder, att *attempt.Attempt) {
	scores := att.GetEffectiveScores()
	passed := isPassed(att.Status, scores)

	statusClass := "pass"
	statusText := "PASS"
	if !passed {
		statusClass = "fail"
		statusText = "FAIL"
	}

	response := ""
	if len(att.Outputs) > 0 {
		response = att.Outputs[0]
	}

	scoresStr := "[]"
	if len(att.Scores) > 0 {
		parts := make([]string, len(att.Scores))
		for i, s := range att.Scores {
			parts[i] = fmt.Sprintf("%.2f", s)
		}
		scoresStr = "[" + strings.Join(parts, ", ") + "]"
	}

	attackType, isMultiTurn := att.Metadata["attack_type"].(string)

	sb.WriteString(fmt.Sprintf("                <div class=\"attempt\">\n                    <div class=\"attempt-header\">\n                        <span class=\"status-badge %s\">%s</span>\n                        <span class=\"scores\">%s</span>\n                    </div>\n",
		statusClass, statusText, scoresStr))
	sb.WriteString("                    <div class=\"attempt-detail\"><strong>Detector:</strong> " + html.EscapeString(att.Detector) + "</div>\n")

	if !isMultiTurn {
		sb.WriteString("                    <div class=\"attempt-detail\"><strong>Prompt:</strong><div class=\"prompt\">" + html.EscapeString(att.Prompt) + "</div></div>\n")
		sb.WriteString("                    <div class=\"attempt-detail\"><strong>Response:</strong><div class=\"response\">" + html.EscapeString(response) + "</div></div>\n")
	}
	sb.WriteString("                    <div class=\"attempt-detail\"><strong>Timestamp:</strong> " + att.Timestamp.Format(time.RFC3339) + "</div>\n")

	if isMultiTurn {
		goal, _ := att.Metadata["goal"].(string)
		totalTurns := metadataInt(att.Metadata, "total_turns")
		succeeded, _ := att.Metadata["succeeded"].(bool)
		totalBacktracks := metadataInt(att.Metadata, "total_backtracks")
		turns := parseTurnRecords(att.Metadata["turn_records"])

		if attackType == "hydra" {
			renderHydraAttack(sb, turns, goal, totalTurns, succeeded, totalBacktracks)
		} else {
			renderStandardMultiTurn(sb, turns, attackType, goal, totalTurns, succeeded)
		}
	}

	sb.WriteString("                </div>\n")
}

// metadataInt extracts an int from metadata, handling both int and float64 (from JSON).
func metadataInt(metadata map[string]any, key string) int {
	if v, ok := metadata[key].(int); ok {
		return v
	}
	if v, ok := metadata[key].(float64); ok {
		return int(v)
	}
	return 0
}

// parseTurnRecords extracts turn data from metadata, handling both in-memory and JSON-deserialized formats.
func parseTurnRecords(raw any) []turnData {
	var turns []turnData
	switch records := raw.(type) {
	case []any:
		for _, r := range records {
			if rec, ok := r.(map[string]any); ok {
				turns = append(turns, parseTurnMap(rec))
			}
		}
	default:
		if records != nil {
			jsonBytes, err := json.Marshal(records)
			if err == nil {
				var rawTurns []map[string]any
				if json.Unmarshal(jsonBytes, &rawTurns) == nil {
					for _, rec := range rawTurns {
						turns = append(turns, parseTurnMap(rec))
					}
				}
			}
		}
	}
	return turns
}

func parseTurnMap(rec map[string]any) turnData {
	td := turnData{}
	if v, ok := rec["turn_number"].(float64); ok {
		td.TurnNumber = int(v)
	}
	if v, ok := rec["turn_number"].(int); ok {
		td.TurnNumber = v
	}
	td.Question, _ = rec["question"].(string)
	td.Response, _ = rec["response"].(string)
	td.WasRefused, _ = rec["was_refused"].(bool)
	td.WasBacktracked, _ = rec["was_backtracked"].(bool)
	if v, ok := rec["judge_score"].(float64); ok {
		td.JudgeScore = v
	}
	td.Strategy, _ = rec["strategy"].(string)
	td.RefusalType, _ = rec["refusal_type"].(string)
	td.Observation, _ = rec["observation"].(string)
	td.Thought, _ = rec["thought"].(string)
	td.JudgeReasoning, _ = rec["judge_reasoning"].(string)
	return td
}

// renderStandardMultiTurn renders the existing flat turn list for Crescendo/GOAT attacks.
func renderStandardMultiTurn(sb *strings.Builder, turns []turnData, attackType, goal string, totalTurns int, succeeded bool) {
	resultText := "NOT ACHIEVED"
	if succeeded {
		resultText = "ACHIEVED"
	}

	sb.WriteString("                    <div class=\"conversation-flow\">\n")
	sb.WriteString("                        <div class=\"conversation-header\">" +
		html.EscapeString(fmt.Sprintf("%s Attack - %d turns - %s", attackType, totalTurns, resultText)) + "</div>")

	if goal != "" {
		sb.WriteString("\n                        <div style=\"margin-bottom: 10px; color: #495057;\"><strong>Goal:</strong> " + html.EscapeString(goal) + "</div>")
	}

	for _, turn := range turns {
		turnClass := "turn"
		if turn.WasRefused {
			turnClass += " turn-refused"
		} else if turn.JudgeScore >= 0.8 {
			turnClass += " turn-success"
		} else if turn.JudgeScore >= 0.5 {
			turnClass += " turn-high"
		} else if turn.JudgeScore >= 0.3 {
			turnClass += " turn-medium"
		} else {
			turnClass += " turn-low"
		}

		successTag := ""
		if turn.JudgeScore >= 0.8 {
			successTag = " [SUCCESS]"
		}
		refusedTag := ""
		if turn.WasRefused {
			refusedTag = " [REFUSED]"
		}

		barColor := "#28a745"
		if turn.JudgeScore >= 0.8 {
			barColor = "#dc3545"
		} else if turn.JudgeScore >= 0.5 {
			barColor = "#fd7e14"
		} else if turn.JudgeScore >= 0.3 {
			barColor = "#ffc107"
		}

		sb.WriteString(fmt.Sprintf("\n                        <div class=\"%s\">\n                            <div class=\"turn-header\"><span>Turn %d%s%s</span><span class=\"turn-score\">Score: %.2f</span></div>\n                            <div class=\"turn-question\"><strong>Attacker:</strong> %s</div>\n                            <div class=\"turn-response\"><strong>Target:</strong> %s</div>\n                            <div class=\"score-bar\"><div class=\"score-bar-fill\" style=\"width: %.0f%%; background: %s;\"></div></div>\n                        </div>",
			turnClass, turn.TurnNumber, successTag, refusedTag, turn.JudgeScore,
			html.EscapeString(turn.Question), html.EscapeString(turn.Response),
			turn.JudgeScore*100, barColor))
	}

	sb.WriteString("\n                    </div>")
}

// renderHydraAttack renders the Hydra-specific graph visualization.
func renderHydraAttack(sb *strings.Builder, turns []turnData, goal string, _ int, succeeded bool, _ int) {
	acceptedCount := 0
	backtrackCount := 0
	bestScore := 0.0
	for _, t := range turns {
		if t.WasBacktracked {
			backtrackCount++
		} else {
			acceptedCount++
		}
		if t.JudgeScore > bestScore {
			bestScore = t.JudgeScore
		}
	}

	resultTagClass := "not-achieved"
	resultText := "NOT ACHIEVED"
	if succeeded {
		resultTagClass = "achieved"
		resultText = "ACHIEVED"
	}

	sb.WriteString("                    <div class=\"hydra-attack\">\n")

	// Header
	sb.WriteString(fmt.Sprintf("                        <div class=\"hydra-header\"><span>Hydra Attack</span><span class=\"hydra-result-tag %s\">%s</span></div>\n", resultTagClass, resultText))

	if goal != "" {
		sb.WriteString("                        <div class=\"hydra-goal\"><strong>Goal:</strong> " + html.EscapeString(goal) + "</div>\n")
	}

	// Stats bar
	sb.WriteString(fmt.Sprintf("                        <div class=\"hydra-stats-bar\">\n                            <span><span class=\"hydra-stat-label\">Accepted Turns:</span> <span class=\"hydra-stat-value\">%d</span></span>\n                            <span><span class=\"hydra-stat-label\">Backtracks:</span> <span class=\"hydra-stat-value\">%d</span></span>\n                            <span><span class=\"hydra-stat-label\">Total Events:</span> <span class=\"hydra-stat-value\">%d</span></span>\n                            <span><span class=\"hydra-stat-label\">Best Score:</span> <span class=\"hydra-stat-value\">%.2f</span></span>\n                        </div>\n",
		acceptedCount, backtrackCount, len(turns), bestScore))

	// Score sparkline
	if len(turns) >= 2 {
		sb.WriteString("                        <div class=\"hydra-chart-section\">\n                            <div class=\"hydra-chart-label\">Score Progression</div>\n                            <div class=\"hydra-chart-box\">\n")
		renderHydraSparkline(sb, turns)
		sb.WriteString("                                <div class=\"hydra-chart-legend\">\n                                    <span class=\"hydra-chart-legend-item\"><span class=\"hydra-chart-legend-dot\" style=\"background:#0366d6\"></span> Accepted turn</span>\n                                    <span class=\"hydra-chart-legend-item\"><span class=\"hydra-chart-legend-x\">&#10005;</span> Backtracked</span>\n                                    <span class=\"hydra-chart-legend-item\"><span style=\"border-top:2px dashed #dc3545;width:16px;display:inline-block;vertical-align:middle\"></span> Success threshold</span>\n                                </div>\n                            </div>\n                        </div>\n")
	}

	// Timeline
	sb.WriteString("                        <div class=\"hydra-timeline-label\">Attack Timeline</div>\n                        <div class=\"hydra-timeline\">\n")

	acceptedIdx := 0
	for _, turn := range turns {
		if turn.WasBacktracked {
			renderHydraBacktrackedEvent(sb, turn)
		} else {
			acceptedIdx++
			renderHydraAcceptedEvent(sb, turn, acceptedIdx)
		}
	}

	sb.WriteString("                        </div>\n")
	sb.WriteString("                    </div>")
}

func renderHydraAcceptedEvent(sb *strings.Builder, turn turnData, displayNum int) {
	badgeColor := strategyColor(turn.Strategy)
	cat := extractCategoryForDisplay(turn.Strategy)
	if cat == "" {
		cat = "UNKNOWN"
	}

	scorePillBg := "#e1e4e8"
	scorePillColor := "#24292e"
	if turn.JudgeScore >= 0.8 {
		scorePillBg = "#ffdce0"
		scorePillColor = "#86181d"
	} else if turn.JudgeScore >= 0.5 {
		scorePillBg = "#fff5b1"
		scorePillColor = "#735c0f"
	} else if turn.JudgeScore >= 0.3 {
		scorePillBg = "#dbedff"
		scorePillColor = "#0366d6"
	}

	refusalBadge := ""
	switch turn.RefusalType {
	case "soft_deflected":
		refusalBadge = "<span class=\"hydra-badge hydra-badge-deflected\">deflected</span>"
	case "partially_complied":
		refusalBadge = "<span class=\"hydra-badge hydra-badge-partial\">partial</span>"
	case "hard_refused":
		refusalBadge = "<span class=\"hydra-badge hydra-badge-refused\">refused</span>"
	case "":
		if turn.JudgeScore >= 0.4 {
			refusalBadge = "<span class=\"hydra-badge hydra-badge-engaged\">engaged</span>"
		}
	}

	successBadge := ""
	if turn.JudgeScore >= 0.8 {
		successBadge = "<span class=\"hydra-badge hydra-badge-success\">goal progress!</span>"
	}

	sb.WriteString(fmt.Sprintf("                            <div class=\"hydra-event hydra-accepted\">\n                                <div class=\"hydra-dot\">%d</div>\n                                <div class=\"hydra-card\">\n                                    <div class=\"hydra-card-header\">\n                                        <span class=\"hydra-strategy-badge\" title=\"%s\" style=\"background:%s\">%s</span>\n                                        <span class=\"hydra-score-pill\" style=\"background:%s;color:%s\">%.2f</span>\n                                        %s%s\n                                    </div>\n",
		displayNum, html.EscapeString(turn.Strategy), badgeColor, html.EscapeString(cat), scorePillBg, scorePillColor, turn.JudgeScore, refusalBadge, successBadge))

	sb.WriteString("                                    <details class=\"hydra-details\">\n                                        <summary>View attacker reasoning &amp; conversation</summary>\n")

	if turn.Observation != "" || turn.Thought != "" {
		sb.WriteString("                                        <div class=\"hydra-reasoning\">\n")
		if turn.Observation != "" {
			sb.WriteString("                                            <div class=\"hydra-reasoning-line\"><strong>Observation:</strong> " + html.EscapeString(turn.Observation) + "</div>\n")
		}
		if turn.Thought != "" {
			sb.WriteString("                                            <div class=\"hydra-reasoning-line\"><strong>Thought:</strong> " + html.EscapeString(turn.Thought) + "</div>\n")
		}
		sb.WriteString("                                        </div>\n")
	}

	sb.WriteString("                                        <div class=\"hydra-conv\">\n                                            <div class=\"hydra-q\"><strong>Attacker:</strong> " + html.EscapeString(turn.Question) + "</div>\n                                            <div class=\"hydra-a\"><strong>Target:</strong> " + html.EscapeString(turn.Response) + "</div>\n                                        </div>\n")

	if turn.JudgeReasoning != "" {
		sb.WriteString("                                        <div class=\"hydra-judge-reasoning\"><strong>Judge:</strong> " + html.EscapeString(turn.JudgeReasoning) + "</div>\n")
	}

	sb.WriteString("                                    </details>\n                                </div>\n                            </div>\n")
}

func renderHydraBacktrackedEvent(sb *strings.Builder, turn turnData) {
	badgeColor := strategyColor(turn.Strategy)
	cat := extractCategoryForDisplay(turn.Strategy)
	if cat == "" {
		cat = "UNKNOWN"
	}

	// Determine labels based on whether this was an actual refusal or just below threshold
	detailsSummary := "View backtracked attempt"
	responseLabelPrefix := "Target:"
	scoreBadge := ""
	if turn.WasRefused {
		detailsSummary = "View refused attempt"
		responseLabelPrefix = "Target refused:"
	} else {
		// Show score for non-refusal backtracks
		scoreBadge = fmt.Sprintf(" <span class=\"hydra-score-pill\" style=\"background:#e1e4e8;color:#6a737d\">%.2f</span>", turn.JudgeScore)
	}

	sb.WriteString(fmt.Sprintf("                            <div class=\"hydra-event hydra-backtracked\">\n                                <div class=\"hydra-dot\">&#10005;</div>\n                                <div class=\"hydra-card\">\n                                    <div class=\"hydra-card-header\">\n                                        <span class=\"hydra-strategy-badge\" title=\"%s\" style=\"background:%s;opacity:0.7\">%s</span>\n                                        <span class=\"hydra-badge hydra-badge-backtrack\">rolled back</span>%s\n                                    </div>\n",
		html.EscapeString(turn.Strategy), badgeColor, html.EscapeString(cat), scoreBadge))

	sb.WriteString("                                    <details class=\"hydra-details\">\n                                        <summary>" + detailsSummary + "</summary>\n")

	if turn.Observation != "" || turn.Thought != "" {
		sb.WriteString("                                        <div class=\"hydra-reasoning\">\n")
		if turn.Observation != "" {
			sb.WriteString("                                            <div class=\"hydra-reasoning-line\"><strong>Observation:</strong> " + html.EscapeString(turn.Observation) + "</div>\n")
		}
		if turn.Thought != "" {
			sb.WriteString("                                            <div class=\"hydra-reasoning-line\"><strong>Thought:</strong> " + html.EscapeString(turn.Thought) + "</div>\n")
		}
		sb.WriteString("                                        </div>\n")
	}

	sb.WriteString("                                        <div class=\"hydra-conv\">\n                                            <div class=\"hydra-q\"><strong>Attacker:</strong> " + html.EscapeString(turn.Question) + "</div>\n                                            <div class=\"hydra-a\"><strong>" + responseLabelPrefix + "</strong> " + html.EscapeString(turn.Response) + "</div>\n                                        </div>\n")

	if turn.JudgeReasoning != "" {
		sb.WriteString("                                        <div class=\"hydra-judge-reasoning\"><strong>Judge:</strong> " + html.EscapeString(turn.JudgeReasoning) + "</div>\n")
	}

	sb.WriteString("                                    </details>\n                                </div>\n                            </div>\n")
}

func renderHydraSparkline(sb *strings.Builder, turns []turnData) {
	svgW := 600.0
	svgH := 80.0
	pad := 12.0
	drawW := svgW - 2*pad
	drawH := svgH - 2*pad

	n := len(turns)
	if n < 2 {
		return
	}

	sb.WriteString(fmt.Sprintf("                                <svg viewBox=\"0 0 %.0f %.0f\" preserveAspectRatio=\"xMidYMid meet\">\n", svgW, svgH))

	// Threshold line
	threshY := pad + (1-0.8)*drawH
	sb.WriteString(fmt.Sprintf("                                    <line x1=\"%.0f\" y1=\"%.1f\" x2=\"%.0f\" y2=\"%.1f\" stroke=\"#dc3545\" stroke-width=\"1\" stroke-dasharray=\"6,4\" opacity=\"0.4\"/>\n", pad, threshY, svgW-pad, threshY))

	// Grid lines
	for _, v := range []float64{0.0, 0.2, 0.4, 0.6} {
		y := pad + (1-v)*drawH
		sb.WriteString(fmt.Sprintf("                                    <line x1=\"%.0f\" y1=\"%.1f\" x2=\"%.0f\" y2=\"%.1f\" stroke=\"#e1e4e8\" stroke-width=\"0.5\"/>\n", pad, y, svgW-pad, y))
	}

	type svgPt struct {
		x, y  float64
		bt    bool
		score float64
	}
	var pts []svgPt
	var accepted []svgPt

	for i, t := range turns {
		x := pad + float64(i)/float64(n-1)*drawW
		score := t.JudgeScore
		if t.WasBacktracked {
			score = 0
		}
		y := pad + (1-score)*drawH
		p := svgPt{x, y, t.WasBacktracked, score}
		pts = append(pts, p)
		if !t.WasBacktracked {
			accepted = append(accepted, p)
		}
	}

	// Line connecting accepted turns
	if len(accepted) >= 2 {
		sb.WriteString("                                    <polyline points=\"")
		for i, p := range accepted {
			if i > 0 {
				sb.WriteString(" ")
			}
			sb.WriteString(fmt.Sprintf("%.1f,%.1f", p.x, p.y))
		}
		sb.WriteString("\" fill=\"none\" stroke=\"#0366d6\" stroke-width=\"2\" opacity=\"0.6\" stroke-linejoin=\"round\"/>\n")
	}

	// Area fill
	if len(accepted) >= 2 {
		baseY := pad + drawH
		sb.WriteString(fmt.Sprintf("                                    <polygon points=\"%.1f,%.1f ", accepted[0].x, baseY))
		for _, p := range accepted {
			sb.WriteString(fmt.Sprintf("%.1f,%.1f ", p.x, p.y))
		}
		sb.WriteString(fmt.Sprintf("%.1f,%.1f\" fill=\"#0366d6\" opacity=\"0.08\"/>\n", accepted[len(accepted)-1].x, baseY))
	}

	// Draw points
	for _, p := range pts {
		if p.bt {
			s := 3.5
			sb.WriteString(fmt.Sprintf("                                    <line x1=\"%.1f\" y1=\"%.1f\" x2=\"%.1f\" y2=\"%.1f\" stroke=\"#cb2431\" stroke-width=\"2\" stroke-linecap=\"round\"/>\n", p.x-s, p.y-s, p.x+s, p.y+s))
			sb.WriteString(fmt.Sprintf("                                    <line x1=\"%.1f\" y1=\"%.1f\" x2=\"%.1f\" y2=\"%.1f\" stroke=\"#cb2431\" stroke-width=\"2\" stroke-linecap=\"round\"/>\n", p.x+s, p.y-s, p.x-s, p.y+s))
		} else {
			color := scoreColor(p.score)
			sb.WriteString(fmt.Sprintf("                                    <circle cx=\"%.1f\" cy=\"%.1f\" r=\"4\" fill=\"%s\" stroke=\"white\" stroke-width=\"1.5\"/>\n", p.x, p.y, color))
		}
	}

	sb.WriteString("                                </svg>\n")
}

func extractCategoryForDisplay(strategy string) string {
	strategy = strings.TrimSpace(strategy)
	if strategy == "" {
		return ""
	}
	// Try to extract category prefix before em dash or hyphen separator
	if idx := strings.Index(strategy, " \u2014 "); idx > 0 {
		return strings.ToUpper(strings.TrimSpace(strategy[:idx]))
	}
	if idx := strings.Index(strategy, " - "); idx > 0 {
		return strings.ToUpper(strings.TrimSpace(strategy[:idx]))
	}
	// No separator — show full strategy as-is
	return strings.ToUpper(strategy)
}
