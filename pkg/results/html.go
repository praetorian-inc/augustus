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

// WriteHTML generates a self-contained HTML report from scan attempts.
//
// The report includes:
//   - Summary dashboard with pass/fail counts
//   - Per-probe breakdown with statistics
//   - Expandable details for each attempt
//   - Inline CSS (no external dependencies)
//
// Parameters:
//   - outputPath: Path to the output HTML file
//   - attempts: Slice of attempts to include in the report
//
// Returns an error if file creation or writing fails.
func WriteHTML(outputPath string, attempts []*attempt.Attempt) error {
	// Compute summary statistics
	summary := ComputeSummary(attempts)

	// Create parent directories if they don't exist
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return fmt.Errorf("failed to create parent directories: %w", err)
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Write HTML content
	var sb strings.Builder

	// HTML header with inline CSS
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Augustus Scan Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            margin-bottom: 10px;
            font-size: 2em;
        }
        h2 {
            color: #2c3e50;
            margin-bottom: 15px;
            font-size: 1.5em;
            margin-top: 20px;
        }
        .timestamp {
            color: #7f8c8d;
            font-size: 0.9em;
            margin-bottom: 30px;
        }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 40px;
        }
        .summary-card {
            background: #ecf0f1;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }
        .summary-card.passed {
            background: #d4edda;
            border-left: 4px solid #28a745;
        }
        .summary-card.failed {
            background: #f8d7da;
            border-left: 4px solid #dc3545;
        }
        .summary-card.total {
            background: #d1ecf1;
            border-left: 4px solid #17a2b8;
        }
        .summary-card h3 {
            font-size: 0.9em;
            color: #6c757d;
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .summary-card .value {
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        .probe-section {
            margin-bottom: 30px;
        }
        .probe-header {
            background: #343a40;
            color: white;
            padding: 15px 20px;
            border-radius: 6px 6px 0 0;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .probe-header:hover {
            background: #23272b;
        }
        .probe-header h2 {
            font-size: 1.2em;
            margin: 0;
        }
        .probe-stats {
            font-size: 0.9em;
            color: #adb5bd;
        }
        .probe-content {
            border: 1px solid #dee2e6;
            border-top: none;
            border-radius: 0 0 6px 6px;
            overflow: hidden;
        }
        .attempt {
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
        }
        .attempt:last-child {
            border-bottom: none;
        }
        .attempt-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .status-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            text-transform: uppercase;
        }
        .status-badge.pass {
            background: #d4edda;
            color: #155724;
        }
        .status-badge.fail {
            background: #f8d7da;
            color: #721c24;
        }
        .attempt-detail {
            margin: 10px 0;
        }
        .attempt-detail strong {
            display: inline-block;
            min-width: 100px;
            color: #495057;
        }
        .prompt, .response {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            margin-top: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .scores {
            display: inline-block;
            padding: 2px 8px;
            background: #e9ecef;
            border-radius: 4px;
            font-family: monospace;
        }
        .no-attempts {
            text-align: center;
            padding: 60px 20px;
            color: #6c757d;
        }
        .no-attempts h2 {
            margin-bottom: 10px;
            font-size: 1.5em;
        }
        .conversation-flow {
            margin: 15px 0;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 6px;
        }
        .conversation-header {
            font-weight: 600;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #dee2e6;
        }
        .turn {
            margin-bottom: 15px;
            padding: 12px;
            border-radius: 6px;
            border-left: 4px solid #dee2e6;
        }
        .turn-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-weight: 600;
        }
        .turn-score {
            font-family: monospace;
        }
        .turn-success {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        .turn-low { border-left-color: #28a745; }
        .turn-medium { border-left-color: #ffc107; }
        .turn-high { border-left-color: #fd7e14; }
        .turn-refused {
            border-left-color: #6c757d;
            background: #f0f0f0;
            opacity: 0.7;
        }
        .turn-question, .turn-response {
            margin: 5px 0;
            padding: 8px;
            border-radius: 4px;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .turn-question {
            background: #e3f2fd;
        }
        .turn-response {
            background: #f5f5f5;
        }
        .score-bar {
            height: 4px;
            background: #e9ecef;
            border-radius: 2px;
            margin-top: 8px;
        }
        .score-bar-fill {
            height: 100%;
            border-radius: 2px;
            transition: width 0.3s;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Augustus Scan Report</h1>
        <div class="timestamp">Generated: ` + time.Now().Format(time.RFC3339) + `</div>
`)

	// Summary section
	sb.WriteString(`        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card total">
                <h3>Total Attempts</h3>
                <div class="value">` + fmt.Sprintf("%d", summary.TotalAttempts) + `</div>
            </div>
            <div class="summary-card passed">
                <h3>Passed</h3>
                <div class="value">` + fmt.Sprintf("%d", summary.Passed) + `</div>
            </div>
            <div class="summary-card failed">
                <h3>Failed</h3>
                <div class="value">` + fmt.Sprintf("%d", summary.Failed) + `</div>
            </div>
        </div>
`)

	// Handle empty attempts
	if len(attempts) == 0 {
		sb.WriteString(`        <div class="no-attempts">
            <h2>No attempts recorded</h2>
            <p>Run a scan to generate results</p>
        </div>
`)
	} else {
		// Group attempts by probe
		probeAttempts := make(map[string][]*attempt.Attempt)
		for _, a := range attempts {
			probeAttempts[a.Probe] = append(probeAttempts[a.Probe], a)
		}

		// Write each probe section
		for probeName, probeAtts := range probeAttempts {
			stats := summary.ByProbe[probeName]

			sb.WriteString(`        <div class="probe-section">
            <div class="probe-header">
                <h2>` + html.EscapeString(probeName) + `</h2>
                <div class="probe-stats">` +
				fmt.Sprintf("%d/%d passed", stats.Passed, stats.Total) +
				`</div>
            </div>
            <div class="probe-content">
`)

			// Write each attempt
			for _, att := range probeAtts {
				// Use centralized score resolution and threshold
				scores := att.GetEffectiveScores()
				passed := isPassed(att.Status, scores)

				statusClass := "pass"
				statusText := "PASS"
				if !passed {
					statusClass = "fail"
					statusText = "FAIL"
				}

				// Get response
				response := ""
				if len(att.Outputs) > 0 {
					response = att.Outputs[0]
				}

				// Format scores
				scoresStr := "[]"
				if len(att.Scores) > 0 {
					scoresStr = fmt.Sprintf("[%.2f]", att.Scores[0])
					for i := 1; i < len(att.Scores); i++ {
						scoresStr = strings.TrimSuffix(scoresStr, "]")
						scoresStr += fmt.Sprintf(", %.2f]", att.Scores[i])
					}
				}

				_, isMultiTurn := att.Metadata["attack_type"].(string)

				sb.WriteString(`                <div class="attempt">
                    <div class="attempt-header">
                        <span class="status-badge ` + statusClass + `">` + statusText + `</span>
                        <span class="scores">` + scoresStr + `</span>
                    </div>
                    <div class="attempt-detail">
                        <strong>Detector:</strong> ` + html.EscapeString(att.Detector) + `
                    </div>
`)
				// Skip redundant prompt/response for multi-turn attacks —
				// the conversation flow section below already shows all turns.
				if !isMultiTurn {
					sb.WriteString(`                    <div class="attempt-detail">
                        <strong>Prompt:</strong>
                        <div class="prompt">` + html.EscapeString(att.Prompt) + `</div>
                    </div>
                    <div class="attempt-detail">
                        <strong>Response:</strong>
                        <div class="response">` + html.EscapeString(response) + `</div>
                    </div>
`)
				}
				sb.WriteString(`                    <div class="attempt-detail">
                        <strong>Timestamp:</strong> ` + att.Timestamp.Format(time.RFC3339) + `
                    </div>
`)

				// Multi-turn conversation flow
				if attackType, ok := att.Metadata["attack_type"].(string); ok {
					goal, _ := att.Metadata["goal"].(string)
					totalTurns, _ := att.Metadata["total_turns"].(int)
					succeeded, _ := att.Metadata["succeeded"].(bool)

					resultText := "NOT ACHIEVED"
					if succeeded {
						resultText = "ACHIEVED"
					}

					sb.WriteString(`                    <div class="conversation-flow">
                        <div class="conversation-header">` +
						html.EscapeString(fmt.Sprintf("%s Attack - %d turns - %s", attackType, totalTurns, resultText)) +
						`</div>`)

					if goal != "" {
						sb.WriteString(`
                        <div style="margin-bottom: 10px; color: #495057;"><strong>Goal:</strong> ` + html.EscapeString(goal) + `</div>`)
					}

					// Render turn records - handle both []TurnRecord and []any (from JSON)
					type turnData struct {
						TurnNumber int
						Question   string
						Response   string
						WasRefused bool
						JudgeScore float64
						Strategy   string
					}
					var turns []turnData

					// Try direct type first (in-memory)
					switch records := att.Metadata["turn_records"].(type) {
					case []any:
						for _, r := range records {
							if rec, ok := r.(map[string]any); ok {
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
								if v, ok := rec["judge_score"].(float64); ok {
									td.JudgeScore = v
								}
								td.Strategy, _ = rec["strategy"].(string)
								turns = append(turns, td)
							}
						}
					default:
						// In-memory TurnRecord slice - marshal/unmarshal to get []any
						if records != nil {
							jsonBytes, err := json.Marshal(records)
							if err == nil {
								var rawTurns []map[string]any
								if json.Unmarshal(jsonBytes, &rawTurns) == nil {
									for _, rec := range rawTurns {
										td := turnData{}
										if v, ok := rec["turn_number"].(float64); ok {
											td.TurnNumber = int(v)
										}
										td.Question, _ = rec["question"].(string)
										td.Response, _ = rec["response"].(string)
										td.WasRefused, _ = rec["was_refused"].(bool)
										if v, ok := rec["judge_score"].(float64); ok {
											td.JudgeScore = v
										}
										td.Strategy, _ = rec["strategy"].(string)
										turns = append(turns, td)
									}
								}
							}
						}
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

						// Score bar color
						barColor := "#28a745" // green
						if turn.JudgeScore >= 0.8 {
							barColor = "#dc3545" // red
						} else if turn.JudgeScore >= 0.5 {
							barColor = "#fd7e14" // orange
						} else if turn.JudgeScore >= 0.3 {
							barColor = "#ffc107" // yellow
						}

						sb.WriteString(fmt.Sprintf(`
                        <div class="%s">
                            <div class="turn-header">
                                <span>Turn %d%s%s</span>
                                <span class="turn-score">Score: %.2f</span>
                            </div>
                            <div class="turn-question"><strong>Attacker:</strong> %s</div>
                            <div class="turn-response"><strong>Target:</strong> %s</div>
                            <div class="score-bar"><div class="score-bar-fill" style="width: %.0f%%; background: %s;"></div></div>
                        </div>`,
							turnClass,
							turn.TurnNumber, successTag, refusedTag,
							turn.JudgeScore,
							html.EscapeString(turn.Question),
							html.EscapeString(turn.Response),
							turn.JudgeScore*100, barColor,
						))
					}

					sb.WriteString(`
                    </div>`)
				}

				sb.WriteString(`
                </div>
`)
			}

			sb.WriteString(`            </div>
        </div>
`)
		}
	}

	// Close HTML
	sb.WriteString(`    </div>
</body>
</html>`)

	// Write to file
	if _, err := file.WriteString(sb.String()); err != nil {
		return fmt.Errorf("failed to write HTML content: %w", err)
	}

	return nil
}
