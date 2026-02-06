package results

import (
	"fmt"
	"html"
	"os"
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
				// Determine pass/fail
				passed := true
				for _, score := range att.Scores {
					if score > 0.5 {
						passed = false
						break
					}
				}

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

				sb.WriteString(`                <div class="attempt">
                    <div class="attempt-header">
                        <span class="status-badge ` + statusClass + `">` + statusText + `</span>
                        <span class="scores">` + scoresStr + `</span>
                    </div>
                    <div class="attempt-detail">
                        <strong>Detector:</strong> ` + html.EscapeString(att.Detector) + `
                    </div>
                    <div class="attempt-detail">
                        <strong>Prompt:</strong>
                        <div class="prompt">` + html.EscapeString(att.Prompt) + `</div>
                    </div>
                    <div class="attempt-detail">
                        <strong>Response:</strong>
                        <div class="response">` + html.EscapeString(response) + `</div>
                    </div>
                    <div class="attempt-detail">
                        <strong>Timestamp:</strong> ` + att.Timestamp.Format(time.RFC3339) + `
                    </div>
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
