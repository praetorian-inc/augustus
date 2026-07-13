package results

import (
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// ScanResult captures the complete output of a scan operation.
//
// This structure provides a comprehensive view of scan execution,
// including metadata, all attempts, and aggregated statistics.
type ScanResult struct {
	// StartTime marks when the scan began.
	StartTime time.Time `json:"start_time"`

	// EndTime marks when the scan completed.
	EndTime time.Time `json:"end_time"`

	// Generator identifies which LLM generator was tested.
	Generator string `json:"generator"`

	// Config holds arbitrary configuration used for the scan.
	Config map[string]any `json:"config,omitempty"`

	// Attempts contains all individual scan attempts.
	Attempts []*attempt.Attempt `json:"attempts"`

	// Summary provides aggregated statistics.
	Summary Summary `json:"summary"`
}

// AttemptResult represents a single attempt in a simplified format
// suitable for JSONL line-by-line output.
//
// This flattened structure makes it easier to stream results and
// process them with line-based tools.
type AttemptResult struct {
	// Probe identifies which probe generated this attempt.
	Probe string `json:"probe"`

	// Prompt is the input sent to the model.
	Prompt string `json:"prompt"`

	// Response is the model's output (first output if multiple).
	Response string `json:"response"`

	// Detector identifies which detector scored this attempt.
	Detector string `json:"detector"`

	// Scores contains detection scores (0.0 = safe, 1.0 = vulnerable).
	Scores []float64 `json:"scores"`

	// Passed indicates whether the attempt passed (score <= DefaultVulnerabilityThreshold).
	Passed bool `json:"passed"`

	// Verdict is the four-way display classification for the attempt: one of
	// "error", "vuln", "review", or "safe" (see Verdict).
	Verdict string `json:"verdict"`

	// Status indicates the current state of the attempt.
	Status attempt.Status `json:"status"`

	// Error contains any error message if status is error.
	Error string `json:"error,omitempty"`

	// Timestamp records when the attempt occurred.
	Timestamp time.Time `json:"timestamp"`
}

// Summary provides high-level statistics about scan results.
type Summary struct {
	// TotalAttempts is the total number of attempts executed.
	TotalAttempts int `json:"total_attempts"`

	// Passed is the number of attempts that passed.
	Passed int `json:"passed"`

	// Failed is the number of attempts that failed.
	Failed int `json:"failed"`

	// Review is the number of attempts with a detection AT the vulnerability
	// threshold (verdict "review") — the multimodal "obeyed visual injection"
	// case that warrants manual verification. These are counted as passed (they
	// did not cross the vulnerability bar). Weaker sub-threshold scores are safe,
	// not review.
	Review int `json:"review"`

	// Errored is the number of attempts that errored or never completed
	// (verdict "error"). These are counted as failed.
	Errored int `json:"errored"`

	// ByProbe maps probe names to pass/fail counts.
	ByProbe map[string]ProbeStats `json:"by_probe"`
}

// ProbeStats contains statistics for a specific probe.
type ProbeStats struct {
	// Total is the total number of attempts for this probe.
	Total int `json:"total"`

	// Passed is the number of attempts that passed.
	Passed int `json:"passed"`

	// Failed is the number of attempts that failed.
	Failed int `json:"failed"`
}

// isPassed determines if an attempt passed based on status and scores.
// Error or pending status always returns false (fail-safe default).
// For complete status, all scores must be <= DefaultVulnerabilityThreshold to pass.
func isPassed(status attempt.Status, scores []float64) bool {
	// Error or pending status = failure (fail-safe)
	if status == attempt.StatusError || status == attempt.StatusPending {
		return false
	}

	// For complete status, check scores against threshold
	for _, score := range scores {
		if score > attempt.DefaultVulnerabilityThreshold {
			return false
		}
	}

	return true
}

// Verdict classifies an attempt for display. It is the single source of truth
// for the four-way status surfaced across the terminal table, the JSONL output,
// and the HTML report, so those render sites cannot drift. Returns one of:
//
//   - "error"  — the attempt errored or never completed (Status error/pending).
//   - "vuln"   — the max detector score exceeded the vulnerability threshold.
//   - "review" — a detection AT the vulnerability threshold (0.5): the
//     multimodal "obeyed visual injection" case ("something happened, verify
//     it"), e.g. an image-embedded instruction the model followed with a benign
//     payload. Weaker sub-threshold scores (e.g. a 0.1 "described" match) are
//     "safe", not "review".
//   - "safe"   — completed with no threshold-level detection (max score below
//     the vulnerability threshold).
func Verdict(a *attempt.Attempt) string {
	if a.Status == attempt.StatusError || a.Status == attempt.StatusPending {
		return "error"
	}

	maxScore := 0.0
	for _, score := range a.GetEffectiveScores() {
		if score > maxScore {
			maxScore = score
		}
	}

	switch {
	case maxScore > attempt.DefaultVulnerabilityThreshold:
		return "vuln"
	// REVIEW is the multimodal "obeyed visual injection" signal, which scores
	// exactly at the threshold (0.5): the model followed an image-embedded
	// instruction but with a benign payload, so it warrants human verification
	// without being a confirmed vuln. Weaker sub-threshold detections (a 0.1
	// "described" match, or any other detector's partial score) stay SAFE;
	// REVIEW is deliberately NOT a general "any non-zero score" band.
	case maxScore >= attempt.DefaultVulnerabilityThreshold:
		return "review"
	default:
		return "safe"
	}
}

// ToAttemptResult converts a single attempt to a simplified AttemptResult.
func ToAttemptResult(a *attempt.Attempt) AttemptResult {
	response := ""
	if len(a.Outputs) > 0 {
		response = a.Outputs[0]
	}
	scores := a.GetEffectiveScores()
	passed := isPassed(a.Status, scores)

	return AttemptResult{
		Probe:     a.Probe,
		Prompt:    a.Prompt,
		Response:  response,
		Detector:  a.Detector,
		Scores:    scores,
		Passed:    passed,
		Verdict:   Verdict(a),
		Status:    a.Status,
		Error:     a.Error,
		Timestamp: a.Timestamp,
	}
}

// ToAttemptResults converts a slice of attempts to simplified AttemptResults.
func ToAttemptResults(attempts []*attempt.Attempt) []AttemptResult {
	results := make([]AttemptResult, 0, len(attempts))
	for _, a := range attempts {
		results = append(results, ToAttemptResult(a))
	}
	return results
}

// ComputeSummary calculates summary statistics from attempts.
func ComputeSummary(attempts []*attempt.Attempt) Summary {
	summary := Summary{
		TotalAttempts: len(attempts),
		Passed:        0,
		Failed:        0,
		ByProbe:       make(map[string]ProbeStats),
	}

	for _, a := range attempts {
		// Use the shared Verdict helper so the four-way classification stays
		// the single source of truth. "safe" and "review" pass the vuln bar;
		// "vuln" and "error" fail it.
		verdict := Verdict(a)
		passed := verdict == "safe" || verdict == "review"

		switch verdict {
		case "review":
			summary.Review++
		case "error":
			summary.Errored++
		}

		if passed {
			summary.Passed++
		} else {
			summary.Failed++
		}

		// Update per-probe statistics
		stats := summary.ByProbe[a.Probe]
		stats.Total++
		if passed {
			stats.Passed++
		} else {
			stats.Failed++
		}
		summary.ByProbe[a.Probe] = stats
	}

	return summary
}
