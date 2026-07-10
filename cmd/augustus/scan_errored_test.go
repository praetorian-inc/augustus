package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// captureStdout runs fn while capturing everything written to os.Stdout and
// returns the captured text.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w
	// Restore stdout unconditionally so a panic or failed assertion in fn does
	// not leave process-wide stdout attached to the pipe for later tests.
	defer func() {
		os.Stdout = orig
		_ = r.Close()
	}()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()
	closeErr := w.Close()
	os.Stdout = orig
	output := <-done
	require.NoError(t, closeErr)
	return output
}

func erroredAttempt() *attempt.Attempt {
	return &attempt.Attempt{
		Probe:    "pdf.OnePointFont",
		Detector: "multimodal.Canary",
		Status:   attempt.StatusError,
		Error:    "anthropic: API error (404, not_found_error): model: claude-3-5-sonnet-20241022",
		Outputs:  []string{},
		Scores:   []float64{},
	}
}

func safeAttempt() *attempt.Attempt {
	return &attempt.Attempt{
		Probe:    "pdf.AnnotationInjection",
		Detector: "multimodal.Canary",
		Status:   attempt.StatusComplete,
		Outputs:  []string{"I can't help with that."},
		Scores:   []float64{0.0},
	}
}

// TestTableEvaluator_ErroredProbe_NotReportedSafe is the core LAB-4316 guard:
// an errored probe must render as ERROR (not SAFE/passed=true/0.00), be counted
// in the Overall "errored" tally, and cause Evaluate to return errProbesErrored.
func TestTableEvaluator_ErroredProbe_NotReportedSafe(t *testing.T) {
	eval := &tableEvaluator{}
	var evalErr error
	out := captureStdout(t, func() {
		evalErr = eval.Evaluate(context.Background(), []*attempt.Attempt{erroredAttempt()})
	})

	assert.ErrorIs(t, evalErr, errProbesErrored, "errored probe must surface errProbesErrored")

	// The errored row must not be dressed up as a clean pass.
	assert.Contains(t, out, "ERROR", "table should show ERROR status")
	assert.NotContains(t, out, "SAFE", "errored probe must not be labeled SAFE")
	assert.NotContains(t, out, "0.00", "errored probe must not show a fabricated 0.00 score")

	// Summary line separates errored from passed/failed.
	assert.Contains(t, out, "Overall: 0 passed, 0 review, 0 failed, 1 errored (total: 1)")
}

// TestTableEvaluator_MixedRun keeps passed/failed/errored in independent buckets.
func TestTableEvaluator_MixedRun(t *testing.T) {
	vuln := &attempt.Attempt{
		Probe:    "pdf.Vuln",
		Detector: "multimodal.Canary",
		Status:   attempt.StatusComplete,
		Outputs:  []string{"CANARY-LEAKED"},
		Scores:   []float64{1.0},
	}

	eval := &tableEvaluator{}
	var evalErr error
	out := captureStdout(t, func() {
		evalErr = eval.Evaluate(context.Background(),
			[]*attempt.Attempt{safeAttempt(), vuln, erroredAttempt()})
	})

	assert.ErrorIs(t, evalErr, errProbesErrored)
	assert.Contains(t, out, "Overall: 1 passed, 0 review, 1 failed, 1 errored (total: 3)")
}

// TestTableEvaluator_CleanRun_NoError confirms a fully-clean run still returns
// nil (exit 0) and reports zero errored.
func TestTableEvaluator_CleanRun_NoError(t *testing.T) {
	eval := &tableEvaluator{}
	var evalErr error
	out := captureStdout(t, func() {
		evalErr = eval.Evaluate(context.Background(), []*attempt.Attempt{safeAttempt()})
	})

	assert.NoError(t, evalErr, "clean run must not surface errProbesErrored")
	assert.Contains(t, out, "Overall: 1 passed, 0 review, 0 failed, 0 errored (total: 1)")
}

// TestJSONLEvaluator_ErroredProbe confirms the machine-readable path also
// signals the errored outcome via the sentinel error.
func TestJSONLEvaluator_ErroredProbe(t *testing.T) {
	eval := &jsonlEvaluator{}
	var evalErr error
	out := captureStdout(t, func() {
		evalErr = eval.Evaluate(context.Background(), []*attempt.Attempt{erroredAttempt()})
	})

	assert.ErrorIs(t, evalErr, errProbesErrored)
	// The JSONL still records the error status for the operator.
	assert.Contains(t, out, `"status":"error"`)
}

// TestCollectingEvaluator_WritesFilesDespiteErroredProbes ensures the sentinel
// from the inner evaluator does not short-circuit JSONL/HTML file output — the
// errored-run artifacts are exactly what an operator needs — while still
// propagating errProbesErrored for the exit code.
func TestCollectingEvaluator_WritesFilesDespiteErroredProbes(t *testing.T) {
	dir := t.TempDir()
	jsonlPath := filepath.Join(dir, "out.jsonl")
	htmlPath := filepath.Join(dir, "out.html")

	eval := &collectingEvaluator{
		inner:     &tableEvaluator{},
		jsonlPath: jsonlPath,
		htmlPath:  htmlPath,
	}

	var evalErr error
	_ = captureStdout(t, func() {
		evalErr = eval.Evaluate(context.Background(), []*attempt.Attempt{erroredAttempt()})
	})

	assert.ErrorIs(t, evalErr, errProbesErrored, "sentinel must propagate for exit code")

	jsonlData, err := os.ReadFile(jsonlPath)
	require.NoError(t, err, "JSONL must be written even when probes errored")
	assert.Contains(t, string(jsonlData), `"status":"error"`)

	htmlData, err := os.ReadFile(htmlPath)
	require.NoError(t, err, "HTML must be written even when probes errored")
	assert.True(t, strings.Contains(string(htmlData), "Errored"), "HTML summary should include Errored")
}

// TestOnlyProbesErrored verifies the exit-code precedence: a scan whose only
// failure is errored probes maps to the distinct code, but an operational error
// (e.g. a failed cleanup hook) joined alongside it must take precedence (exit 1).
func TestOnlyProbesErrored(t *testing.T) {
	cleanupErr := errors.New("cleanup hook failed")

	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unrelated runtime error", errors.New("boom"), false},
		{"bare sentinel", errProbesErrored, true},
		{"wrapped sentinel", fmt.Errorf("evaluation failed: %w", errProbesErrored), true},
		{"sentinel joined with operational error", errors.Join(errProbesErrored, cleanupErr), false},
		{
			"wrapped sentinel joined with operational error",
			errors.Join(fmt.Errorf("evaluation failed: %w", errProbesErrored), cleanupErr), false,
		},
		{"operational error only", errors.Join(nil, cleanupErr), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, onlyProbesErrored(tt.err))
		})
	}
}
