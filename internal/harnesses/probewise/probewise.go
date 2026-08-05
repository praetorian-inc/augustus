// Package probewise provides the probewise harness implementation.
//
// The probewise harness executes probes concurrently using the scanner package,
// then runs detectors sequentially on all probe attempts. This provides significant
// performance improvements over the original sequential implementation while
// maintaining a per-probe execution strategy.
package probewise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/scanner"
)

// Errors returned by the probewise harness.
var (
	ErrNoProbes    = errors.New("no probes provided")
	ErrNoDetectors = errors.New("no detectors provided")
)

// Probewise implements the probewise harness strategy.
//
// For each probe, it:
// 1. Runs the probe against the generator to get attempts
// 2. Runs all detectors on each attempt
// 3. Stores detector results in the attempt
// 4. Marks the attempt as complete
// 5. Calls the evaluator with all attempts
type Probewise struct {
	opts                   *scanner.Options
	onAttemptProcessed     func(*attempt.Attempt)
	probeDetectorOverrides map[string][]detectors.Detector
	// detectorsExplicit is true when the user passed --detector/--detectors-glob.
	// It controls the per-attempt fallback when a probe has no override entry:
	// explicit → the shared detectorList; auto → the probe's own primary only.
	detectorsExplicit bool
}

// New creates a new probewise harness.
func New() *Probewise {
	return &Probewise{}
}

// Name returns the fully qualified harness name.
func (p *Probewise) Name() string {
	return "probewise.Probewise"
}

// Description returns a human-readable description.
func (p *Probewise) Description() string {
	return "Executes probes one at a time, running detectors on each probe's attempts"
}

// formatProgressStatus formats the progress status symbol and error message.
// Returns "✓" with empty error message on success, or "✗" with formatted error on failure.
func formatProgressStatus(probeErr error) (status, errMsg string) {
	if probeErr == nil {
		return "✓", ""
	}
	msg := probeErr.Error()
	if len(msg) > 80 {
		msg = msg[:77] + "..."
	}
	return "✗", fmt.Sprintf(" (%s)", msg)
}

// createFreshEvalContext creates a fresh evaluation context if the scan context has expired.
// If scanCtx is still valid, returns it unchanged. Otherwise, creates a new context with 5-minute timeout.
func createFreshEvalContext(scanCtx context.Context) (context.Context, context.CancelFunc) {
	if scanCtx.Err() == nil {
		return scanCtx, func() {}
	}
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// reportScanErrors checks for probe failures and scan-level errors and returns appropriate error.
// Returns nil if no errors occurred.
func reportScanErrors(results *scanner.Results, scanErr error, allAttempts []*attempt.Attempt) error {
	// Check for probe failures first
	if len(results.Errors) > 0 {
		// Log each probe error
		for _, err := range results.Errors {
			slog.Error("probe failed", "error", err)
		}
		// Wrap the underlying errors rather than only counting them. Probes export
		// sentinels so a consumer can CLASSIFY a failure — most importantly
		// types.ErrCatalogTruncated, which distinguishes "the tool surface could not be
		// fully enumerated" from "the target was unreachable". Those need opposite
		// handling downstream: one means rescan or report an incomplete surface, the
		// other means the target is down. A count-only error strands every such
		// sentinel here, leaving errors.Is false for callers (e.g. the Guard wrapper)
		// that are the whole reason the probes fail closed in the first place.
		return fmt.Errorf("%d of %d probes failed: %w", results.Failed, results.Total,
			errors.Join(results.Errors...))
	}

	// Check for scan-level errors (e.g., timeout)
	if scanErr != nil {
		return fmt.Errorf("scan interrupted after processing %d/%d probes (%d attempts): %w",
			results.Succeeded, results.Total, len(allAttempts), scanErr)
	}

	return nil
}

// Run executes the probe-by-probe scan workflow.
//
// It validates inputs, then for each probe:
//   - Runs the probe against the generator
//   - Applies all detectors to each attempt
//   - Marks attempts as complete
//   - Calls the evaluator with accumulated attempts
func (p *Probewise) Run(
	ctx context.Context,
	gen generators.Generator,
	probeList []probes.Prober,
	detectorList []detectors.Detector,
	eval harnesses.Evaluator,
) error {
	// Validate inputs
	if len(probeList) == 0 {
		return ErrNoProbes
	}
	if len(detectorList) == 0 {
		return ErrNoDetectors
	}

	// Check context cancellation early
	if err := ctx.Err(); err != nil {
		return err
	}

	// Use scanner for concurrent probe execution
	opts := scanner.DefaultOptions()
	if p.opts != nil {
		opts = *p.opts
	}
	s := scanner.New(opts)

	// Wire up progress logging to stderr
	s.SetProgressCallback(func(probeName string, completed, total int, elapsed time.Duration, probeErr error) {
		status, errMsg := formatProgressStatus(probeErr)
		fmt.Fprintf(os.Stderr, "[%d/%d] %s %s%s (%s)\n",
			completed, total, probeName, status, errMsg, elapsed.Round(time.Millisecond))
	})

	results := s.Run(ctx, probeList, gen)

	// Capture scanner-level errors but don't return yet - process partial results first.
	// When scan times out, completed probes have their attempts in results.Attempts.
	scanErr := results.Error

	// If scan context expired, create a fresh context for detection and evaluation.
	// Detection and evaluation are fast operations that should always complete.
	evalCtx, evalCancel := createFreshEvalContext(ctx)
	defer evalCancel()

	// If scanner failed with zero attempts, nothing to process
	if scanErr != nil && len(results.Attempts) == 0 {
		return fmt.Errorf("scan failed with no results: %w", scanErr)
	}

	// Continue processing successful attempts even if some probes failed.
	// We'll report probe errors at the end, after processing partial results.

	// Apply detectors to all attempts and stream results
	for _, a := range results.Attempts {
		// Check context cancellation between attempts
		if err := evalCtx.Err(); err != nil {
			return err
		}

		// Set the generator name if not already set
		if a.Generator == "" {
			a.Generator = gen.Name()
		}

		// Select detector list: per-probe override takes precedence; otherwise
		// scope to the probe's own primary (auto mode) or the shared list
		// (explicit mode) — never the cross-probe union in auto mode.
		activeDetectors := harnesses.SelectProbeDetectors(a, detectorList, p.probeDetectorOverrides, p.detectorsExplicit)

		// Run detectors using shared logic (SkipOnError for partial results)
		if err := harnesses.ApplyDetectors(evalCtx, a, activeDetectors, harnesses.SkipOnError); err != nil {
			return err
		}

		// Stream result immediately after detection
		if p.onAttemptProcessed != nil {
			p.onAttemptProcessed(a)
		}
	}

	allAttempts := results.Attempts

	// Call evaluator if provided (even with partial results). An
	// errProbesErrored result is a verdict signal (some attempts never reached
	// the model); capture it but do not return yet, so genuine probe-level
	// failures still get reported below (LAB-4316).
	var evalErr error
	if eval != nil && len(allAttempts) > 0 {
		if err := eval.Evaluate(evalCtx, allAttempts); err != nil {
			evalErr = fmt.Errorf("evaluation failed: %w", err)
		}
	}

	// Report any scan errors (probe failures or scan-level errors). These take
	// precedence over the errored-attempts sentinel: a "N of M probes failed"
	// report is more actionable than the no-verdict signal, and must not be
	// masked when a run hits both.
	if err := reportScanErrors(&results, scanErr, allAttempts); err != nil {
		return err
	}
	return evalErr
}

// init registers the probewise harness with the global registry.
func init() {
	harnesses.Register("probewise.Probewise", func(cfg registry.Config) (harnesses.Harness, error) {
		p := New()
		// Extract scanner options if provided
		if scannerOpts, ok := cfg["scanner_opts"].(*scanner.Options); ok {
			p.opts = scannerOpts
		} else if _, exists := cfg["scanner_opts"]; exists {
			slog.Warn("probewise: key has unexpected type, ignoring", "key", "scanner_opts", "type", fmt.Sprintf("%T", cfg["scanner_opts"]))
		}
		// Extract streaming callback if provided
		if cb, ok := cfg["on_attempt_processed"].(func(*attempt.Attempt)); ok {
			p.onAttemptProcessed = cb
		} else if _, exists := cfg["on_attempt_processed"]; exists {
			slog.Warn("probewise: key has unexpected type, ignoring", "key", "on_attempt_processed", "type", fmt.Sprintf("%T", cfg["on_attempt_processed"]))
		}
		// Extract per-probe detector overrides if provided
		if overrides, ok := cfg["probe_detector_overrides"].(map[string][]detectors.Detector); ok {
			p.probeDetectorOverrides = overrides
		} else if _, exists := cfg["probe_detector_overrides"]; exists {
			slog.Warn("probewise: key has unexpected type, ignoring", "key", "probe_detector_overrides", "type", fmt.Sprintf("%T", cfg["probe_detector_overrides"]))
		}
		// Extract detector-selection mode (controls the per-attempt fallback).
		if explicit, ok := cfg["detectors_explicit"].(bool); ok {
			p.detectorsExplicit = explicit
		}
		return p, nil
	})
}

// Registry helper functions for package-level access.

// List returns all registered harness names.
func List() []string {
	return harnesses.List()
}

// Get retrieves a harness factory by name.
func Get(name string) (func(registry.Config) (harnesses.Harness, error), bool) {
	return harnesses.Get(name)
}

// Create instantiates a harness by name.
func Create(name string, cfg registry.Config) (harnesses.Harness, error) {
	return harnesses.Create(name, cfg)
}
