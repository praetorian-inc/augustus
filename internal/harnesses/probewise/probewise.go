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
type Probewise struct{
	opts *scanner.Options
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

	// Apply detectors to all attempts (sequential, but fast)
	for _, a := range results.Attempts {
		// Check context cancellation between attempts
		if err := evalCtx.Err(); err != nil {
			return err
		}

		// Set the generator name if not already set
		if a.Generator == "" {
			a.Generator = gen.Name()
		}

		// Run detectors using shared logic (SkipOnError for partial results)
		if err := harnesses.ApplyDetectors(evalCtx, a, detectorList, harnesses.SkipOnError); err != nil {
			return err
		}
	}

	allAttempts := results.Attempts

	// Call evaluator if provided (even with partial results)
	if eval != nil && len(allAttempts) > 0 {
		if err := eval.Evaluate(evalCtx, allAttempts); err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}
	}

	// Report probe failures after processing partial results
	if len(results.Errors) > 0 {
		// Log each probe error
		for _, err := range results.Errors {
			slog.Error("probe failed", "error", err)
		}

		// Return error indicating how many probes failed
		return fmt.Errorf("%d of %d probes failed", results.Failed, results.Total)
	}

	// Report scan-level errors (e.g., timeout) after processing partial results
	if scanErr != nil {
		return fmt.Errorf("scan interrupted after processing %d/%d probes (%d attempts): %w",
			results.Succeeded, results.Total, len(allAttempts), scanErr)
	}

	return nil
}

// init registers the probewise harness with the global registry.
func init() {
	harnesses.Register("probewise.Probewise", func(cfg registry.Config) (harnesses.Harness, error) {
		p := New()
		// Extract scanner options if provided
		if scannerOpts, ok := cfg["scanner_opts"].(*scanner.Options); ok {
			p.opts = scannerOpts
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
