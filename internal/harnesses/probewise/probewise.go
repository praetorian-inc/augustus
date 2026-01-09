// Package probewise provides the probewise harness implementation.
//
// The probewise harness executes probes concurrently using the scanner package,
// then runs detectors sequentially on all probe attempts. This provides significant
// performance improvements over the original sequential implementation while
// maintaining compatibility with Python garak's probewise harness.
package probewise

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

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
	results := s.Run(ctx, probeList, gen)

	// Check for scanner-level errors (context cancellation, etc.)
	if results.Error != nil {
		return results.Error
	}

	// Continue processing successful attempts even if some probes failed.
	// We'll report probe errors at the end, after processing partial results.

	// Apply detectors to all attempts (sequential, but fast)
	for _, a := range results.Attempts {
		// Check context cancellation between attempts
		if err := ctx.Err(); err != nil {
			return err
		}

		// Set the generator name if not already set
		if a.Generator == "" {
			a.Generator = gen.Name()
		}

		// Run each detector and track highest score (Option 4 fix)
		maxScore := 0.0
		primaryDetector := ""
		var primaryScores []float64
		firstDetector := ""
		var firstScores []float64

		for _, detector := range detectorList {
			slog.Debug("running detector", "detector", detector.Name(), "probe", a.Probe)

			scores, err := detector.Detect(ctx, a)
			if err != nil {
				return fmt.Errorf("detector %s failed on probe %s: %w",
					detector.Name(), a.Probe, err)
			}

			// Store detector results
			a.SetDetectorResults(detector.Name(), scores)

			// Remember first detector as fallback
			if firstDetector == "" {
				firstDetector = detector.Name()
				firstScores = scores
			}

			// Track detector with highest score
			for _, score := range scores {
				if score > maxScore {
					maxScore = score
					primaryDetector = detector.Name()
					primaryScores = scores
				}
			}
		}

		// Set primary detector to one with highest score
		// If no detector had scores, use first detector
		// This ensures console and JSONL outputs are consistent
		if primaryDetector != "" {
			a.Detector = primaryDetector
			a.Scores = primaryScores
		} else if firstDetector != "" {
			a.Detector = firstDetector
			a.Scores = firstScores
		}

		// Mark attempt as complete only if not in error state
		if a.Status != attempt.StatusError {
			a.Complete()
		}
	}

	allAttempts := results.Attempts

	// Call evaluator if provided (even with partial results)
	if eval != nil && len(allAttempts) > 0 {
		if err := eval.Evaluate(ctx, allAttempts); err != nil {
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
