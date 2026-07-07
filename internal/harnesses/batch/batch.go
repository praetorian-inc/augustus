// Package batch provides the batch harness implementation.
//
// The batch harness executes probes in parallel with configurable concurrency.
// This allows for faster scanning by running multiple probes simultaneously
// while controlling resource usage via concurrency limits.
package batch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Errors returned by the batch harness.
var (
	ErrNoProbes    = errors.New("no probes provided")
	ErrNoDetectors = errors.New("no detectors provided")
)

// Batch implements the batch harness strategy with parallel probe execution.
type Batch struct {
	concurrency int
	timeout     time.Duration
	// probeDetectorOverrides scopes detectors per probe (primary + declared
	// secondaries) so an attempt is scored only by its own probe's detectors,
	// keeping unrelated detectors out of the MAX-based verdict. Keyed by probe name.
	probeDetectorOverrides map[string][]detectors.Detector
	// detectorsExplicit controls the per-attempt fallback when a probe has no
	// override entry: explicit → the shared detectorList; auto → the probe's own
	// primary only (never the cross-probe union).
	detectorsExplicit bool
}

// New creates a new batch harness from configuration.
func New(cfg registry.Config) (*Batch, error) {
	b := &Batch{
		concurrency: 10,               // Default concurrency
		timeout:     30 * time.Second, // Default timeout
	}

	// Optional: concurrency limit
	if concurrency, ok := cfg["concurrency"].(int); ok && concurrency > 0 {
		b.concurrency = concurrency
	} else if concurrency, ok := cfg["concurrency"].(float64); ok && concurrency > 0 {
		b.concurrency = int(concurrency)
	}

	// Optional: timeout
	if timeoutStr, ok := cfg["timeout"].(string); ok {
		if dur, err := time.ParseDuration(timeoutStr); err == nil {
			b.timeout = dur
		}
	} else if timeoutDur, ok := cfg["timeout"].(time.Duration); ok {
		b.timeout = timeoutDur
	}

	// Optional: per-probe detector overrides
	if overrides, ok := cfg["probe_detector_overrides"].(map[string][]detectors.Detector); ok {
		b.probeDetectorOverrides = overrides
	} else if _, exists := cfg["probe_detector_overrides"]; exists {
		slog.Warn("batch: key has unexpected type, ignoring", "key", "probe_detector_overrides", "type", fmt.Sprintf("%T", cfg["probe_detector_overrides"]))
	}

	// Optional: detector-selection mode (controls the per-attempt fallback).
	if explicit, ok := cfg["detectors_explicit"].(bool); ok {
		b.detectorsExplicit = explicit
	}

	return b, nil
}

// Name returns the fully qualified harness name.
func (b *Batch) Name() string {
	return "batch.Batch"
}

// Description returns a human-readable description.
func (b *Batch) Description() string {
	return fmt.Sprintf("Executes probes in parallel (concurrency=%d, timeout=%v)", b.concurrency, b.timeout)
}

// Run executes the batch scan workflow with parallel probe execution.
func (b *Batch) Run(
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

	// Create semaphore for concurrency control
	sem := make(chan struct{}, b.concurrency)

	// Collect all attempts across all probes
	var mu sync.Mutex
	var allAttempts []*attempt.Attempt
	var wg sync.WaitGroup
	errs := make(chan error, len(probeList))

	// Process each probe in parallel
	for _, probe := range probeList {
		wg.Add(1)

		go func(p probes.Prober) {
			defer wg.Done()

			// Acquire semaphore slot
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				errs <- ctx.Err()
				return
			}

			slog.Debug("running probe", "probe", p.Name())

			// Run the probe to get attempts
			attempts, err := p.Probe(ctx, gen)
			if err != nil {
				errs <- fmt.Errorf("probe %s failed: %w", p.Name(), err)
				return
			}

			// Run all detectors on each attempt
			for _, a := range attempts {
				// Check context cancellation
				if err := ctx.Err(); err != nil {
					errs <- err
					return
				}

				// Set the generator name if not already set
				if a.Generator == "" {
					a.Generator = gen.Name()
				}

				// Select detector list: per-probe override takes precedence;
				// otherwise scope to the probe's own primary (auto mode) or the
				// shared list (explicit mode) — never the cross-probe union in
				// auto mode.
				activeDetectors := harnesses.SelectProbeDetectors(a, detectorList, b.probeDetectorOverrides, b.detectorsExplicit)

				// Run detectors using shared logic (FailOnError routes to errs channel)
				if err := harnesses.ApplyDetectors(ctx, a, activeDetectors, harnesses.FailOnError); err != nil {
					errs <- err
					return
				}
			}

			// Add attempts to collection (thread-safe)
			mu.Lock()
			allAttempts = append(allAttempts, attempts...)
			mu.Unlock()
		}(probe)
	}

	// Wait for all probes to complete
	wg.Wait()
	close(errs)

	// Check for errors
	for err := range errs {
		if err != nil {
			return err
		}
	}

	// Call evaluator if provided
	if eval != nil && len(allAttempts) > 0 {
		if err := eval.Evaluate(ctx, allAttempts); err != nil {
			return fmt.Errorf("evaluation failed: %w", err)
		}
	}

	return nil
}

// init registers the batch harness with the global registry.
func init() {
	harnesses.Register("batch.Batch", func(cfg registry.Config) (harnesses.Harness, error) {
		return New(cfg)
	})
}
