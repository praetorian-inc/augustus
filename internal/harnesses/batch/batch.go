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
}

// New creates a new batch harness from configuration.
func New(cfg registry.Config) (*Batch, error) {
	b := &Batch{
		concurrency: 10,              // Default concurrency
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

				// Run each detector
				maxScore := 0.0
				primaryDetector := ""
				var primaryScores []float64
				firstDetector := ""
				var firstScores []float64

				for _, detector := range detectorList {
					slog.Debug("running detector", "detector", detector.Name(), "probe", p.Name())

					scores, err := detector.Detect(ctx, a)
					if err != nil {
						errs <- fmt.Errorf("detector %s failed on probe %s: %w",
							detector.Name(), p.Name(), err)
						return
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
