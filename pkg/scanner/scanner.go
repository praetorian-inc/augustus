package scanner

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/metrics"
	"github.com/praetorian-inc/augustus/pkg/retry"
	"github.com/praetorian-inc/augustus/pkg/types"
	"golang.org/x/sync/errgroup"
)

// Generator is a type alias for backward compatibility.
// See types.Generator for the canonical interface definition.
type Generator = types.Generator

// Prober is a type alias for backward compatibility.
// See types.Prober for the canonical interface definition.
type Prober = types.Prober

// Scanner executes probes concurrently with configurable limits.
type Scanner struct {
	opts             Options
	progressCallback func(probeName string, completed, total int, elapsed time.Duration, err error)
	metrics          *metrics.Metrics
	metricsMu        sync.Mutex // Protects metrics updates and reads
}

// Results contains the aggregated results from all probe executions.
type Results struct {
	// Attempts contains all attempts from all probes.
	Attempts []*attempt.Attempt

	// Total is the total number of probes executed.
	Total int

	// Succeeded is the number of probes that completed successfully.
	Succeeded int

	// Failed is the number of probes that failed or timed out.
	Failed int

	// Errors contains any errors that occurred during execution.
	Errors []error

	// Error is the overall error if scanner execution failed.
	Error error
}

// New creates a new Scanner with the given options.
func New(opts Options) *Scanner {
	// Initialize metrics if not provided
	m := opts.Metrics
	if m == nil {
		m = &metrics.Metrics{}
	}

	return &Scanner{
		opts:    opts,
		metrics: m,
	}
}

// SetProgressCallback sets a callback function that is invoked after each probe completes.
func (s *Scanner) SetProgressCallback(callback func(probeName string, completed, total int, elapsed time.Duration, err error)) {
	s.progressCallback = callback
}

// GetMetricsMutex returns a pointer to the mutex protecting metrics access.
// This is used by PrometheusExporter to safely read metrics.
func (s *Scanner) GetMetricsMutex() *sync.Mutex {
	return &s.metricsMu
}

// Run executes all probes concurrently and returns aggregated results.
func (s *Scanner) Run(ctx context.Context, probes []Prober, gen Generator) Results {
	// Apply overall timeout if configured
	if s.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.opts.Timeout)
		defer cancel()
	}

	// Initialize results
	results := Results{
		Attempts: make([]*attempt.Attempt, 0),
		Total:    len(probes),
		Errors:   make([]error, 0),
	}

	// Handle empty probe list
	if len(probes) == 0 {
		return results
	}

	// Thread-safe result collection
	var mu sync.Mutex
	completed := 0

	// Create errgroup with concurrency limit
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(s.opts.Concurrency)

	// Execute each probe concurrently
	for _, probe := range probes {
		probe := probe // Capture loop variable

		g.Go(func() error {
			start := time.Now()

			// Apply per-probe timeout if configured
			probeCtx := gctx
			if s.opts.ProbeTimeout > 0 {
				var cancel context.CancelFunc
				probeCtx, cancel = context.WithTimeout(gctx, s.opts.ProbeTimeout)
				defer cancel()
			}

			// Execute probe with retry logic
			var attempts []*attempt.Attempt
			var err error

			if s.opts.RetryCount > 0 {
				// Configure retry with scanner options
				cfg := retry.Config{
					MaxAttempts:  s.opts.RetryCount,
					InitialDelay: s.opts.RetryBackoff,
					MaxDelay:     s.opts.RetryBackoff * 10, // Cap at 10x initial delay
					Multiplier:   1.0,                      // Linear backoff (use configured delay)
					Jitter:       0.1,                      // 10% jitter to avoid thundering herd
				}

				// Wrap probe execution with retry
				err = retry.Do(probeCtx, cfg, func() error {
					var probeErr error
					attempts, probeErr = probe.Probe(probeCtx, gen)
					return probeErr
				})
			} else {
				// No retry configured, execute once
				attempts, err = probe.Probe(probeCtx, gen)
			}

			// Check for context cancellation/timeout - these should stop all work
			if probeCtx.Err() != nil {
				// Capture timeout error with probe name
				timeoutErr := fmt.Errorf("probe %s timeout: %w", probe.Name(), probeCtx.Err())

				// If context was canceled, return error to stop other probes
				if gctx.Err() != nil {
					return gctx.Err()
				}
				// If only probe context timed out, record as probe failure
				mu.Lock()
				completed++
				results.Failed++
				results.Errors = append(results.Errors, timeoutErr)
				currentCompleted := completed
				currentTotal := results.Total
				mu.Unlock()

				// Update metrics separately with metricsMu
				s.metricsMu.Lock()
				s.metrics.ProbesTotal++
				s.metrics.ProbesFailed++
				s.metricsMu.Unlock()

				// Call progress callback outside of mutex to avoid blocking
				if s.progressCallback != nil {
					s.progressCallback(probe.Name(), currentCompleted, currentTotal, time.Since(start), timeoutErr)
				}

				return nil
			}

			// Collect results (thread-safe)
			mu.Lock()
			completed++
			if err != nil {
				results.Failed++
				results.Errors = append(results.Errors, fmt.Errorf("probe %s failed: %w", probe.Name(), err))
			} else {
				results.Succeeded++
				results.Attempts = append(results.Attempts, attempts...)
			}
			currentCompleted := completed
			currentTotal := results.Total
			mu.Unlock()

			// Update metrics separately with metricsMu
			s.metricsMu.Lock()
			s.metrics.ProbesTotal++
			if err != nil {
				s.metrics.ProbesFailed++
			} else {
				s.metrics.ProbesSucceeded++
				// Track attempt metrics
				for _, att := range attempts {
					s.metrics.AttemptsTotal++
					if att.IsVulnerable() {
						s.metrics.AttemptsVuln++
					}
				}
			}
			s.metricsMu.Unlock()

			// Call progress callback outside of mutex to avoid blocking
			if s.progressCallback != nil {
				s.progressCallback(probe.Name(), currentCompleted, currentTotal, time.Since(start), err)
			}

			// Return nil to continue with other probes even if this one failed
			return nil
		})
	}

	// Wait for all probes to complete
	if err := g.Wait(); err != nil {
		results.Error = err
	}

	return results
}
