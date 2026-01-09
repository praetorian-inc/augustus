package retry

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// Config defines the retry behavior configuration.
type Config struct {
	// MaxAttempts is the maximum number of attempts (including the initial attempt).
	// A value of 0 means only one attempt with no retries.
	MaxAttempts int

	// InitialDelay is the delay before the first retry.
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries.
	// Delays will be capped at this value.
	MaxDelay time.Duration

	// Multiplier is the factor by which the delay increases after each retry.
	// For exponential backoff, use a value > 1 (e.g., 2.0).
	Multiplier float64

	// Jitter is the fraction of randomness to add to delays (0.0 to 1.0).
	// For example, 0.5 means delays will vary by ±50%.
	// A value of 0 means no jitter.
	Jitter float64

	// RetryableFunc determines whether an error should trigger a retry.
	// If nil, all errors trigger retries.
	// Return true to retry, false to stop retrying.
	RetryableFunc func(error) bool
}

// Do executes the given function with retry logic according to the provided config.
// It returns nil if the function succeeds, or the last error if all retries are exhausted.
// The function stops retrying if:
// - The function succeeds (returns nil)
// - MaxAttempts is reached
// - The context is cancelled
// - RetryableFunc returns false for an error
func Do(ctx context.Context, cfg Config, fn func() error) error {
	// Handle edge case: zero MaxAttempts means try once
	maxAttempts := cfg.MaxAttempts
	if maxAttempts == 0 {
		maxAttempts = 1
	}

	var lastErr error
	delay := cfg.InitialDelay

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Execute the function
		err := fn()

		// Success - return immediately
		if err == nil {
			return nil
		}

		lastErr = err

		// Check if we should retry this error
		if cfg.RetryableFunc != nil && !cfg.RetryableFunc(err) {
			return err
		}

		// If this was the last attempt, return the error
		if attempt >= maxAttempts {
			return err
		}

		// Calculate delay for next retry with exponential backoff
		actualDelay := delay

		// Apply jitter if configured
		if cfg.Jitter > 0 {
			jitterFactor := 1.0 + (rand.Float64()*2.0-1.0)*cfg.Jitter
			actualDelay = time.Duration(float64(actualDelay) * jitterFactor)
		}

		// Cap at MaxDelay
		if actualDelay > cfg.MaxDelay {
			actualDelay = cfg.MaxDelay
		}

		// Wait with context cancellation support
		select {
		case <-ctx.Done():
			// Context cancelled - return context error
			return ctx.Err()
		case <-time.After(actualDelay):
			// Continue to next retry
		}

		// Increase delay for next iteration (exponential backoff)
		delay = time.Duration(float64(delay) * cfg.Multiplier)
	}

	return lastErr
}

// ErrMaxAttemptsExceeded is returned when all retry attempts are exhausted.
var ErrMaxAttemptsExceeded = errors.New("max retry attempts exceeded")

// IsRetryable is a helper function that creates a RetryableFunc for common patterns.
// Example usage:
//   cfg.RetryableFunc = retry.IsRetryable(func(err error) bool {
//       return errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded)
//   })
func IsRetryable(fn func(error) bool) func(error) bool {
	return fn
}

// DefaultConfig returns a Config with sensible defaults:
// - MaxAttempts: 3
// - InitialDelay: 100ms
// - MaxDelay: 30s
// - Multiplier: 2.0 (exponential)
// - Jitter: 0.1 (10%)
// - RetryableFunc: nil (retry all errors)
func DefaultConfig() Config {
	return Config{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		Multiplier:    2.0,
		Jitter:        0.1,
		RetryableFunc: nil,
	}
}
