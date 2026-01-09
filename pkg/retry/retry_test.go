package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestBasicRetrySuccess tests that a function succeeding after N retries works correctly
func TestBasicRetrySuccess(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary error")
		}
		return nil
	}

	cfg := Config{
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	err := Do(context.Background(), cfg, fn)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}

	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

// TestMaxAttemptsExceeded tests that retries stop after MaxAttempts
func TestMaxAttemptsExceeded(t *testing.T) {
	attempts := 0
	testErr := errors.New("persistent error")
	fn := func() error {
		attempts++
		return testErr
	}

	cfg := Config{
		MaxAttempts:  3,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
	}

	err := Do(context.Background(), cfg, fn)
	if err == nil {
		t.Fatal("expected error after max attempts, got nil")
	}

	if attempts != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", attempts)
	}

	if !errors.Is(err, testErr) {
		t.Errorf("expected final error to be testErr, got: %v", err)
	}
}

// TestExponentialBackoff tests that delays increase exponentially
func TestExponentialBackoff(t *testing.T) {
	attempts := 0
	delays := []time.Duration{}
	lastTime := time.Now()

	fn := func() error {
		now := time.Now()
		if attempts > 0 {
			delays = append(delays, now.Sub(lastTime))
		}
		lastTime = now
		attempts++
		if attempts < 4 {
			return errors.New("retry")
		}
		return nil
	}

	cfg := Config{
		MaxAttempts:  5,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       0, // No jitter for predictable testing
	}

	err := Do(context.Background(), cfg, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify exponential growth
	// Expected delays: ~10ms, ~20ms, ~40ms (with some tolerance)
	if len(delays) != 3 {
		t.Fatalf("expected 3 delays, got %d", len(delays))
	}

	// Allow 50% tolerance for timing variations
	expectedDelays := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}
	for i, expected := range expectedDelays {
		actual := delays[i]
		tolerance := expected / 2
		if actual < expected-tolerance || actual > expected+tolerance {
			t.Errorf("delay[%d]: expected ~%v (tolerance ±%v), got %v", i, expected, tolerance, actual)
		}
	}
}

// TestMaxDelayCap tests that delay is capped at MaxDelay
func TestMaxDelayCap(t *testing.T) {
	attempts := 0
	delays := []time.Duration{}
	lastTime := time.Now()

	fn := func() error {
		now := time.Now()
		if attempts > 0 {
			delays = append(delays, now.Sub(lastTime))
		}
		lastTime = now
		attempts++
		if attempts < 5 {
			return errors.New("retry")
		}
		return nil
	}

	cfg := Config{
		MaxAttempts:  6,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     30 * time.Millisecond, // Cap at 30ms
		Multiplier:   2.0,
		Jitter:       0,
	}

	err := Do(context.Background(), cfg, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Expected: 10ms, 20ms, 30ms (capped), 30ms (capped)
	if len(delays) != 4 {
		t.Fatalf("expected 4 delays, got %d", len(delays))
	}

	// Verify last two delays are capped
	maxDelayTolerance := 15 * time.Millisecond // 50% tolerance
	for i := 2; i < len(delays); i++ {
		if delays[i] > cfg.MaxDelay+maxDelayTolerance {
			t.Errorf("delay[%d]: expected ≤%v (tolerance +%v), got %v", i, cfg.MaxDelay, maxDelayTolerance, delays[i])
		}
	}
}

// TestContextCancellation tests that context cancellation stops retries
func TestContextCancellation(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("retry")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after first attempt
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()

	cfg := Config{
		MaxAttempts:  10,
		InitialDelay: 20 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	err := Do(ctx, cfg, fn)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}

	// Should have attempted at least once but not all 10 times
	if attempts >= 10 {
		t.Errorf("expected fewer than 10 attempts due to cancellation, got %d", attempts)
	}
}

// TestRetryableFunc tests configurable retry conditions
func TestRetryableFunc(t *testing.T) {
	retryableErr := errors.New("retryable")
	permanentErr := errors.New("permanent")

	attempts := 0
	fn := func() error {
		attempts++
		if attempts == 1 {
			return retryableErr
		}
		return permanentErr
	}

	cfg := Config{
		MaxAttempts:  5,
		InitialDelay: 1 * time.Millisecond,
		MaxDelay:     100 * time.Millisecond,
		Multiplier:   2.0,
		RetryableFunc: func(err error) bool {
			return errors.Is(err, retryableErr)
		},
	}

	err := Do(context.Background(), cfg, fn)
	if err == nil {
		t.Fatal("expected error from non-retryable error")
	}

	if !errors.Is(err, permanentErr) {
		t.Errorf("expected permanentErr, got: %v", err)
	}

	// Should stop after 2 attempts (first retryable, second not)
	if attempts != 2 {
		t.Errorf("expected 2 attempts, got %d", attempts)
	}
}

// TestJitterVariation tests that jitter adds randomness to delays
func TestJitterVariation(t *testing.T) {
	attempts := 0
	delays := []time.Duration{}
	lastTime := time.Now()

	fn := func() error {
		now := time.Now()
		if attempts > 0 {
			delays = append(delays, now.Sub(lastTime))
		}
		lastTime = now
		attempts++
		if attempts < 4 {
			return errors.New("retry")
		}
		return nil
	}

	cfg := Config{
		MaxAttempts:  5,
		InitialDelay: 50 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
		Jitter:       0.5, // 50% jitter
	}

	err := Do(context.Background(), cfg, fn)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(delays) != 3 {
		t.Fatalf("expected 3 delays, got %d", len(delays))
	}

	// With 50% jitter, delays should be within [delay * 0.5, delay * 1.5]
	// Base delays: 50ms, 100ms, 200ms
	baseDelays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}

	for i, base := range baseDelays {
		actual := delays[i]
		min := time.Duration(float64(base) * 0.5)
		max := time.Duration(float64(base) * 1.5)

		if actual < min || actual > max {
			t.Errorf("delay[%d] with 50%% jitter: expected range [%v, %v], got %v", i, min, max, actual)
		}
	}
}

// TestImmediateSuccess tests function succeeding on first attempt
func TestImmediateSuccess(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		return nil
	}

	cfg := Config{
		MaxAttempts:  5,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	err := Do(context.Background(), cfg, fn)
	if err != nil {
		t.Fatalf("expected success on first attempt, got error: %v", err)
	}

	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

// TestZeroMaxAttempts tests that zero MaxAttempts is treated as no retry
func TestZeroMaxAttempts(t *testing.T) {
	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("error")
	}

	cfg := Config{
		MaxAttempts:  0,
		InitialDelay: 10 * time.Millisecond,
		MaxDelay:     1 * time.Second,
		Multiplier:   2.0,
	}

	err := Do(context.Background(), cfg, fn)
	if err == nil {
		t.Fatal("expected error with zero max attempts")
	}

	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}
