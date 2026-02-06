package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/metrics"
	"github.com/praetorian-inc/augustus/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockProbe is a test probe that returns attempts or errors based on configuration
type mockProbe struct {
	name     string
	delay    time.Duration
	err      error
	attempts []*attempt.Attempt
}

func (m *mockProbe) Probe(ctx context.Context, gen scanner.Generator) ([]*attempt.Attempt, error) {
	if m.delay > 0 {
		select {
		case <-time.After(m.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	if m.err != nil {
		return nil, m.err
	}

	return m.attempts, nil
}

func (m *mockProbe) Name() string        { return m.name }
func (m *mockProbe) Description() string { return m.name + " description" }
func (m *mockProbe) Goal() string        { return m.name + " goal" }
func (m *mockProbe) GetPrimaryDetector() string { return "test.Detector" }
func (m *mockProbe) GetPrompts() []string { return []string{"test prompt"} }

// mockGenerator is a test generator
type mockGenerator struct{}

func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	return []attempt.Message{{Role: "assistant", Content: "test response"}}, nil
}

func (m *mockGenerator) ClearHistory() {}

func (m *mockGenerator) Name() string        { return "test.Generator" }
func (m *mockGenerator) Description() string { return "test generator for scanner tests" }

func TestScanner_Run_Basic(t *testing.T) {
	// Test basic concurrent execution with multiple probes
	ctx := context.Background()
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "probe2", attempts: []*attempt.Attempt{{ID: "2"}}},
		&mockProbe{name: "probe3", attempts: []*attempt.Attempt{{ID: "3"}}},
	}

	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)
	assert.Len(t, results.Attempts, 3, "should have 3 attempts from 3 probes")
	assert.Equal(t, 3, results.Total)
	assert.Equal(t, 3, results.Succeeded)
	assert.Equal(t, 0, results.Failed)
}

func TestScanner_Run_ConcurrencyLimit(t *testing.T) {
	// Test that concurrency limit is respected
	ctx := context.Background()
	gen := &mockGenerator{}

	// Create probes that take time to execute
	probes := make([]scanner.Prober, 10)
	for i := 0; i < 10; i++ {
		probes[i] = &mockProbe{
			name:  fmt.Sprintf("probe%d", i),
			delay: 50 * time.Millisecond,
			attempts: []*attempt.Attempt{{ID: fmt.Sprintf("test%d", i)}},
		}
	}

	opts := scanner.Options{
		Concurrency: 3, // Max 3 concurrent
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)

	// Track progress
	var progressCallbackCalled bool
	s.SetProgressCallback(func(completed, total int) {
		progressCallbackCalled = true
	})

	// We can't directly track concurrency within the scanner's goroutines from outside,
	// so we verify errgroup's SetLimit is working by ensuring all probes complete
	// and the total time is consistent with the concurrency limit
	start := time.Now()
	results := s.Run(ctx, probes, gen)
	elapsed := time.Since(start)

	require.NoError(t, results.Error)
	assert.True(t, progressCallbackCalled, "progress callback should be called")
	assert.Equal(t, 10, results.Succeeded, "all 10 probes should succeed")

	// With 10 probes at 50ms each and concurrency of 3:
	// - Perfect serial: 500ms (10 * 50ms)
	// - Perfect parallel (3): ~167ms (10/3 * 50ms = 333ms, but first batch starts immediately)
	// - Actual should be between 150ms and 400ms
	assert.Greater(t, elapsed, 150*time.Millisecond, "should take more than 150ms (not fully parallel)")
	assert.Less(t, elapsed, 400*time.Millisecond, "should take less than 400ms (benefits from parallelism)")
}

func TestScanner_Run_ContextCancellation(t *testing.T) {
	// Test graceful cancellation via context
	ctx, cancel := context.WithCancel(context.Background())
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", delay: 100 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "probe2", delay: 100 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "2"}}},
		&mockProbe{name: "probe3", delay: 100 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "3"}}},
	}

	opts := scanner.Options{
		Concurrency: 1,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)

	// Cancel after first probe starts
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	results := s.Run(ctx, probes, gen)

	assert.Error(t, results.Error)
	assert.True(t, errors.Is(results.Error, context.Canceled), "error should be context.Canceled")
	assert.Less(t, results.Succeeded, 3, "should not complete all probes after cancellation")
}

func TestScanner_Run_Timeout(t *testing.T) {
	// Test overall timeout
	ctx := context.Background()
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", delay: 200 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "probe2", delay: 200 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "2"}}},
	}

	opts := scanner.Options{
		Concurrency: 1,
		Timeout:     100 * time.Millisecond, // Timeout before probes complete
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	assert.Error(t, results.Error)
	assert.True(t, errors.Is(results.Error, context.DeadlineExceeded), "error should be context.DeadlineExceeded")
}

func TestScanner_Run_ProbeTimeout(t *testing.T) {
	// Test per-probe timeout
	ctx := context.Background()
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "fast", delay: 10 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "slow", delay: 200 * time.Millisecond, attempts: []*attempt.Attempt{{ID: "2"}}},
	}

	opts := scanner.Options{
		Concurrency:  2,
		Timeout:      10 * time.Second,
		ProbeTimeout: 50 * time.Millisecond, // Timeout slow probe
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)
	assert.Equal(t, 1, results.Succeeded, "only fast probe should succeed")
	assert.Equal(t, 1, results.Failed, "slow probe should timeout")
	assert.Len(t, results.Errors, 1, "should have error for timeout")
}

func TestScanner_Run_ProbeError(t *testing.T) {
	// Test handling of probe errors
	ctx := context.Background()
	gen := &mockGenerator{}

	probeErr := errors.New("probe execution failed")
	probes := []scanner.Prober{
		&mockProbe{name: "good", attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "bad", err: probeErr},
		&mockProbe{name: "good2", attempts: []*attempt.Attempt{{ID: "3"}}},
	}

	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error, "scanner should not fail even if probes fail")
	assert.Equal(t, 2, results.Succeeded)
	assert.Equal(t, 1, results.Failed)
	assert.Len(t, results.Errors, 1, "should have one probe error")
	if len(results.Errors) > 0 {
		assert.Contains(t, results.Errors[0].Error(), "probe execution failed")
	}
}

func TestScanner_Run_ProgressCallback(t *testing.T) {
	// Test progress callback is invoked
	ctx := context.Background()
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", attempts: []*attempt.Attempt{{ID: "1"}}},
		&mockProbe{name: "probe2", attempts: []*attempt.Attempt{{ID: "2"}}},
		&mockProbe{name: "probe3", attempts: []*attempt.Attempt{{ID: "3"}}},
	}

	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)

	callCount := 0
	s.SetProgressCallback(func(completed, total int) {
		callCount++
		assert.LessOrEqual(t, completed, total, "completed should not exceed total")
	})

	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)
	assert.Equal(t, 3, callCount, "progress callback should be called 3 times")
}

func TestScanner_Run_EmptyProbes(t *testing.T) {
	// Test with no probes
	ctx := context.Background()
	gen := &mockGenerator{}

	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)
	results := s.Run(ctx, []scanner.Prober{}, gen)

	require.NoError(t, results.Error)
	assert.Len(t, results.Attempts, 0)
	assert.Equal(t, 0, results.Total)
}

func TestScanner_Run_ResultAggregation(t *testing.T) {
	// Test that results from multiple probes are properly aggregated
	ctx := context.Background()
	gen := &mockGenerator{}

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", attempts: []*attempt.Attempt{
			{ID: "1a", Probe: "probe1"},
			{ID: "1b", Probe: "probe1"},
		}},
		&mockProbe{name: "probe2", attempts: []*attempt.Attempt{
			{ID: "2a", Probe: "probe2"},
		}},
	}

	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)
	assert.Len(t, results.Attempts, 3, "should aggregate all attempts from all probes")

	// Verify attempts are from correct probes
	probeNames := make(map[string]int)
	for _, att := range results.Attempts {
		probeNames[att.Probe]++
	}
	assert.Equal(t, 2, probeNames["probe1"])
	assert.Equal(t, 1, probeNames["probe2"])
}

func TestOptions_DefaultValues(t *testing.T) {
	// Test default options
	opts := scanner.DefaultOptions()

	assert.Greater(t, opts.Concurrency, 0, "should have default concurrency")
	assert.Greater(t, opts.Timeout, time.Duration(0), "should have default timeout")
}

func TestScanner_New(t *testing.T) {
	// Test scanner creation
	opts := scanner.Options{
		Concurrency: 5,
		Timeout:     30 * time.Second,
	}

	s := scanner.New(opts)
	assert.NotNil(t, s)
}

// retryableProbe is a test probe that fails for the first N attempts, then succeeds
type retryableProbe struct {
	name           string
	failuresNeeded int
	attemptCount   *int // pointer so it's shared across retries
	attempts       []*attempt.Attempt
}

func (r *retryableProbe) Probe(ctx context.Context, gen scanner.Generator) ([]*attempt.Attempt, error) {
	*r.attemptCount++

	if *r.attemptCount <= r.failuresNeeded {
		return nil, errors.New("temporary failure")
	}

	return r.attempts, nil
}

func (r *retryableProbe) Name() string                { return r.name }
func (r *retryableProbe) Description() string         { return r.name + " description" }
func (r *retryableProbe) Goal() string                { return r.name + " goal" }
func (r *retryableProbe) GetPrimaryDetector() string  { return "test.Detector" }
func (r *retryableProbe) GetPrompts() []string        { return []string{"test prompt"} }

func TestScanner_Run_RetriesOnFailure(t *testing.T) {
	// Test that Scanner retries failed probes according to RetryCount
	ctx := context.Background()
	gen := &mockGenerator{}

	// Create a probe that fails twice, then succeeds on third attempt
	attemptCount := 0
	probe := &retryableProbe{
		name:           "flaky-probe",
		failuresNeeded: 2, // Fails first 2 attempts
		attemptCount:   &attemptCount,
		attempts:       []*attempt.Attempt{{ID: "success"}},
	}

	opts := scanner.Options{
		Concurrency:  1,
		Timeout:      10 * time.Second,
		RetryCount:   3,                    // Retry up to 3 times
		RetryBackoff: 10 * time.Millisecond, // Short backoff for tests
	}

	s := scanner.New(opts)
	results := s.Run(ctx, []scanner.Prober{probe}, gen)

	require.NoError(t, results.Error)
	assert.Equal(t, 3, attemptCount, "probe should be attempted 3 times (initial + 2 retries)")
	assert.Equal(t, 1, results.Succeeded, "probe should succeed after retries")
	assert.Equal(t, 0, results.Failed, "probe should not fail after successful retry")
	assert.Len(t, results.Attempts, 1, "should have 1 attempt from successful probe")
	assert.Len(t, results.Errors, 0, "should have no errors after successful retry")
}

func TestScanner_Run_PopulatesMetrics(t *testing.T) {
	// Test that Scanner populates metrics during execution
	ctx := context.Background()
	gen := &mockGenerator{}

	// Create attempts with varying vulnerability scores
	safeAttempt := attempt.New("safe prompt")
	safeAttempt.AddScore(0.2) // Below threshold, not vulnerable

	vulnAttempt1 := attempt.New("vuln prompt 1")
	vulnAttempt1.AddScore(0.8) // Above threshold, vulnerable

	vulnAttempt2 := attempt.New("vuln prompt 2")
	vulnAttempt2.AddScore(0.9) // Above threshold, vulnerable

	probes := []scanner.Prober{
		&mockProbe{name: "probe1", attempts: []*attempt.Attempt{safeAttempt}},
		&mockProbe{name: "probe2", attempts: []*attempt.Attempt{vulnAttempt1, vulnAttempt2}},
		&mockProbe{name: "probe3", err: errors.New("probe failed")},
	}

	// Create metrics struct and pass to scanner
	m := &metrics.Metrics{}
	opts := scanner.Options{
		Concurrency: 2,
		Timeout:     10 * time.Second,
		Metrics:     m,
	}

	s := scanner.New(opts)
	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)

	// Verify metrics were populated
	assert.Equal(t, int64(3), atomic.LoadInt64(&m.ProbesTotal), "should count all probes")
	assert.Equal(t, int64(2), atomic.LoadInt64(&m.ProbesSucceeded), "should count succeeded probes")
	assert.Equal(t, int64(1), atomic.LoadInt64(&m.ProbesFailed), "should count failed probes")
	assert.Equal(t, int64(3), atomic.LoadInt64(&m.AttemptsTotal), "should count all attempts")
	assert.Equal(t, int64(2), atomic.LoadInt64(&m.AttemptsVuln), "should count vulnerable attempts")
}
