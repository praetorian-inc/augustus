package scanner_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/hooks"
	"github.com/praetorian-inc/augustus/pkg/metrics"
	"github.com/praetorian-inc/augustus/pkg/scanner"
	"github.com/praetorian-inc/augustus/pkg/types"
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

func (m *mockProbe) Name() string               { return m.name }
func (m *mockProbe) Description() string        { return m.name + " description" }
func (m *mockProbe) Goal() string               { return m.name + " goal" }
func (m *mockProbe) GetPrimaryDetector() string { return "test.Detector" }
func (m *mockProbe) GetPrompts() []string       { return []string{"test prompt"} }

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
			name:     fmt.Sprintf("probe%d", i),
			delay:    50 * time.Millisecond,
			attempts: []*attempt.Attempt{{ID: fmt.Sprintf("test%d", i)}},
		}
	}

	opts := scanner.Options{
		Concurrency: 3, // Max 3 concurrent
		Timeout:     10 * time.Second,
	}

	s := scanner.New(opts)

	// Track progress
	var progressCallbackCalled atomic.Bool
	s.SetProgressCallback(func(probeName string, completed, total int, elapsed time.Duration, err error) {
		progressCallbackCalled.Store(true)
	})

	// We can't directly track concurrency within the scanner's goroutines from outside,
	// so we verify errgroup's SetLimit is working by ensuring all probes complete
	// and the total time is consistent with the concurrency limit
	start := time.Now()
	results := s.Run(ctx, probes, gen)
	elapsed := time.Since(start)

	require.NoError(t, results.Error)
	assert.True(t, progressCallbackCalled.Load(), "progress callback should be called")
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

	var callCount atomic.Int32
	s.SetProgressCallback(func(probeName string, completed, total int, elapsed time.Duration, err error) {
		callCount.Add(1)
		assert.LessOrEqual(t, completed, total, "completed should not exceed total")
	})

	results := s.Run(ctx, probes, gen)

	require.NoError(t, results.Error)
	assert.Equal(t, int32(3), callCount.Load(), "progress callback should be called 3 times")
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
	assert.Equal(t, time.Duration(0), opts.Timeout, "default timeout should be 0 (no global timeout; per-probe timeouts control execution)")
	assert.Equal(t, time.Duration(0), opts.ProbeTimeout, "default probe timeout should be 0 (no timeout; set explicitly when needed)")
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

func (r *retryableProbe) Name() string               { return r.name }
func (r *retryableProbe) Description() string        { return r.name + " description" }
func (r *retryableProbe) Goal() string               { return r.name + " goal" }
func (r *retryableProbe) GetPrimaryDetector() string { return "test.Detector" }
func (r *retryableProbe) GetPrompts() []string       { return []string{"test prompt"} }

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
		RetryCount:   3,                     // Retry up to 3 times
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

	// Verify metrics were populated via the preferred SnapshotLocked API.
	snapshot := m.SnapshotLocked()

	assert.Equal(t, int64(3), snapshot.ProbesTotal, "should count all probes")
	assert.Equal(t, int64(2), snapshot.ProbesSucceeded, "should count succeeded probes")
	assert.Equal(t, int64(1), snapshot.ProbesFailed, "should count failed probes")
	assert.Equal(t, int64(3), snapshot.AttemptsTotal, "should count all attempts")
	assert.Equal(t, int64(2), snapshot.AttemptsVuln, "should count vulnerable attempts")
}

// ─── Token-accounting helpers ────────────────────────────────────────────────

// usageMockGenerator implements types.Generator + types.UsageReporter.
// Every Generate call adds tokensPerCall to the embedded UsageCounter, making
// it easy to assert exact TokensConsumed values after a scanner run.
type usageMockGenerator struct {
	types.UsageCounter
	tokensPerCall int64
	delay         time.Duration // optional artificial latency for race tests
}

func (g *usageMockGenerator) Generate(_ context.Context, _ *attempt.Conversation, _ int) ([]attempt.Message, error) {
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	g.AddTokens(g.tokensPerCall)
	return []attempt.Message{attempt.NewAssistantMessage("ok")}, nil
}

func (g *usageMockGenerator) ClearHistory()       {}
func (g *usageMockGenerator) Name() string        { return "test.UsageMock" }
func (g *usageMockGenerator) Description() string { return "usage mock generator" }

// callingProbe is a probe that actually invokes gen.Generate once, so that
// UsageCounter Add calls flow through during a real scanner.Run.
type callingProbe struct {
	name string
}

func (p *callingProbe) Name() string               { return p.name }
func (p *callingProbe) Description() string        { return p.name }
func (p *callingProbe) Goal() string               { return p.name }
func (p *callingProbe) GetPrimaryDetector() string { return "test.Detector" }
func (p *callingProbe) GetPrompts() []string       { return []string{"test"} }

func (p *callingProbe) Probe(ctx context.Context, gen scanner.Generator) ([]*attempt.Attempt, error) {
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	_, err := gen.Generate(ctx, conv, 1)
	if err != nil {
		return nil, err
	}
	return []*attempt.Attempt{}, nil
}

// ─── Category (ii): TokensConsumed end-to-end ────────────────────────────────

// TestScanner_Run_RecordsTokenUsage proves the always-0 bug is fixed:
// a generator that calls AddTokens on each Generate results in a non-zero
// TokensConsumed in the metrics snapshot after scanner.Run.
func TestScanner_Run_RecordsTokenUsage(t *testing.T) {
	ctx := context.Background()

	const tokensPerCall = int64(7)
	const probeCount = 3

	gen := &usageMockGenerator{tokensPerCall: tokensPerCall}
	probeList := make([]scanner.Prober, probeCount)
	for i := range probeList {
		probeList[i] = &callingProbe{name: fmt.Sprintf("p%d", i)}
	}

	m := &metrics.Metrics{}
	s := scanner.New(scanner.Options{Concurrency: 2, Metrics: m})
	s.Run(ctx, probeList, gen)

	snapshot := m.SnapshotLocked()
	require.Equal(
		t,
		tokensPerCall*probeCount,
		snapshot.TokensConsumed,
		"TokensConsumed must equal sum of per-probe token additions",
	)
}

// TestScanner_Run_NoUsageReporter_TokensZero ensures that a plain generator
// without UsageReporter leaves TokensConsumed at 0 and does not panic.
func TestScanner_Run_NoUsageReporter_TokensZero(t *testing.T) {
	ctx := context.Background()
	gen := &mockGenerator{} // does NOT implement UsageReporter
	probeList := []scanner.Prober{&callingProbe{name: "p0"}}

	m := &metrics.Metrics{}
	s := scanner.New(scanner.Options{Concurrency: 1, Metrics: m})
	s.Run(ctx, probeList, gen)

	snapshot := m.SnapshotLocked()
	assert.Equal(t, int64(0), snapshot.TokensConsumed, "generator without UsageReporter must leave TokensConsumed 0")
}

// ─── Category (iii): Delta / no-double-count ─────────────────────────────────

// TestScanner_Run_ReusedGenerator_NoDoubleCount guards correction (e):
// when the SAME generator instance is reused across two scanner.Run calls
// (each with its own fresh Metrics), each run's TokensConsumed reflects only
// that run's delta — not the cumulative generator total.
func TestScanner_Run_ReusedGenerator_NoDoubleCount(t *testing.T) {
	ctx := context.Background()

	const tokensPerCall = int64(5)
	gen := &usageMockGenerator{tokensPerCall: tokensPerCall}
	probeList := []scanner.Prober{
		&callingProbe{name: "pa"},
		&callingProbe{name: "pb"},
	}
	expected := tokensPerCall * int64(len(probeList))

	// First run
	m1 := &metrics.Metrics{}
	s1 := scanner.New(scanner.Options{Concurrency: 1, Metrics: m1})
	s1.Run(ctx, probeList, gen)
	first := m1.SnapshotLocked().TokensConsumed
	require.Equal(t, expected, first, "first run: TokensConsumed must equal probeCount*tokensPerCall")

	// Second run reuses the same gen — cumulative counter is now 2× but the
	// delta approach must record only this run's contribution.
	m2 := &metrics.Metrics{}
	s2 := scanner.New(scanner.Options{Concurrency: 1, Metrics: m2})
	s2.Run(ctx, probeList, gen)
	second := m2.SnapshotLocked().TokensConsumed

	require.Equal(t, expected, second, "second run with reused generator must equal delta, not cumulative total")
}

// ─── Category (iv): Decorator forwarding ─────────────────────────────────────

// TestScanner_Run_HookedGeneratorForwardsTokens guards correction (b):
// when the scanner's gen is a *hooks.HookedGenerator wrapping a UsageReporter,
// tokens still flow through to Metrics.TokensConsumed.
func TestScanner_Run_HookedGeneratorForwardsTokens(t *testing.T) {
	ctx := context.Background()

	const tokensPerCall = int64(11)
	inner := &usageMockGenerator{tokensPerCall: tokensPerCall}
	wrapped := hooks.NewHookedGenerator(inner, nil, nil)

	probeList := []scanner.Prober{
		&callingProbe{name: "hook-p0"},
		&callingProbe{name: "hook-p1"},
	}
	expected := tokensPerCall * int64(len(probeList))

	m := &metrics.Metrics{}
	s := scanner.New(scanner.Options{Concurrency: 1, Metrics: m})
	s.Run(ctx, probeList, wrapped)

	snapshot := m.SnapshotLocked()
	require.Equal(
		t,
		expected,
		snapshot.TokensConsumed,
		"HookedGenerator must forward UsageReporter so tokens reach Metrics",
	)
}

// ─── Category (i): Race test — concurrent writes + live snapshot ──────────────

// TestScanner_ConcurrentWritesAndSnapshot_RaceClean models the
// /metrics-scrape-during-scan scenario: probe goroutines call RecordProbeResult
// and AddTokens while a concurrent reader calls SnapshotLocked (and
// PrometheusExporter.Export). The test must be -race clean and would fail if
// any write bypassed the embedded mutex.
func TestScanner_ConcurrentWritesAndSnapshot_RaceClean(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	const tokensPerCall = int64(3)
	gen := &usageMockGenerator{
		tokensPerCall: tokensPerCall,
		delay:         1 * time.Millisecond, // slow enough for reader to interleave
	}

	const probeCount = 20
	probeList := make([]scanner.Prober, probeCount)
	for i := range probeList {
		probeList[i] = &callingProbe{name: fmt.Sprintf("race-p%d", i)}
	}

	m := &metrics.Metrics{}

	// Live reader: hammers SnapshotLocked() concurrently with the scanner run.
	// A data race here would mean the single-lock invariant is broken. We use
	// SnapshotLocked directly so the race detector exercises the same code path
	// that PrometheusExporter.Export uses under the hood.
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				_ = m.SnapshotLocked()
			}
		}
	}()

	s := scanner.New(scanner.Options{Concurrency: 5, Metrics: m})
	s.Run(ctx, probeList, gen)

	cancel() // stop reader
	<-readerDone

	snapshot := m.SnapshotLocked()
	// After all probes: each probe called Generate once → tokensPerCall each.
	require.Equal(
		t,
		tokensPerCall*probeCount,
		snapshot.TokensConsumed,
		"TokensConsumed must reflect all probe token additions after race-clean run",
	)
}

// ─── Category (v): ClearHistory preserves counter ────────────────────────────

// TestUsageMockGenerator_ClearHistory_PreservesCounter guards correction (d):
// ClearHistory must NOT reset AccumulatedTokens (lifetime of instance).
// Tested on the usageMockGenerator since real generators' ClearHistory are
// currently no-ops w.r.t. the counter; the invariant is proven at this level.
func TestUsageMockGenerator_ClearHistory_PreservesCounter(t *testing.T) {
	gen := &usageMockGenerator{tokensPerCall: 17}
	ctx := context.Background()
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	_, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)

	before := gen.AccumulatedTokens()
	require.Positive(t, before, "AccumulatedTokens must be positive after Generate")

	gen.ClearHistory()

	require.Equal(t, before, gen.AccumulatedTokens(), "ClearHistory must not reset AccumulatedTokens")
}

// ─── Category (vi): Backward-compat shims ────────────────────────────────────

// TestMetrics_BackwardCompatShims_SnapshotAndExporter guards that the two
// deprecated APIs still compile and behave correctly:
//   - Snapshot(_ *sync.Mutex) returns the same data as SnapshotLocked().
//   - NewPrometheusExporter(m, any-mutex-or-nil).Export() still works and is race-safe.
//
//nolint:staticcheck // intentional deprecated-API backward-compat test
func TestMetrics_BackwardCompatShims_SnapshotAndExporter(t *testing.T) {
	m := &metrics.Metrics{}
	m.RecordProbeResult(true, 4, 2)
	m.AddTokens(100)

	// Deprecated Snapshot(_ *sync.Mutex) must return same data as SnapshotLocked.
	var mu sync.Mutex
	deprecated := m.Snapshot(&mu)
	preferred := m.SnapshotLocked()

	assert.Equal(t, preferred.ProbesTotal, deprecated.ProbesTotal, "Snapshot: ProbesTotal mismatch")
	assert.Equal(t, preferred.ProbesSucceeded, deprecated.ProbesSucceeded, "Snapshot: ProbesSucceeded mismatch")
	assert.Equal(t, preferred.AttemptsTotal, deprecated.AttemptsTotal, "Snapshot: AttemptsTotal mismatch")
	assert.Equal(t, preferred.TokensConsumed, deprecated.TokensConsumed, "Snapshot: TokensConsumed mismatch")

	// NewPrometheusExporter with a fresh (non-nil) mutex must not panic and must Export.
	exporter := metrics.NewPrometheusExporter(m, &mu)
	out := exporter.Export()
	assert.Contains(t, out, "augustus_probes_total", "Export via deprecated constructor must produce output")

	// nil mutex must also work (the shim ignores the argument).
	exporterNil := metrics.NewPrometheusExporter(m, nil)
	outNil := exporterNil.Export()
	assert.Contains(t, outNil, "augustus_probes_total", "Export via nil-mutex deprecated constructor must produce output")
}
