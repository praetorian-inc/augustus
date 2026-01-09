package batch

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// mockProbe simulates a probe with configurable delay
type mockProbe struct {
	name      string
	delay     time.Duration
	callCount *atomic.Int32
}

func newMockProbe(name string, delay time.Duration) *mockProbe {
	return &mockProbe{
		name:      name,
		delay:     delay,
		callCount: &atomic.Int32{},
	}
}

func (m *mockProbe) Name() string {
	return m.name
}

func (m *mockProbe) Description() string {
	return "mock probe for testing"
}

func (m *mockProbe) Goal() string {
	return "test goal"
}

func (m *mockProbe) GetPrimaryDetector() string {
	return "mock"
}

func (m *mockProbe) GetPrompts() []string {
	return []string{"test prompt"}
}

func (m *mockProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	m.callCount.Add(1)

	// Simulate work
	select {
	case <-time.After(m.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Return mock attempt
	a := &attempt.Attempt{
		Prompt:  "test prompt",
		Outputs: []string{"test response"},
		Probe:   m.name,
		Status:  attempt.StatusPending,
	}

	return []*attempt.Attempt{a}, nil
}

// mockGenerator for testing
type mockGenerator struct{}

func (m *mockGenerator) Name() string { return "mock" }
func (m *mockGenerator) Description() string { return "mock generator" }
func (m *mockGenerator) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	return []attempt.Message{
		{Role: "assistant", Content: "test response"},
	}, nil
}
func (m *mockGenerator) ClearHistory() {}

// mockDetector for testing
type mockDetector struct{}

func (m *mockDetector) Name() string { return "mock" }
func (m *mockDetector) Description() string { return "mock detector" }
func (m *mockDetector) Detect(ctx context.Context, a *attempt.Attempt) ([]float64, error) {
	return []float64{0.5}, nil
}

// mockEvaluator for testing
type mockEvaluator struct {
	attempts []*attempt.Attempt
}

func (m *mockEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	m.attempts = attempts
	return nil
}

func TestBatchHarness_ParallelExecution(t *testing.T) {
	// Create 3 probes with 100ms delay each
	probe1 := newMockProbe("probe1", 100*time.Millisecond)
	probe2 := newMockProbe("probe2", 100*time.Millisecond)
	probe3 := newMockProbe("probe3", 100*time.Millisecond)

	probeList := []probes.Prober{probe1, probe2, probe3}

	// Create harness with concurrency=3 (all probes run in parallel)
	h, err := New(registry.Config{
		"concurrency": 3,
		"timeout":     "5s",
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Create mock dependencies
	gen := &mockGenerator{}
	detectorList := []detectors.Detector{&mockDetector{}}
	eval := &mockEvaluator{}

	// Run harness
	start := time.Now()
	err = h.Run(context.Background(), gen, probeList, detectorList, eval)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	// PARALLEL: Should take ~100ms (all run at once), not 300ms (sequential)
	// Allow some overhead, but should be < 200ms
	if elapsed > 200*time.Millisecond {
		t.Errorf("Expected parallel execution (~100ms), got %v (sequential?)", elapsed)
	}

	// Verify all probes were called
	if probe1.callCount.Load() != 1 {
		t.Errorf("probe1 call count = %d, want 1", probe1.callCount.Load())
	}
	if probe2.callCount.Load() != 1 {
		t.Errorf("probe2 call count = %d, want 1", probe2.callCount.Load())
	}
	if probe3.callCount.Load() != 1 {
		t.Errorf("probe3 call count = %d, want 1", probe3.callCount.Load())
	}

	// Verify evaluator received all attempts
	if len(eval.attempts) != 3 {
		t.Errorf("evaluator received %d attempts, want 3", len(eval.attempts))
	}
}

func TestBatchHarness_ConcurrencyLimit(t *testing.T) {
	// Create 5 probes with 100ms delay each
	var probeList []probes.Prober
	for i := 0; i < 5; i++ {
		probeList = append(probeList, newMockProbe("probe", 100*time.Millisecond))
	}

	// Create harness with concurrency=2 (only 2 run at once)
	h, err := New(registry.Config{
		"concurrency": 2,
		"timeout":     "5s",
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Create mock dependencies
	gen := &mockGenerator{}
	detectorList := []detectors.Detector{&mockDetector{}}
	eval := &mockEvaluator{}

	// Run harness
	start := time.Now()
	err = h.Run(context.Background(), gen, probeList, detectorList, eval)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Run() failed: %v", err)
	}

	// With limit=2: 5 probes / 2 concurrent = 3 batches
	// 3 batches * 100ms = ~300ms
	// Allow overhead, should be >= 250ms and < 400ms
	if elapsed < 250*time.Millisecond {
		t.Errorf("Expected ~300ms with limit=2, got %v (too fast, limit not working?)", elapsed)
	}
	if elapsed > 400*time.Millisecond {
		t.Errorf("Expected ~300ms with limit=2, got %v (too slow)", elapsed)
	}
}

func TestBatchHarness_ContextCancellation(t *testing.T) {
	// Create 3 probes with long delays
	probeList := []probes.Prober{
		newMockProbe("probe1", 1*time.Second),
		newMockProbe("probe2", 1*time.Second),
		newMockProbe("probe3", 1*time.Second),
	}

	h, err := New(registry.Config{
		"concurrency": 3,
		"timeout":     "5s",
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	// Create context that cancels after 100ms
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	gen := &mockGenerator{}
	detectorList := []detectors.Detector{&mockDetector{}}
	eval := &mockEvaluator{}

	// Run should fail quickly due to cancellation
	start := time.Now()
	err = h.Run(ctx, gen, probeList, detectorList, eval)
	elapsed := time.Since(start)

	// Should return error
	if err == nil {
		t.Error("Expected error due to context cancellation, got nil")
	}

	// Should return quickly (< 200ms), not wait for all probes
	if elapsed > 200*time.Millisecond {
		t.Errorf("Expected quick cancellation (~100ms), got %v", elapsed)
	}
}

func TestBatchHarness_NoProbes(t *testing.T) {
	h, err := New(registry.Config{
		"concurrency": 3,
		"timeout":     "5s",
	})
	if err != nil {
		t.Fatalf("failed to create harness: %v", err)
	}

	gen := &mockGenerator{}
	detectorList := []detectors.Detector{&mockDetector{}}
	eval := &mockEvaluator{}

	// Should return error for empty probe list
	err = h.Run(context.Background(), gen, []probes.Prober{}, detectorList, eval)
	if err == nil {
		t.Error("Expected error for empty probe list, got nil")
	}
}

func TestBatchHarness_DefaultConfig(t *testing.T) {
	// Test with empty config (should use defaults)
	h, err := New(registry.Config{})
	if err != nil {
		t.Fatalf("failed to create harness with default config: %v", err)
	}

	// Should have default values
	if h.concurrency != 10 {
		t.Errorf("default concurrency = %d, want 10", h.concurrency)
	}
	if h.timeout != 30*time.Second {
		t.Errorf("default timeout = %v, want 30s", h.timeout)
	}
}
