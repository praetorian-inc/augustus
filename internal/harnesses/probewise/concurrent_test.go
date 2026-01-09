package probewise

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

// delayedProbe implements a probe that takes a fixed amount of time to execute.
// Used to verify concurrent vs sequential execution.
type delayedProbe struct {
	name            string
	delay           time.Duration
	primaryDetector string
}

func (d *delayedProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	// Simulate probe work with a delay
	select {
	case <-time.After(d.delay):
		// Probe completes after delay
		a := attempt.New("test prompt")
		a.Probe = d.name
		a.AddOutput("test response")
		return []*attempt.Attempt{a}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *delayedProbe) Name() string                { return d.name }
func (d *delayedProbe) Description() string         { return "delayed probe for testing" }
func (d *delayedProbe) Goal() string                { return "test concurrent execution" }
func (d *delayedProbe) GetPrimaryDetector() string  { return d.primaryDetector }
func (d *delayedProbe) GetPrompts() []string        { return []string{"test prompt"} }

// TestProbewise_Run_ConcurrentExecution verifies that multiple probes execute concurrently.
//
// This is a RED test that should FAIL with the current sequential implementation
// and PASS after wiring the concurrent scanner.
//
// Test strategy:
//   - Create 3 probes that each take 100ms
//   - Sequential execution: ~300ms total
//   - Concurrent execution: ~100ms total (all run in parallel)
//   - Assert total time is < 200ms (proving concurrent execution)
func TestProbewise_Run_ConcurrentExecution(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probeDelay := 100 * time.Millisecond
	probeCount := 3

	// Create probes that each take 100ms
	probeList := make([]probes.Prober, 0, probeCount)
	for i := 0; i < probeCount; i++ {
		probeList = append(probeList, &delayedProbe{
			name:            "test.DelayedProbe",
			delay:           probeDelay,
			primaryDetector: "always.Pass",
		})
	}

	detector := &mockDetector{
		name:   "always.Pass",
		scores: []float64{0.0},
	}

	eval := &mockEvaluator{}

	// Measure execution time
	start := time.Now()
	h := New()
	err := h.Run(ctx, gen, probeList, []detectors.Detector{detector}, eval)
	elapsed := time.Since(start)

	require.NoError(t, err)

	// Verify all probes completed
	assert.Len(t, eval.attempts, probeCount, "should have attempts from all probes")

	// Calculate expected times
	sequentialTime := probeDelay * time.Duration(probeCount) // 300ms
	concurrentTime := probeDelay                             // 100ms (all parallel)

	// Allow 50ms overhead for test setup, detector execution, etc.
	maxConcurrentTime := concurrentTime + (50 * time.Millisecond)

	t.Logf("Execution time: %v", elapsed)
	t.Logf("Sequential would take: %v", sequentialTime)
	t.Logf("Concurrent should take: ~%v", concurrentTime)

	// This assertion will FAIL with sequential execution (~300ms)
	// and PASS with concurrent execution (~100ms)
	assert.Less(t, elapsed, maxConcurrentTime,
		"probes should execute concurrently (<%v), not sequentially (>=%v)",
		maxConcurrentTime, sequentialTime)
}

// TestProbewise_Run_ConcurrentExecutionWithManyProbes verifies scalability
// with a larger number of probes (10 probes, each 50ms).
//
// Sequential: 500ms
// Concurrent (10 workers): ~50ms
func TestProbewise_Run_ConcurrentExecutionWithManyProbes(t *testing.T) {
	ctx := context.Background()

	gen := &mockGenerator{
		name:      "test.Mock",
		responses: []string{"response"},
	}

	probeDelay := 50 * time.Millisecond
	probeCount := 10

	// Create 10 probes that each take 50ms
	probeList := make([]probes.Prober, 0, probeCount)
	for i := 0; i < probeCount; i++ {
		probeList = append(probeList, &delayedProbe{
			name:            "test.DelayedProbe",
			delay:           probeDelay,
			primaryDetector: "always.Pass",
		})
	}

	detector := &mockDetector{
		name:   "always.Pass",
		scores: []float64{0.0},
	}

	eval := &mockEvaluator{}

	// Measure execution time
	start := time.Now()
	h := New()
	err := h.Run(ctx, gen, probeList, []detectors.Detector{detector}, eval)
	elapsed := time.Since(start)

	require.NoError(t, err)

	// Verify all probes completed
	assert.Len(t, eval.attempts, probeCount, "should have attempts from all probes")

	// Calculate expected times
	sequentialTime := probeDelay * time.Duration(probeCount) // 500ms
	concurrentTime := probeDelay                             // 50ms (all parallel)

	// Allow 100ms overhead for larger test
	maxConcurrentTime := concurrentTime + (100 * time.Millisecond)

	t.Logf("Execution time: %v", elapsed)
	t.Logf("Sequential would take: %v", sequentialTime)
	t.Logf("Concurrent should take: ~%v", concurrentTime)

	// This should demonstrate significant speedup
	assert.Less(t, elapsed, maxConcurrentTime,
		"10 probes should execute concurrently (<%v), not sequentially (>=%v)",
		maxConcurrentTime, sequentialTime)
}
