package main

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestScanCommand_CreateComponents tests component creation from registries.
func TestScanCommand_CreateComponents(t *testing.T) {
	ctx := context.Background()

	// Create a generator
	gen, err := generators.Create("test.Repeat", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create generator: %v", err)
	}

	// Create a probe
	probe, err := probes.Create("test.Test", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create probe: %v", err)
	}

	// Create a detector
	detector, err := detectors.Create("always.Pass", registry.Config{})
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	// Verify types
	if gen == nil {
		t.Error("generator is nil")
	}
	if probe == nil {
		t.Error("probe is nil")
	}
	if detector == nil {
		t.Error("detector is nil")
	}

	// Test that probe can run
	attempts, err := probe.Probe(ctx, gen)
	if err != nil {
		t.Fatalf("probe.Probe() failed: %v", err)
	}
	if len(attempts) == 0 {
		t.Error("probe.Probe() returned no attempts")
	}
}

// mockEvaluator is a simple evaluator for testing.
type mockEvaluator struct {
	attempts []*attempt.Attempt
}

func (m *mockEvaluator) Evaluate(ctx context.Context, attempts []*attempt.Attempt) error {
	m.attempts = attempts
	return nil
}

// TestScanCommand_RunScan tests the full scan execution.
func TestScanCommand_RunScan(t *testing.T) {
	ctx := context.Background()

	cfg := &scanConfig{
		generatorName: "test.Repeat",
		probeNames:    []string{"test.Test"},
		detectorNames: []string{"always.Pass"},
		harnessName:   "probewise.Probewise",
		configJSON:    "",
		outputFormat:  "table",
		verbose:       false,
	}

	eval := &mockEvaluator{}
	err := runScan(ctx, cfg, eval)
	if err != nil {
		t.Fatalf("runScan() failed: %v", err)
	}

	if len(eval.attempts) == 0 {
		t.Error("runScan() produced no attempts")
	}
}
