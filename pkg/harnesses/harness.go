// Package harnesses provides the harness interface for orchestrating scans.
//
// Harnesses coordinate probes, generators, and detectors to execute
// complete vulnerability scans. They handle the execution flow and
// result aggregation.
package harnesses

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Evaluator processes detection results and determines outcomes.
type Evaluator interface {
	// Evaluate processes all attempts and returns aggregated results.
	Evaluate(ctx context.Context, attempts []*attempt.Attempt) error
}

// Harness orchestrates probe execution against generators with detection.
type Harness interface {
	// Run executes the scan workflow.
	Run(ctx context.Context, gen generators.Generator, probeList []probes.Prober,
		detectorList []detectors.Detector, eval Evaluator) error
	// Name returns the harness name.
	Name() string
	// Description returns a human-readable description.
	Description() string
}

// Registry is the global harness registry.
var Registry = registry.New[Harness]("harnesses")

// Register adds a harness factory to the global registry.
func Register(name string, factory func(registry.Config) (Harness, error)) {
	Registry.Register(name, factory)
}

// List returns all registered harness names.
func List() []string {
	return Registry.List()
}

// Get retrieves a harness factory by name.
func Get(name string) (func(registry.Config) (Harness, error), bool) {
	return Registry.Get(name)
}

// Create instantiates a harness by name.
func Create(name string, cfg registry.Config) (Harness, error) {
	return Registry.Create(name, cfg)
}
