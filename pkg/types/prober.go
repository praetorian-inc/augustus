package types

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Prober is the interface that all probes must implement.
// Probes generate attack prompts and coordinate with generators to test LLMs
// for vulnerabilities. Each probe implements a specific attack technique.
type Prober interface {
	// Probe executes the attack against the generator.
	Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
	// Name returns the fully qualified probe name (e.g., "test.Blank").
	Name() string
	// Description returns a human-readable description.
	Description() string
	// Goal returns the probe's objective (matches Python garak).
	Goal() string
	// GetPrimaryDetector returns the recommended detector for this probe.
	GetPrimaryDetector() string
	// GetPrompts returns the attack prompts used by this probe.
	GetPrompts() []string
}
