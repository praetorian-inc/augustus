package types

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Prober is the minimal interface that all probes must implement.
// This follows the Interface Segregation Principle (ISP) - clients that only
// execute probes (like Scanner) don't pay for metadata methods they don't use.
type Prober interface {
	// Probe executes the attack against the generator.
	Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error)
	// Name returns the fully qualified probe name (e.g., "test.Blank").
	Name() string
}

// ProbeMetadata is an optional interface for probes that expose metadata.
// Implement this interface when your probe needs to expose information for
// reporting, filtering, or UI display. Clients can check for metadata support
// via type assertion: if pm, ok := prober.(ProbeMetadata); ok { ... }
type ProbeMetadata interface {
	// Description returns a human-readable description.
	Description() string
	// Goal returns the probe's objective (matches Python garak).
	Goal() string
	// GetPrimaryDetector returns the recommended detector for this probe.
	GetPrimaryDetector() string
	// GetPrompts returns the attack prompts used by this probe.
	GetPrompts() []string
}
