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
	// Goal returns the probe's objective.
	Goal() string
	// GetPrimaryDetector returns the recommended detector for this probe.
	GetPrimaryDetector() string
	// GetPrompts returns the attack prompts used by this probe.
	GetPrompts() []string
}

// ProbeDetectorConfig is an optional interface for probes that carry
// per-probe detector configuration overrides.
// When a probe implements this interface and GetDetectorConfig() returns a
// non-empty map, the scanner creates a dedicated detector instance for that
// probe (merging probe overrides on top of the global detector config)
// instead of reusing the shared global instance.
//
// Check for support via type assertion:
//
//	if pdc, ok := prober.(ProbeDetectorConfig); ok { ... }
type ProbeDetectorConfig interface {
	// GetDetectorConfig returns configuration overrides for the probe's detector.
	// Keys and values are merged on top of the YAML/global detector config.
	// Returns nil or an empty map when the probe has no per-probe overrides.
	GetDetectorConfig() map[string]any
}
