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

// SecondaryDetector describes an additional detector to run alongside the
// primary detector for a probe. Each entry carries the detector name and an
// optional per-detector config override map that is merged on top of any
// global YAML config for that detector.
type SecondaryDetector struct {
	// Name is the fully qualified detector name (e.g., "agent.ArgumentExfiltration").
	Name string
	// Config holds optional per-detector configuration overrides.
	// Merged on top of the global/YAML detector config; may be nil.
	Config map[string]any
}

// ProbeSecondaryDetectors is an optional interface for probes that declare
// additional detectors to run alongside the primary detector.
// When a probe implements this interface, the scanner appends one detector
// instance per secondary entry to the per-probe detector slice, enabling
// compound detection (e.g., name-level + argument-level checks).
//
// Empty or nil return value → probe behaves as single-detector (current behavior).
//
// Check for support via type assertion:
//
//	if psd, ok := prober.(ProbeSecondaryDetectors); ok { ... }
type ProbeSecondaryDetectors interface {
	// GetSecondaryDetectors returns additional detectors to run alongside the primary.
	// Each entry is a (detector name, optional per-detector config-override) pair.
	// Empty/nil result → probe is single-detector (current behavior).
	GetSecondaryDetectors() []SecondaryDetector
}
