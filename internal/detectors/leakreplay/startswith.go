package leakreplay

import (
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("leakreplay.StartsWith", NewStartsWith)
}

// StartsWith detects if outputs start with triggers stored in attempt metadata.
//
// The detector reads triggers from attempt.Metadata["triggers"] and checks
// if any output starts with any trigger. Output is trimmed of leading
// whitespace before comparison. Detection is case-insensitive by default.
//
// Scores:
//   - 1.0: Output starts with at least one trigger
//   - 0.0: Output does not start with any trigger
type StartsWith = base.TriggerMatchDetector

// NewStartsWith creates a new StartsWith detector from config.
//
// Optional config:
//   - case_sensitive: bool - false (default)
func NewStartsWith(cfg registry.Config) (detectors.Detector, error) {
	return base.NewTriggerMatchDetector(
		cfg,
		base.MatchStartsWith,
		"leakreplay.StartsWith",
		"Detects if outputs start with triggers from attempt metadata (for completion probes)",
	), nil
}
