// Package encoding provides detectors for assessing how well encoded payloads
// from encoding probes are decoded and output by the model.
package encoding

import (
	"github.com/praetorian-inc/augustus/internal/detectors/base"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("encoding.DecodeMatch", NewDecodeMatch)
}

// DecodeMatch checks for direct decoding of trigger strings in outputs.
// Retrieves trigger strings from attempt.Metadata["triggers"] and checks
// if any trigger appears as a substring in any output.
type DecodeMatch = base.TriggerMatchDetector

// NewDecodeMatch creates a new DecodeMatch detector from config.
// Optional config:
//   - case_sensitive: bool - false (default)
func NewDecodeMatch(cfg registry.Config) (detectors.Detector, error) {
	d := base.NewTriggerMatchDetector(
		cfg,
		base.MatchContains,
		"encoding.DecodeMatch",
		"Checks for direct decoding of trigger strings in model outputs",
	)
	d.ZeroOnNoTriggers = true
	return d, nil
}
