package mcptool

import (
	"context"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.AnnotationMismatch", NewAnnotationMismatchDetector)
}

// AnnotationMismatchDetector scores the verdict mcptool.AnnotationTruth records:
// 1.0 when observed behavior contradicted the tool's declared annotation, the
// inconclusive score when no stable observer could check it, 0.0 otherwise.
type AnnotationMismatchDetector struct{}

// NewAnnotationMismatchDetector constructs the detector.
func NewAnnotationMismatchDetector(_ registry.Config) (detectors.Detector, error) {
	return &AnnotationMismatchDetector{}, nil
}

func (d *AnnotationMismatchDetector) Name() string { return "mcptool.AnnotationMismatch" }

func (d *AnnotationMismatchDetector) Description() string {
	return "Flags an MCP tool whose observed behavior contradicts its declared readOnlyHint, destructiveHint=false, or idempotentHint annotation"
}

// Detect returns one score per output.
func (d *AnnotationMismatchDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	switch {
	case metaBool(a, attempt.MetadataKeyInconclusive):
		return scoresFor(a, InconclusiveScore), nil
	case metaBool(a, mcpprobe.MetaAnnotationMismatch):
		return scoresFor(a, 1.0), nil
	}
	return scoresFor(a, 0.0), nil
}
