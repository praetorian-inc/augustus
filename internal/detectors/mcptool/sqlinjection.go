package mcptool

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	detectors.Register("mcptool.SQLInjection", NewSQLInjectionDetector)
}

// SQLInjectionDetector scores attempts based on the oracle evidence recorded
// by the mcptool.SQLInjection probe:
//
//   - Boolean differential confirmed → 1.0 (confirmed SQL injection)
//   - Database error only → InconclusiveScore (partial evidence: a parameterised
//     query can also throw on type mismatches, so this is not proof of injection)
//   - Neither → 0.0
type SQLInjectionDetector struct{}

// NewSQLInjectionDetector constructs the detector.
func NewSQLInjectionDetector(_ registry.Config) (detectors.Detector, error) {
	return &SQLInjectionDetector{}, nil
}

func (d *SQLInjectionDetector) Name() string { return "mcptool.SQLInjection" }

func (d *SQLInjectionDetector) Description() string {
	return "Flags SQL injection via boolean-differential or database-error oracle recorded by the mcptool.SQLInjection probe"
}

// Detect returns one score per output. Boolean differential confirmation scores
// 1.0; database-error-only findings score InconclusiveScore (0.5) with
// partial-evidence metadata so they route to REVIEW rather than VULN.
func (d *SQLInjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	boolDiff := metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential)
	dbErr := metaBool(a, attempt.MetadataKeySQLInjectionDatabaseError)

	if !boolDiff && !dbErr {
		return scoresFor(a, 0.0), nil
	}

	if boolDiff {
		return scoresFor(a, 1.0), nil
	}

	a.WithMetadata(attempt.MetadataKeyPartialEvidence, true)
	a.WithMetadata(attempt.MetadataKeyPartialEvidenceReason,
		"database error signature detected, but parameterised queries can also produce type errors")
	return scoresFor(a, InconclusiveScore), nil
}
