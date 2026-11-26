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

// SQLInjectionDetector flags an attempt as vulnerable when the mcptool.SQLInjection
// probe recorded either a boolean-differential confirmation or a database-error
// confirmation in the attempt metadata.
type SQLInjectionDetector struct{}

// NewSQLInjectionDetector constructs the detector.
func NewSQLInjectionDetector(_ registry.Config) (detectors.Detector, error) {
	return &SQLInjectionDetector{}, nil
}

func (d *SQLInjectionDetector) Name() string { return "mcptool.SQLInjection" }

func (d *SQLInjectionDetector) Description() string {
	return "Flags SQL injection via boolean-differential or database-error oracle recorded by the mcptool.SQLInjection probe"
}

// Detect returns one score per output. A confirmed SQL injection scores 1.0 when
// either the boolean-differential oracle or the database-error oracle fired. With
// neither signal it returns all-zero.
func (d *SQLInjectionDetector) Detect(_ context.Context, a *attempt.Attempt) ([]float64, error) {
	confirmed := metaBool(a, attempt.MetadataKeySQLInjectionBooleanDifferential) ||
		metaBool(a, attempt.MetadataKeySQLInjectionDatabaseError)

	scores := make([]float64, len(a.Outputs))
	if !confirmed {
		return scores, nil
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores, nil
}
