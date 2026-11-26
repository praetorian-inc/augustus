package mcptool

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func newSQLInjectionDetector(t *testing.T) *SQLInjectionDetector {
	t.Helper()
	d, err := NewSQLInjectionDetector(registry.Config{})
	require.NoError(t, err)
	return d.(*SQLInjectionDetector)
}

func TestSQLInjectionDetector(t *testing.T) {
	tests := []struct {
		name             string
		boolDifferential bool
		dbError          bool
		outputs          []string
		wantLen          int
		wantFirstScore   float64
	}{
		{
			name:             "boolean differential confirmed -> vuln",
			boolDifferential: true,
			dbError:          false,
			outputs:          []string{"some result"},
			wantLen:          1,
			wantFirstScore:   1.0,
		},
		{
			name:             "database error confirmed -> vuln",
			boolDifferential: false,
			dbError:          true,
			outputs:          []string{"sqlite error"},
			wantLen:          1,
			wantFirstScore:   1.0,
		},
		{
			name:             "both confirmed -> vuln",
			boolDifferential: true,
			dbError:          true,
			outputs:          []string{"result"},
			wantLen:          1,
			wantFirstScore:   1.0,
		},
		{
			name:             "neither confirmed -> safe",
			boolDifferential: false,
			dbError:          false,
			outputs:          []string{"normal response"},
			wantLen:          1,
			wantFirstScore:   0.0,
		},
		{
			name:             "no metadata at all -> safe",
			boolDifferential: false,
			dbError:          false,
			outputs:          []string{"hello"},
			wantLen:          1,
			wantFirstScore:   0.0,
		},
	}

	d := newSQLInjectionDetector(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attempt.New("' OR '1'='1")
			if tt.boolDifferential {
				a.Metadata[attempt.MetadataKeySQLInjectionBooleanDifferential] = true
			}
			if tt.dbError {
				a.Metadata[attempt.MetadataKeySQLInjectionDatabaseError] = true
			}
			for _, o := range tt.outputs {
				a.AddOutput(o)
			}
			scores, err := d.Detect(context.Background(), a)
			require.NoError(t, err)
			assert.Len(t, scores, tt.wantLen)
			if tt.wantLen > 0 {
				assert.Equal(t, tt.wantFirstScore, scores[0])
			}
		})
	}
}

func TestSQLInjectionDetector_Name(t *testing.T) {
	d := newSQLInjectionDetector(t)
	assert.Equal(t, "mcptool.SQLInjection", d.Name())
}
