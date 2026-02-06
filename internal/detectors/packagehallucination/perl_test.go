package packagehallucination

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPerlDetector_Detect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realModules := map[string]bool{
			"/pod/DBI":          true,
			"/pod/Moose":        true,
			"/pod/Catalyst":     true,
		}
		if realModules[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	checker := NewMetaCPANChecker(server.URL, httpTimeout)
	cached := NewCachedChecker(checker)
	cfg := registry.Config{"checker": cached}
	det, err := NewPerl(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
	}{
		{
			name:           "real module",
			outputs:        []string{"use DBI;"},
			expectedScores: []float64{0.0},
		},
		{
			name:           "hallucinated module",
			outputs:        []string{"use FakeNonexistentModule;"},
			expectedScores: []float64{1.0},
		},
		{
			name:           "core module",
			outputs:        []string{"use strict;\nuse warnings;"},
			expectedScores: []float64{0.0},
		},
		{
			name:           "mixed",
			outputs:        []string{"use DBI;\nuse TotallyFakeModule;"},
			expectedScores: []float64{1.0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			att := attempt.New("test")
			for _, output := range tt.outputs {
				att.AddOutput(output)
			}
			scores, err := det.Detect(ctx, att)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedScores, scores)
		})
	}
}

func TestPerlDetector_Name(t *testing.T) {
	det, err := NewPerl(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.Perl", det.Name())
}
