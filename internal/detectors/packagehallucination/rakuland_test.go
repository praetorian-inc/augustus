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

func TestRakuLandDetector_Detect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realModules := map[string]bool{
			"/zef:raku-community-modules/JSON::Fast": true,
			"/zef:tony-o/DBIish":                     true,
		}
		if realModules[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	checker := NewRakuLandChecker(server.URL, httpTimeout)
	cached := NewCachedChecker(checker)
	cfg := registry.Config{"checker": cached, "author": "raku-community-modules"}
	det, err := NewRakuLand(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
	}{
		{
			name:           "real module",
			outputs:        []string{"use JSON::Fast;"},
			expectedScores: []float64{0.0},
		},
		{
			name:           "hallucinated module",
			outputs:        []string{"use FakeNonexistentModule;"},
			expectedScores: []float64{1.0},
		},
		{
			name:           "no use statements",
			outputs:        []string{"say 'hello world';"},
			expectedScores: []float64{0.0},
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

func TestRakuLandDetector_Name(t *testing.T) {
	det, err := NewRakuLand(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.RakuLand", det.Name())
}
