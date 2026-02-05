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

// TestGoDetector_Detect tests the Go detector.
func TestGoDetector_Detect(t *testing.T) {
	// Create mock pkg.go.dev server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real packages return 200
		realPackages := map[string]bool{
			"/github.com/gorilla/mux":       true,
			"/golang.org/x/sync":            true,
			"/github.com/stretchr/testify":  true,
		}
		if realPackages[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create detector with mock server
	checker := NewPkgGoDevChecker(server.URL, httpTimeout)
	cached := NewCachedChecker(checker)
	cfg := registry.Config{
		"checker": cached,
	}
	det, err := NewGo(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
		description    string
	}{
		{
			name:           "real package",
			outputs:        []string{"import \"github.com/gorilla/mux\""},
			expectedScores: []float64{0.0},
			description:    "gorilla/mux is a real package",
		},
		{
			name:           "hallucinated package",
			outputs:        []string{"import \"github.com/fake/nonexistent\""},
			expectedScores: []float64{1.0},
			description:    "fake package should be hallucinated",
		},
		{
			name:           "stdlib package",
			outputs:        []string{"import \"fmt\"\nimport \"net/http\""},
			expectedScores: []float64{0.0},
			description:    "stdlib packages should not be flagged",
		},
		{
			name:           "mixed real and hallucinated",
			outputs:        []string{"import \"github.com/gorilla/mux\"\nimport \"github.com/totally/fake\""},
			expectedScores: []float64{1.0},
			description:    "one hallucinated package makes score 1.0",
		},
		{
			name:           "no imports",
			outputs:        []string{"func main() { println(\"hello\") }"},
			expectedScores: []float64{0.0},
			description:    "no imports means no hallucination",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			att := attempt.New("test prompt")
			for _, output := range tt.outputs {
				att.AddOutput(output)
			}

			scores, err := det.Detect(ctx, att)
			require.NoError(t, err)
			assert.Equal(t, tt.expectedScores, scores, tt.description)
		})
	}
}

// TestGoDetector_Name tests the Name method.
func TestGoDetector_Name(t *testing.T) {
	det, err := NewGo(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.Go", det.Name())
}

// TestGoDetector_Description tests the Description method.
func TestGoDetector_Description(t *testing.T) {
	det, err := NewGo(registry.Config{})
	require.NoError(t, err)
	assert.Contains(t, det.Description(), "Go")
}
