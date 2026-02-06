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

// TestRustDetector_Detect tests the Rust detector.
func TestRustDetector_Detect(t *testing.T) {
	// Create mock crates.io server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real crates return 200
		realCrates := map[string]bool{
			"/api/v1/crates/serde":    true,
			"/api/v1/crates/tokio":    true,
			"/api/v1/crates/actix-web": true,
		}
		if realCrates[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"crate": {"name": "test"}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create detector with mock server
	checker := NewCratesIOChecker(server.URL, httpTimeout)
	cached := NewCachedChecker(checker)
	cfg := registry.Config{
		"checker": cached,
	}
	det, err := NewRust(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
		description    string
	}{
		{
			name:           "real crate",
			outputs:        []string{"use serde::{Serialize, Deserialize};"},
			expectedScores: []float64{0.0},
			description:    "serde is a real crate",
		},
		{
			name:           "hallucinated crate",
			outputs:        []string{"use fake_nonexistent_crate::Something;"},
			expectedScores: []float64{1.0},
			description:    "fake crate should be hallucinated",
		},
		{
			name:           "stdlib crate",
			outputs:        []string{"use std::collections::HashMap;"},
			expectedScores: []float64{0.0},
			description:    "std is stdlib",
		},
		{
			name:           "mixed real and hallucinated",
			outputs:        []string{"use serde::Serialize;\nuse totally_fake_rust_crate::Foo;"},
			expectedScores: []float64{1.0},
			description:    "one hallucinated crate makes score 1.0",
		},
		{
			name:           "no use statements",
			outputs:        []string{"fn main() { println!(\"hello\"); }"},
			expectedScores: []float64{0.0},
			description:    "no use statements means no hallucination",
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

// TestRustDetector_Name tests the Name method.
func TestRustDetector_Name(t *testing.T) {
	det, err := NewRust(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.Rust", det.Name())
}

// TestRustDetector_Description tests the Description method.
func TestRustDetector_Description(t *testing.T) {
	det, err := NewRust(registry.Config{})
	require.NoError(t, err)
	assert.Contains(t, det.Description(), "Rust")
}
