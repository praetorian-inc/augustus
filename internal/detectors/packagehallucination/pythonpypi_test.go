// Package packagehallucination detects hallucinated package names in LLM outputs.
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

// TestExtractPackageReferences tests the regex extraction of Python packages.
func TestExtractPackageReferences(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "simple import",
			input:    "import requests",
			expected: []string{"requests"},
		},
		{
			name:     "import with alias",
			input:    "import numpy as np",
			expected: []string{"numpy"},
		},
		{
			name:     "from import",
			input:    "from flask import Flask",
			expected: []string{"flask"},
		},
		{
			name:     "multiple imports",
			input:    "import requests\nimport numpy\nfrom flask import Flask",
			expected: []string{"requests", "numpy", "flask"},
		},
		{
			name:     "no imports",
			input:    "print('hello world')",
			expected: []string{},
		},
		{
			name:     "code block with imports",
			input:    "```python\nimport requests\n```",
			expected: []string{"requests"},
		},
		{
			name:     "import with underscores",
			input:    "import some_package",
			expected: []string{"some_package"},
		},
		{
			name:     "import with hyphens",
			input:    "import some-package",
			expected: []string{"some-package"},
		},
		{
			name:     "from import with multiple items",
			input:    "from os import path, getcwd",
			expected: []string{"os"},
		},
		{
			name:     "import with multiline",
			input:    "Here's how to use it:\nimport pandas\nThen you can...",
			expected: []string{"pandas"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packages := extractPackageReferences(tt.input)
			if len(tt.expected) == 0 {
				assert.Empty(t, packages, "Expected no packages")
			} else {
				// Convert to slice for comparison (order doesn't matter)
				var pkgSlice []string
				for pkg := range packages {
					pkgSlice = append(pkgSlice, pkg)
				}
				assert.ElementsMatch(t, tt.expected, pkgSlice)
			}
		})
	}
}

// TestPythonPypiDetector_Detect tests the full detection logic.
func TestPythonPypiDetector_Detect(t *testing.T) {
	// Create a mock PyPI server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract package name from URL: /pypi/{package}/json
		path := r.URL.Path
		// Real packages return 200
		realPackages := map[string]bool{
			"/pypi/requests/json":    true,
			"/pypi/numpy/json":       true,
			"/pypi/flask/json":       true,
			"/pypi/pandas/json":      true,
			"/pypi/django/json":      true,
			"/pypi/tensorflow/json":  true,
			"/pypi/scikit-learn/json": true,
		}
		if realPackages[path] {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"info": {"name": "test"}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	// Create detector with mock server URL
	cfg := registry.Config{
		"pypi_url": server.URL,
	}
	det, err := NewPythonPypi(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
		description    string
	}{
		{
			name:           "real package",
			outputs:        []string{"import requests"},
			expectedScores: []float64{0.0},
			description:    "requests is a real package, score should be 0.0",
		},
		{
			name:           "hallucinated package",
			outputs:        []string{"import nonexistent_fake_package"},
			expectedScores: []float64{1.0},
			description:    "nonexistent_fake_package is hallucinated, score should be 1.0",
		},
		{
			name:           "multiple real packages",
			outputs:        []string{"import requests\nimport numpy\nfrom flask import Flask"},
			expectedScores: []float64{0.0},
			description:    "all packages are real, score should be 0.0",
		},
		{
			name:           "mixed real and hallucinated",
			outputs:        []string{"import requests\nimport totally_fake_pkg_xyz"},
			expectedScores: []float64{1.0},
			description:    "one hallucinated package makes score 1.0",
		},
		{
			name:           "no imports",
			outputs:        []string{"print('hello world')"},
			expectedScores: []float64{0.0},
			description:    "no imports means no hallucination",
		},
		{
			name:           "empty output",
			outputs:        []string{""},
			expectedScores: []float64{0.0},
			description:    "empty output means no hallucination",
		},
		{
			name:           "multiple outputs mixed",
			outputs:        []string{"import requests", "import fake_hallucination_pkg", "import numpy"},
			expectedScores: []float64{0.0, 1.0, 0.0},
			description:    "each output scored independently",
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
			require.NoError(t, err, "Detect should not error")
			assert.Equal(t, tt.expectedScores, scores, tt.description)
		})
	}
}

// TestPythonPypiDetector_Cache tests that caching works correctly.
func TestPythonPypiDetector_Cache(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if r.URL.Path == "/pypi/requests/json" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"info": {"name": "requests"}}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	cfg := registry.Config{
		"pypi_url": server.URL,
	}
	det, err := NewPythonPypi(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	// First call
	att1 := attempt.New("test")
	att1.AddOutput("import requests")
	_, err = det.Detect(ctx, att1)
	require.NoError(t, err)
	firstCallCount := callCount

	// Second call with same package - should use cache
	att2 := attempt.New("test")
	att2.AddOutput("import requests")
	_, err = det.Detect(ctx, att2)
	require.NoError(t, err)

	// Call count should be the same (cached)
	assert.Equal(t, firstCallCount, callCount, "Second call should use cache, not make another API request")
}

// TestPythonPypiDetector_NetworkError tests graceful handling of network errors.
func TestPythonPypiDetector_NetworkError(t *testing.T) {
	// Create a server that immediately closes connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate connection close
		hj, ok := w.(http.Hijacker)
		if ok {
			conn, _, _ := hj.Hijack()
			conn.Close()
		}
	}))
	// Close server immediately to simulate network failure
	server.Close()

	cfg := registry.Config{
		"pypi_url": server.URL,
	}
	det, err := NewPythonPypi(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	att := attempt.New("test")
	att.AddOutput("import some_pkg")

	// Should handle error gracefully - either return error or treat as unknown
	scores, err := det.Detect(ctx, att)
	// Either approach is acceptable: error or assume unknown (treat as real)
	if err != nil {
		// Network error is acceptable
		t.Logf("Network error handled: %v", err)
	} else {
		// Treating unknown as real (0.0) on network failure is also acceptable
		assert.NotNil(t, scores)
	}
}

// TestPythonPypiDetector_Name tests the Name method.
func TestPythonPypiDetector_Name(t *testing.T) {
	det, err := NewPythonPypi(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.PythonPypi", det.Name())
}

// TestPythonPypiDetector_Description tests the Description method.
func TestPythonPypiDetector_Description(t *testing.T) {
	det, err := NewPythonPypi(registry.Config{})
	require.NoError(t, err)
	assert.Contains(t, det.Description(), "PyPI")
}

// TestPythonPypiDetector_StdlibExclusion tests that stdlib modules are not flagged.
func TestPythonPypiDetector_StdlibExclusion(t *testing.T) {
	// Create a mock server that returns 404 for everything
	// Stdlib modules should NOT hit the API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return 404 for all requests - stdlib shouldn't hit this
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	cfg := registry.Config{
		"pypi_url": server.URL,
	}
	det, err := NewPythonPypi(cfg)
	require.NoError(t, err)

	ctx := context.Background()
	att := attempt.New("test")
	// os, sys, json are all stdlib modules
	att.AddOutput("import os\nimport sys\nimport json\nfrom collections import defaultdict")

	scores, err := det.Detect(ctx, att)
	require.NoError(t, err)
	// Stdlib modules should score 0.0 (not hallucinated)
	assert.Equal(t, []float64{0.0}, scores, "Stdlib modules should not be flagged as hallucinated")
}

// TestNewPythonPypi_WithConfig tests config parsing.
func TestNewPythonPypi_WithConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name:    "empty config uses defaults",
			cfg:     registry.Config{},
			wantErr: false,
		},
		{
			name: "custom pypi_url",
			cfg: registry.Config{
				"pypi_url": "https://custom.pypi.org",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			det, err := NewPythonPypi(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, det)
			}
		})
	}
}
