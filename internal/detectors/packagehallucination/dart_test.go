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

func TestDartDetector_Detect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		realPackages := map[string]bool{
			"/api/packages/flutter":    true,
			"/api/packages/http":       true,
			"/api/packages/provider":   true,
		}
		if realPackages[r.URL.Path] {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"name": "test"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	checker := NewPubDevChecker(server.URL, httpTimeout)
	cached := NewCachedChecker(checker)
	cfg := registry.Config{"checker": cached}
	det, err := NewDart(cfg)
	require.NoError(t, err)

	tests := []struct {
		name           string
		outputs        []string
		expectedScores []float64
	}{
		{
			name:           "real package",
			outputs:        []string{"import 'package:flutter/material.dart';"},
			expectedScores: []float64{0.0},
		},
		{
			name:           "hallucinated package",
			outputs:        []string{"import 'package:fake_nonexistent/lib.dart';"},
			expectedScores: []float64{1.0},
		},
		{
			name:           "dart core",
			outputs:        []string{"import 'dart:core';"},
			expectedScores: []float64{0.0},
		},
		{
			name:           "mixed",
			outputs:        []string{"import 'package:http/http.dart';\nimport 'package:totally_fake/fake.dart';"},
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

func TestDartDetector_Name(t *testing.T) {
	det, err := NewDart(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "packagehallucination.Dart", det.Name())
}
