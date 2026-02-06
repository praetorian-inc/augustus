// Package ragpoison provides detectors for RAG (Retrieval-Augmented Generation) poisoning attacks.
package ragpoison

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRAGPoisonConfigFromMap(t *testing.T) {
	m := registry.Config{
		"expected_answer": "The sky is green",
		"threshold":       0.9,
	}

	cfg, err := RAGPoisonConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "The sky is green", cfg.ExpectedAnswer)
	assert.Equal(t, 0.9, cfg.Threshold)
}

func TestRAGPoisonConfigDefaults(t *testing.T) {
	cfg := DefaultRAGPoisonConfig()

	assert.Empty(t, cfg.ExpectedAnswer) // Must be set
	assert.Equal(t, 0.8, cfg.Threshold)
}

func TestRAGPoisonConfigFromMapMissingExpectedAnswer(t *testing.T) {
	m := registry.Config{}

	_, err := RAGPoisonConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected_answer")
}

func TestRAGPoisonConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyRAGPoisonOptions(
		DefaultRAGPoisonConfig(),
		WithExpectedAnswer("Poisoned answer here"),
		WithThreshold(0.95),
	)

	assert.Equal(t, "Poisoned answer here", cfg.ExpectedAnswer)
	assert.Equal(t, 0.95, cfg.Threshold)
}
