package batch

import (
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBatchConfigFromMap(t *testing.T) {
	m := registry.Config{
		"concurrency": 20,
		"timeout":     "60s",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, 20, cfg.Concurrency)
	assert.Equal(t, 60*time.Second, cfg.Timeout)
}

func TestBatchConfigFromMapFloat(t *testing.T) {
	// JSON numbers are float64
	m := registry.Config{
		"concurrency": 15.0,
		"timeout":     "45s",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, 15, cfg.Concurrency)
	assert.Equal(t, 45*time.Second, cfg.Timeout)
}

func TestBatchConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	assert.Equal(t, 10, cfg.Concurrency)
	assert.Equal(t, 30*time.Second, cfg.Timeout)
}

func TestBatchConfigFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(
		DefaultConfig(),
		WithConcurrency(25),
		WithTimeout(2*time.Minute),
	)

	assert.Equal(t, 25, cfg.Concurrency)
	assert.Equal(t, 2*time.Minute, cfg.Timeout)
}
