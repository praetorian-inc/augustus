package probes_test

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistry_RegisterAndGet(t *testing.T) {
	// Create a test probe factory
	testFactory := func(cfg registry.Config) (probes.Prober, error) {
		return probes.NewSimpleProbe(
			"test-probe",
			"test goal",
			"test-detector",
			"test description",
			[]string{"test prompt"},
		), nil
	}

	// Register the test probe
	probes.Register("test-probe", testFactory)

	// Verify List() contains the registered probe
	names := probes.List()
	assert.Contains(t, names, "test-probe", "List() should contain registered probe")

	// Verify Get() returns the factory
	factory, found := probes.Get("test-probe")
	assert.True(t, found, "Get() should find registered probe")
	assert.NotNil(t, factory, "Get() should return non-nil factory")

	// Verify Create() returns a valid probe
	probe, err := probes.Create("test-probe", registry.Config{})
	require.NoError(t, err, "Create() should not error for registered probe")
	assert.NotNil(t, probe, "Create() should return non-nil probe")
	assert.Equal(t, "test-probe", probe.Name(), "Created probe should have correct name")
}

func TestRegistry_GetNotFound(t *testing.T) {
	// Try to get a nonexistent probe
	factory, found := probes.Get("nonexistent-probe")
	assert.False(t, found, "Get() should return false for nonexistent probe")
	assert.Nil(t, factory, "Get() should return nil factory for nonexistent probe")
}

func TestRegistry_CreateNotFound(t *testing.T) {
	// Try to create a nonexistent probe
	probe, err := probes.Create("nonexistent-probe", registry.Config{})
	assert.Error(t, err, "Create() should return error for nonexistent probe")
	assert.Nil(t, probe, "Create() should return nil probe for nonexistent probe")
}
