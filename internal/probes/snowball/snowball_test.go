package snowball

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ----------------------------------------------------------------------------
// GraphConnectivity Tests
// ----------------------------------------------------------------------------

func TestGraphConnectivityFull_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.GraphConnectivityFull")
	require.True(t, ok, "GraphConnectivityFull should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.GraphConnectivityFull", p.Name())
	assert.Equal(t, "snowball.DontStartYes", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "flight routing")
}

func TestGraphConnectivityFull_PromptCount(t *testing.T) {
	p, err := NewGraphConnectivityFull(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 500, len(prompts), "Full version should have 500 prompts")

	// Verify first prompt looks like a graph connectivity question
	assert.Contains(t, prompts[0], "flight")
	assert.Contains(t, prompts[0], "city")
}

func TestGraphConnectivity_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.GraphConnectivity")
	require.True(t, ok, "GraphConnectivity should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.GraphConnectivity", p.Name())
	assert.Equal(t, "snowball.DontStartYes", p.GetPrimaryDetector())
}

func TestGraphConnectivity_PromptCount(t *testing.T) {
	p, err := NewGraphConnectivity(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 100, len(prompts), "Limited version should have 100 prompts")
}

func TestGraphConnectivity_Probe(t *testing.T) {
	p, err := NewGraphConnectivity(registry.Config{})
	require.NoError(t, err)

	// Use only first prompt for testing
	gen := testutil.NewMockGenerator("Yes, there is a route from F to I via L.")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.Equal(t, "snowball.GraphConnectivity", a.Probe)
	assert.Equal(t, "snowball.DontStartYes", a.Detector)
	assert.NotEmpty(t, a.Outputs)
	assert.Equal(t, "Yes, there is a route from F to I via L.", a.Outputs[0])
}

// ----------------------------------------------------------------------------
// Primes Tests
// ----------------------------------------------------------------------------

func TestPrimesFull_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.PrimesFull")
	require.True(t, ok, "PrimesFull should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.PrimesFull", p.Name())
	assert.Equal(t, "snowball.DontStartNo", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "prime")
}

func TestPrimesFull_PromptCount(t *testing.T) {
	p, err := NewPrimesFull(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 500, len(prompts), "Full version should have 500 prompts")

	// Verify first prompt looks like a primality question
	assert.Contains(t, prompts[0], "prime")
}

func TestPrimes_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.Primes")
	require.True(t, ok, "Primes should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.Primes", p.Name())
	assert.Equal(t, "snowball.DontStartNo", p.GetPrimaryDetector())
}

func TestPrimes_PromptCount(t *testing.T) {
	p, err := NewPrimes(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 100, len(prompts), "Limited version should have 100 prompts")
}

func TestPrimes_Probe(t *testing.T) {
	p, err := NewPrimes(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("No, 7411 is not a prime number.")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.Equal(t, "snowball.Primes", a.Probe)
	assert.Equal(t, "snowball.DontStartNo", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// ----------------------------------------------------------------------------
// Senators Tests
// ----------------------------------------------------------------------------

func TestSenatorsFull_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.SenatorsFull")
	require.True(t, ok, "SenatorsFull should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.SenatorsFull", p.Name())
	assert.Equal(t, "snowball.DontStartYes", p.GetPrimaryDetector())
	assert.Contains(t, p.Goal(), "senator")
}

func TestSenatorsFull_PromptCount(t *testing.T) {
	p, err := NewSenatorsFull(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 500, len(prompts), "Full version should have 500 prompts")

	// Verify first prompt looks like a senator question
	assert.Contains(t, prompts[0], "senator")
	assert.Contains(t, prompts[0], "alma mater")
}

func TestSenators_Registration(t *testing.T) {
	factory, ok := probes.Get("snowball.Senators")
	require.True(t, ok, "Senators should be registered")

	p, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "snowball.Senators", p.Name())
	assert.Equal(t, "snowball.DontStartYes", p.GetPrimaryDetector())
}

func TestSenators_PromptCount(t *testing.T) {
	p, err := NewSenators(registry.Config{})
	require.NoError(t, err)

	prompts := p.GetPrompts()
	assert.Equal(t, 100, len(prompts), "Limited version should have 100 prompts")
}

func TestSenators_Probe(t *testing.T) {
	p, err := NewSenators(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("Yes, Senator John Smith represented Alabama.")

	attempts, err := p.Probe(context.Background(), gen)
	require.NoError(t, err)
	require.NotEmpty(t, attempts)

	// Check first attempt
	a := attempts[0]
	assert.Equal(t, "snowball.Senators", a.Probe)
	assert.Equal(t, "snowball.DontStartYes", a.Detector)
	assert.NotEmpty(t, a.Outputs)
}

// ----------------------------------------------------------------------------
// Data Integrity Tests
// ----------------------------------------------------------------------------

func TestDataFiles_LoadCorrectly(t *testing.T) {
	// Verify all data files can be loaded and parsed

	t.Run("graph_connectivity", func(t *testing.T) {
		p, err := NewGraphConnectivityFull(registry.Config{})
		require.NoError(t, err)
		assert.Equal(t, 500, len(p.GetPrompts()))
	})

	t.Run("primality_testing", func(t *testing.T) {
		p, err := NewPrimesFull(registry.Config{})
		require.NoError(t, err)
		assert.Equal(t, 500, len(p.GetPrompts()))
	})

	t.Run("senator_search", func(t *testing.T) {
		p, err := NewSenatorsFull(registry.Config{})
		require.NoError(t, err)
		assert.Equal(t, 500, len(p.GetPrompts()))
	})
}

func TestLimitedVersions_UseLastPrompts(t *testing.T) {
	// Verify limited versions use the LAST 100 prompts (not first)

	t.Run("GraphConnectivity", func(t *testing.T) {
		full, err := NewGraphConnectivityFull(registry.Config{})
		require.NoError(t, err)

		limited, err := NewGraphConnectivity(registry.Config{})
		require.NoError(t, err)

		fullPrompts := full.GetPrompts()
		limitedPrompts := limited.GetPrompts()

		// Last prompt of limited should match last prompt of full
		assert.Equal(t, fullPrompts[499], limitedPrompts[99])
		// First prompt of limited should match 400th prompt of full
		assert.Equal(t, fullPrompts[400], limitedPrompts[0])
	})

	t.Run("Primes", func(t *testing.T) {
		full, err := NewPrimesFull(registry.Config{})
		require.NoError(t, err)

		limited, err := NewPrimes(registry.Config{})
		require.NoError(t, err)

		fullPrompts := full.GetPrompts()
		limitedPrompts := limited.GetPrompts()

		assert.Equal(t, fullPrompts[499], limitedPrompts[99])
		assert.Equal(t, fullPrompts[400], limitedPrompts[0])
	})

	t.Run("Senators", func(t *testing.T) {
		full, err := NewSenatorsFull(registry.Config{})
		require.NoError(t, err)

		limited, err := NewSenators(registry.Config{})
		require.NoError(t, err)

		fullPrompts := full.GetPrompts()
		limitedPrompts := limited.GetPrompts()

		assert.Equal(t, fullPrompts[499], limitedPrompts[99])
		assert.Equal(t, fullPrompts[400], limitedPrompts[0])
	})
}

// ----------------------------------------------------------------------------
// Integration with Detectors
// ----------------------------------------------------------------------------

func TestProbeDetectorPairing(t *testing.T) {
	// Verify each probe uses the correct detector

	tests := []struct {
		probeName    string
		detectorName string
	}{
		{"snowball.GraphConnectivityFull", "snowball.DontStartYes"},
		{"snowball.GraphConnectivity", "snowball.DontStartYes"},
		{"snowball.PrimesFull", "snowball.DontStartNo"},
		{"snowball.Primes", "snowball.DontStartNo"},
		{"snowball.SenatorsFull", "snowball.DontStartYes"},
		{"snowball.Senators", "snowball.DontStartYes"},
	}

	for _, tt := range tests {
		t.Run(tt.probeName, func(t *testing.T) {
			factory, ok := probes.Get(tt.probeName)
			require.True(t, ok)

			p, err := factory(registry.Config{})
			require.NoError(t, err)
			assert.Equal(t, tt.detectorName, p.GetPrimaryDetector())
		})
	}
}

func TestAllProbes_RegisteredCount(t *testing.T) {
	// Verify all 6 probes are registered
	registered := []string{
		"snowball.GraphConnectivityFull",
		"snowball.GraphConnectivity",
		"snowball.PrimesFull",
		"snowball.Primes",
		"snowball.SenatorsFull",
		"snowball.Senators",
	}

	for _, name := range registered {
		t.Run(name, func(t *testing.T) {
			_, ok := probes.Get(name)
			assert.True(t, ok, "%s should be registered", name)
		})
	}
}
