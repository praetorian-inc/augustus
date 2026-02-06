package guardrail

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test GuardrailBypass probe structure and interface implementation
func TestGuardrailBypass_Structure(t *testing.T) {
	tests := []struct {
		name      string
		technique BypassTechnique
		target    GuardrailTarget
		wantName  string
	}{
		{
			name:      "CharacterInjection with Azure",
			technique: CharacterInjection,
			target:    AzurePromptShield,
			wantName:  "guardrail.CharacterInjection.azure",
		},
		{
			name:      "TokenBoundary with Generic",
			technique: TokenBoundary,
			target:    Generic,
			wantName:  "guardrail.TokenBoundary.generic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &GuardrailBypass{
				name:      tt.wantName,
				technique: tt.technique,
				target:    tt.target,
			}

			// Verify probe implements Prober interface
			var _ probes.Prober = probe

			// Test Name method
			assert.Contains(t, probe.Name(), string(tt.target))
			assert.Contains(t, probe.Name(), "guardrail")
		})
	}
}

// Test bypass technique constants
func TestBypassTechnique_Constants(t *testing.T) {
	techniques := []BypassTechnique{
		CharacterInjection,
		TokenBoundary,
		EncodingMix,
		SynonymSubstitution,
		SentenceFragmentation,
	}

	// Verify all techniques have unique values
	seen := make(map[BypassTechnique]bool)
	for _, tech := range techniques {
		assert.False(t, seen[tech], "Duplicate technique value: %v", tech)
		seen[tech] = true
	}

	assert.Len(t, techniques, 5, "Expected 5 bypass techniques")
}

// Test guardrail target constants
func TestGuardrailTarget_Constants(t *testing.T) {
	targets := []GuardrailTarget{
		AzurePromptShield,
		MetaPromptGuard,
		OpenAIModeration,
		Generic,
	}

	// Verify all targets have non-empty values
	for _, target := range targets {
		assert.NotEmpty(t, string(target), "Target should not be empty")
	}

	assert.Len(t, targets, 4, "Expected 4 guardrail targets")
}

// Test probe factory function
func TestNewGuardrailBypass(t *testing.T) {
	t.Run("Valid configuration", func(t *testing.T) {
		cfg := registry.Config{
			"technique": "CharacterInjection",
			"target":    "azure",
		}

		probe, err := NewGuardrailBypass(cfg)
		require.NoError(t, err)
		require.NotNil(t, probe)

		// Verify probe properties
		assert.Contains(t, probe.Name(), "guardrail")
		assert.NotEmpty(t, probe.Description())
		assert.NotEmpty(t, probe.Goal())
		assert.NotEmpty(t, probe.GetPrimaryDetector())
	})

	t.Run("Default configuration", func(t *testing.T) {
		cfg := registry.Config{}

		probe, err := NewGuardrailBypass(cfg)
		require.NoError(t, err)
		require.NotNil(t, probe)

		// Should use default values
		assert.Contains(t, probe.Name(), "guardrail")
	})
}

// Test probe execution with bypass techniques
func TestGuardrailBypass_Probe(t *testing.T) {
	t.Run("Successful probe execution", func(t *testing.T) {
		probe := &GuardrailBypass{
			name:            "guardrail.CharacterInjection.AzurePromptShield",
			primaryDetector: "guardrail.Bypass",
			technique:       CharacterInjection,
			target:          AzurePromptShield,
		}

		ctx := context.Background()
		gen := testutil.NewMockGenerator("test response")

		attempts, err := probe.Probe(ctx, gen)
		require.NoError(t, err)
		assert.NotEmpty(t, attempts, "Should generate at least one attempt")
	})
}

// Test success rate tracking
func TestGuardrailBypass_SuccessRateTracking(t *testing.T) {
	t.Run("Track bypass attempts", func(t *testing.T) {
		probe := &GuardrailBypass{
			name:      "guardrail.CharacterInjection.AzurePromptShield",
			technique: CharacterInjection,
			target:    AzurePromptShield,
		}

		stats := probe.GetStats()
		assert.NotNil(t, stats, "Stats should not be nil")
		assert.Equal(t, 0, stats.TotalAttempts)
		assert.Equal(t, 0, stats.SuccessfulBypasses)
		assert.Equal(t, 0.0, stats.SuccessRate)
	})
}
