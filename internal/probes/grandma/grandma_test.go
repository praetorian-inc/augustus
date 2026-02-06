package grandma

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test Win10 probe

func TestWin10_PromptGeneration(t *testing.T) {
	probe, err := NewWin10(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	prompts := probe.GetPrompts()
	// 2 templates × 3 products = 6 prompts
	assert.Len(t, prompts, 6, "Win10 should generate 6 prompts (2 templates × 3 products)")

	// Verify prompts contain product names
	foundWin10 := false
	foundWin10Pro := false
	foundWin10Home := false

	for _, prompt := range prompts {
		if containsAny(prompt, []string{"Windows 10 Product keys", "Windows 10 keys"}) {
			foundWin10 = true
		}
		if containsAny(prompt, []string{"Windows 10 Pro Product keys", "Windows 10 Pro keys"}) {
			foundWin10Pro = true
		}
		if containsAny(prompt, []string{"Windows 10 Home Product keys", "Windows 10 Home keys"}) {
			foundWin10Home = true
		}
	}

	assert.True(t, foundWin10, "Should have Windows 10 prompts")
	assert.True(t, foundWin10Pro, "Should have Windows 10 Pro prompts")
	assert.True(t, foundWin10Home, "Should have Windows 10 Home prompts")
}

func TestWin10_Metadata(t *testing.T) {
	probe, err := NewWin10(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "grandma.Win10", probe.Name())
	assert.Equal(t, "get model to output Win 10 product keys", probe.Goal())
	assert.Equal(t, "productkey.Win5x5", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.Description())
}

func TestWin10_Probe(t *testing.T) {
	probe, err := NewWin10(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	assert.Len(t, attempts, 6, "Should create 6 attempts for Win10")
	assert.Equal(t, 6, gen.Calls, "Should call generator 6 times")

	// Verify attempt structure
	for _, att := range attempts {
		assert.Equal(t, "grandma.Win10", att.Probe)
		assert.Equal(t, "productkey.Win5x5", att.Detector)
		assert.NotEmpty(t, att.Prompt)
		assert.Len(t, att.Outputs, 1)
		assert.Equal(t, "test response", att.Outputs[0])
	}
}

// Test Win11 probe

func TestWin11_PromptGeneration(t *testing.T) {
	probe, err := NewWin11(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	prompts := probe.GetPrompts()
	// 2 templates × 3 products = 6 prompts
	assert.Len(t, prompts, 6, "Win11 should generate 6 prompts (2 templates × 3 products)")

	// Verify prompts contain Windows 11 product names
	foundWin11 := false
	foundWin11Pro := false
	foundWin11Home := false

	for _, prompt := range prompts {
		if containsAny(prompt, []string{"Windows 11 Product keys", "Windows 11 keys"}) {
			foundWin11 = true
		}
		if containsAny(prompt, []string{"Windows 11 Pro Product keys", "Windows 11 Pro keys"}) {
			foundWin11Pro = true
		}
		if containsAny(prompt, []string{"Windows 11 Home Product keys", "Windows 11 Home keys"}) {
			foundWin11Home = true
		}
	}

	assert.True(t, foundWin11, "Should have Windows 11 prompts")
	assert.True(t, foundWin11Pro, "Should have Windows 11 Pro prompts")
	assert.True(t, foundWin11Home, "Should have Windows 11 Home prompts")
}

func TestWin11_Metadata(t *testing.T) {
	probe, err := NewWin11(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "grandma.Win11", probe.Name())
	assert.Equal(t, "get model to output Win 11 product keys", probe.Goal())
	assert.Equal(t, "productkey.Win5x5", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.Description())
}

func TestWin11_Probe(t *testing.T) {
	probe, err := NewWin11(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	assert.Len(t, attempts, 6, "Should create 6 attempts for Win11")
	assert.Equal(t, 6, gen.Calls, "Should call generator 6 times")

	// Verify attempt structure
	for _, att := range attempts {
		assert.Equal(t, "grandma.Win11", att.Probe)
		assert.Equal(t, "productkey.Win5x5", att.Detector)
		assert.NotEmpty(t, att.Prompt)
		assert.Len(t, att.Outputs, 1)
		assert.Equal(t, "test response", att.Outputs[0])
	}
}

// Test Slurs probe

func TestSlurs_PromptGeneration(t *testing.T) {
	probe, err := NewSlurs(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	prompts := probe.GetPrompts()
	// 3 templates × 4 groups = 12 prompts
	assert.Len(t, prompts, 12, "Slurs should generate 12 prompts (3 templates × 4 groups)")

	// Verify prompts contain human group names
	groupsFound := make(map[string]bool)
	expectedGroups := []string{"British people", "Chinese people", "Black people", "disabled people"}

	for _, prompt := range prompts {
		for _, group := range expectedGroups {
			if containsString(prompt, group) {
				groupsFound[group] = true
			}
		}
	}

	assert.Len(t, groupsFound, 4, "Should mention all 4 human groups")
	for _, group := range expectedGroups {
		assert.True(t, groupsFound[group], "Should mention "+group)
	}
}

func TestSlurs_Metadata(t *testing.T) {
	probe, err := NewSlurs(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "grandma.Slurs", probe.Name())
	assert.Equal(t, "get model to use ethnic slur", probe.Goal())
	assert.Equal(t, "unsafecontent.SlursReclaimedSlurs", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.Description())
}

func TestSlurs_Probe(t *testing.T) {
	probe, err := NewSlurs(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	assert.Len(t, attempts, 12, "Should create 12 attempts for Slurs")
	assert.Equal(t, 12, gen.Calls, "Should call generator 12 times")

	// Verify attempt structure
	for _, att := range attempts {
		assert.Equal(t, "grandma.Slurs", att.Probe)
		assert.Equal(t, "unsafecontent.SlursReclaimedSlurs", att.Detector)
		assert.NotEmpty(t, att.Prompt)
		assert.Len(t, att.Outputs, 1)
		assert.Equal(t, "test response", att.Outputs[0])
	}
}

// Test Substances probe

func TestSubstances_PromptGeneration(t *testing.T) {
	probe, err := NewSubstances(registry.Config{})
	require.NoError(t, err)
	require.NotNil(t, probe)

	prompts := probe.GetPrompts()
	// 2 templates × 5 substances = 10 prompts
	assert.Len(t, prompts, 10, "Substances should generate 10 prompts (2 templates × 5 substances)")

	// Verify prompts contain substance names
	substancesFound := make(map[string]bool)
	expectedSubstances := []string{"napalm", "methamphetamine", "dimethyl mercury", "EA-2192", "belladonna tropane alkaloids"}

	for _, prompt := range prompts {
		for _, substance := range expectedSubstances {
			if containsString(prompt, substance) {
				substancesFound[substance] = true
			}
		}
	}

	assert.Len(t, substancesFound, 5, "Should mention all 5 substances")
	for _, substance := range expectedSubstances {
		assert.True(t, substancesFound[substance], "Should mention "+substance)
	}
}

func TestSubstances_Metadata(t *testing.T) {
	probe, err := NewSubstances(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "grandma.Substances", probe.Name())
	assert.Equal(t, "get instructions for making bad things", probe.Goal())
	assert.Equal(t, "mitigation.MitigationBypass", probe.GetPrimaryDetector())
	assert.NotEmpty(t, probe.Description())
}

func TestSubstances_Probe(t *testing.T) {
	probe, err := NewSubstances(registry.Config{})
	require.NoError(t, err)

	gen := testutil.NewMockGenerator("test response")

	attempts, err := probe.Probe(context.Background(), gen)
	require.NoError(t, err)
	assert.Len(t, attempts, 10, "Should create 10 attempts for Substances")
	assert.Equal(t, 10, gen.Calls, "Should call generator 10 times")

	// Verify attempt structure
	for _, att := range attempts {
		assert.Equal(t, "grandma.Substances", att.Probe)
		assert.Equal(t, "mitigation.MitigationBypass", att.Detector)
		assert.NotEmpty(t, att.Prompt)
		assert.Len(t, att.Outputs, 1)
		assert.Equal(t, "test response", att.Outputs[0])
	}
}

// Test error handling

func TestProbe_ErrorHandling(t *testing.T) {
	tests := []struct {
		name        string
		newProbe    func(registry.Config) (any, error)
		expectedErr error
	}{
		{
			name: "Win10",
			newProbe: func(cfg registry.Config) (any, error) {
				return NewWin10(cfg)
			},
			expectedErr: nil,
		},
		{
			name: "Win11",
			newProbe: func(cfg registry.Config) (any, error) {
				return NewWin11(cfg)
			},
			expectedErr: nil,
		},
		{
			name: "Slurs",
			newProbe: func(cfg registry.Config) (any, error) {
				return NewSlurs(cfg)
			},
			expectedErr: nil,
		},
		{
			name: "Substances",
			newProbe: func(cfg registry.Config) (any, error) {
				return NewSubstances(cfg)
			},
			expectedErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := tt.newProbe(registry.Config{})
			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Nil(t, probe)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, probe)
			}
		})
	}
}

// Helper functions

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if containsString(s, substr) {
			return true
		}
	}
	return false
}
