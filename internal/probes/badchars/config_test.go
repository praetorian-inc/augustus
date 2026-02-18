package badchars

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultDeletionsConfig verifies default configuration values
func TestDefaultDeletionsConfig(t *testing.T) {
	cfg := DefaultDeletionsConfig()

	assert.Equal(t, 1, cfg.Budget, "Default budget should be 1")
	assert.Equal(t, 6, cfg.MaxPositions, "Default max_positions should be 6")
	assert.Equal(t, 16, cfg.MaxASCIIVariants, "Default max_ascii_variants should be 16")
}

// TestDeletionsConfigFromMap verifies parsing from registry.Config
func TestDeletionsConfigFromMap(t *testing.T) {
	m := registry.Config{
		"budget":            2,
		"max_positions":     12,
		"max_ascii_variants": 32,
	}

	cfg, err := DeletionsConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, 2, cfg.Budget)
	assert.Equal(t, 12, cfg.MaxPositions)
	assert.Equal(t, 32, cfg.MaxASCIIVariants)
}

// TestDeletionsConfigFromMapDefaults verifies nil map returns defaults
func TestDeletionsConfigFromMapDefaults(t *testing.T) {
	cfg, err := DeletionsConfigFromMap(nil)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Budget)
	assert.Equal(t, 6, cfg.MaxPositions)
	assert.Equal(t, 16, cfg.MaxASCIIVariants)
}

// TestDeletionsConfigFromMapPartial verifies partial config merges with defaults
func TestDeletionsConfigFromMapPartial(t *testing.T) {
	m := registry.Config{
		"max_positions": 8,
	}

	cfg, err := DeletionsConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, 1, cfg.Budget, "Should use default budget")
	assert.Equal(t, 8, cfg.MaxPositions, "Should use provided max_positions")
	assert.Equal(t, 16, cfg.MaxASCIIVariants, "Should use default max_ascii_variants")
}

// TestRepresentativeASCII verifies the representative ASCII set
func TestRepresentativeASCII(t *testing.T) {
	assert.Len(t, RepresentativeASCII, 16, "Should have exactly 16 representative characters")

	// Verify all chars are in printable ASCII range
	for i, ch := range RepresentativeASCII {
		assert.GreaterOrEqual(t, int(ch), 0x20, "Char at index %d should be >= 0x20", i)
		assert.LessOrEqual(t, int(ch), 0x7E, "Char at index %d should be <= 0x7E", i)
	}

	// Verify no duplicates
	seen := make(map[rune]bool)
	for _, ch := range RepresentativeASCII {
		assert.False(t, seen[ch], "Character %c (0x%02X) appears more than once", ch, int(ch))
		seen[ch] = true
	}

	// Verify specific key characters are present
	expectedChars := []rune{' ', '"', '\'', '<', '>', '{', '}', '\\'}
	for _, expected := range expectedChars {
		found := false
		for _, ch := range RepresentativeASCII {
			if ch == expected {
				found = true
				break
			}
		}
		assert.True(t, found, "Expected character %c (0x%02X) should be in RepresentativeASCII", expected, int(expected))
	}
}

// TestSelectDeletionASCII verifies selection logic for various counts
func TestSelectDeletionASCII(t *testing.T) {
	tests := []struct {
		name     string
		count    int
		wantLen  int
		wantType string // "representative", "full", "subset"
	}{
		{
			name:     "count 1",
			count:    1,
			wantLen:  1,
			wantType: "representative",
		},
		{
			name:     "count 8",
			count:    8,
			wantLen:  8,
			wantType: "representative",
		},
		{
			name:     "count 16 (exact representative)",
			count:    16,
			wantLen:  16,
			wantType: "representative",
		},
		{
			name:     "count 32 (more than representative)",
			count:    32,
			wantLen:  32,
			wantType: "subset",
		},
		{
			name:     "count 95 (all printable)",
			count:    95,
			wantLen:  95,
			wantType: "full",
		},
		{
			name:     "count 0 (returns all)",
			count:    0,
			wantLen:  95,
			wantType: "full",
		},
		{
			name:     "count negative (returns all)",
			count:    -1,
			wantLen:  95,
			wantType: "full",
		},
		{
			name:     "count > 95 (returns all)",
			count:    100,
			wantLen:  95,
			wantType: "full",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectDeletionASCII(tt.count)
			assert.Len(t, got, tt.wantLen)

			// Verify all chars are printable ASCII
			for i, ch := range got {
				assert.GreaterOrEqual(t, int(ch), 0x20, "Char at index %d should be >= 0x20", i)
				assert.Less(t, int(ch), 0x7F, "Char at index %d should be < 0x7F", i)
			}

			// Type-specific checks
			switch tt.wantType {
			case "representative":
				// When count <= 16, should be first N from RepresentativeASCII
				for i := 0; i < tt.wantLen; i++ {
					assert.Equal(t, RepresentativeASCII[i], got[i], "Should match RepresentativeASCII at index %d", i)
				}
			case "full":
				// Should have all 95 printable ASCII characters
				assert.Equal(t, rune(0x20), got[0], "First should be space")
				assert.Equal(t, rune(0x7E), got[len(got)-1], "Last should be tilde")
			case "subset":
				// Should use selectASCII fallback
				// Just verify it's a valid subset
				assert.Greater(t, tt.wantLen, 16, "Subset should be > 16")
				assert.Less(t, tt.wantLen, 95, "Subset should be < 95")
			}
		})
	}
}

// TestNewDeletionsWithConfig verifies creating probe with custom config
func TestNewDeletionsWithConfig(t *testing.T) {
	// Test with default config
	defaultProbe, err := NewDeletions(nil)
	require.NoError(t, err)
	defaultProbeWithMeta := defaultProbe.(probes.ProbeMetadata)
	defaultPrompts := defaultProbeWithMeta.GetPrompts()

	// Test with reduced config (should produce fewer prompts)
	reducedConfig := registry.Config{
		"max_positions":     3,
		"max_ascii_variants": 8,
		"budget":            1,
	}
	reducedProbe, err := NewDeletions(reducedConfig)
	require.NoError(t, err)
	reducedProbeWithMeta := reducedProbe.(probes.ProbeMetadata)
	reducedPrompts := reducedProbeWithMeta.GetPrompts()

	// Reduced config should produce fewer prompts
	assert.Less(t, len(reducedPrompts), len(defaultPrompts), "Reduced config should produce fewer prompts")

	// Test with exhaustive config (should produce more prompts)
	exhaustiveConfig := registry.Config{
		"max_positions":     24,
		"max_ascii_variants": 95,
		"budget":            1,
	}
	exhaustiveProbe, err := NewDeletions(exhaustiveConfig)
	require.NoError(t, err)
	exhaustiveProbeWithMeta := exhaustiveProbe.(probes.ProbeMetadata)
	exhaustivePrompts := exhaustiveProbeWithMeta.GetPrompts()

	// Exhaustive config should produce more prompts than default
	assert.Greater(t, len(exhaustivePrompts), len(defaultPrompts), "Exhaustive config should produce more prompts")
}
