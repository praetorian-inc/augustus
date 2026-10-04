package openai

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func parse(m registry.Config) error {
	_, err := ConfigFromMap(m)
	return err
}

// TestRequiredKeysAreRequired proves the required/optional split against the
// parser with no env fallback in effect: the required keys alone parse, and
// dropping any one of them fails.
func TestRequiredKeysAreRequired(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "")
	testutil.RequireKeysAreRequired(t, RequiredKeys(), OptionalKeys(), parse)
}

// TestKeyEnvFallbacksSatisfyRequiredKeys proves each env fallback stands in
// for its required key, and that only required keys declare one.
func TestKeyEnvFallbacksSatisfyRequiredKeys(t *testing.T) {
	assert.Subset(t, RequiredKeys(), slices.Collect(maps.Keys(KeyEnvFallbacks())))
	testutil.RequireEnvSatisfies(t, RequiredKeys(), KeyEnvFallbacks(), parse)
}
