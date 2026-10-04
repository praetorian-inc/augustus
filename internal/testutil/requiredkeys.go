package testutil

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// RequireKeysAreRequired proves a parser's required/optional split against
// its behavior: the required keys alone (each set to a URL-shaped string)
// parse, and dropping any one of them fails. It also requires the two lists
// to be free of duplicates and disjoint, so no key is listed as both.
func RequireKeysAreRequired(t *testing.T, required, optional []string, parse func(registry.Config) error) {
	t.Helper()
	seen := map[string]bool{}
	for _, k := range append(slices.Clone(required), optional...) {
		assert.Falsef(t, seen[k], "key %q listed more than once across required and optional", k)
		seen[k] = true
	}

	base := registry.Config{}
	for _, k := range required {
		base[k] = "http://example.invalid"
	}
	require.NoError(t, parse(base), "required keys alone must parse")

	for _, k := range required {
		m := maps.Clone(base)
		delete(m, k)
		assert.Errorf(t, parse(m), "parser accepted config without required key %q", k)
	}
}
