package testutil

import (
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// keyValue is the URL-shaped string every key under test is set to.
const keyValue = "http://example.invalid"

// RequireKeysAreRequired proves a parser's required/optional split against
// its behavior when no alias is supplied: the required keys alone (each set
// to a URL-shaped string) parse, and dropping any one of them fails. A
// required key that an alias can satisfy is covered by RequireAliasesSatisfy.
// It also requires the two lists to be free of duplicates and disjoint, so no
// key is listed as both.
func RequireKeysAreRequired(t *testing.T, required, optional []string, parse func(registry.Config) error) {
	t.Helper()
	seen := map[string]bool{}
	for _, k := range append(slices.Clone(required), optional...) {
		assert.Falsef(t, seen[k], "key %q listed more than once across required and optional", k)
		seen[k] = true
	}

	base := requiredBase(required)
	require.NoError(t, parse(base), "required keys alone must parse")

	for _, k := range required {
		m := maps.Clone(base)
		delete(m, k)
		assert.Errorf(t, parse(m), "parser accepted config without required key %q", k)
	}
}

// RequireAliasesSatisfy proves each alias stands in for its required key: with
// the required keys set, replacing an aliased key by any one of its aliases
// still parses, and dropping the key together with all its aliases fails.
func RequireAliasesSatisfy(t *testing.T, required []string, aliases map[string][]string, parse func(registry.Config) error) {
	t.Helper()
	require.NotEmpty(t, aliases, "no aliases to prove")
	base := requiredBase(required)
	for _, k := range slices.Sorted(maps.Keys(aliases)) {
		require.Containsf(t, required, k, "aliased key %q is not required", k)
		require.NotEmptyf(t, aliases[k], "aliased key %q lists no aliases", k)

		without := maps.Clone(base)
		delete(without, k)
		for _, a := range aliases[k] {
			m := maps.Clone(without)
			m[a] = keyValue
			assert.NoErrorf(t, parse(m), "alias %q must satisfy required key %q", a, k)
		}
		assert.Errorf(t, parse(without), "parser accepted config without %q or any of its aliases %v", k, aliases[k])
	}
}

func requiredBase(required []string) registry.Config {
	base := registry.Config{}
	for _, k := range required {
		base[k] = keyValue
	}
	return base
}
