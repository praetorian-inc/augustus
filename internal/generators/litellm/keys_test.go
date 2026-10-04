package litellm

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestRequiredKeysAreRequired proves the required/optional split against the
// parser: the required keys alone parse, and dropping any one of them fails.
func TestRequiredKeysAreRequired(t *testing.T) {
	testutil.RequireKeysAreRequired(t, RequiredKeys(), OptionalKeys(), func(m registry.Config) error {
		_, err := ConfigFromMap(m)
		return err
	})
}

// TestKeyAliasesSatisfyRequired proves each KeyAliases entry can stand in for
// its required key, and that the key is still needed when no alias is set.
func TestKeyAliasesSatisfyRequired(t *testing.T) {
	testutil.RequireAliasesSatisfy(t, RequiredKeys(), KeyAliases(), func(m registry.Config) error {
		_, err := ConfigFromMap(m)
		return err
	})
}
