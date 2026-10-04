package openai

import (
	"testing"

	"github.com/praetorian-inc/augustus/internal/testutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// TestRequiredKeysAreRequired proves the required/optional split against the
// parser: the required keys alone parse, and dropping any one of them fails.
func TestRequiredKeysAreRequired(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-test")
	testutil.RequireKeysAreRequired(t, RequiredKeys(), OptionalKeys(), func(m registry.Config) error {
		_, err := ConfigFromMap(m)
		return err
	})
}
