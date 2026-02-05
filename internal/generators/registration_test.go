package generators_test

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/stretchr/testify/assert"

	// Import all generators to trigger registration
	_ "github.com/praetorian-inc/augustus/internal/generators/function"
	_ "github.com/praetorian-inc/augustus/internal/generators/langchain"
)

func TestPhase3GeneratorsRegistered(t *testing.T) {
	phase3Generators := []string{
		"function.Single",
		"function.Multiple",
		"langchain.LangChain",
	}

	registeredGenerators := generators.List()

	for _, expected := range phase3Generators {
		assert.Contains(t, registeredGenerators, expected, "Generator %s should be registered", expected)
	}

	// Verify we can get the factory functions
	for _, name := range phase3Generators {
		factory, ok := generators.Get(name)
		assert.True(t, ok, "Generator %s should have a factory function", name)
		assert.NotNil(t, factory, "Generator %s factory should not be nil", name)
	}
}

