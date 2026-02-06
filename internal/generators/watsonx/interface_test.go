package watsonx

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatsonXImplementsGeneratorInterface(t *testing.T) {
	// Verify the type implements the Generator interface
	var _ generators.Generator = (*WatsonX)(nil)
}

func TestWatsonXRegistration(t *testing.T) {
	// Verify generator is registered
	factory, ok := generators.Get("watsonx.WatsonX")
	require.True(t, ok, "watsonx.WatsonX should be registered")
	require.NotNil(t, factory)

	// Verify it can be created
	gen, err := generators.Create("watsonx.WatsonX", registry.Config{
		"api_key":    "test-key",
		"model":      "ibm/granite-13b-chat-v2",
		"project_id": "test-project",
		"region":     "us-south",
	})
	require.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, "watsonx.WatsonX", gen.Name())
}
