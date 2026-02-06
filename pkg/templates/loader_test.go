package templates

import (
	"embed"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed testdata/*.yaml
var testTemplates embed.FS

func TestLoadTemplate(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	tmpl, err := loader.Load("test.yaml")
	require.NoError(t, err)

	assert.Equal(t, "test.TestProbe", tmpl.ID)
	assert.Equal(t, "Test Probe", tmpl.Info.Name)
	assert.Equal(t, "test the loader", tmpl.Info.Goal)
	assert.Len(t, tmpl.Prompts, 1)
}

func TestLoadAllTemplates(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	templates, err := loader.LoadAll()
	require.NoError(t, err)

	assert.Len(t, templates, 1)
	assert.Equal(t, "test.TestProbe", templates[0].ID)
}

func TestLoadTemplateNotFound(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	_, err := loader.Load("nonexistent.yaml")
	assert.Error(t, err)
}

func TestLoadFromPath(t *testing.T) {
	// LoadFromPath loads templates from filesystem (not embedded)
	templates, err := LoadFromPath("testdata")
	require.NoError(t, err)

	assert.GreaterOrEqual(t, len(templates), 1, "should load at least one template")

	// Verify the test template was loaded
	found := false
	for _, tmpl := range templates {
		if tmpl.ID == "test.TestProbe" {
			found = true
			assert.Equal(t, "Test Probe", tmpl.Info.Name)
			assert.Equal(t, "test the loader", tmpl.Info.Goal)
			assert.Len(t, tmpl.Prompts, 1)
			break
		}
	}
	assert.True(t, found, "should find test.TestProbe in loaded templates")
}

func TestLoadFromPathNotFound(t *testing.T) {
	_, err := LoadFromPath("nonexistent-directory")
	assert.Error(t, err)
}
