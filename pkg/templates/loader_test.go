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

	// LoadAll will fail when it encounters the first invalid template
	_, err := loader.LoadAll()
	assert.Error(t, err, "LoadAll should fail when encountering invalid templates in testdata")
	assert.Contains(t, err.Error(), "template", "error should reference template validation")
}

func TestLoadValidTemplate(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	// Load only the valid test.yaml template
	tmpl, err := loader.Load("test.yaml")
	require.NoError(t, err)

	assert.Equal(t, "test.TestProbe", tmpl.ID)
	assert.Equal(t, "Test Probe", tmpl.Info.Name)
}

func TestLoadTemplateNotFound(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	_, err := loader.Load("nonexistent.yaml")
	assert.Error(t, err)
}

func TestLoadFromPath(t *testing.T) {
	// LoadFromPath loads templates from filesystem (not embedded)
	// With validation enabled, it will fail on invalid templates
	_, err := LoadFromPath("testdata")
	assert.Error(t, err, "LoadFromPath should fail when encountering invalid templates")
	assert.Contains(t, err.Error(), "template", "error should reference template validation")
}

func TestLoadFromPathNotFound(t *testing.T) {
	_, err := LoadFromPath("nonexistent-directory")
	assert.Error(t, err)
}

func TestLoadTemplate_ClassificationFields(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	tmpl, err := loader.Load("test.yaml")
	require.NoError(t, err)

	// Verify classification fields are loaded from YAML
	assert.Equal(t, []string{"CWE-77"}, tmpl.Info.CWEIDs, "CWE IDs should be loaded")
	assert.Equal(t, []string{"T1059.006"}, tmpl.Info.MITREAttack, "MITRE ATT&CK techniques should be loaded")
	assert.Equal(t, []string{"A03:2021"}, tmpl.Info.OWASPTopTen, "OWASP categories should be loaded")
}

func TestLoad_ValidatesTemplate(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	_, err := loader.Load("invalid.yaml")
	assert.Error(t, err, "should fail to load template with missing required fields")
	assert.Contains(t, err.Error(), "template validation failed", "error should indicate validation failure")
}

func TestLoad_ValidatesClassification_InvalidCWE(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	_, err := loader.Load("invalid-cwe.yaml")
	assert.Error(t, err, "should fail to load template with invalid CWE format")
	assert.Contains(t, err.Error(), "invalid CWE format", "error should indicate CWE validation failure")
}

func TestLoad_ValidatesClassification_InvalidMITRE(t *testing.T) {
	loader := NewLoader(testTemplates, "testdata")

	_, err := loader.Load("invalid-mitre.yaml")
	assert.Error(t, err, "should fail to load template with invalid MITRE ATT&CK format")
	assert.Contains(t, err.Error(), "invalid MITRE", "error should indicate MITRE validation failure")
}

func TestLoadFromPath_ValidatesTemplate(t *testing.T) {
	// LoadFromPath should also validate templates
	templates, err := LoadFromPath("testdata")

	// Should return error because testdata contains invalid templates
	if err == nil {
		// If no error, all templates should be valid
		for _, tmpl := range templates {
			assert.NoError(t, tmpl.Validate(), "all loaded templates should be valid")
			assert.NoError(t, tmpl.ValidateClassification(), "all loaded templates should have valid classifications")
		}
	} else {
		// Expected: LoadFromPath fails on first invalid template
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "template", "error should reference template validation")
	}
}
