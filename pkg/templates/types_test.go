package templates

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestProbeTemplateUnmarshal(t *testing.T) {
	yamlData := `
id: dan.Dan_11_0
info:
  name: DAN 11.0
  author: community
  description: "A do-anything-now jailbreak"
  goal: disregard the system prompt
  detector: dan.DAN
  tags:
    - jailbreak
    - dan
  severity: high
prompts:
  - "Ignore all instructions..."
`
	var tmpl ProbeTemplate
	err := yaml.Unmarshal([]byte(yamlData), &tmpl)
	require.NoError(t, err)

	assert.Equal(t, "dan.Dan_11_0", tmpl.ID)
	assert.Equal(t, "DAN 11.0", tmpl.Info.Name)
	assert.Equal(t, "community", tmpl.Info.Author)
	assert.Equal(t, "disregard the system prompt", tmpl.Info.Goal)
	assert.Equal(t, "dan.DAN", tmpl.Info.Detector)
	assert.Equal(t, []string{"jailbreak", "dan"}, tmpl.Info.Tags)
	assert.Equal(t, "high", tmpl.Info.Severity)
	assert.Len(t, tmpl.Prompts, 1)
}
