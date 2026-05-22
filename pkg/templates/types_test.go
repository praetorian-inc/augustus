package templates

import (
	"os"
	"path/filepath"
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

// TestProbeTemplateUnmarshal_DetectorConfig verifies G1+G2: the detector_config
// YAML block is correctly decoded into ProbeInfo.DetectorConfig and the
// TemplateProbe.GetDetectorConfig() method returns the same map content.
// Four cases are covered: scalar string list, nested map values, missing block, empty block.
func TestProbeTemplateUnmarshal_DetectorConfig(t *testing.T) {
	cases := []struct {
		name          string
		yamlData      string
		wantNil       bool
		wantEmpty     bool
		wantPatterns  []any
		wantNestedKey string
		wantNestedVal any
	}{
		{
			name: "scalar string list",
			yamlData: `
id: test.Probe1
info:
  name: Test Probe 1
  author: test
  description: test
  goal: test
  detector: agent.ArgumentExfiltration
  severity: high
  detector_config:
    forbidden_patterns:
      - "(?i)evil\\.com"
      - "(?i)attacker"
prompts:
  - "Hello."
`,
			wantPatterns: []any{"(?i)evil\\.com", "(?i)attacker"},
		},
		{
			name: "nested map values",
			yamlData: `
id: test.Probe2
info:
  name: Test Probe 2
  author: test
  description: test
  goal: test
  detector: agent.ArgumentExfiltration
  severity: high
  detector_config:
    nested_key:
      sub_key: sub_value
prompts:
  - "Hello."
`,
			wantNestedKey: "nested_key",
			wantNestedVal: map[string]any{"sub_key": "sub_value"},
		},
		{
			name: "missing block returns nil",
			yamlData: `
id: test.Probe3
info:
  name: Test Probe 3
  author: test
  description: test
  goal: test
  detector: agent.ArgumentExfiltration
  severity: high
prompts:
  - "Hello."
`,
			wantNil: true,
		},
		{
			name: "empty block returns empty map",
			yamlData: `
id: test.Probe4
info:
  name: Test Probe 4
  author: test
  description: test
  goal: test
  detector: agent.ArgumentExfiltration
  severity: high
  detector_config: {}
prompts:
  - "Hello."
`,
			wantEmpty: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var tmpl ProbeTemplate
			require.NoError(t, yaml.Unmarshal([]byte(tc.yamlData), &tmpl))

			probe := NewTemplateProbe(&tmpl)
			cfg := probe.GetDetectorConfig()

			switch {
			case tc.wantNil:
				assert.Nil(t, cfg, "missing detector_config should return nil")

			case tc.wantEmpty:
				assert.NotNil(t, cfg, "empty detector_config should return non-nil map")
				assert.Len(t, cfg, 0, "empty detector_config should return empty map")

			case tc.wantPatterns != nil:
				require.NotNil(t, cfg)
				patterns, ok := cfg["forbidden_patterns"]
				require.True(t, ok, "expected 'forbidden_patterns' key in detector_config")
				assert.Equal(t, tc.wantPatterns, patterns)

			case tc.wantNestedKey != "":
				require.NotNil(t, cfg)
				val, ok := cfg[tc.wantNestedKey]
				require.True(t, ok, "expected nested key %q in detector_config", tc.wantNestedKey)
				assert.Equal(t, tc.wantNestedVal, val)
			}

			// Also verify tmpl.Info.DetectorConfig matches probe.GetDetectorConfig() (G2).
			assert.Equal(t, tmpl.Info.DetectorConfig, cfg, "GetDetectorConfig() must return tmpl.Info.DetectorConfig")
		})
	}
}

// TestProbeTemplateValidate_RejectsDuplicateSecondary verifies that Validate()
// returns ErrDuplicateSecondaryDetectorName when two secondary_detectors entries
// share the same name.
func TestProbeTemplateValidate_RejectsDuplicateSecondary(t *testing.T) {
	const yamlData = `
id: test.DupSecondary
info:
  name: Dup Secondary
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
  secondary_detectors:
    - name: agent.ArgumentExfiltration
      config:
        forbidden_patterns:
          - '(?i)evil'
    - name: agent.ArgumentExfiltration
      config:
        forbidden_patterns:
          - '(?i)other'
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	err := tmpl.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDuplicateSecondaryDetectorName,
		"duplicate secondary detector name should fail validation")
}

// TestProbeTemplateValidate_RejectsSelfReference verifies that Validate() returns
// ErrSecondaryDetectorSelfReference when a secondary entry name equals the primary.
func TestProbeTemplateValidate_RejectsSelfReference(t *testing.T) {
	const yamlData = `
id: test.SelfRef
info:
  name: Self Ref
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
  secondary_detectors:
    - name: agent.ToolManipulation
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	err := tmpl.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecondaryDetectorSelfReference,
		"secondary entry equal to primary should fail validation")
}

// TestProbeTemplateValidate_RejectsEmptySecondaryName verifies that Validate()
// returns ErrEmptySecondaryDetectorName when a secondary entry has a blank name.
func TestProbeTemplateValidate_RejectsEmptySecondaryName(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.EmptyName",
		Info: ProbeInfo{
			Name:     "Empty Name",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			SecondaryDetectors: []SecondaryDetectorYAML{
				{Name: ""},
			},
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEmptySecondaryDetectorName)
}

// TestProbeTemplateValidate_WhitespacePaddedDuplicate verifies that Validate()
// returns ErrDuplicateSecondaryDetectorName when two secondary entries have names
// that are equal after trimming whitespace (e.g. "foo" and " foo ").
func TestProbeTemplateValidate_WhitespacePaddedDuplicate(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.WhitespaceDuplicate",
		Info: ProbeInfo{
			Name:     "Whitespace Duplicate",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			SecondaryDetectors: []SecondaryDetectorYAML{
				{Name: "foo"},
				{Name: " foo "},
			},
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDuplicateSecondaryDetectorName,
		"whitespace-padded duplicate secondary detector name should fail validation")
}

// TestProbeTemplateValidate_WhitespacePaddedSelfReference verifies that Validate()
// returns ErrSecondaryDetectorSelfReference when a secondary entry name matches
// the primary detector after trimming whitespace (e.g. " detectorName " == "detectorName").
func TestProbeTemplateValidate_WhitespacePaddedSelfReference(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.WhitespaceSelfRef",
		Info: ProbeInfo{
			Name:     "Whitespace Self Reference",
			Goal:     "test",
			Detector: "detectorName",
			Severity: "high",
			SecondaryDetectors: []SecondaryDetectorYAML{
				{Name: " detectorName "},
			},
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrSecondaryDetectorSelfReference,
		"whitespace-padded self-reference secondary detector name should fail validation")
}

// TestProbeTemplateUnmarshal_SecondaryDetectors verifies that secondary_detectors
// round-trips through YAML correctly (field names, config map content).
func TestProbeTemplateUnmarshal_SecondaryDetectors(t *testing.T) {
	const yamlData = `
id: test.SecondaryRoundTrip
info:
  name: Secondary Round Trip
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
  secondary_detectors:
    - name: agent.ArgumentExfiltration
      config:
        forbidden_patterns:
          - '(?i)telemetry\.example\.com'
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	require.Len(t, tmpl.Info.SecondaryDetectors, 1)

	sec := tmpl.Info.SecondaryDetectors[0]
	assert.Equal(t, "agent.ArgumentExfiltration", sec.Name)
	require.NotNil(t, sec.Config)

	patterns, ok := sec.Config["forbidden_patterns"]
	require.True(t, ok, "expected forbidden_patterns in secondary config")
	assert.Equal(t, []any{"(?i)telemetry\\.example\\.com"}, patterns)
}

// TestProbeInfo_Mode_Parsed verifies that the mode field is decoded from YAML
// into ProbeInfo.Mode and that GetMode() returns the same slice.
func TestProbeInfo_Mode_Parsed(t *testing.T) {
	const yamlData = `
id: test.ModeProbe
info:
  name: Mode Probe
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
  mode: [native, chat]
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	assert.Equal(t, []string{"native", "chat"}, tmpl.Info.Mode)

	probe := NewTemplateProbe(&tmpl)
	assert.Equal(t, []string{"native", "chat"}, probe.GetMode())
}

// TestProbeInfo_Mode_Absent verifies that a template without a mode field
// produces a nil/empty Mode slice.
func TestProbeInfo_Mode_Absent(t *testing.T) {
	const yamlData = `
id: test.NoMode
info:
  name: No Mode
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	assert.Empty(t, tmpl.Info.Mode)

	probe := NewTemplateProbe(&tmpl)
	assert.Empty(t, probe.GetMode())
}

// TestProbeTemplate_Validate_RejectsInvalidMode verifies that Validate()
// returns an error when mode contains an unrecognized value.
func TestProbeTemplate_Validate_RejectsInvalidMode(t *testing.T) {
	const yamlData = `
id: test.BadMode
info:
  name: Bad Mode
  author: test
  description: test
  goal: test
  detector: agent.ToolManipulation
  severity: high
  mode: [invalid]
prompts:
  - "Hello."
`
	var tmpl ProbeTemplate
	require.NoError(t, yaml.Unmarshal([]byte(yamlData), &tmpl))
	err := tmpl.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
	assert.Contains(t, err.Error(), "invalid")
}

// TestProbeTemplate_Validate_RejectsEmptyToolName verifies that Validate()
// returns an error containing "non-empty name" when a ToolDefinition has an empty Name.
func TestProbeTemplate_Validate_RejectsEmptyToolName(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.EmptyToolName",
		Info: ProbeInfo{
			Name:     "Empty Tool Name",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools:    []ToolDefinition{{Name: ""}},
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "non-empty name")
}

// TestProbeTemplate_Validate_RejectsDuplicateToolName verifies that Validate()
// returns an error containing "duplicate tool name" when two ToolDefinitions share a name.
func TestProbeTemplate_Validate_RejectsDuplicateToolName(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.DuplicateTool",
		Info: ProbeInfo{
			Name:     "Duplicate Tool",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools: []ToolDefinition{
				{Name: "web_search"},
				{Name: "web_search"},
			},
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate tool name")
}

// TestProbeTemplate_Validate_RejectsInvalidToolChoice verifies that Validate()
// returns an error containing "tool_choice" and the invalid name when tool_choice
// references a tool name that is not declared and not a standard keyword.
func TestProbeTemplate_Validate_RejectsInvalidToolChoice(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.BadToolChoice",
		Info: ProbeInfo{
			Name:       "Bad Tool Choice",
			Goal:       "test",
			Detector:   "agent.ToolManipulation",
			Severity:   "high",
			Tools:      []ToolDefinition{{Name: "web_search"}},
			ToolChoice: "nonexistent_tool",
		},
		Prompts: []string{"Hello."},
	}
	err := tmpl.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tool_choice")
	assert.Contains(t, err.Error(), "nonexistent_tool")
}

// TestProbeTemplate_Validate_AcceptsToolChoiceByName verifies that Validate()
// returns nil when tool_choice is set to a declared tool name.
func TestProbeTemplate_Validate_AcceptsToolChoiceByName(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.ToolChoiceByName",
		Info: ProbeInfo{
			Name:       "Tool Choice By Name",
			Goal:       "test",
			Detector:   "agent.ToolManipulation",
			Severity:   "high",
			Tools:      []ToolDefinition{{Name: "web_search"}},
			ToolChoice: "web_search",
		},
		Prompts: []string{"Hello."},
	}
	assert.NoError(t, tmpl.Validate())
}

// TestProbeTemplate_Validate_AcceptsStandardToolChoiceKeywords verifies that
// Validate() returns nil for each of the standard tool_choice keywords.
func TestProbeTemplate_Validate_AcceptsStandardToolChoiceKeywords(t *testing.T) {
	for _, kw := range []string{"auto", "required", "none"} {
		t.Run(kw, func(t *testing.T) {
			tmpl := ProbeTemplate{
				ID: "test.Standard_" + kw,
				Info: ProbeInfo{
					Name:       "Standard " + kw,
					Goal:       "test",
					Detector:   "agent.ToolManipulation",
					Severity:   "high",
					Tools:      []ToolDefinition{{Name: "web_search"}},
					ToolChoice: kw,
				},
				Prompts: []string{"Hello."},
			}
			assert.NoError(t, tmpl.Validate())
		})
	}
}

// TestProbeTemplate_Validate_AcceptsEmptyToolChoice verifies that Validate()
// returns nil when tools are declared but tool_choice is empty (optional field).
func TestProbeTemplate_Validate_AcceptsEmptyToolChoice(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.EmptyToolChoice",
		Info: ProbeInfo{
			Name:     "Empty Tool Choice",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools:    []ToolDefinition{{Name: "web_search"}},
		},
		Prompts: []string{"Hello."},
	}
	assert.NoError(t, tmpl.Validate())
}

// TestProbeTemplate_Validate_AcceptsValidTools verifies that Validate() returns
// nil for a template with two uniquely named tools, parameters set, and a valid tool_choice.
func TestProbeTemplate_Validate_AcceptsValidTools(t *testing.T) {
	tmpl := ProbeTemplate{
		ID: "test.ValidTools",
		Info: ProbeInfo{
			Name:     "Valid Tools",
			Goal:     "test",
			Detector: "agent.ToolManipulation",
			Severity: "high",
			Tools: []ToolDefinition{
				{
					Name:        "web_search",
					Description: "Search the web",
					Parameters:  map[string]any{"type": "object"},
				},
				{
					Name:        "read_file",
					Description: "Read a file",
					Parameters:  map[string]any{"type": "object"},
				},
			},
			ToolChoice: "auto",
		},
		Prompts: []string{"Hello."},
	}
	assert.NoError(t, tmpl.Validate())
}

// TestToolUseProbes_ParseWithMode verifies that all 14 existing probe YAML
// files in internal/probes/tooluse/data/ parse successfully with the new
// Mode field — none should fail validation due to the Mode addition.
func TestToolUseProbes_ParseWithMode(t *testing.T) {
	dataDir := filepath.Join("..", "..", "internal", "probes", "tooluse", "data")
	entries, err := os.ReadDir(dataDir)
	require.NoError(t, err, "tooluse data directory must exist")

	var yamlFiles []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".yaml" {
			yamlFiles = append(yamlFiles, e.Name())
		}
	}
	require.NotEmpty(t, yamlFiles, "expected YAML probe files in tooluse/data/")

	for _, name := range yamlFiles {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dataDir, name))
			require.NoError(t, err)

			var tmpl ProbeTemplate
			require.NoError(t, yaml.Unmarshal(data, &tmpl), "YAML parse failed")
			require.NoError(t, tmpl.Validate(), "template validation failed")
		})
	}
}
