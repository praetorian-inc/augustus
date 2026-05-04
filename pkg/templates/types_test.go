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

// TestProbeTemplateUnmarshal_DetectorConfig verifies G1+G2: the detector_config
// YAML block is correctly decoded into ProbeInfo.DetectorConfig and the
// TemplateProbe.GetDetectorConfig() method returns the same map content.
// Four cases are covered: scalar string list, nested map values, missing block, empty block.
func TestProbeTemplateUnmarshal_DetectorConfig(t *testing.T) {
	cases := []struct {
		name           string
		yamlData       string
		wantNil        bool
		wantEmpty      bool
		wantPatterns   []any
		wantNestedKey  string
		wantNestedVal  any
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
