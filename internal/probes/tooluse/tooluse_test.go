package tooluse

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/templates"
)

// expectedProbes lists all tool-use probe IDs that must be registered.
var expectedProbes = []string{
	"tool.UnauthorizedInvocation",
	"tool.FunctionCallingJailbreak",
	"tool.ParameterInjection",
	"tool.DataExfiltration",
	"tool.SelectionHijacking",
	"tool.ChainAmplification",
	"tool.IndirectReturnExploitation",
	"tool.OnboardingPoisoning",
	"tool.ParserSpoofing",
	"tool.MCPSupplyChainPoisoning",
	"tool.SchemaMutation",
	"tool.MemoryPoisoning",
	"tool.CrossAgentPropagation",
	"tool.ConfusedDeputyTokenReuse",
}

func TestAllProbesRegistered(t *testing.T) {
	for _, id := range expectedProbes {
		t.Run(id, func(t *testing.T) {
			factory, ok := probes.Get(id)
			require.True(t, ok, "probe %q not registered", id)
			require.NotNil(t, factory)
		})
	}
}

func TestProbeCreation(t *testing.T) {
	for _, id := range expectedProbes {
		t.Run(id, func(t *testing.T) {
			factory, ok := probes.Get(id)
			require.True(t, ok)

			probe, err := factory(nil)
			require.NoError(t, err)
			require.NotNil(t, probe)
			assert.Equal(t, id, probe.Name())
		})
	}
}

// expectedDetectors maps each probe to its required primary detector.
//
// Argument-content probes (ParameterInjection, DataExfiltration, and the
// P3 agent-security probes) use agent.ArgumentExfiltration to inspect tool
// call argument values for exfiltration indicators.
//
// Name-based probes (UnauthorizedInvocation, FunctionCallingJailbreak,
// OnboardingPoisoning, IndirectReturnExploitation, SelectionHijacking,
// MCPSupplyChainPoisoning) use agent.ToolManipulation, which requires
// operator-supplied expected_tools or forbidden_tools config to produce a
// non-zero score. See each probe's description for details.
//
// tool.ChainAmplification uses agent.ChainLength (count-based) to score
// the 658× chain amplification attack from arXiv:2601.10955.
var expectedDetectors = map[string]string{
	"tool.UnauthorizedInvocation":     "agent.ToolManipulation",
	"tool.FunctionCallingJailbreak":   "agent.ToolManipulation",
	"tool.ParameterInjection":         "agent.ArgumentExfiltration",
	"tool.DataExfiltration":           "agent.ArgumentExfiltration",
	"tool.SelectionHijacking":         "agent.ToolManipulation",
	"tool.ChainAmplification":         "agent.ChainLength",
	"tool.IndirectReturnExploitation": "agent.ToolManipulation",
	"tool.OnboardingPoisoning":        "agent.ToolManipulation",
	"tool.ParserSpoofing":             "agent.FakeToolCallText",
	"tool.MCPSupplyChainPoisoning":    "agent.ToolManipulation",
	"tool.SchemaMutation":             "agent.ArgumentExfiltration",
	"tool.MemoryPoisoning":            "agent.ArgumentExfiltration",
	"tool.CrossAgentPropagation":      "agent.ArgumentExfiltration",
	"tool.ConfusedDeputyTokenReuse":   "agent.ArgumentExfiltration",
}

func TestProbeMetadata(t *testing.T) {
	type metadataProvider interface {
		Description() string
		Goal() string
		GetPrimaryDetector() string
		GetPrompts() []string
	}

	for _, id := range expectedProbes {
		t.Run(id, func(t *testing.T) {
			factory, ok := probes.Get(id)
			require.True(t, ok)

			probe, err := factory(nil)
			require.NoError(t, err)

			md, ok := probe.(metadataProvider)
			require.True(t, ok, "probe %q does not implement ProbeMetadata", id)

			assert.NotEmpty(t, md.Description(), "description should not be empty")
			assert.NotEmpty(t, md.Goal(), "goal should not be empty")

			wantDetector := expectedDetectors[id]
			assert.Equal(t, wantDetector, md.GetPrimaryDetector(),
				"probe %q should use detector %q", id, wantDetector)
			assert.NotEmpty(t, md.GetPrompts(), "prompts should not be empty")
		})
	}
}

// TestProbeToolsNonNil verifies that all tool-use probes except ParserSpoofing
// have non-nil, non-empty tools defined. This catches the silent-discard bug
// where tools/tool_choice fields at the YAML top level are ignored by yaml.v3
// because ProbeTemplate only maps id:, info:, and prompts:.
func TestProbeToolsNonNil(t *testing.T) {
	for _, id := range expectedProbes {
		t.Run(id, func(t *testing.T) {
			if id == "tool.ParserSpoofing" {
				// ParserSpoofing deliberately has no tools (chat-mode text probe)
				return
			}

			factory, ok := probes.Get(id)
			require.True(t, ok)

			probe, err := factory(nil)
			require.NoError(t, err)

			tp, ok := probe.(*templates.TemplateProbe)
			require.True(t, ok, "probe %q must be a *templates.TemplateProbe", id)

			tools := tp.GetTools()
			assert.NotNil(t, tools, "probe %q: GetTools() must not return nil (tools: field is likely at YAML top level, not under info:)", id)
			assert.Greater(t, len(tools), 0, "probe %q: GetTools() must return at least one tool definition", id)
		})
	}
}

func TestProbeCount(t *testing.T) {
	count := 0
	for _, id := range expectedProbes {
		if _, ok := probes.Get(id); ok {
			count++
		}
	}
	assert.Equal(t, len(expectedProbes), count,
		"expected %d tool-use probes, got %d", len(expectedProbes), count)
}

func TestToolUsePrefix(t *testing.T) {
	for _, id := range expectedProbes {
		assert.Regexp(t, `^tool\.`, id, "probe %q must have tool.* prefix", id)
	}
}
