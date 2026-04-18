package tooluse

import (
	"testing"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
// Most tooluse probes use agent.ToolManipulation (name-based), while
// tool.ChainAmplification uses agent.ChainLength (count-based) to score
// the 658× chain amplification attack from arXiv:2601.10955.
var expectedDetectors = map[string]string{
	"tool.UnauthorizedInvocation":     "agent.ToolManipulation",
	"tool.FunctionCallingJailbreak":   "agent.ToolManipulation",
	"tool.ParameterInjection":         "agent.ToolManipulation",
	"tool.DataExfiltration":           "agent.ToolManipulation",
	"tool.SelectionHijacking":         "agent.ToolManipulation",
	"tool.ChainAmplification":         "agent.ChainLength",
	"tool.IndirectReturnExploitation": "agent.ToolManipulation",
	"tool.OnboardingPoisoning":        "agent.ToolManipulation",
	"tool.ParserSpoofing":             "agent.FakeToolCallText",
	"tool.MCPSupplyChainPoisoning":    "agent.ToolManipulation",
	"tool.SchemaMutation":             "agent.ToolManipulation",
	"tool.MemoryPoisoning":            "agent.ToolManipulation",
	"tool.CrossAgentPropagation":      "agent.ToolManipulation",
	"tool.ConfusedDeputyTokenReuse":   "agent.ToolManipulation",
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
