package mcptool

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

type equivMockInvoker struct {
	responses map[string]types.ToolResult
}

func (m *equivMockInvoker) ListTools(_ context.Context) ([]map[string]any, error) {
	return nil, nil
}

func (m *equivMockInvoker) CallTool(_ context.Context, name string, _ map[string]any) (types.ToolResult, error) {
	if res, ok := m.responses[name]; ok {
		return res, nil
	}
	return types.ToolResult{IsError: true, Text: "not found"}, nil
}

func TestInconsistentAuthz_DVMCPShape(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)

	probe := p.(*InconsistentAuthorization)

	toolA := dvmcpTool("get_user_role")
	toolB := dvmcpTool("get_user_roles")

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role":  {Text: `{"role": "viewer"}`},
			"get_user_roles": {Text: `{"roles": ["admin", "superuser", "system"]}`},
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	require.NotNil(t, a)

	assert.Equal(t, "mcptool.InconsistentAuthorization", a.Probe)
	assert.Equal(t, "mcptool.InconsistentAuthorization", a.Detector)

	toolAMeta, _ := a.GetMetadata(mcpprobe.MetaEquivToolA)
	toolBMeta, _ := a.GetMetadata(mcpprobe.MetaEquivToolB)
	assert.Equal(t, "get_user_role", toolAMeta)
	assert.Equal(t, "get_user_roles", toolBMeta)

	respA, _ := a.GetMetadata(mcpprobe.MetaEquivResponseA)
	respB, _ := a.GetMetadata(mcpprobe.MetaEquivResponseB)
	assert.Contains(t, respA, "viewer")
	assert.Contains(t, respB, "admin")

	method, _ := a.GetMetadata(mcpprobe.MetaEquivPairingMethod)
	assert.Equal(t, "name-heuristic", method)

	require.Len(t, a.Outputs, 2)
}

func TestInconsistentAuthz_NoSharedParams(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	toolA := map[string]any{
		"name": "get_user",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"user_id": map[string]any{"type": "string"},
			},
		},
	}
	toolB := map[string]any{
		"name": "get_users",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"group_name": map[string]any{"type": "string"},
			},
		},
	}

	invoker := &equivMockInvoker{responses: map[string]types.ToolResult{}}
	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	assert.Nil(t, a)
}

func TestInconsistentAuthz_IdenticalResponses(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	toolA := dvmcpTool("get_user_role")
	toolB := dvmcpTool("get_user_roles")

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role":  {Text: `{"role": "viewer"}`},
			"get_user_roles": {Text: `{"role": "viewer"}`},
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	require.NotNil(t, a)
	require.Len(t, a.Outputs, 2)
	assert.Equal(t, a.Outputs[0], a.Outputs[1])
}

func TestInconsistentAuthz_Metadata(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)

	assert.Equal(t, "mcptool.InconsistentAuthorization", p.Name())
	pm := p.(types.ProbeMetadata)
	assert.Equal(t, "mcptool.InconsistentAuthorization", pm.GetPrimaryDetector())
	assert.NotEmpty(t, pm.Description())
	assert.NotEmpty(t, pm.Goal())
	assert.NotEmpty(t, pm.GetPrompts())

	rd := p.(types.RiskDescriber)
	info := rd.RiskInfo()
	assert.NotEmpty(t, info.Description)
	assert.NotEmpty(t, info.Impact)
	assert.NotEmpty(t, info.CVSSVector)
	assert.Contains(t, info.Taxonomies, "862")
}

func dvmcpTool(name string) map[string]any {
	return map[string]any{
		"name":        name,
		"description": "Returns user role information",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string", "description": "The username to query"},
			},
			"required": []any{"username"},
		},
	}
}
