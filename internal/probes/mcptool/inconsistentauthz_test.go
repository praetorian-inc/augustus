package mcptool

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

type equivMockInvoker struct {
	responses map[string]types.ToolResult
	errors    map[string]error
}

func (m *equivMockInvoker) ListTools(_ context.Context) ([]map[string]any, error) {
	return nil, nil
}

func (m *equivMockInvoker) CallTool(_ context.Context, name string, _ map[string]any) (types.ToolResult, error) {
	if m.errors != nil {
		if err, ok := m.errors[name]; ok {
			return types.ToolResult{}, err
		}
	}
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

func TestInconsistentAuthz_ExtraRequiredParamSkipped(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	toolA := map[string]any{
		"name": "list_files",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path": map[string]any{"type": "string"},
			},
			"required": []any{"path"},
		},
	}
	toolB := map[string]any{
		"name": "list_files_recursive",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"path":      map[string]any{"type": "string"},
				"max_depth": map[string]any{"type": "integer"},
			},
			"required": []any{"path", "max_depth"},
		},
	}

	invoker := &equivMockInvoker{responses: map[string]types.ToolResult{}}
	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	assert.Nil(t, a, "pair with asymmetric required params should be skipped to avoid false differential")
}

func TestInconsistentAuthz_TransportErrorSkipped(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	toolA := dvmcpTool("get_user_role")
	toolB := dvmcpTool("get_user_roles")

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role": {Text: `{"role": "viewer"}`},
		},
		errors: map[string]error{
			"get_user_roles": fmt.Errorf("connection reset"),
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	assert.Nil(t, a, "transport error on one leg should not produce an attempt")
}

func TestInconsistentAuthz_CallRefusalRecorded(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	toolA := dvmcpTool("get_user_role")
	toolB := dvmcpTool("get_user_roles")

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role": {Text: `{"role": "viewer"}`},
		},
		errors: map[string]error{
			"get_user_roles": fmt.Errorf("access denied: %w", types.ErrCallRefused),
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	require.NotNil(t, a, "call refusal is meaningful evidence")
	require.Len(t, a.Outputs, 2)
	assert.Contains(t, a.Outputs[1], "[refused:")
}

func TestInconsistentAuthz_NestedPathMismatchSkipped(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	// Tool A has "filter.username" (nested), tool B has "username" (top-level).
	// Same leaf name but different full paths — different wire shapes.
	toolA := map[string]any{
		"name": "search_users",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"filter": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"username": map[string]any{"type": "string"},
					},
					"required": []any{"username"},
				},
			},
			"required": []any{"filter"},
		},
	}
	toolB := map[string]any{
		"name": "search_users_v2",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
			},
			"required": []any{"username"},
		},
	}

	invoker := &equivMockInvoker{responses: map[string]types.ToolResult{}}
	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	assert.Nil(t, a, "nested vs flat path mismatch should be skipped — different wire shapes")
}

func TestInconsistentAuthz_OptionalInARequiredInB(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	// Tool A: username required, tenant optional
	// Tool B: username required, tenant required
	// Shared set = {username, tenant}, both tools' required params are in shared set.
	// tenant is optional in A → BenignCall won't fill it, but B needs it.
	toolA := map[string]any{
		"name": "get_user_role",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
				"tenant":   map[string]any{"type": "string"},
			},
			"required": []any{"username"},
		},
	}
	toolB := map[string]any{
		"name": "get_user_roles",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
				"tenant":   map[string]any{"type": "string"},
			},
			"required": []any{"username", "tenant"},
		},
	}

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role":  {Text: `{"role": "viewer"}`},
			"get_user_roles": {Text: `{"roles": ["admin"]}`},
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	require.NotNil(t, a, "optional-in-A/required-in-B should still produce attempt with param filled")
	require.Len(t, a.Outputs, 2)
}

func TestInconsistentAuthz_AllOptionalSharedParams(t *testing.T) {
	p, err := NewInconsistentAuthorization(registry.Config{})
	require.NoError(t, err)
	probe := p.(*InconsistentAuthorization)

	// Both tools share "username" as optional only — no required params.
	toolA := map[string]any{
		"name": "get_user_role",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
			},
		},
	}
	toolB := map[string]any{
		"name": "get_user_roles",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"username": map[string]any{"type": "string"},
			},
		},
	}

	invoker := &equivMockInvoker{
		responses: map[string]types.ToolResult{
			"get_user_role":  {Text: `{"role": "viewer"}`},
			"get_user_roles": {Text: `{"roles": ["admin"]}`},
		},
	}

	a := probe.probePair(context.Background(), invoker, toolA, toolB, "name-heuristic")
	require.NotNil(t, a, "all-optional shared params should still produce attempt with empty args")
	require.Len(t, a.Outputs, 2)
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
