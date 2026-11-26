package mcpprobe

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNearNamePairs(t *testing.T) {
	tests := []struct {
		name  string
		tools []map[string]any
		want  []ToolPair
	}{
		{
			name: "singular/plural (DVMCP challenge 5 shape)",
			tools: []map[string]any{
				toolDesc("get_user_role", "username"),
				toolDesc("get_user_roles", "username"),
			},
			want: []ToolPair{{ToolA: "get_user_role", ToolB: "get_user_roles", Method: "name-heuristic"}},
		},
		{
			name: "legitimate scope difference — no shared param",
			tools: []map[string]any{
				toolDesc("list_files", "directory"),
				toolDesc("list_users", "group"),
			},
			want: nil,
		},
		{
			name: "one-token substitution with shared param",
			tools: []map[string]any{
				toolDesc("get_user", "id"),
				toolDesc("get_admin", "id"),
			},
			want: []ToolPair{{ToolA: "get_admin", ToolB: "get_user", Method: "name-heuristic"}},
		},
		{
			name: "qualifier addition with shared param",
			tools: []map[string]any{
				toolDesc("list_files", "path"),
				toolDesc("list_files_recursive", "path"),
			},
			want: []ToolPair{{ToolA: "list_files", ToolB: "list_files_recursive", Method: "name-heuristic"}},
		},
		{
			name: "completely different tools — not paired",
			tools: []map[string]any{
				toolDesc("send_email", "to"),
				toolDesc("read_database", "query"),
			},
			want: nil,
		},
		{
			name: "single tool — not paired with itself",
			tools: []map[string]any{
				toolDesc("get_data", "id"),
			},
			want: nil,
		},
		{
			name: "camelCase pairing",
			tools: []map[string]any{
				toolDescCamel("getUserRole", "username"),
				toolDescCamel("getUserRoles", "username"),
			},
			want: []ToolPair{{ToolA: "getUserRole", ToolB: "getUserRoles", Method: "name-heuristic"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NearNamePairs(tt.tools)
			if tt.want == nil {
				assert.Empty(t, got)
				return
			}
			require.Len(t, got, len(tt.want))
			for i := range got {
				assert.Equal(t, tt.want[i].ToolA, got[i].ToolA)
				assert.Equal(t, tt.want[i].ToolB, got[i].ToolB)
				assert.Equal(t, tt.want[i].Method, got[i].Method)
			}
		})
	}
}

func TestNameTokens(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"underscore", "get_user_role", []string{"get", "user", "role"}},
		{"camelCase", "getUserRole", []string{"get", "user", "role"}},
		{"mixed", "get_userRole", []string{"get", "user", "role"}},
		{"dots", "api.get.user", []string{"api", "get", "user"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nameTokens(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseSemanticPairs(t *testing.T) {
	tools := []map[string]any{
		{"name": "get_role"},
		{"name": "fetch_permissions"},
		{"name": "unrelated"},
	}
	text := `[{"a":"get_role","b":"fetch_permissions"}]`
	got := parseSemanticPairs(text, tools, map[string]bool{})
	require.Len(t, got, 1)
	assert.Equal(t, "fetch_permissions", got[0].ToolA)
	assert.Equal(t, "get_role", got[0].ToolB)
	assert.Equal(t, "llm-semantic", got[0].Method)
}

func TestParseSemanticPairs_SkipExisting(t *testing.T) {
	tools := []map[string]any{{"name": "a"}, {"name": "b"}}
	text := `[{"a":"a","b":"b"}]`
	skip := map[string]bool{"a\x00b": true}
	got := parseSemanticPairs(text, tools, skip)
	assert.Empty(t, got)
}

func TestParseSemanticPairs_InvalidTool(t *testing.T) {
	tools := []map[string]any{{"name": "real_tool"}}
	text := `[{"a":"real_tool","b":"hallucinated_tool"}]`
	got := parseSemanticPairs(text, tools, map[string]bool{})
	assert.Empty(t, got)
}

func TestParseSemanticPairs_MalformedJSON(t *testing.T) {
	tools := []map[string]any{{"name": "a"}, {"name": "b"}}
	text := `not json at all`
	got := parseSemanticPairs(text, tools, map[string]bool{})
	assert.Empty(t, got)
}

func toolDesc(name, paramName string) map[string]any {
	return map[string]any{
		"name": name,
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				paramName: map[string]any{"type": "string"},
			},
			"required": []any{paramName},
		},
	}
}

func toolDescCamel(name, paramName string) map[string]any {
	return toolDesc(name, paramName)
}
