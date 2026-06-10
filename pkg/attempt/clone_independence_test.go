package attempt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConversationClone_ToolsMapIndependence(t *testing.T) {
	conv := NewConversation()
	conv.Tools = []map[string]any{
		{"name": "web_search", "description": "search"},
	}

	cloned := conv.Clone()
	cloned.Tools[0]["name"] = "MUTATED"

	assert.Equal(t, "web_search", conv.Tools[0]["name"])
}

func TestConversationClone_ToolCallsIndependence(t *testing.T) {
	conv := NewConversation()
	resp := Message{
		Role:      RoleAssistant,
		ToolCalls: []map[string]any{{"name": "web_search", "id": "call_123"}},
	}
	conv.AddTurn(Turn{
		Prompt:   Message{Role: RoleUser, Content: "test"},
		Response: &resp,
	})

	cloned := conv.Clone()
	cloned.Turns[0].Response.ToolCalls[0]["name"] = "MUTATED"

	assert.Equal(t, "web_search", conv.Turns[0].Response.ToolCalls[0]["name"])
}

// TestConversationClone_NestedArgsIndependence is a regression test for the
// deepCopyValue fix (Fix 3). Before the fix, deepCopyToolCalls shallow-copied
// each top-level tool-call map, meaning the nested "args" map[string]any was
// shared between source and clone. Mutating clone's args therefore mutated the
// source. The fix introduced deepCopyValue which recursively copies map[string]any
// and []any values so clones are fully independent.
func TestConversationClone_NestedArgsIndependence(t *testing.T) {
	conv := NewConversation()
	resp := Message{
		Role: RoleAssistant,
		ToolCalls: []map[string]any{
			{"name": "read_file", "args": map[string]any{"x": "original"}},
		},
	}
	conv.AddTurn(Turn{
		Prompt:   Message{Role: RoleUser, Content: "test"},
		Response: &resp,
	})

	cloned := conv.Clone()
	cloned.Turns[0].Response.ToolCalls[0]["args"].(map[string]any)["x"] = "MUTATED"

	assert.Equal(t, "original",
		conv.Turns[0].Response.ToolCalls[0]["args"].(map[string]any)["x"],
		"mutating clone's nested args must not affect source conversation",
	)
}
