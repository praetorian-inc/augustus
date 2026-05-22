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
