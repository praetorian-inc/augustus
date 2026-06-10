package attempt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewToolResultMessage(t *testing.T) {
	msg := NewToolResultMessage("call_abc123", "Search results: AI safety is important")

	assert.Equal(t, RoleTool, msg.Role)
	assert.Equal(t, "call_abc123", msg.ToolCallID)
	assert.Equal(t, "Search results: AI safety is important", msg.Content)
	assert.Nil(t, msg.ToolCalls)
}
