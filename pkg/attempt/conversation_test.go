package attempt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConversationLastPrompt(t *testing.T) {
	conv := NewConversation()
	conv.AddPrompt("Hello")
	conv.AddTurn(NewTurn("How are you?").WithResponse("Fine"))

	assert.Equal(t, "How are you?", conv.LastPrompt())
}

func TestConversationLastPrompt_Empty(t *testing.T) {
	conv := NewConversation()
	assert.Equal(t, "", conv.LastPrompt())
}

func TestConversationClone(t *testing.T) {
	conv := NewConversation()
	conv.WithSystem("Test system")
	conv.AddPrompt("Hello")
	conv.AddTurn(NewTurn("Question").WithResponse("Answer"))

	cloned := conv.Clone()

	// Modify original
	conv.AddPrompt("Modified")

	// Clone should not be affected
	assert.Equal(t, 2, len(cloned.Turns))
	assert.Equal(t, 3, len(conv.Turns))

	// Verify deep copy of system message
	assert.NotNil(t, cloned.System)
	assert.Equal(t, "Test system", cloned.System.Content)
}

func TestConversationReplaceLastPrompt(t *testing.T) {
	conv := NewConversation()
	conv.AddPrompt("Hello")
	conv.AddTurn(NewTurn("Question").WithResponse("Answer"))
	conv.AddPrompt("Original")

	conv.ReplaceLastPrompt("Replaced")

	assert.Equal(t, "Replaced", conv.LastPrompt())
	assert.Equal(t, 3, len(conv.Turns), "Should still have 3 turns")
}

func TestConversationReplaceLastPrompt_Empty(t *testing.T) {
	conv := NewConversation()

	// Should do nothing when no turns exist
	conv.ReplaceLastPrompt("Test")

	assert.Equal(t, 0, len(conv.Turns))
}
