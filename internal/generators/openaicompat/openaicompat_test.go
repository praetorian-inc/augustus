package openaicompat

import (
	"testing"

	goopenai "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// ---------------------------------------------------------------------------
// Group 5: ConversationToMessages Handles Tool Role Messages
// ---------------------------------------------------------------------------

func TestConversationToMessages_ToolResultMessage(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPrompt("Search for AI safety")

	// Simulate Turn 1 response with tool calls
	turn1Resp := attempt.NewAssistantMessage("")
	turn1Resp.ToolCalls = []map[string]any{
		{"name": "web_search", "id": "call_abc", "args": map[string]any{"query": "AI safety"}},
	}
	conv.Turns[0].Response = &turn1Resp

	// Add tool result as Turn 2
	toolResult := attempt.NewToolResultMessage("call_abc", "Results: AI safety is important")
	conv.AddTurn(attempt.Turn{Prompt: toolResult})

	messages := ConversationToMessages(conv)

	// Expected: user, assistant (with tool_calls), tool
	require.Len(t, messages, 3)
	assert.Equal(t, "user", messages[0].Role)
	assert.Equal(t, "assistant", messages[1].Role)
	require.Len(t, messages[1].ToolCalls, 1)
	assert.Equal(t, "call_abc", messages[1].ToolCalls[0].ID)
	assert.Equal(t, "tool", messages[2].Role)
	assert.Equal(t, "call_abc", messages[2].ToolCallID)
	assert.Equal(t, "Results: AI safety is important", messages[2].Content)
}

func TestConversationToMessages_AssistantWithToolCalls(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPrompt("Search")

	turn1Resp := attempt.NewAssistantMessage("Searching...")
	turn1Resp.ToolCalls = []map[string]any{
		{"name": "web_search", "id": "call_123", "args": map[string]any{"q": "test"}},
	}
	conv.Turns[0].Response = &turn1Resp

	messages := ConversationToMessages(conv)

	require.Len(t, messages, 2)
	assert.Equal(t, "assistant", messages[1].Role)
	require.Len(t, messages[1].ToolCalls, 1)
	assert.Equal(t, "call_123", messages[1].ToolCalls[0].ID)
	assert.Equal(t, "web_search", messages[1].ToolCalls[0].Function.Name)
}

// ---------------------------------------------------------------------------
// Group 6: canonicalToOpenAIToolCalls Reverse Conversion
// ---------------------------------------------------------------------------

func TestCanonicalToOpenAIToolCalls_Basic(t *testing.T) {
	canonical := []map[string]any{
		{"name": "web_search", "id": "call_abc", "args": map[string]any{"query": "test"}},
	}

	result := canonicalToOpenAIToolCalls(canonical)

	require.Len(t, result, 1)
	assert.Equal(t, "call_abc", result[0].ID)
	assert.Equal(t, goopenai.ToolTypeFunction, result[0].Type)
	assert.Equal(t, "web_search", result[0].Function.Name)
	assert.Contains(t, result[0].Function.Arguments, `"query"`)
	assert.Contains(t, result[0].Function.Arguments, `"test"`)
}

func TestCanonicalToOpenAIToolCalls_MissingID(t *testing.T) {
	canonical := []map[string]any{
		{"name": "web_search", "args": map[string]any{"query": "test"}},
		// No "id" key
	}

	result := canonicalToOpenAIToolCalls(canonical)

	require.Len(t, result, 1)
	assert.Equal(t, "call_web_search", result[0].ID, "missing id should get call_ prefix")
}

func TestCanonicalToOpenAIToolCalls_NilArgs(t *testing.T) {
	canonical := []map[string]any{
		{"name": "noop", "id": "call_1"},
		// No "args" key
	}

	result := canonicalToOpenAIToolCalls(canonical)

	require.Len(t, result, 1)
	// json.Marshal(nil) produces "null"
	assert.Equal(t, "null", result[0].Function.Arguments)
}
