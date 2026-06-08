package attackengine

import (
	"encoding/json"
	"testing"

	goopenai "github.com/sashabaranov/go-openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// NormalizeOpenAIToolCalls
// ---------------------------------------------------------------------------

func TestNormalizeOpenAIToolCalls_SingleValidCall(t *testing.T) {
	tc := goopenai.ToolCall{
		Type: goopenai.ToolTypeFunction,
		Function: goopenai.FunctionCall{
			Name:      "send_email",
			Arguments: `{"to":"user@example.com","subject":"hello"}`,
		},
	}

	got := NormalizeOpenAIToolCalls([]goopenai.ToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "send_email", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok, "args should be map[string]any")
	assert.Equal(t, "user@example.com", args["to"])
	assert.Equal(t, "hello", args["subject"])
}

func TestNormalizeOpenAIToolCalls_MultipleValidCalls(t *testing.T) {
	calls := []goopenai.ToolCall{
		{Function: goopenai.FunctionCall{Name: "read_file", Arguments: `{"path":"/etc/hosts"}`}},
		{Function: goopenai.FunctionCall{Name: "write_file", Arguments: `{"path":"/tmp/out","content":"data"}`}},
	}

	got := NormalizeOpenAIToolCalls(calls)

	require.Len(t, got, 2)
	assert.Equal(t, "read_file", got[0]["name"])
	assert.Equal(t, "write_file", got[1]["name"])
}

func TestNormalizeOpenAIToolCalls_EmptyInput(t *testing.T) {
	got := NormalizeOpenAIToolCalls([]goopenai.ToolCall{})
	assert.Nil(t, got, "empty input should return nil")
}

func TestNormalizeOpenAIToolCalls_NilInput(t *testing.T) {
	got := NormalizeOpenAIToolCalls(nil)
	assert.Nil(t, got, "nil input should return nil")
}

func TestNormalizeOpenAIToolCalls_MalformedArgumentsSkipsCall(t *testing.T) {
	const rawMalformed = `{not valid json`
	calls := []goopenai.ToolCall{
		{Function: goopenai.FunctionCall{Name: "good_tool", Arguments: `{"key":"value"}`}},
		{Function: goopenai.FunctionCall{Name: "bad_tool", Arguments: rawMalformed}},
	}

	// Should not panic; the malformed call must have an empty "args" map and
	// the raw string preserved under "_raw_args" so detector regex chains can
	// still inspect the payload.
	got := NormalizeOpenAIToolCalls(calls)

	require.Len(t, got, 2, "malformed args should produce empty-args entry, not be skipped entirely")
	assert.Equal(t, "good_tool", got[0]["name"])
	goodArgs, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", goodArgs["key"])

	assert.Equal(t, "bad_tool", got[1]["name"])
	badArgs, ok := got[1]["args"].(map[string]any)
	require.True(t, ok, "malformed args should yield empty map[string]any, not nil")
	assert.Empty(t, badArgs, "malformed args map should be empty")
	assert.Equal(t, rawMalformed, got[1]["_raw_args"], "_raw_args sentinel must equal the original raw string")
}

func TestNormalizeOpenAIToolCalls_EmptyFunctionNameSkipped(t *testing.T) {
	calls := []goopenai.ToolCall{
		{Function: goopenai.FunctionCall{Name: "", Arguments: `{"key":"value"}`}},
		{Function: goopenai.FunctionCall{Name: "legit_tool", Arguments: `{}`}},
	}

	got := NormalizeOpenAIToolCalls(calls)

	require.Len(t, got, 1, "call with empty name should be skipped")
	assert.Equal(t, "legit_tool", got[0]["name"])
}

func TestNormalizeOpenAIToolCalls_AllEmptyNamesReturnsNil(t *testing.T) {
	calls := []goopenai.ToolCall{
		{Function: goopenai.FunctionCall{Name: "", Arguments: `{"key":"value"}`}},
	}

	got := NormalizeOpenAIToolCalls(calls)
	assert.Nil(t, got, "all-skipped slice should return nil")
}

func TestNormalizeOpenAIToolCalls_EmptyArguments(t *testing.T) {
	tc := goopenai.ToolCall{
		Function: goopenai.FunctionCall{
			Name:      "noop",
			Arguments: "",
		},
	}

	got := NormalizeOpenAIToolCalls([]goopenai.ToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "noop", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, args, "empty arguments string should yield empty args map")
}

// ---------------------------------------------------------------------------
// NormalizeAnthropicToolUseBlocks
// ---------------------------------------------------------------------------

func TestNormalizeAnthropicToolUseBlocks_MixedBlockTypes(t *testing.T) {
	textBlock := AnthropicToolUseBlock{Type: "text", Name: "", Input: json.RawMessage(`null`)}
	toolBlock := AnthropicToolUseBlock{
		Type:  "tool_use",
		ID:    "call_1",
		Name:  "search",
		Input: json.RawMessage(`{"query":"exfil"}`),
	}

	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{textBlock, toolBlock})

	require.Len(t, got, 1, "only tool_use blocks should be included")
	assert.Equal(t, "search", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "exfil", args["query"])
}

func TestNormalizeAnthropicToolUseBlocks_SingleToolUse(t *testing.T) {
	block := AnthropicToolUseBlock{
		Type:  "tool_use",
		ID:    "call_abc",
		Name:  "list_dir",
		Input: json.RawMessage(`{"path":"/home/user"}`),
	}

	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{block})

	require.Len(t, got, 1)
	assert.Equal(t, "list_dir", got[0]["name"])
	args := got[0]["args"].(map[string]any)
	assert.Equal(t, "/home/user", args["path"])
}

func TestNormalizeAnthropicToolUseBlocks_MultipleToolUseBlocks(t *testing.T) {
	blocks := []AnthropicToolUseBlock{
		{Type: "tool_use", Name: "read_file", Input: json.RawMessage(`{"path":"/etc/passwd"}`)},
		{Type: "tool_use", Name: "send_data", Input: json.RawMessage(`{"dest":"attacker.example.com"}`)},
	}

	got := NormalizeAnthropicToolUseBlocks(blocks)

	require.Len(t, got, 2)
	assert.Equal(t, "read_file", got[0]["name"])
	assert.Equal(t, "send_data", got[1]["name"])
}

func TestNormalizeAnthropicToolUseBlocks_EmptyInput(t *testing.T) {
	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{})
	assert.Nil(t, got, "empty input should return nil")
}

func TestNormalizeAnthropicToolUseBlocks_NilInput(t *testing.T) {
	got := NormalizeAnthropicToolUseBlocks(nil)
	assert.Nil(t, got, "nil input should return nil")
}

func TestNormalizeAnthropicToolUseBlocks_EmptyNameSkipped(t *testing.T) {
	blocks := []AnthropicToolUseBlock{
		{Type: "tool_use", Name: "", Input: json.RawMessage(`{"key":"val"}`)},
		{Type: "tool_use", Name: "valid_tool", Input: json.RawMessage(`{}`)},
	}

	got := NormalizeAnthropicToolUseBlocks(blocks)

	require.Len(t, got, 1, "tool_use block with empty name should be skipped")
	assert.Equal(t, "valid_tool", got[0]["name"])
}

func TestNormalizeAnthropicToolUseBlocks_MalformedInput(t *testing.T) {
	const rawMalformed = `{invalid`
	// json.RawMessage that is not a valid JSON object must not panic; "args"
	// must be an empty map and the raw bytes preserved under "_raw_args" so
	// that detector regex chains can still inspect the payload.
	block := AnthropicToolUseBlock{
		Type:  "tool_use",
		Name:  "broken",
		Input: json.RawMessage(rawMalformed),
	}

	require.NotPanics(t, func() {
		got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{block})
		require.Len(t, got, 1, "malformed input should still produce an entry")
		args, ok := got[0]["args"].(map[string]any)
		require.True(t, ok)
		assert.Empty(t, args, "malformed input should yield empty args map")
		assert.Equal(t, rawMalformed, got[0]["_raw_args"], "_raw_args sentinel must equal the original raw bytes as string")
	})
}

func TestNormalizeAnthropicToolUseBlocks_AllTextBlocksReturnsNil(t *testing.T) {
	blocks := []AnthropicToolUseBlock{
		{Type: "text", Name: "irrelevant"},
	}

	got := NormalizeAnthropicToolUseBlocks(blocks)
	assert.Nil(t, got, "no tool_use blocks should return nil")
}

func TestNormalizeAnthropicToolUseBlocks_NullInput(t *testing.T) {
	block := AnthropicToolUseBlock{
		Type:  "tool_use",
		Name:  "empty_args_tool",
		Input: json.RawMessage(`null`),
	}

	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{block})

	require.Len(t, got, 1)
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, args, "null Input should yield empty args map")
}

// ---------------------------------------------------------------------------
// Group 8: ID Preservation in Normalizers
// ---------------------------------------------------------------------------

func TestNormalizeOpenAIToolCalls_PreservesID(t *testing.T) {
	tc := goopenai.ToolCall{
		ID:   "call_abc123",
		Type: goopenai.ToolTypeFunction,
		Function: goopenai.FunctionCall{
			Name:      "web_search",
			Arguments: `{"query":"test"}`,
		},
	}

	got := NormalizeOpenAIToolCalls([]goopenai.ToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "call_abc123", got[0]["id"])
}

func TestNormalizeOpenAIToolCalls_OmitsEmptyID(t *testing.T) {
	tc := goopenai.ToolCall{
		// ID is empty string
		Function: goopenai.FunctionCall{
			Name:      "web_search",
			Arguments: `{"query":"test"}`,
		},
	}

	got := NormalizeOpenAIToolCalls([]goopenai.ToolCall{tc})

	require.Len(t, got, 1)
	_, hasID := got[0]["id"]
	assert.False(t, hasID, "empty ID should not be present in canonical form")
}

func TestNormalizeAnthropicToolUseBlocks_PreservesID(t *testing.T) {
	block := AnthropicToolUseBlock{
		Type:  "tool_use",
		ID:    "toolu_xyz789",
		Name:  "web_search",
		Input: json.RawMessage(`{"query":"test"}`),
	}

	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{block})

	require.Len(t, got, 1)
	assert.Equal(t, "toolu_xyz789", got[0]["id"])
}

func TestNormalizeAnthropicToolUseBlocks_OmitsEmptyID(t *testing.T) {
	block := AnthropicToolUseBlock{
		Type: "tool_use",
		// ID empty
		Name:  "web_search",
		Input: json.RawMessage(`{}`),
	}

	got := NormalizeAnthropicToolUseBlocks([]AnthropicToolUseBlock{block})

	require.Len(t, got, 1)
	_, hasID := got[0]["id"]
	assert.False(t, hasID, "empty ID should not be present")
}

// ---------------------------------------------------------------------------
// NormalizeGeminiFunctionCalls
// ---------------------------------------------------------------------------

func TestNormalizeGeminiFunctionCalls_SingleValidCall(t *testing.T) {
	fc := GeminiFunctionCall{
		Name: "send_email",
		Args: map[string]any{"to": "user@example.com", "subject": "hello"},
	}

	got := NormalizeGeminiFunctionCalls([]GeminiFunctionCall{fc})

	require.Len(t, got, 1)
	assert.Equal(t, "send_email", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok, "args should be map[string]any")
	assert.Equal(t, "user@example.com", args["to"])
	assert.Equal(t, "hello", args["subject"])
}

func TestNormalizeGeminiFunctionCalls_MultipleValidCalls(t *testing.T) {
	calls := []GeminiFunctionCall{
		{Name: "read_file", Args: map[string]any{"path": "/etc/hosts"}},
		{Name: "write_file", Args: map[string]any{"path": "/tmp/out", "content": "data"}},
	}

	got := NormalizeGeminiFunctionCalls(calls)

	require.Len(t, got, 2)
	assert.Equal(t, "read_file", got[0]["name"])
	assert.Equal(t, "write_file", got[1]["name"])
}

func TestNormalizeGeminiFunctionCalls_EmptyInput(t *testing.T) {
	got := NormalizeGeminiFunctionCalls([]GeminiFunctionCall{})
	assert.Nil(t, got, "empty input should return nil")
}

func TestNormalizeGeminiFunctionCalls_NilInput(t *testing.T) {
	got := NormalizeGeminiFunctionCalls(nil)
	assert.Nil(t, got, "nil input should return nil")
}

func TestNormalizeGeminiFunctionCalls_EmptyNameSkipped(t *testing.T) {
	calls := []GeminiFunctionCall{
		{Name: "", Args: map[string]any{"key": "value"}},
		{Name: "legit_tool", Args: map[string]any{}},
	}

	got := NormalizeGeminiFunctionCalls(calls)

	require.Len(t, got, 1, "call with empty name should be skipped")
	assert.Equal(t, "legit_tool", got[0]["name"])
}

func TestNormalizeGeminiFunctionCalls_AllEmptyNamesReturnsNil(t *testing.T) {
	calls := []GeminiFunctionCall{
		{Name: "", Args: map[string]any{"key": "value"}},
	}

	got := NormalizeGeminiFunctionCalls(calls)
	assert.Nil(t, got, "all-skipped slice should return nil")
}

func TestNormalizeGeminiFunctionCalls_NilArgs(t *testing.T) {
	fc := GeminiFunctionCall{
		Name: "noop",
		Args: nil,
	}

	got := NormalizeGeminiFunctionCalls([]GeminiFunctionCall{fc})

	require.Len(t, got, 1)
	assert.Equal(t, "noop", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok, "nil args should yield map[string]any")
	assert.Empty(t, args, "nil args should yield empty args map")
}

func TestNormalizeGeminiFunctionCalls_IDEqualsName(t *testing.T) {
	// NormalizeGeminiFunctionCalls sets "id" to the bare function name so that
	// the Vertex serialization path (conversationToContents) can use ToolCallID
	// directly as functionResponse.name, satisfying Gemini's requirement that
	// functionResponse.name == functionCall.name. Without this, RunTwoTurnPrompts
	// would fall back to "call_"+name which Gemini rejects.
	fc := GeminiFunctionCall{
		Name: "search",
		Args: map[string]any{"query": "exfil"},
	}

	got := NormalizeGeminiFunctionCalls([]GeminiFunctionCall{fc})

	require.Len(t, got, 1)
	id, hasID := got[0]["id"]
	require.True(t, hasID, "Gemini normalized entries must carry id=name for Vertex tool-result routing")
	assert.Equal(t, "search", id, "id must equal the bare function name")
}

// ---------------------------------------------------------------------------
// NormalizeCohereToolCalls
// ---------------------------------------------------------------------------

func TestNormalizeCohereToolCalls_SingleValidCall(t *testing.T) {
	tc := CohereToolCall{
		ID:   "call_abc123",
		Type: "function",
		Function: CohereToolFunction{
			Name:      "send_email",
			Arguments: `{"to":"user@example.com","subject":"hello"}`,
		},
	}

	got := NormalizeCohereToolCalls([]CohereToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "send_email", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok, "args should be map[string]any")
	assert.Equal(t, "user@example.com", args["to"])
	assert.Equal(t, "hello", args["subject"])
}

func TestNormalizeCohereToolCalls_MultipleValidCalls(t *testing.T) {
	calls := []CohereToolCall{
		{Function: CohereToolFunction{Name: "read_file", Arguments: `{"path":"/etc/hosts"}`}},
		{Function: CohereToolFunction{Name: "write_file", Arguments: `{"path":"/tmp/out","content":"data"}`}},
	}

	got := NormalizeCohereToolCalls(calls)

	require.Len(t, got, 2)
	assert.Equal(t, "read_file", got[0]["name"])
	assert.Equal(t, "write_file", got[1]["name"])
}

func TestNormalizeCohereToolCalls_EmptyInput(t *testing.T) {
	got := NormalizeCohereToolCalls([]CohereToolCall{})
	assert.Nil(t, got, "empty input should return nil")
}

func TestNormalizeCohereToolCalls_NilInput(t *testing.T) {
	got := NormalizeCohereToolCalls(nil)
	assert.Nil(t, got, "nil input should return nil")
}

func TestNormalizeCohereToolCalls_MalformedArguments(t *testing.T) {
	const rawMalformed = `{not valid json`
	calls := []CohereToolCall{
		{Function: CohereToolFunction{Name: "good_tool", Arguments: `{"key":"value"}`}},
		{Function: CohereToolFunction{Name: "bad_tool", Arguments: rawMalformed}},
	}

	// Should not panic; the malformed call must have an empty "args" map and
	// the raw string preserved under "_raw_args" so detector regex chains can
	// still inspect the payload.
	got := NormalizeCohereToolCalls(calls)

	require.Len(t, got, 2, "malformed args should produce empty-args entry, not be skipped entirely")
	assert.Equal(t, "good_tool", got[0]["name"])
	goodArgs, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "value", goodArgs["key"])

	assert.Equal(t, "bad_tool", got[1]["name"])
	badArgs, ok := got[1]["args"].(map[string]any)
	require.True(t, ok, "malformed args should yield empty map[string]any, not nil")
	assert.Empty(t, badArgs, "malformed args map should be empty")
	assert.Equal(t, rawMalformed, got[1]["_raw_args"], "_raw_args sentinel must equal the original raw string")
}

func TestNormalizeCohereToolCalls_EmptyFunctionNameSkipped(t *testing.T) {
	calls := []CohereToolCall{
		{Function: CohereToolFunction{Name: "", Arguments: `{"key":"value"}`}},
		{Function: CohereToolFunction{Name: "legit_tool", Arguments: `{}`}},
	}

	got := NormalizeCohereToolCalls(calls)

	require.Len(t, got, 1, "call with empty name should be skipped")
	assert.Equal(t, "legit_tool", got[0]["name"])
}

func TestNormalizeCohereToolCalls_EmptyArguments(t *testing.T) {
	tc := CohereToolCall{
		Function: CohereToolFunction{
			Name:      "noop",
			Arguments: "",
		},
	}

	got := NormalizeCohereToolCalls([]CohereToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "noop", got[0]["name"])
	args, ok := got[0]["args"].(map[string]any)
	require.True(t, ok)
	assert.Empty(t, args, "empty arguments string should yield empty args map")
}

func TestNormalizeCohereToolCalls_PreservesID(t *testing.T) {
	tc := CohereToolCall{
		ID:   "call_xyz789",
		Type: "function",
		Function: CohereToolFunction{
			Name:      "web_search",
			Arguments: `{"query":"test"}`,
		},
	}

	got := NormalizeCohereToolCalls([]CohereToolCall{tc})

	require.Len(t, got, 1)
	assert.Equal(t, "call_xyz789", got[0]["id"])
}

func TestNormalizeCohereToolCalls_OmitsEmptyID(t *testing.T) {
	tc := CohereToolCall{
		// ID is empty string
		Function: CohereToolFunction{
			Name:      "web_search",
			Arguments: `{"query":"test"}`,
		},
	}

	got := NormalizeCohereToolCalls([]CohereToolCall{tc})

	require.Len(t, got, 1)
	_, hasID := got[0]["id"]
	assert.False(t, hasID, "empty ID should not be present in canonical form")
}

func TestNormalizeCohereToolCalls_AllEmptyNamesReturnsNil(t *testing.T) {
	calls := []CohereToolCall{
		{Function: CohereToolFunction{Name: "", Arguments: `{"key":"value"}`}},
	}
	got := NormalizeCohereToolCalls(calls)
	assert.Nil(t, got, "all-skipped slice should return nil")
}
