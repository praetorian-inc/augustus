// Package attempt provides core data types for LLM vulnerability scanning.
//
// This package defines the fundamental data structures used throughout Augustus:
// Message, Turn, Conversation, and Attempt. These types represent the core data structures for LLM interaction
// module while following Go idioms.
package attempt

// Role represents the sender of a message in a conversation.
type Role string

const (
	// RoleSystem represents system/instruction messages.
	RoleSystem Role = "system"
	// RoleUser represents user/human messages.
	RoleUser Role = "user"
	// RoleAssistant represents assistant/model messages.
	RoleAssistant Role = "assistant"
	// RoleTool represents a tool result message injected into the conversation.
	// Used for 2-turn tool-result probing where a canned result is sent back
	// to the model after its initial tool call.
	RoleTool Role = "tool"
)

// Message represents a single message in a conversation.
type Message struct {
	// Role identifies who sent the message.
	Role Role `json:"role"`
	// Content is the text content of the message.
	Content string `json:"content"`
	// ToolCalls holds any tool/function calls made by the model in this
	// message, in the canonical detector shape:
	//
	//   []map[string]any{{"name": string, "args": map[string]any}, ...}
	//
	// Generators populate this field when the model returns tool calls.
	// It is nil for text-only responses. Callers (e.g. RunPrompts) copy
	// this into the corresponding attempt's metadata under
	// attempt.MetadataKeyToolCalls.
	ToolCalls []map[string]any `json:"tool_calls,omitempty"`
	// ToolCallID is the ID of the tool call this message is a result for.
	// Only set when Role == RoleTool (injected tool results for 2-turn probing).
	ToolCallID string `json:"tool_call_id,omitempty"`
}

// NewMessage creates a new message with the given role and content.
func NewMessage(role Role, content string) Message {
	return Message{
		Role:    role,
		Content: content,
	}
}

// NewToolResultMessage creates a tool-result message for 2-turn probing.
// The toolCallID must match the ID from the model's prior tool call.
func NewToolResultMessage(toolCallID, content string) Message {
	return Message{
		Role:       RoleTool,
		Content:    content,
		ToolCallID: toolCallID,
	}
}

// NewUserMessage creates a new user message.
func NewUserMessage(content string) Message {
	return NewMessage(RoleUser, content)
}

// NewAssistantMessage creates a new assistant message.
func NewAssistantMessage(content string) Message {
	return NewMessage(RoleAssistant, content)
}

// NewSystemMessage creates a new system message.
func NewSystemMessage(content string) Message {
	return NewMessage(RoleSystem, content)
}
