// Package attempt provides core data types for LLM vulnerability scanning.
//
// This package defines the fundamental data structures used throughout Augustus:
// Message, Turn, Conversation, and Attempt. These types mirror garak's attempt
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
)

// Message represents a single message in a conversation.
type Message struct {
	// Role identifies who sent the message.
	Role Role `json:"role"`
	// Content is the text content of the message.
	Content string `json:"content"`
}

// NewMessage creates a new message with the given role and content.
func NewMessage(role Role, content string) Message {
	return Message{
		Role:    role,
		Content: content,
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
