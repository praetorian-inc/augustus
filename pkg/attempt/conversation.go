package attempt

// Turn represents a single exchange in a conversation (prompt + response).
type Turn struct {
	// Prompt is the user's input message.
	Prompt Message `json:"prompt"`
	// Response is the assistant's output message (may be empty if pending).
	Response *Message `json:"response,omitempty"`
}

// NewTurn creates a new turn with a user prompt.
func NewTurn(prompt string) Turn {
	return Turn{
		Prompt: NewUserMessage(prompt),
	}
}

// WithResponse returns a new turn with the response set.
func (t Turn) WithResponse(response string) Turn {
	resp := NewAssistantMessage(response)
	return Turn{
		Prompt:   t.Prompt,
		Response: &resp,
	}
}

// Conversation represents a multi-turn dialogue.
type Conversation struct {
	// System is the optional system prompt.
	System *Message `json:"system,omitempty"`
	// Turns contains the sequence of exchanges.
	Turns []Turn `json:"turns"`
	// Tools holds tool schemas for native function calling.
	// Generators translate these to provider-specific wire formats.
	Tools []map[string]any `json:"tools,omitempty"`
	// ToolChoice controls tool selection behavior ("auto", "required", "none", or tool name).
	ToolChoice string `json:"tool_choice,omitempty"`
}

// NewConversation creates an empty conversation.
func NewConversation() *Conversation {
	return &Conversation{
		Turns: make([]Turn, 0),
	}
}

// WithSystem sets the system prompt and returns the conversation.
func (c *Conversation) WithSystem(system string) *Conversation {
	msg := NewSystemMessage(system)
	c.System = &msg
	return c
}

// AddTurn appends a turn to the conversation.
func (c *Conversation) AddTurn(turn Turn) {
	c.Turns = append(c.Turns, turn)
}

// AddPrompt adds a new user prompt as a turn.
func (c *Conversation) AddPrompt(prompt string) {
	c.AddTurn(NewTurn(prompt))
}

// ToMessages flattens the conversation to a slice of messages.
// This is useful for APIs that expect a flat message list.
func (c *Conversation) ToMessages() []Message {
	messages := make([]Message, 0, len(c.Turns)*2+1)

	if c.System != nil {
		messages = append(messages, *c.System)
	}

	for _, turn := range c.Turns {
		messages = append(messages, turn.Prompt)
		if turn.Response != nil {
			messages = append(messages, *turn.Response)
		}
	}

	return messages
}

// LastPrompt returns the last user prompt, or empty string if none.
func (c *Conversation) LastPrompt() string {
	if len(c.Turns) == 0 {
		return ""
	}
	return c.Turns[len(c.Turns)-1].Prompt.Content
}

// deepCopyValue recursively deep-copies a value that may be a map[string]any,
// []any, or a scalar. Scalars are returned as-is (they are immutable or
// value-typed in Go). This is used by deepCopyToolCalls to prevent cloned
// conversations from sharing nested "args" maps with their source.
func deepCopyValue(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(val))
		for k, vv := range val {
			out[k] = deepCopyValue(vv)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, vv := range val {
			out[i] = deepCopyValue(vv)
		}
		return out
	default:
		// Scalar types (string, int, float64, bool, nil, etc.) are safe to share.
		return v
	}
}

// deepCopyToolCalls creates an independent deep copy of a tool calls slice.
// Nested values (e.g. the "args" map[string]any) are recursively copied so
// that mutating a clone's tool call args does not affect the source.
func deepCopyToolCalls(tcs []map[string]any) []map[string]any {
	if len(tcs) == 0 {
		return tcs
	}
	out := make([]map[string]any, len(tcs))
	for i, tc := range tcs {
		if tc == nil {
			continue
		}
		tcCopy := make(map[string]any, len(tc))
		for k, v := range tc {
			tcCopy[k] = deepCopyValue(v)
		}
		out[i] = tcCopy
	}
	return out
}

// Clone creates a deep copy of the conversation.
func (c *Conversation) Clone() *Conversation {
	clone := NewConversation()

	if c.System != nil {
		sys := *c.System
		clone.System = &sys
	}

	clone.Turns = make([]Turn, len(c.Turns))
	for i, turn := range c.Turns {
		prompt := turn.Prompt
		prompt.ToolCalls = deepCopyToolCalls(turn.Prompt.ToolCalls)
		clone.Turns[i] = Turn{
			Prompt: prompt,
		}
		if turn.Response != nil {
			resp := *turn.Response
			resp.ToolCalls = deepCopyToolCalls(turn.Response.ToolCalls)
			clone.Turns[i].Response = &resp
		}
	}

	if len(c.Tools) > 0 {
		clone.Tools = make([]map[string]any, len(c.Tools))
		for i, tool := range c.Tools {
			if tool == nil {
				continue
			}
			toolCopy := make(map[string]any, len(tool))
			for k, v := range tool {
				// One-level deep copy is sufficient for tool definitions.
				// Nested values (like parameters map) are read-only in practice.
				toolCopy[k] = v
			}
			clone.Tools[i] = toolCopy
		}
	}
	clone.ToolChoice = c.ToolChoice

	return clone
}

// ReplaceLastPrompt replaces the content of the last turn's prompt.
// Does nothing if there are no turns.
func (c *Conversation) ReplaceLastPrompt(content string) {
	if len(c.Turns) == 0 {
		return
	}
	lastIdx := len(c.Turns) - 1
	c.Turns[lastIdx].Prompt.Content = content
}
