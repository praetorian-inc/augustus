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

// Clone creates a deep copy of the conversation.
func (c *Conversation) Clone() *Conversation {
	clone := NewConversation()

	if c.System != nil {
		sys := *c.System
		clone.System = &sys
	}

	clone.Turns = make([]Turn, len(c.Turns))
	for i, turn := range c.Turns {
		clone.Turns[i] = Turn{
			Prompt: turn.Prompt,
		}
		if turn.Response != nil {
			resp := *turn.Response
			clone.Turns[i].Response = &resp
		}
	}

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
