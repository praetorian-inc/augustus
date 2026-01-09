package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("test.Repeat", NewRepeat)
}

// Repeat is a test generator that echoes the input prompt.
// Useful for testing probes without LLM access.
type Repeat struct {
	prefix string
}

// NewRepeat creates a new Repeat generator.
func NewRepeat(cfg registry.Config) (generators.Generator, error) {
	r := &Repeat{
		prefix: "",
	}

	// Allow custom prefix via config
	if p, ok := cfg["prefix"].(string); ok {
		r.prefix = p
	}

	return r, nil
}

// Generate echoes the last prompt from the conversation.
func (r *Repeat) Generate(_ context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		n = 1
	}

	// Get the last prompt to repeat
	prompt := conv.LastPrompt()
	response := r.prefix + prompt

	responses := make([]attempt.Message, n)
	for i := range responses {
		responses[i] = attempt.NewAssistantMessage(response)
	}

	return responses, nil
}

// ClearHistory is a no-op for Repeat generator.
func (r *Repeat) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (r *Repeat) Name() string {
	return "test.Repeat"
}

// Description returns a human-readable description.
func (r *Repeat) Description() string {
	return "Echoes the input prompt for testing probe behavior"
}
