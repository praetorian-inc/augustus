// Package function provides function-based generators for Augustus.
//
// These generators wrap user-provided functions that generate responses.
// Two variants are supported:
//   - Single: functions that return a single response regardless of n
//   - Multiple: functions that accept n and return n responses
//
// This is designed for programmatic use, not CLI invocation.
package function

import (
	"context"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	generators.Register("function.Single", NewSingle)
	generators.Register("function.Multiple", NewMultiple)
}

// SingleFunc is the signature for single-response generator functions.
// Takes a prompt string and returns a slice of strings (typically with one element).
type SingleFunc func(string) []string

// MultipleFunc is the signature for multiple-response generator functions.
// Takes a prompt string and count n, returns a slice of n strings.
type MultipleFunc func(string, int) []string

// Single is a generator that wraps a user-provided function for single responses.
// The function is called once regardless of the n parameter.
type Single struct {
	fn SingleFunc
}

// NewSingle creates a new Single generator from configuration.
func NewSingle(cfg registry.Config) (generators.Generator, error) {
	// Required: function
	fn, ok := cfg["function"]
	if !ok {
		return nil, fmt.Errorf("function.Single generator requires 'function' configuration")
	}

	// Type-check the function
	typedFn, ok := fn.(func(string) []string)
	if !ok {
		return nil, fmt.Errorf("function.Single: function must have signature func(string) []string")
	}

	return &Single{fn: typedFn}, nil
}

// Generate calls the wrapped function and returns the response.
// The n parameter is ignored (Single does not support multiple generations).
func (s *Single) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	prompt := conv.LastPrompt()
	responses := s.fn(prompt)

	// Handle nil or empty responses
	if len(responses) == 0 {
		return []attempt.Message{attempt.NewAssistantMessage("")}, nil
	}

	// Return first response only (Single doesn't support n>1)
	return []attempt.Message{attempt.NewAssistantMessage(responses[0])}, nil
}

// ClearHistory is a no-op for function generators (stateless).
func (s *Single) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (s *Single) Name() string {
	return "function.Single"
}

// Description returns a human-readable description.
func (s *Single) Description() string {
	return "Function-based generator (single response)"
}

// Multiple is a generator that wraps a user-provided function for multiple responses.
// The function is called with the n parameter and should return n responses.
type Multiple struct {
	fn MultipleFunc
}

// NewMultiple creates a new Multiple generator from configuration.
func NewMultiple(cfg registry.Config) (generators.Generator, error) {
	// Required: function
	fn, ok := cfg["function"]
	if !ok {
		return nil, fmt.Errorf("function.Multiple generator requires 'function' configuration")
	}

	// Type-check the function
	typedFn, ok := fn.(func(string, int) []string)
	if !ok {
		return nil, fmt.Errorf("function.Multiple: function must have signature func(string, int) []string")
	}

	return &Multiple{fn: typedFn}, nil
}

// Generate calls the wrapped function with the n parameter.
func (m *Multiple) Generate(ctx context.Context, conv *attempt.Conversation, n int) ([]attempt.Message, error) {
	if n <= 0 {
		return []attempt.Message{}, nil
	}

	prompt := conv.LastPrompt()
	responses := m.fn(prompt, n)

	// Handle nil responses - return n empty messages
	if responses == nil {
		messages := make([]attempt.Message, n)
		for i := 0; i < n; i++ {
			messages[i] = attempt.NewAssistantMessage("")
		}
		return messages, nil
	}

	// Convert responses to messages
	messages := make([]attempt.Message, len(responses))
	for i, resp := range responses {
		messages[i] = attempt.NewAssistantMessage(resp)
	}

	return messages, nil
}

// ClearHistory is a no-op for function generators (stateless).
func (m *Multiple) ClearHistory() {}

// Name returns the generator's fully qualified name.
func (m *Multiple) Name() string {
	return "function.Multiple"
}

// Description returns a human-readable description.
func (m *Multiple) Description() string {
	return "Function-based generator (multiple responses)"
}
