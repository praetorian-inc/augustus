// Package testutil provides shared test utilities for Augustus probe and generator tests.
package testutil

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// MockGenerator implements types.Generator for testing. It returns pre-configured
// responses and tracks how many times Generate was called.
type MockGenerator struct {
	// Responses are returned as message content, cycling through the slice.
	Responses []string
	// Calls tracks how many times Generate has been called.
	Calls int
	// GenName is the name returned by Name(). Defaults to "mock-generator".
	GenName string
}

// NewMockGenerator creates a MockGenerator that returns the given responses.
func NewMockGenerator(responses ...string) *MockGenerator {
	return &MockGenerator{
		Responses: responses,
		GenName:   "mock-generator",
	}
}

// Generate returns attempt.Messages built from the Responses slice.
func (m *MockGenerator) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	m.Calls++
	msgs := make([]attempt.Message, n)
	for i := 0; i < n; i++ {
		resp := ""
		if i < len(m.Responses) {
			resp = m.Responses[i]
		}
		msgs[i] = attempt.Message{Content: resp}
	}
	return msgs, nil
}

// ClearHistory is a no-op for testing.
func (m *MockGenerator) ClearHistory() {}

// Name returns the generator name.
func (m *MockGenerator) Name() string {
	if m.GenName == "" {
		return "mock-generator"
	}
	return m.GenName
}

// Description returns a static description.
func (m *MockGenerator) Description() string {
	return "mock generator for testing"
}
