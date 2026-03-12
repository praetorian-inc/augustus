package parsers

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockGenerator is a test double for types.Generator
type mockGenerator struct {
	messages []attempt.Message
	err      error
}

func (m *mockGenerator) Generate(_ context.Context, _ *attempt.Conversation, n int) ([]attempt.Message, error) {
	if m.err != nil {
		return nil, m.err
	}
	if n > len(m.messages) {
		n = len(m.messages)
	}
	return m.messages[:n], nil
}

func (m *mockGenerator) ClearHistory()       {}
func (m *mockGenerator) Name() string        { return "mock.Generator" }
func (m *mockGenerator) Description() string { return "Mock generator for testing" }

// mockParser is a test double for types.Parser
type mockParser struct {
	transform func(string) string
	err       error
}

func (m *mockParser) Parse(_ context.Context, raw []byte, _ string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.transform != nil {
		return m.transform(string(raw)), nil
	}
	return string(raw), nil
}

func (m *mockParser) Name() string        { return "mock.Parser" }
func (m *mockParser) Description() string { return "Mock parser for testing" }

func TestNewParsedGenerator(t *testing.T) {
	gen := &mockGenerator{}
	parser := &mockParser{}

	pg := NewParsedGenerator(gen, parser)
	if pg == nil {
		t.Fatal("NewParsedGenerator returned nil")
	}
	if pg.Inner() != gen {
		t.Error("Inner() did not return the wrapped generator")
	}
	if pg.Parser() != parser {
		t.Error("Parser() did not return the parser")
	}
}

func TestParsedGenerator_Generate(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		messages   []attempt.Message
		transform  func(string) string
		wantOutput string
	}{
		{
			name: "passthrough",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "Hello, world!"},
			},
			transform:  nil, // no transformation
			wantOutput: "Hello, world!",
		},
		{
			name: "uppercase transformation",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "hello"},
			},
			transform: func(s string) string {
				return "PARSED: " + s
			},
			wantOutput: "PARSED: hello",
		},
		{
			name: "multiple messages",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "first"},
				{Role: attempt.RoleAssistant, Content: "second"},
			},
			transform: func(s string) string {
				return "[" + s + "]"
			},
			wantOutput: "[first]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &mockGenerator{messages: tt.messages}
			parser := &mockParser{transform: tt.transform}
			pg := NewParsedGenerator(gen, parser)

			conv := attempt.NewConversation()
			messages, err := pg.Generate(ctx, conv, 1)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			if len(messages) == 0 {
				t.Fatal("Generate returned no messages")
			}
			if messages[0].Content != tt.wantOutput {
				t.Errorf("Content = %q, want %q", messages[0].Content, tt.wantOutput)
			}
		})
	}
}

func TestParsedGenerator_GenerateError(t *testing.T) {
	ctx := context.Background()

	t.Run("generator error", func(t *testing.T) {
		gen := &mockGenerator{err: context.DeadlineExceeded}
		parser := &mockParser{}
		pg := NewParsedGenerator(gen, parser)

		conv := attempt.NewConversation()
		_, err := pg.Generate(ctx, conv, 1)
		if err == nil {
			t.Error("Expected error from generator")
		}
	})

	t.Run("parser error", func(t *testing.T) {
		gen := &mockGenerator{
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "content"},
			},
		}
		parser := &mockParser{err: context.DeadlineExceeded}
		pg := NewParsedGenerator(gen, parser)

		conv := attempt.NewConversation()
		_, err := pg.Generate(ctx, conv, 1)
		if err == nil {
			t.Error("Expected error from parser")
		}
	})
}

func TestParsedGenerator_DelegatedMethods(t *testing.T) {
	gen := &mockGenerator{}
	parser := &mockParser{}
	pg := NewParsedGenerator(gen, parser)

	// Test Name delegation
	if got := pg.Name(); got != "mock.Generator" {
		t.Errorf("Name() = %q, want %q", got, "mock.Generator")
	}

	// Test Description delegation
	if got := pg.Description(); got != "Mock generator for testing" {
		t.Errorf("Description() = %q, want %q", got, "Mock generator for testing")
	}

	// Test ClearHistory doesn't panic
	pg.ClearHistory()
}

func TestParsedGenerator_ImplementsInterface(t *testing.T) {
	var _ types.Generator = (*ParsedGenerator)(nil)
}
