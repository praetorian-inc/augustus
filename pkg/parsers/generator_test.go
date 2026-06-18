package parsers

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

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
		name        string
		messages    []attempt.Message
		transform   func(string) string
		n           int
		wantOutputs []string
	}{
		{
			name: "passthrough",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "Hello, world!"},
			},
			transform:   nil,
			n:           1,
			wantOutputs: []string{"Hello, world!"},
		},
		{
			name: "uppercase transformation",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "hello"},
			},
			transform: func(s string) string {
				return "PARSED: " + s
			},
			n:           1,
			wantOutputs: []string{"PARSED: hello"},
		},
		{
			name: "multiple messages all parsed",
			messages: []attempt.Message{
				{Role: attempt.RoleAssistant, Content: "first"},
				{Role: attempt.RoleAssistant, Content: "second"},
			},
			transform: func(s string) string {
				return "[" + s + "]"
			},
			n:           2,
			wantOutputs: []string{"[first]", "[second]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := &mockGenerator{messages: tt.messages}
			parser := &mockParser{transform: tt.transform}
			pg := NewParsedGenerator(gen, parser)

			conv := attempt.NewConversation()
			messages, err := pg.Generate(ctx, conv, tt.n)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			if len(messages) != len(tt.wantOutputs) {
				t.Fatalf("got %d messages, want %d", len(messages), len(tt.wantOutputs))
			}
			for i, want := range tt.wantOutputs {
				if messages[i].Content != want {
					t.Errorf("messages[%d].Content = %q, want %q", i, messages[i].Content, want)
				}
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

	if got := pg.Name(); got != "mock.Generator" {
		t.Errorf("Name() = %q, want %q", got, "mock.Generator")
	}
	if got := pg.Description(); got != "Mock generator for testing" {
		t.Errorf("Description() = %q, want %q", got, "Mock generator for testing")
	}

	// ClearHistory doesn't panic
	pg.ClearHistory()
}

func TestParsedGenerator_ImplementsInterface(t *testing.T) {
	var _ types.Generator = (*ParsedGenerator)(nil)
}
