package test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestBlankGenerator_Name(t *testing.T) {
	g := &Blank{}
	if got := g.Name(); got != "test.Blank" {
		t.Errorf("Name() = %q, want %q", got, "test.Blank")
	}
}

func TestBlankGenerator_Description(t *testing.T) {
	g := &Blank{}
	desc := g.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestBlankGenerator_Generate(t *testing.T) {
	tests := []struct {
		name  string
		n     int
		wantN int
	}{
		{
			name:  "n=1",
			n:     1,
			wantN: 1,
		},
		{
			name:  "n=5",
			n:     5,
			wantN: 5,
		},
		{
			name:  "n=0 defaults to 1",
			n:     0,
			wantN: 1,
		},
		{
			name:  "n=-1 defaults to 1",
			n:     -1,
			wantN: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Blank{}
			conv := attempt.NewConversation()
			conv.AddPrompt("test prompt")

			responses, err := g.Generate(context.Background(), conv, tt.n)
			if err != nil {
				t.Fatalf("Generate() error = %v, want nil", err)
			}

			if len(responses) != tt.wantN {
				t.Errorf("Generate() returned %d responses, want %d", len(responses), tt.wantN)
			}

			// All responses should be empty strings
			for i, resp := range responses {
				if resp.Role != attempt.RoleAssistant {
					t.Errorf("responses[%d].Role = %v, want %v", i, resp.Role, attempt.RoleAssistant)
				}
				if resp.Content != "" {
					t.Errorf("responses[%d].Content = %q, want empty string", i, resp.Content)
				}
			}
		})
	}
}

func TestBlankGenerator_Generate_IgnoresConversation(t *testing.T) {
	g := &Blank{}

	// Test with various conversation states
	tests := []struct {
		name string
		conv *attempt.Conversation
	}{
		{
			name: "empty conversation",
			conv: attempt.NewConversation(),
		},
		{
			name: "conversation with prompt",
			conv: func() *attempt.Conversation {
				c := attempt.NewConversation()
				c.AddPrompt("test prompt")
				return c
			}(),
		},
		{
			name: "conversation with system message",
			conv: attempt.NewConversation().WithSystem("system prompt"),
		},
		{
			name: "conversation with multiple turns",
			conv: func() *attempt.Conversation {
				c := attempt.NewConversation()
				c.AddPrompt("first")
				c.AddPrompt("second")
				c.AddPrompt("third")
				return c
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := g.Generate(context.Background(), tt.conv, 1)
			if err != nil {
				t.Fatalf("Generate() error = %v, want nil", err)
			}

			if len(responses) != 1 {
				t.Fatalf("Generate() returned %d responses, want 1", len(responses))
			}

			// Should always return empty string regardless of conversation
			if responses[0].Content != "" {
				t.Errorf("Generate() returned %q, want empty string", responses[0].Content)
			}
		})
	}
}

func TestBlankGenerator_ClearHistory(t *testing.T) {
	g := &Blank{}

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() after ClearHistory error = %v, want nil", err)
	}
	if len(responses) != 1 {
		t.Errorf("Generate() after ClearHistory returned %d responses, want 1", len(responses))
	}
}

func TestBlankGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("test.Blank")
	if !ok {
		t.Fatal("test.Blank not registered in generators registry")
	}

	// Test factory creates valid generator
	g, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if g.Name() != "test.Blank" {
		t.Errorf("factory created generator with name %q, want %q", g.Name(), "test.Blank")
	}
}

func TestNewBlankGenerator(t *testing.T) {
	tests := []struct {
		name   string
		config registry.Config
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: registry.Config{},
		},
		{
			name: "config with data",
			config: registry.Config{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewBlank(tt.config)
			if err != nil {
				t.Fatalf("NewBlank() error = %v, want nil", err)
			}
			if g == nil {
				t.Fatal("NewBlank() returned nil generator")
			}
			if g.Name() != "test.Blank" {
				t.Errorf("generator.Name() = %q, want %q", g.Name(), "test.Blank")
			}
		})
	}
}

func TestBlankGenerator_ContextCancellation(t *testing.T) {
	g := &Blank{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Blank generator ignores context, should still work
	responses, err := g.Generate(ctx, conv, 1)
	if err != nil {
		t.Fatalf("Generate() with cancelled context error = %v, want nil", err)
	}
	if len(responses) != 1 {
		t.Errorf("Generate() returned %d responses, want 1", len(responses))
	}
}
