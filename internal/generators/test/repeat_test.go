package test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestRepeatGenerator_Name(t *testing.T) {
	g := &Repeat{}
	if got := g.Name(); got != "test.Repeat" {
		t.Errorf("Name() = %q, want %q", got, "test.Repeat")
	}
}

func TestRepeatGenerator_Description(t *testing.T) {
	g := &Repeat{}
	desc := g.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestRepeatGenerator_Generate(t *testing.T) {
	tests := []struct {
		name       string
		prompt     string
		n          int
		wantN      int
		wantOutput string
	}{
		{
			name:       "n=1 simple prompt",
			prompt:     "hello",
			n:          1,
			wantN:      1,
			wantOutput: "hello",
		},
		{
			name:       "n=5 simple prompt",
			prompt:     "test",
			n:          5,
			wantN:      5,
			wantOutput: "test",
		},
		{
			name:       "n=0 defaults to 1",
			prompt:     "default",
			n:          0,
			wantN:      1,
			wantOutput: "default",
		},
		{
			name:       "n=-1 defaults to 1",
			prompt:     "negative",
			n:          -1,
			wantN:      1,
			wantOutput: "negative",
		},
		{
			name:       "empty prompt",
			prompt:     "",
			n:          1,
			wantN:      1,
			wantOutput: "",
		},
		{
			name:       "multiline prompt",
			prompt:     "line1\nline2\nline3",
			n:          1,
			wantN:      1,
			wantOutput: "line1\nline2\nline3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Repeat{prefix: ""}
			conv := attempt.NewConversation()
			conv.AddPrompt(tt.prompt)

			responses, err := g.Generate(context.Background(), conv, tt.n)
			if err != nil {
				t.Fatalf("Generate() error = %v, want nil", err)
			}

			if len(responses) != tt.wantN {
				t.Errorf("Generate() returned %d responses, want %d", len(responses), tt.wantN)
			}

			// All responses should echo the prompt
			for i, resp := range responses {
				if resp.Role != attempt.RoleAssistant {
					t.Errorf("responses[%d].Role = %v, want %v", i, resp.Role, attempt.RoleAssistant)
				}
				if resp.Content != tt.wantOutput {
					t.Errorf("responses[%d].Content = %q, want %q", i, resp.Content, tt.wantOutput)
				}
			}
		})
	}
}

func TestRepeatGenerator_Generate_WithPrefix(t *testing.T) {
	tests := []struct {
		name       string
		prefix     string
		prompt     string
		wantOutput string
	}{
		{
			name:       "simple prefix",
			prefix:     "ECHO: ",
			prompt:     "hello",
			wantOutput: "ECHO: hello",
		},
		{
			name:       "empty prefix",
			prefix:     "",
			prompt:     "hello",
			wantOutput: "hello",
		},
		{
			name:       "prefix with empty prompt",
			prefix:     "PREFIX: ",
			prompt:     "",
			wantOutput: "PREFIX: ",
		},
		{
			name:       "multiword prefix",
			prefix:     "Response from test generator: ",
			prompt:     "test",
			wantOutput: "Response from test generator: test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Repeat{prefix: tt.prefix}
			conv := attempt.NewConversation()
			conv.AddPrompt(tt.prompt)

			responses, err := g.Generate(context.Background(), conv, 1)
			if err != nil {
				t.Fatalf("Generate() error = %v, want nil", err)
			}

			if len(responses) != 1 {
				t.Fatalf("Generate() returned %d responses, want 1", len(responses))
			}

			if responses[0].Content != tt.wantOutput {
				t.Errorf("Generate() = %q, want %q", responses[0].Content, tt.wantOutput)
			}
		})
	}
}

func TestRepeatGenerator_Generate_MultiTurn(t *testing.T) {
	g := &Repeat{prefix: ""}
	conv := attempt.NewConversation()
	conv.AddPrompt("first prompt")
	conv.AddPrompt("second prompt")
	conv.AddPrompt("third prompt")

	// Should echo the last prompt
	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	if responses[0].Content != "third prompt" {
		t.Errorf("Generate() = %q, want %q", responses[0].Content, "third prompt")
	}
}

func TestRepeatGenerator_Generate_EmptyConversation(t *testing.T) {
	g := &Repeat{prefix: "PREFIX: "}
	conv := attempt.NewConversation()

	// Empty conversation should have empty last prompt
	responses, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatalf("Generate() error = %v, want nil", err)
	}

	if len(responses) != 1 {
		t.Fatalf("Generate() returned %d responses, want 1", len(responses))
	}

	// Should return just the prefix since LastPrompt() is empty
	if responses[0].Content != "PREFIX: " {
		t.Errorf("Generate() = %q, want %q", responses[0].Content, "PREFIX: ")
	}
}

func TestRepeatGenerator_ClearHistory(t *testing.T) {
	g := &Repeat{prefix: ""}

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
	if responses[0].Content != "test" {
		t.Errorf("Generate() after ClearHistory = %q, want %q", responses[0].Content, "test")
	}
}

func TestRepeatGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("test.Repeat")
	if !ok {
		t.Fatal("test.Repeat not registered in generators registry")
	}

	// Test factory creates valid generator
	g, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if g.Name() != "test.Repeat" {
		t.Errorf("factory created generator with name %q, want %q", g.Name(), "test.Repeat")
	}
}

func TestNewRepeat(t *testing.T) {
	tests := []struct {
		name       string
		config     registry.Config
		wantPrefix string
	}{
		{
			name:       "default prefix (empty)",
			config:     registry.Config{},
			wantPrefix: "",
		},
		{
			name: "custom prefix",
			config: registry.Config{
				"prefix": "ECHO: ",
			},
			wantPrefix: "ECHO: ",
		},
		{
			name: "invalid prefix type ignored",
			config: registry.Config{
				"prefix": 123,
			},
			wantPrefix: "",
		},
		{
			name: "empty string prefix",
			config: registry.Config{
				"prefix": "",
			},
			wantPrefix: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := NewRepeat(tt.config)
			if err != nil {
				t.Fatalf("NewRepeat() error = %v, want nil", err)
			}
			if g == nil {
				t.Fatal("NewRepeat() returned nil generator")
			}

			// Test the prefix by generating a response
			conv := attempt.NewConversation()
			conv.AddPrompt("test")
			responses, err := g.Generate(context.Background(), conv, 1)
			if err != nil {
				t.Fatalf("Generate() error = %v, want nil", err)
			}

			expectedOutput := tt.wantPrefix + "test"
			if responses[0].Content != expectedOutput {
				t.Errorf("Generate() = %q, want %q (prefix %q not applied)", responses[0].Content, expectedOutput, tt.wantPrefix)
			}
		})
	}
}

func TestRepeatGenerator_ContextCancellation(t *testing.T) {
	g := &Repeat{prefix: ""}
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Repeat generator ignores context, should still work
	responses, err := g.Generate(ctx, conv, 1)
	if err != nil {
		t.Fatalf("Generate() with cancelled context error = %v, want nil", err)
	}
	if len(responses) != 1 {
		t.Errorf("Generate() returned %d responses, want 1", len(responses))
	}
	if responses[0].Content != "test" {
		t.Errorf("Generate() = %q, want %q", responses[0].Content, "test")
	}
}
