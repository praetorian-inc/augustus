package test

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonesGenerator_Name(t *testing.T) {
	g := &Nones{}
	assert.Equal(t, "test.Nones", g.Name())
}

func TestNonesGenerator_Description(t *testing.T) {
	g := &Nones{}
	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Greater(t, len(desc), 10)
}

func TestNonesGenerator_Generate(t *testing.T) {
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
			g := &Nones{}
			conv := attempt.NewConversation()
			conv.AddPrompt("test prompt")

			responses, err := g.Generate(context.Background(), conv, tt.n)
			require.NoError(t, err)
			assert.Len(t, responses, tt.wantN)

			// All responses should be empty messages
			for i, resp := range responses {
				assert.Equal(t, attempt.RoleAssistant, resp.Role, "responses[%d].Role", i)
				assert.Empty(t, resp.Content, "responses[%d].Content should be empty", i)
			}
		})
	}
}

func TestNonesGenerator_Generate_IgnoresConversation(t *testing.T) {
	g := &Nones{}

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
			require.NoError(t, err)
			require.Len(t, responses, 1)

			// Should always return empty message regardless of conversation
			assert.Empty(t, responses[0].Content)
		})
	}
}

func TestNonesGenerator_ClearHistory(t *testing.T) {
	g := &Nones{}

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Empty(t, responses[0].Content)
}

func TestNonesGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("test.Nones")
	require.True(t, ok, "test.Nones not registered in generators registry")

	// Test factory creates valid generator
	g, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "test.Nones", g.Name())
}

func TestNewNones(t *testing.T) {
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
			g, err := NewNones(tt.config)
			require.NoError(t, err)
			require.NotNil(t, g)
			assert.Equal(t, "test.Nones", g.Name())
		})
	}
}

func TestNonesGenerator_ContextCancellation(t *testing.T) {
	g := &Nones{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Nones generator ignores context, should still work
	responses, err := g.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Empty(t, responses[0].Content)
}
