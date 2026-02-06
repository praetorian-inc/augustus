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

func TestSingleGenerator_Name(t *testing.T) {
	g := &Single{}
	assert.Equal(t, "test.Single", g.Name())
}

func TestSingleGenerator_Description(t *testing.T) {
	g := &Single{}
	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Greater(t, len(desc), 10)
}

func TestSingleGenerator_Generate_ReturnsELIM(t *testing.T) {
	g := &Single{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)

	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
	assert.Equal(t, "ELIM", responses[0].Content)
}

func TestSingleGenerator_Generate_RefusesMultiple(t *testing.T) {
	g := &Single{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	tests := []struct {
		name string
		n    int
	}{
		{
			name: "n=2",
			n:    2,
		},
		{
			name: "n=5",
			n:    5,
		},
		{
			name: "n=10",
			n:    10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := g.Generate(context.Background(), conv, tt.n)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "multiple generations")
		})
	}
}

func TestSingleGenerator_Generate_IgnoresConversation(t *testing.T) {
	g := &Single{}

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
				c.AddPrompt("different prompt")
				return c
			}(),
		},
		{
			name: "conversation with system message",
			conv: attempt.NewConversation().WithSystem("system prompt"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := g.Generate(context.Background(), tt.conv, 1)
			require.NoError(t, err)
			require.Len(t, responses, 1)
			assert.Equal(t, "ELIM", responses[0].Content)
		})
	}
}

func TestSingleGenerator_ClearHistory(t *testing.T) {
	g := &Single{}

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "ELIM", responses[0].Content)
}

func TestSingleGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("test.Single")
	require.True(t, ok, "test.Single not registered in generators registry")

	// Test factory creates valid generator
	g, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "test.Single", g.Name())
}

func TestNewSingle(t *testing.T) {
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
			g, err := NewSingle(tt.config)
			require.NoError(t, err)
			require.NotNil(t, g)
			assert.Equal(t, "test.Single", g.Name())
		})
	}
}

func TestSingleGenerator_ContextCancellation(t *testing.T) {
	g := &Single{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Single generator ignores context, should still work
	responses, err := g.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "ELIM", responses[0].Content)
}
