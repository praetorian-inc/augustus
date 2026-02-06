package test

import (
	"context"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLipsumGenerator_Name(t *testing.T) {
	g := &Lipsum{}
	assert.Equal(t, "test.Lipsum", g.Name())
}

func TestLipsumGenerator_Description(t *testing.T) {
	g := &Lipsum{}
	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Greater(t, len(desc), 10)
}

func TestLipsumGenerator_Generate(t *testing.T) {
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
			g := &Lipsum{}
			conv := attempt.NewConversation()
			conv.AddPrompt("test prompt")

			responses, err := g.Generate(context.Background(), conv, tt.n)
			require.NoError(t, err)
			assert.Len(t, responses, tt.wantN)

			// All responses should be non-empty text
			for i, resp := range responses {
				assert.Equal(t, attempt.RoleAssistant, resp.Role, "responses[%d].Role", i)
				assert.NotEmpty(t, resp.Content, "responses[%d].Content should not be empty", i)
				// Should contain at least one word
				assert.Greater(t, len(strings.Fields(resp.Content)), 0, "responses[%d].Content should have words", i)
				// Should end with period (sentence format)
				assert.True(t, strings.HasSuffix(resp.Content, "."), "responses[%d].Content should end with period", i)
			}
		})
	}
}

func TestLipsumGenerator_Generate_VariesOutputs(t *testing.T) {
	g := &Lipsum{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test prompt")

	// Generate multiple times to verify outputs vary
	var outputs []string
	for i := 0; i < 5; i++ {
		responses, err := g.Generate(context.Background(), conv, 1)
		require.NoError(t, err)
		require.Len(t, responses, 1)
		outputs = append(outputs, responses[0].Content)
	}

	// At least some outputs should differ (not all identical)
	allSame := true
	for i := 1; i < len(outputs); i++ {
		if outputs[i] != outputs[0] {
			allSame = false
			break
		}
	}
	assert.False(t, allSame, "Lipsum should generate varying outputs, got all identical: %v", outputs[0])
}

func TestLipsumGenerator_Generate_IgnoresConversation(t *testing.T) {
	g := &Lipsum{}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responses, err := g.Generate(context.Background(), tt.conv, 1)
			require.NoError(t, err)
			require.Len(t, responses, 1)

			// Should return Lorem Ipsum text regardless of conversation
			assert.NotEmpty(t, responses[0].Content)
		})
	}
}

func TestLipsumGenerator_ClearHistory(t *testing.T) {
	g := &Lipsum{}

	// ClearHistory should not panic
	g.ClearHistory()

	// Should still work after ClearHistory
	conv := attempt.NewConversation()
	conv.AddPrompt("test")
	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.NotEmpty(t, responses[0].Content)
}

func TestLipsumGenerator_Registration(t *testing.T) {
	// Test that the generator is registered via init()
	factory, ok := generators.Get("test.Lipsum")
	require.True(t, ok, "test.Lipsum not registered in generators registry")

	// Test factory creates valid generator
	g, err := factory(registry.Config{})
	require.NoError(t, err)
	assert.Equal(t, "test.Lipsum", g.Name())
}

func TestNewLipsum(t *testing.T) {
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
			g, err := NewLipsum(tt.config)
			require.NoError(t, err)
			require.NotNil(t, g)
			assert.Equal(t, "test.Lipsum", g.Name())
		})
	}
}

func TestLipsumGenerator_ContextCancellation(t *testing.T) {
	g := &Lipsum{}
	conv := attempt.NewConversation()
	conv.AddPrompt("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Lipsum generator ignores context, should still work
	responses, err := g.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.NotEmpty(t, responses[0].Content)
}
