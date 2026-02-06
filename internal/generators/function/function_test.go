package function

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test function that returns a single response
func testFunctionSingle(prompt string) []string {
	return []string{"response to: " + prompt}
}

// Test function that returns multiple responses
func testFunctionMultiple(prompt string, n int) []string {
	responses := make([]string, n)
	for i := 0; i < n; i++ {
		responses[i] = "response " + string(rune('A'+i)) + " to: " + prompt
	}
	return responses
}

// Test function that returns nil
func testFunctionNil(prompt string) []string {
	return nil
}

func TestNewSingle(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name: "valid function",
			cfg: registry.Config{
				"function": testFunctionSingle,
			},
			wantErr: false,
		},
		{
			name:    "missing function",
			cfg:     registry.Config{},
			wantErr: true,
		},
		{
			name: "invalid function type",
			cfg: registry.Config{
				"function": "not a function",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewSingle(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, gen)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, gen)
			}
		})
	}
}

func TestSingle_Generate(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionSingle,
	}

	gen, err := NewSingle(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test prompt"))

	messages, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "response to: test prompt", messages[0].Content)
}

func TestSingle_GenerateIgnoresN(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionSingle,
	}

	gen, err := NewSingle(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	// Single generator ignores n>1 (not supported)
	messages, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// Should only return 1 message
	assert.Len(t, messages, 1)
}

func TestSingle_NilResponse(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionNil,
	}

	gen, err := NewSingle(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	messages, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "", messages[0].Content)
}

func TestNewMultiple(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name: "valid function",
			cfg: registry.Config{
				"function": testFunctionMultiple,
			},
			wantErr: false,
		},
		{
			name:    "missing function",
			cfg:     registry.Config{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewMultiple(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, gen)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, gen)
			}
		})
	}
}

func TestMultiple_Generate(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionMultiple,
	}

	gen, err := NewMultiple(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test prompt"))

	messages, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)
	assert.Len(t, messages, 3)
	assert.Equal(t, "response A to: test prompt", messages[0].Content)
	assert.Equal(t, "response B to: test prompt", messages[1].Content)
	assert.Equal(t, "response C to: test prompt", messages[2].Content)
}

func TestMultiple_NilResponse(t *testing.T) {
	nilFunc := func(prompt string, n int) []string {
		return nil
	}

	cfg := registry.Config{
		"function": nilFunc,
	}

	gen, err := NewMultiple(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	messages, err := gen.Generate(context.Background(), conv, 2)
	require.NoError(t, err)

	// Should return n empty messages
	assert.Len(t, messages, 2)
	for _, msg := range messages {
		assert.Equal(t, "", msg.Content)
	}
}

func TestSingle_Name(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionSingle,
	}

	gen, err := NewSingle(cfg)
	require.NoError(t, err)

	assert.Equal(t, "function.Single", gen.Name())
}

func TestMultiple_Name(t *testing.T) {
	cfg := registry.Config{
		"function": testFunctionMultiple,
	}

	gen, err := NewMultiple(cfg)
	require.NoError(t, err)

	assert.Equal(t, "function.Multiple", gen.Name())
}
