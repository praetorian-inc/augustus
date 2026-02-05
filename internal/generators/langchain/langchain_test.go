package langchain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLangChain(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name: "valid config with URI",
			cfg: registry.Config{
				"uri": "http://localhost:8000/invoke",
			},
			wantErr: false,
		},
		{
			name:    "missing URI",
			cfg:     registry.Config{},
			wantErr: true,
		},
		{
			name: "invalid URI",
			cfg: registry.Config{
				"uri": "::invalid-uri",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewLangChain(tt.cfg)
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

func TestLangChain_Generate(t *testing.T) {
	// Mock LangChain server that responds like invoke()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// LangChain invoke returns {"content": "response text"}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content": "test response"}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"uri": server.URL + "/invoke",
	}

	gen, err := NewLangChain(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test prompt"))

	messages, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "test response", messages[0].Content)
}

func TestLangChain_GenerateMultiple(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"content": "response"}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"uri": server.URL + "/invoke",
	}

	gen, err := NewLangChain(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	// LangChain generator does NOT support n>1 (calls invoke once)
	messages, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// Should only make 1 call regardless of n
	assert.Equal(t, 1, callCount)
	assert.Len(t, messages, 1)
}

func TestLangChain_ErrorHandling(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cfg := registry.Config{
		"uri": server.URL + "/invoke",
	}

	gen, err := NewLangChain(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	_, err = gen.Generate(context.Background(), conv, 1)
	assert.Error(t, err)
}

func TestLangChain_Name(t *testing.T) {
	cfg := registry.Config{
		"uri": "http://localhost:8000/invoke",
	}

	gen, err := NewLangChain(cfg)
	require.NoError(t, err)

	assert.Equal(t, "langchain.LangChain", gen.Name())
}

func TestLangChain_Description(t *testing.T) {
	cfg := registry.Config{
		"uri": "http://localhost:8000/invoke",
	}

	gen, err := NewLangChain(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "LangChain")
}
