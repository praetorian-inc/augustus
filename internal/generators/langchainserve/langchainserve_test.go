package langchainserve

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

func TestNewLangChainServe(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name: "valid config with base_url",
			cfg: registry.Config{
				"base_url": "http://127.0.0.1:8000/rag-chroma-private",
			},
			wantErr: false,
		},
		{
			name:    "missing base_url",
			cfg:     registry.Config{},
			wantErr: true,
		},
		{
			name: "invalid base_url",
			cfg: registry.Config{
				"base_url": "::invalid-url",
			},
			wantErr: true,
		},
		{
			name: "with custom timeout",
			cfg: registry.Config{
				"base_url": "http://localhost:8000/chain",
				"timeout":  60,
			},
			wantErr: false,
		},
		{
			name: "with headers",
			cfg: registry.Config{
				"base_url": "http://localhost:8000/chain",
				"headers": map[string]string{
					"Authorization": "Bearer token",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewLangChainServe(tt.cfg)
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

func TestLangChainServe_Generate(t *testing.T) {
	// Mock LangChain Serve server that responds like invoke endpoint
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request format
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/invoke", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))

		// LangChain Serve returns {"output": ["response text"]}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"output": ["test response from langchain serve"]}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url": server.URL,
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test prompt"))

	messages, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Len(t, messages, 1)
	assert.Equal(t, "test response from langchain serve", messages[0].Content)
}

func TestLangChainServe_GenerateMultiple(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"output": ["response"]}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url": server.URL,
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	// LangChain Serve does NOT support n>1 (calls invoke once)
	messages, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// Should only make 1 call regardless of n
	assert.Equal(t, 1, callCount)
	assert.Len(t, messages, 1)
}

func TestLangChainServe_ErrorHandling(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		response   string
		wantErr    bool
	}{
		{
			name:       "server error 500",
			statusCode: http.StatusInternalServerError,
			response:   `{"error": "server error"}`,
			wantErr:    true,
		},
		{
			name:       "client error 400",
			statusCode: http.StatusBadRequest,
			response:   `{"error": "bad request"}`,
			wantErr:    true,
		},
		{
			name:       "missing output field",
			statusCode: http.StatusOK,
			response:   `{"content": "wrong format"}`,
			wantErr:    true,
		},
		{
			name:       "invalid json",
			statusCode: http.StatusOK,
			response:   `invalid json`,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.response))
			}))
			defer server.Close()

			cfg := registry.Config{
				"base_url": server.URL,
			}

			gen, err := NewLangChainServe(cfg)
			require.NoError(t, err)

			conv := attempt.NewConversation()
			conv.AddTurn(attempt.NewTurn("test"))

			_, err = gen.Generate(context.Background(), conv, 1)
			assert.Error(t, err)
		})
	}
}

func TestLangChainServe_CustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify custom header is present
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "test-value", r.Header.Get("X-Custom-Header"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"output": ["response"]}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url": server.URL,
		"headers": map[string]any{
			"Authorization":   "Bearer test-token",
			"X-Custom-Header": "test-value",
		},
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	_, err = gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
}

func TestLangChainServe_ConfigHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify config_hash query parameter
		assert.Equal(t, "custom-hash", r.URL.Query().Get("config_hash"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"output": ["response"]}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url":    server.URL,
		"config_hash": "custom-hash",
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddTurn(attempt.NewTurn("test"))

	_, err = gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
}

func TestLangChainServe_Name(t *testing.T) {
	cfg := registry.Config{
		"base_url": "http://localhost:8000/my-chain",
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	assert.Equal(t, "langchain_serve.LangChainServe", gen.Name())
}

func TestLangChainServe_Description(t *testing.T) {
	cfg := registry.Config{
		"base_url": "http://localhost:8000/chain",
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, desc, "LangChain Serve")
}

func TestLangChainServe_ClearHistory(t *testing.T) {
	cfg := registry.Config{
		"base_url": "http://localhost:8000/chain",
	}

	gen, err := NewLangChainServe(cfg)
	require.NoError(t, err)

	// ClearHistory should not panic (it's a no-op for stateless generators)
	gen.ClearHistory()
}
