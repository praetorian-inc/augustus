package guardrails

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNeMoGuardrails_Name(t *testing.T) {
	g := &NeMoGuardrails{}
	assert.Equal(t, "guardrails.NeMoGuardrails", g.Name())
}

func TestNeMoGuardrails_Description(t *testing.T) {
	g := &NeMoGuardrails{}
	assert.Contains(t, g.Description(), "NeMo Guardrails")
}

func TestNeMoGuardrails_ClearHistory(t *testing.T) {
	g := &NeMoGuardrails{}
	// Should not panic
	g.ClearHistory()
}

func TestNewNeMoGuardrails_MissingConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr string
	}{
		{
			name:    "missing rails_config",
			cfg:     registry.Config{},
			wantErr: "requires 'rails_config'",
		},
		{
			name: "missing base_url with api_key",
			cfg: registry.Config{
				"rails_config": "test_config",
			},
			wantErr: "requires 'base_url'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewNeMoGuardrails(tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestNewNeMoGuardrails_ValidConfig(t *testing.T) {
	cfg := registry.Config{
		"base_url":     "http://localhost:8000",
		"rails_config": "test_config",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)
	require.NotNil(t, gen)

	g := gen.(*NeMoGuardrails)
	assert.Equal(t, "http://localhost:8000", g.baseURL)
	assert.Equal(t, "test_config", g.railsConfig)
	assert.Empty(t, g.apiKey)
}

func TestNewNeMoGuardrails_WithAPIKey(t *testing.T) {
	cfg := registry.Config{
		"base_url":     "http://localhost:8000",
		"rails_config": "test_config",
		"api_key":      "test-key",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	g := gen.(*NeMoGuardrails)
	assert.Equal(t, "test-key", g.apiKey)
}

func TestNeMoGuardrails_Generate_Success(t *testing.T) {
	// Mock NeMo Guardrails HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/chat/completions", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Verify request body
		var req map[string]any
		err := json.NewDecoder(r.Body).Decode(&req)
		require.NoError(t, err)

		assert.Equal(t, "test_config", req["config_id"])
		messages := req["messages"].([]any)
		assert.Len(t, messages, 1)

		msg := messages[0].(map[string]any)
		assert.Equal(t, "user", msg["role"])
		assert.Equal(t, "Hello, world!", msg["content"])

		// Send mock response
		resp := map[string]any{
			"messages": []map[string]any{
				{
					"role":    "assistant",
					"content": "Hello! How can I help you?",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url":     server.URL,
		"rails_config": "test_config",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Hello, world!")

	ctx := context.Background()
	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "Hello! How can I help you?", responses[0].Content)
}

func TestNeMoGuardrails_Generate_WithAPIKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify API key in header
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		resp := map[string]any{
			"messages": []map[string]any{
				{
					"role":    "assistant",
					"content": "Response",
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url":     server.URL,
		"rails_config": "test_config",
		"api_key":      "test-key",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test")

	ctx := context.Background()
	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
}

func TestNeMoGuardrails_Generate_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty messages
		resp := map[string]any{
			"messages": []map[string]any{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url":     server.URL,
		"rails_config": "test_config",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test")

	ctx := context.Background()
	responses, err := gen.Generate(ctx, conv, 1)
	require.NoError(t, err)
	require.Len(t, responses, 1)
	assert.Equal(t, "", responses[0].Content)
}

func TestNeMoGuardrails_Generate_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error": "Invalid request"}`))
	}))
	defer server.Close()

	cfg := registry.Config{
		"base_url":     server.URL,
		"rails_config": "test_config",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Test")

	ctx := context.Background()
	_, err = gen.Generate(ctx, conv, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad request")
}

func TestNeMoGuardrails_Generate_Zero(t *testing.T) {
	cfg := registry.Config{
		"base_url":     "http://localhost:8000",
		"rails_config": "test_config",
	}

	gen, err := NewNeMoGuardrails(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	ctx := context.Background()

	responses, err := gen.Generate(ctx, conv, 0)
	require.NoError(t, err)
	assert.Empty(t, responses)
}
