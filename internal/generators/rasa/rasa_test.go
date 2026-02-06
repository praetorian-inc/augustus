package rasa

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRasaRestGenerator_Name tests the Name method.
func TestRasaRestGenerator_Name(t *testing.T) {
	cfg := Config{
		BaseURL: "http://localhost:5005",
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	assert.Equal(t, "rasa.RasaRest", gen.Name())
}

// TestRasaRestGenerator_Description tests the Description method.
func TestRasaRestGenerator_Description(t *testing.T) {
	cfg := Config{
		BaseURL: "http://localhost:5005",
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	desc := gen.Description()
	assert.Contains(t, desc, "Rasa")
}

// TestRasaRestGenerator_Generate_SingleMessage tests generating one response.
func TestRasaRestGenerator_Generate_SingleMessage(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		assert.Equal(t, "POST", r.Method)
		assert.Contains(t, r.URL.Path, "/webhooks/rest/webhook")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		// Parse request body
		var reqBody map[string]any
		err := json.NewDecoder(r.Body).Decode(&reqBody)
		require.NoError(t, err)

		// Verify request structure
		assert.Equal(t, "test-sender", reqBody["sender"])
		assert.Equal(t, "Hello, Rasa!", reqBody["message"])

		// Send response
		resp := []map[string]any{
			{"text": "Hello from Rasa!"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create generator with mock server URL
	cfg := Config{
		BaseURL: server.URL,
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	// Create conversation
	conv := attempt.NewConversation()
	conv.AddPrompt("Hello, Rasa!")

	// Generate response
	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	// Verify response
	require.Len(t, responses, 1)
	assert.Equal(t, "Hello from Rasa!", responses[0].Content)
	assert.Equal(t, attempt.RoleAssistant, responses[0].Role)
}

// TestRasaRestGenerator_Generate_MultipleMessages tests generating multiple responses.
func TestRasaRestGenerator_Generate_MultipleMessages(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send multiple messages in response array
		resp := []map[string]any{
			{"text": "Response 1"},
			{"text": "Response 2"},
			{"text": "Response 3"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		BaseURL: server.URL,
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Tell me three things")

	// Generate responses (n=3 should be ignored, Rasa returns array)
	responses, err := gen.Generate(context.Background(), conv, 3)
	require.NoError(t, err)

	// Verify all responses received
	require.Len(t, responses, 3)
	assert.Equal(t, "Response 1", responses[0].Content)
	assert.Equal(t, "Response 2", responses[1].Content)
	assert.Equal(t, "Response 3", responses[2].Content)
}

// TestRasaRestGenerator_ClearHistory tests the ClearHistory method.
func TestRasaRestGenerator_ClearHistory(t *testing.T) {
	cfg := Config{
		BaseURL: "http://localhost:5005",
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	// ClearHistory should not panic
	gen.ClearHistory()
}

// TestRasaRestGenerator_EmptyResponse tests handling of empty response array.
func TestRasaRestGenerator_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Send empty array
		resp := []map[string]any{}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cfg := Config{
		BaseURL: server.URL,
		Model:   "test-model",
		Sender:  "test-sender",
	}

	gen, err := NewRasaRestTyped(cfg)
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("No response please")

	responses, err := gen.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	assert.Empty(t, responses)
}

// TestRasaRestGenerator_ConfigValidation tests configuration validation.
func TestRasaRestGenerator_ConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				BaseURL: "http://localhost:5005",
				Model:   "test-model",
				Sender:  "test-sender",
			},
			wantErr: false,
		},
		{
			name: "missing base_url",
			cfg: Config{
				Model:  "test-model",
				Sender: "test-sender",
			},
			wantErr: true,
		},
		{
			name: "missing model",
			cfg: Config{
				BaseURL: "http://localhost:5005",
				Sender:  "test-sender",
			},
			wantErr: true,
		},
		{
			name: "missing sender",
			cfg: Config{
				BaseURL: "http://localhost:5005",
				Model:   "test-model",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewRasaRestTyped(tt.cfg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
