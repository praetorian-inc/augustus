package nim

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNVMultimodal_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNVMultimodal(registry.Config{
		"model":    "microsoft/phi-4-multimodal-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nim.NVMultimodal", g.Name())
}

func TestNVMultimodal_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewNVMultimodal(registry.Config{
		"model":    "microsoft/phi-4-multimodal-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, strings.ToLower(desc), "multimodal")
}

func TestNVMultimodal_Generate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Multimodal response", 1))
	}))
	defer server.Close()

	g, err := NewNVMultimodal(registry.Config{
		"model":    "microsoft/phi-4-multimodal-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("Describe this image")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Multimodal response", responses[0].Content)
}

func TestNVMultimodal_Registration(t *testing.T) {
	factory, ok := generators.Get("nim.NVMultimodal")
	assert.True(t, ok, "nim.NVMultimodal should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "microsoft/phi-4-multimodal-instruct",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nim.NVMultimodal", g.Name())
}

func TestVision_Name(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewVision(registry.Config{
		"model":    "microsoft/phi-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	assert.Equal(t, "nim.Vision", g.Name())
}

func TestVision_Description(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("response", 1))
	}))
	defer server.Close()

	g, err := NewVision(registry.Config{
		"model":    "microsoft/phi-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	desc := g.Description()
	assert.NotEmpty(t, desc)
	assert.Contains(t, strings.ToLower(desc), "vision")
}

func TestVision_Generate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Vision response", 1))
	}))
	defer server.Close()

	g, err := NewVision(registry.Config{
		"model":    "microsoft/phi-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("What is in this image?")

	responses, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	assert.Len(t, responses, 1)
	assert.Equal(t, "Vision response", responses[0].Content)
}

func TestVision_Registration(t *testing.T) {
	factory, ok := generators.Get("nim.Vision")
	assert.True(t, ok, "nim.Vision should be registered")

	if !ok {
		return
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(mockNIMResponse("Response", 1))
	}))
	defer server.Close()

	g, err := factory(registry.Config{
		"model":    "microsoft/phi-4-vision",
		"api_key":  "test-key",
		"base_url": server.URL,
	})
	require.NoError(t, err)
	assert.Equal(t, "nim.Vision", g.Name())
}
