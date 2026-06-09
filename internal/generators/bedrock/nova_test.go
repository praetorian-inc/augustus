package bedrock

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockBedrockNovaResponse mirrors the wire shape Amazon Nova returns on Bedrock
// (output.message.content[].text).
func mockBedrockNovaResponse(content string) map[string]any {
	return map[string]any{
		"output": map[string]any{
			"message": map[string]any{
				"role": "assistant",
				"content": []map[string]any{
					{"text": content},
				},
			},
		},
		"stopReason": "end_turn",
		"usage": map[string]any{
			"inputTokens":  12,
			"outputTokens": 8,
			"totalTokens":  20,
		},
	}
}

func TestNovaImageFormat(t *testing.T) {
	cases := map[string]string{
		"image/png":  "png",
		"image/PNG":  "png",
		"image/jpeg": "jpeg",
		"image/jpg":  "jpeg",
		"image/gif":  "gif",
		"image/webp": "webp",
		"image/heic": "", // unknown → empty (caller skips)
		"":           "", // empty → empty (caller skips)
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			assert.Equal(t, want, novaImageFormat(in))
		})
	}
}

// TestBuildNovaContent_SkipsUnsupportedImageMIME verifies that images with
// MIME types Nova doesn't accept are dropped rather than relabeled.
func TestBuildNovaContent_SkipsUnsupportedImageMIME(t *testing.T) {
	msg := &attempt.Message{
		Role:    attempt.RoleUser,
		Content: "what is this?",
		Images: []attempt.Image{
			{Data: []byte{0x01}, MimeType: "image/png"},  // kept
			{Data: []byte{0x02}, MimeType: "image/heic"}, // dropped
			{Data: []byte{0x03}, MimeType: "image/jpeg"}, // kept
		},
	}
	blocks := buildNovaContent(msg)
	// text + 2 image blocks (heic dropped)
	require.Len(t, blocks, 3)
	assert.Equal(t, "what is this?", blocks[0].(map[string]any)["text"])
	formats := []string{}
	for _, b := range blocks[1:] {
		formats = append(formats, b.(map[string]any)["image"].(map[string]any)["format"].(string))
	}
	assert.Equal(t, []string{"png", "jpeg"}, formats)
}

func TestBedrockGenerator_NovaSupported(t *testing.T) {
	setFakeAWSCredentials(t)

	for _, modelID := range []string{
		"amazon.nova-micro-v1:0",
		"amazon.nova-lite-v1:0",
		"amazon.nova-pro-v1:0",
	} {
		t.Run(modelID, func(t *testing.T) {
			g, err := NewBedrock(registry.Config{
				"model":  modelID,
				"region": "us-east-1",
			})
			require.NoError(t, err)
			assert.Contains(t, g.Name(), "bedrock")
		})
	}
}

func TestBedrockGenerator_Generate_NovaTextOnly(t *testing.T) {
	setFakeAWSCredentials(t)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockNovaResponse("hi from nova"))
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "amazon.nova-lite-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	resps, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resps, 1)
	assert.Equal(t, "hi from nova", resps[0].Content)

	var req struct {
		SchemaVersion string `json:"schemaVersion"`
		Messages      []struct {
			Role    string          `json:"role"`
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
		InferenceConfig map[string]any  `json:"inferenceConfig"`
		System          json.RawMessage `json:"system,omitempty"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	assert.Equal(t, "messages-v1", req.SchemaVersion)
	require.Len(t, req.Messages, 1)
	assert.Equal(t, "user", req.Messages[0].Role)
	assert.Empty(t, req.System, "no system prompt should mean no system field")

	// Content must be an array of one text block.
	var content []map[string]any
	require.NoError(t, json.Unmarshal(req.Messages[0].Content, &content))
	require.Len(t, content, 1)
	assert.Equal(t, "hi", content[0]["text"])
}

func TestBedrockGenerator_Generate_NovaWithImage(t *testing.T) {
	setFakeAWSCredentials(t)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockNovaResponse("I see it"))
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "amazon.nova-pro-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	img := attempt.Image{Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}, MimeType: "image/png"}
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("what's in this?", []attempt.Image{img}))

	resps, err := g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)
	require.Len(t, resps, 1)
	assert.Equal(t, "I see it", resps[0].Content)

	// Decode and assert Nova content shape: text block then image block with
	// format derived from MIME and base64 source bytes.
	var req struct {
		Messages []struct {
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Messages, 1)
	require.Len(t, req.Messages[0].Content, 2)

	assert.Equal(t, "what's in this?", req.Messages[0].Content[0]["text"])

	imgBlock, ok := req.Messages[0].Content[1]["image"].(map[string]any)
	require.True(t, ok, "expected image content block")
	assert.Equal(t, "png", imgBlock["format"])
	src := imgBlock["source"].(map[string]any)
	assert.Equal(t, base64.StdEncoding.EncodeToString(img.Data), src["bytes"])
}

func TestBedrockGenerator_Generate_NovaWithSystem(t *testing.T) {
	setFakeAWSCredentials(t)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockNovaResponse("ack"))
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "amazon.nova-micro-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	sys := attempt.NewSystemMessage("be concise")
	conv.System = &sys
	conv.AddPrompt("hi")

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	var req struct {
		Messages []map[string]any `json:"messages"`
		System   []map[string]any `json:"system"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.System, 1, "system must be an array of one block per Nova spec")
	assert.Equal(t, "be concise", req.System[0]["text"])
	// And the system must NOT appear in messages.
	require.Len(t, req.Messages, 1)
	assert.Equal(t, "user", req.Messages[0]["role"])
}

func TestBedrockGenerator_Generate_NovaWithMultipleImages(t *testing.T) {
	setFakeAWSCredentials(t)

	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(mockBedrockNovaResponse("ok"))
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "amazon.nova-pro-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	images := []attempt.Image{
		{Data: []byte{0x01}, MimeType: "image/png"},
		{Data: []byte{0x02}, MimeType: "image/jpeg"},
		{Data: []byte{0x03}, MimeType: "image/webp"},
	}
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("compare", images))

	_, err = g.Generate(context.Background(), conv, 1)
	require.NoError(t, err)

	var req struct {
		Messages []struct {
			Content []map[string]any `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(capturedBody, &req))
	require.Len(t, req.Messages[0].Content, 4, "expected 1 text + 3 image blocks")

	formats := []string{}
	for _, c := range req.Messages[0].Content[1:] {
		formats = append(formats, c["image"].(map[string]any)["format"].(string))
	}
	assert.Equal(t, []string{"png", "jpeg", "webp"}, formats)
}

// TestBedrockGenerator_NovaHandlesMalformedJSON verifies the Nova response
// parser surfaces a wrapped parse error when the API returns invalid JSON.
// (5xx and context-cancellation paths are covered by the Claude-targeted
// equivalents in bedrock_test.go since both share the Generate codepath.)
func TestBedrockGenerator_NovaHandlesMalformedJSON(t *testing.T) {
	setFakeAWSCredentials(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"output":{"message":{`)) // truncated
	}))
	defer server.Close()

	g, err := NewBedrock(registry.Config{
		"model":    "amazon.nova-micro-v1:0",
		"region":   "us-east-1",
		"endpoint": server.URL,
	})
	require.NoError(t, err)

	conv := attempt.NewConversation()
	conv.AddPrompt("hi")

	_, err = g.Generate(context.Background(), conv, 1)
	require.Error(t, err)
	// bedrock.go wraps parse errors with "failed to parse response"
	assert.Contains(t, strings.ToLower(err.Error()), "parse",
		"expected parse failure in error, got: %v", err)
}
