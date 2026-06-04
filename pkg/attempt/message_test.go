package attempt

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUserMessageWithImages(t *testing.T) {
	images := []Image{
		{MimeType: "image/png", Base64: "abc123"},
		{MimeType: "image/jpeg", Data: []byte{0xFF, 0xD8}},
	}
	msg := NewUserMessageWithImages("describe this", images)

	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "describe this", msg.Content)
	require.Len(t, msg.Images, 2)
	assert.Equal(t, "image/png", msg.Images[0].MimeType)
	assert.Equal(t, "image/jpeg", msg.Images[1].MimeType)
}

func TestMessageJSONRoundtrip_WithImages(t *testing.T) {
	original := NewUserMessageWithImages("look at this", []Image{
		{MimeType: "image/png", Base64: "dGVzdA=="},
	})

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Message
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Role, decoded.Role)
	assert.Equal(t, original.Content, decoded.Content)
	require.Len(t, decoded.Images, 1)
	assert.Equal(t, "image/png", decoded.Images[0].MimeType)
	assert.Equal(t, "dGVzdA==", decoded.Images[0].Base64)
}

func TestNewUserMessage_BackwardCompatible(t *testing.T) {
	msg := NewUserMessage("hello")

	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "hello", msg.Content)
	assert.Nil(t, msg.Images)
}

func TestMessageJSONRoundtrip_NoImages(t *testing.T) {
	original := NewUserMessage("text only")

	data, err := json.Marshal(original)
	require.NoError(t, err)

	// Verify multimodal fields are omitted in JSON when nil
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	_, hasImages := raw["images"]
	assert.False(t, hasImages, "images field should be omitted when nil")
	_, hasAudio := raw["audio"]
	assert.False(t, hasAudio, "audio field should be omitted when nil")
	_, hasDocs := raw["documents"]
	assert.False(t, hasDocs, "documents field should be omitted when nil")
}

func TestNewUserMessageWithAudio(t *testing.T) {
	audio := []Audio{
		{MimeType: "audio/wav", Base64: "UklGRg=="},
		{MimeType: "audio/mp3", Data: []byte{0xFF, 0xFB}},
	}
	msg := NewUserMessageWithAudio("transcribe", audio)

	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "transcribe", msg.Content)
	assert.Nil(t, msg.Images)
	require.Len(t, msg.Audio, 2)
	assert.Equal(t, "audio/wav", msg.Audio[0].MimeType)
	assert.Equal(t, "audio/mp3", msg.Audio[1].MimeType)
}

func TestNewUserMessageWithDocuments(t *testing.T) {
	docs := []Document{
		{MimeType: "application/pdf", Base64: "JVBERi0="},
	}
	msg := NewUserMessageWithDocuments("summarize", docs)

	assert.Equal(t, RoleUser, msg.Role)
	assert.Equal(t, "summarize", msg.Content)
	assert.Nil(t, msg.Images)
	assert.Nil(t, msg.Audio)
	require.Len(t, msg.Documents, 1)
	assert.Equal(t, "application/pdf", msg.Documents[0].MimeType)
}

func TestMessageJSONRoundtrip_WithAudio(t *testing.T) {
	original := NewUserMessageWithAudio("hear this", []Audio{
		{MimeType: "audio/wav", Base64: "UklGRg=="},
	})

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Message
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Audio, 1)
	assert.Equal(t, "audio/wav", decoded.Audio[0].MimeType)
	assert.Equal(t, "UklGRg==", decoded.Audio[0].Base64)
}

func TestMessageJSONRoundtrip_WithDocuments(t *testing.T) {
	original := NewUserMessageWithDocuments("read", []Document{
		{MimeType: "application/pdf", Base64: "JVBERi0="},
	})

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Message
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Documents, 1)
	assert.Equal(t, "application/pdf", decoded.Documents[0].MimeType)
	assert.Equal(t, "JVBERi0=", decoded.Documents[0].Base64)
}
