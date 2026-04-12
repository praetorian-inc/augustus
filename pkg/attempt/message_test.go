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

	// Verify images field is omitted in JSON when nil
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &raw))
	_, hasImages := raw["images"]
	assert.False(t, hasImages, "images field should be omitted when nil")
}
