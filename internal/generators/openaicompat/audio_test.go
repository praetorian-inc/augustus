package openaicompat

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAudioFormatFromMime(t *testing.T) {
	tests := []struct {
		mime string
		want string
	}{
		{"audio/wav", "wav"},
		{"audio/x-wav", "wav"},
		{"audio/wave", "wav"},
		{"AUDIO/WAV", "wav"},
		{"  audio/wav  ", "wav"},
		{"audio/mp3", "mp3"},
		{"audio/mpeg", "mp3"},
		{"AUDIO/MPEG", "mp3"},
		{"audio/ogg", ""},
		{"audio/flac", ""},
		{"image/png", ""},
		{"", ""},
	}
	for _, tc := range tests {
		t.Run(tc.mime, func(t *testing.T) {
			assert.Equal(t, tc.want, AudioFormatFromMime(tc.mime))
		})
	}
}

func TestAudioContentPart_MarshalsToOpenAIWireFormat(t *testing.T) {
	part := AudioContentPart{
		Type: "input_audio",
		InputAudio: InputAudioPayload{
			Data:   "QUJDRA==",
			Format: "wav",
		},
	}
	data, err := json.Marshal(part)
	assert.NoError(t, err)

	// Round-trip through generic map to verify the exact wire shape.
	var got map[string]any
	assert.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, "input_audio", got["type"])
	ia, ok := got["input_audio"].(map[string]any)
	assert.True(t, ok, "input_audio must be an object")
	assert.Equal(t, "QUJDRA==", ia["data"])
	assert.Equal(t, "wav", ia["format"])
}
