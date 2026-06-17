package openaicompat

import "strings"

// AudioContentPart is the raw JSON shape of an OpenAI input_audio content part.
// The go-openai SDK (≤v1.41.2) does not natively model this content-part type —
// its ChatMessagePart struct exposes only `text` and `image_url` slots — so
// audio content cannot ride on top of the typed SDK message at this time.
//
// This type captures the wire shape so probes and tests can produce / verify
// the correct JSON, and so a future openaicompat audio path (custom HTTP
// invocation that bypasses the typed SDK builder) can serialize it directly.
//
// Wire reference (OpenAI Chat Completions API for gpt-4o-audio-preview):
//
//	{
//	  "type": "input_audio",
//	  "input_audio": {
//	    "data":   "<base64-encoded audio bytes>",
//	    "format": "wav" | "mp3"
//	  }
//	}
type AudioContentPart struct {
	Type       string            `json:"type"` // always "input_audio"
	InputAudio InputAudioPayload `json:"input_audio"`
}

// InputAudioPayload carries the audio bytes and an OpenAI-recognized format
// string ("wav" or "mp3"). Use AudioFormatFromMime to derive Format from a
// standard MIME type.
type InputAudioPayload struct {
	Data   string `json:"data"`
	Format string `json:"format"`
}

// AudioFormatFromMime maps a standard audio MIME type to the OpenAI format
// string accepted by gpt-4o-audio-preview's input_audio content part.
// Returns "" for unsupported types so callers can decide whether to skip
// the part or surface an error.
func AudioFormatFromMime(mime string) string {
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "audio/wav", "audio/x-wav", "audio/wave":
		return "wav"
	case "audio/mp3", "audio/mpeg":
		return "mp3"
	default:
		return ""
	}
}
