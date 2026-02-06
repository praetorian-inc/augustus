package attempt

import "time"

// Image represents an image attachment for multimodal attacks.
//
// Images can be provided in three ways:
// - Raw bytes (Data field)
// - Base64 encoded string (Base64 field)
// - File path (Path field)
type Image struct {
	// Data contains the raw image bytes.
	Data []byte `json:"data,omitempty"`

	// Base64 contains the base64-encoded image data.
	Base64 string `json:"base64,omitempty"`

	// MimeType specifies the image format (e.g., "image/png", "image/jpeg").
	MimeType string `json:"mime_type"`

	// Path is the filesystem path to the image file.
	Path string `json:"path,omitempty"`
}

// Audio represents an audio attachment for multimodal attacks.
//
// Audio can be provided in three ways:
// - Raw bytes (Data field)
// - Base64 encoded string (Base64 field)
// - File path (Path field)
type Audio struct {
	// Data contains the raw audio bytes.
	Data []byte `json:"data,omitempty"`

	// Base64 contains the base64-encoded audio data.
	Base64 string `json:"base64,omitempty"`

	// MimeType specifies the audio format (e.g., "audio/mp3", "audio/wav").
	MimeType string `json:"mime_type"`

	// Path is the filesystem path to the audio file.
	Path string `json:"path,omitempty"`

	// Duration specifies the length of the audio.
	Duration time.Duration `json:"duration,omitempty"`
}

// MultimodalAttempt extends Attempt to include image and audio data.
//
// This enables probes to test LLMs with multimodal inputs (text + images + audio).
// The embedded Attempt contains the text prompt and text-based responses,
// while Images and Audio contain the multimodal attachments.
type MultimodalAttempt struct {
	// Attempt is the base attempt with text prompts and outputs.
	Attempt

	// Images contains image attachments sent to the model.
	Images []Image `json:"images,omitempty"`

	// Audio contains audio attachments sent to the model.
	Audio []Audio `json:"audio,omitempty"`
}
