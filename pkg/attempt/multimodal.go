package attempt

import (
	"encoding/base64"
	"os"
	"time"
)

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

// ToBase64 returns the image data as a base64-encoded string.
// Priority: Base64 field > Data field > Path field.
// Returns empty string if no data is available.
func (img *Image) ToBase64() string {
	if img.Base64 != "" {
		return img.Base64
	}
	if len(img.Data) > 0 {
		return base64.StdEncoding.EncodeToString(img.Data)
	}
	if img.Path != "" {
		data, err := os.ReadFile(img.Path)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(data)
	}
	return ""
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

// ToBase64 returns the audio data as a base64-encoded string.
// Priority: Base64 field > Data field > Path field.
// Returns empty string if no data is available.
func (a *Audio) ToBase64() string {
	if a.Base64 != "" {
		return a.Base64
	}
	if len(a.Data) > 0 {
		return base64.StdEncoding.EncodeToString(a.Data)
	}
	if a.Path != "" {
		data, err := os.ReadFile(a.Path)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(data)
	}
	return ""
}

// Document represents a document attachment for multimodal attacks
// (e.g., PDFs for Anthropic Claude's native document content blocks,
// Gemini's inlineData with application/pdf, etc.).
//
// Documents can be provided in three ways:
// - Raw bytes (Data field)
// - Base64 encoded string (Base64 field)
// - File path (Path field)
type Document struct {
	// Data contains the raw document bytes.
	Data []byte `json:"data,omitempty"`

	// Base64 contains the base64-encoded document data.
	Base64 string `json:"base64,omitempty"`

	// MimeType specifies the document format (e.g., "application/pdf").
	MimeType string `json:"mime_type"`

	// Path is the filesystem path to the document file.
	Path string `json:"path,omitempty"`
}

// ToBase64 returns the document data as a base64-encoded string.
// Priority: Base64 field > Data field > Path field.
// Returns empty string if no data is available.
func (d *Document) ToBase64() string {
	if d.Base64 != "" {
		return d.Base64
	}
	if len(d.Data) > 0 {
		return base64.StdEncoding.EncodeToString(d.Data)
	}
	if d.Path != "" {
		data, err := os.ReadFile(d.Path)
		if err != nil {
			return ""
		}
		return base64.StdEncoding.EncodeToString(data)
	}
	return ""
}
