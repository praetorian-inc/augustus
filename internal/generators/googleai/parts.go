package googleai

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// inlineImageMIMEs is the set of image MIME types Gemini accepts as inline_data
// on both the direct API and Vertex AI.
// https://ai.google.dev/gemini-api/docs/image-understanding
var inlineImageMIMEs = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
	"image/heic": true,
	"image/heif": true,
}

// inlineDocumentMIMEs is the set of document MIME types Gemini accepts as
// inline_data on both the direct API and Vertex AI. The document harness
// (internal/probes/pdf) only produces PDFs, so PDF is the sole supported type;
// mirrors inlineImageMIMEs and keeps unsupported types a loud error rather than
// a silently dropped attachment.
// https://ai.google.dev/gemini-api/docs/document-processing
var inlineDocumentMIMEs = map[string]bool{
	"application/pdf": true,
}

// BuildDocumentParts converts document attachments (e.g. PDFs) into Gemini
// inline_data parts, base64-encoding each document exactly once via
// Document.ToBase64. It mirrors BuildImageParts and is called by both the gemini
// (direct API) and vertex generators so their document handling cannot drift.
//
// It returns an error (rather than emitting a part the API will reject) when a
// document has an unset or unsupported MIME type, fails to encode, or resolves
// to no data. Callers should surface the error so a dropped attachment never
// masquerades as a clean text-only request.
func BuildDocumentParts(docs []attempt.Document) ([]ContentPart, error) {
	parts := make([]ContentPart, 0, len(docs))
	for _, doc := range docs {
		if doc.MimeType == "" {
			return nil, fmt.Errorf("googleai: document has empty MIME type")
		}
		if !inlineDocumentMIMEs[doc.MimeType] {
			return nil, fmt.Errorf("googleai: unsupported document MIME type %q (want application/pdf)", doc.MimeType)
		}
		data, err := doc.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("googleai: encode document: %w", err)
		}
		if data == "" {
			return nil, fmt.Errorf("googleai: document has no data (empty Data/Base64/Path)")
		}
		parts = append(parts, ContentPart{
			InlineData: &InlineData{MimeType: doc.MimeType, Data: data},
		})
	}
	return parts, nil
}

// BuildImageParts converts image attachments into Gemini inline_data parts,
// base64-encoding each image exactly once via Image.ToBase64.
//
// Both the gemini (direct API) and vertex generators call this so their
// multimodal handling cannot drift apart — historically vertex silently
// dropped images because it had no equivalent of gemini's part builder.
//
// It returns an error (rather than emitting a part the API will reject) when an
// image has an unset or unsupported MIME type, fails to encode, or resolves to
// no data. Callers should surface the error so a dropped attachment never
// masquerades as a clean text-only request.
func BuildImageParts(images []attempt.Image) ([]ContentPart, error) {
	parts := make([]ContentPart, 0, len(images))
	for _, img := range images {
		if img.MimeType == "" {
			return nil, fmt.Errorf("googleai: image has empty MIME type")
		}
		if !inlineImageMIMEs[img.MimeType] {
			return nil, fmt.Errorf("googleai: unsupported image MIME type %q (want one of png, jpeg, webp, heic, heif)", img.MimeType)
		}
		data, err := img.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("googleai: encode image: %w", err)
		}
		if data == "" {
			return nil, fmt.Errorf("googleai: image has no data (empty Data/Base64/Path)")
		}
		parts = append(parts, ContentPart{
			InlineData: &InlineData{MimeType: img.MimeType, Data: data},
		})
	}
	return parts, nil
}
