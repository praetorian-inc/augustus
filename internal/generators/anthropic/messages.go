package anthropic

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Message is the wire-format message for Anthropic's Messages API.
// Content is json.RawMessage so it can hold either a plain string
// (text-only turns) or a JSON array of typed content blocks (multimodal turns).
// AWS Bedrock's Claude invocation accepts the same shape.
type Message struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

// BuildMessages converts an Augustus Conversation into Anthropic Messages API
// wire format. It returns the messages array and the system prompt (extracted
// from conv.System, since Anthropic carries the system prompt as a top-level
// request field, not as a message).
//
// When a turn has no attachments, the message Content is a plain string
// (preserves backwards-compatible JSON shape). When attachments are present,
// Content becomes a JSON array of typed content blocks per the Anthropic spec:
//
//	{"type": "text",  "text": "..."}
//	{"type": "image", "source": {"type": "base64", "media_type": "...", "data": "..."}}
//
// This helper is exported so the Bedrock generator can reuse it for Claude
// models hosted on AWS (identical wire format).
func BuildMessages(conv *attempt.Conversation) ([]Message, string, error) {
	if conv == nil {
		return nil, "", nil
	}

	var system string
	if conv.System != nil {
		system = conv.System.Content
	}

	messages := make([]Message, 0, len(conv.Turns)*2)
	for _, turn := range conv.Turns {
		userContent, err := buildContent(&turn.Prompt)
		if err != nil {
			return nil, "", fmt.Errorf("anthropic: build user content: %w", err)
		}
		messages = append(messages, Message{Role: "user", Content: userContent})

		if turn.Response != nil {
			// Assistant responses are always plain text in Augustus.
			respContent, err := json.Marshal(turn.Response.Content)
			if err != nil {
				return nil, "", fmt.Errorf("anthropic: marshal assistant content: %w", err)
			}
			messages = append(messages, Message{Role: "assistant", Content: respContent})
		}
	}
	return messages, system, nil
}

// buildContent serializes a single Message into the Anthropic content field.
// Text-only messages marshal to a plain JSON string; multimodal messages
// (images and/or documents) marshal to a JSON array of typed content blocks.
func buildContent(msg *attempt.Message) (json.RawMessage, error) {
	if len(msg.Images) == 0 && len(msg.Documents) == 0 {
		// Backwards-compatible: emit plain string.
		return json.Marshal(msg.Content)
	}

	blocks := make([]any, 0, 1+len(msg.Images)+len(msg.Documents))
	if msg.Content != "" {
		blocks = append(blocks, map[string]any{
			"type": "text",
			"text": msg.Content,
		})
	}
	for _, img := range msg.Images {
		blocks = append(blocks, map[string]any{
			"type": "image",
			"source": map[string]any{
				"type":       "base64",
				"media_type": img.MimeType,
				"data":       img.ToBase64(),
			},
		})
	}
	for _, doc := range msg.Documents {
		blocks = append(blocks, map[string]any{
			"type": "document",
			"source": map[string]any{
				"type":       "base64",
				"media_type": doc.MimeType,
				"data":       doc.ToBase64(),
			},
		})
	}
	return json.Marshal(blocks)
}
