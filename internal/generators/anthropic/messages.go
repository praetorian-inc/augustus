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

	// Build an intermediate slice whose Content is `any` so that consecutive
	// tool_result turns can be coalesced into a single user message (Anthropic
	// rejects consecutive same-role messages and requires all tool_result blocks
	// for one assistant turn to be sent in a single user message). Each entry is
	// marshaled to json.RawMessage at the end to produce the wire-format
	// []Message.
	type intermediate struct {
		Role    string
		Content any
	}

	built := make([]intermediate, 0, len(conv.Turns)*2)
	for i := range conv.Turns {
		turn := &conv.Turns[i]
		switch turn.Prompt.Role {
		case attempt.RoleTool:
			// Tool result: append a tool_result block, coalescing consecutive
			// RoleTool turns into a single user message.
			block := map[string]any{
				"type":        "tool_result",
				"tool_use_id": turn.Prompt.ToolCallID,
				"content":     turn.Prompt.Content,
			}
			if i > 0 && conv.Turns[i-1].Prompt.Role == attempt.RoleTool {
				last := &built[len(built)-1]
				blocks, _ := last.Content.([]any)
				last.Content = append(blocks, block)
			} else {
				built = append(built, intermediate{Role: "user", Content: []any{block}})
			}
		default:
			// Standard user prompt with optional text/image/document blocks.
			userContent, err := buildContent(&turn.Prompt)
			if err != nil {
				return nil, "", fmt.Errorf("anthropic: build user content: %w", err)
			}
			built = append(built, intermediate{Role: "user", Content: userContent})
		}

		if turn.Response != nil {
			if len(turn.Response.ToolCalls) > 0 {
				// Assistant with tool_use blocks: structured content.
				content := make([]any, 0, 1+len(turn.Response.ToolCalls))
				if turn.Response.Content != "" {
					content = append(content, map[string]any{
						"type": "text",
						"text": turn.Response.Content,
					})
				}
				for _, tc := range turn.Response.ToolCalls {
					name, _ := tc["name"].(string)
					id, _ := tc["id"].(string)
					if id == "" {
						id = "toolu_" + name
					}
					args, _ := tc["args"].(map[string]any)
					if args == nil {
						args = map[string]any{}
					}
					content = append(content, map[string]any{
						"type":  "tool_use",
						"id":    id,
						"name":  name,
						"input": args,
					})
				}
				built = append(built, intermediate{Role: "assistant", Content: content})
			} else {
				// Plain text assistant response.
				built = append(built, intermediate{Role: "assistant", Content: turn.Response.Content})
			}
		}
	}

	messages := make([]Message, 0, len(built))
	for _, m := range built {
		raw, ok := m.Content.(json.RawMessage)
		if !ok {
			marshaled, err := json.Marshal(m.Content)
			if err != nil {
				return nil, "", fmt.Errorf("anthropic: marshal %s content: %w", m.Role, err)
			}
			raw = marshaled
		}
		messages = append(messages, Message{Role: m.Role, Content: raw})
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
		data, err := img.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("anthropic: encode image: %w", err)
		}
		blocks = append(blocks, map[string]any{
			"type": "image",
			"source": map[string]any{
				"type":       "base64",
				"media_type": img.MimeType,
				"data":       data,
			},
		})
	}
	for _, doc := range msg.Documents {
		data, err := doc.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("anthropic: encode document: %w", err)
		}
		blocks = append(blocks, map[string]any{
			"type": "document",
			"source": map[string]any{
				"type":       "base64",
				"media_type": doc.MimeType,
				"data":       data,
			},
		})
	}
	return json.Marshal(blocks)
}
