package bedrock

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// Amazon Nova on Bedrock uses its own native wire format, distinct from both
// Anthropic's Messages API and the legacy InvokeModel bodies of Titan / Llama.
//
// Request (messages-v1 schema):
//
//	{
//	  "schemaVersion": "messages-v1",
//	  "messages": [
//	    {
//	      "role": "user",
//	      "content": [
//	        {"text": "describe"},
//	        {"image": {"format": "png", "source": {"bytes": "<base64>"}}}
//	      ]
//	    }
//	  ],
//	  "system": [{"text": "..."}],          // optional, array form
//	  "inferenceConfig": {
//	    "max_new_tokens": 300,
//	    "temperature": 0.7,
//	    "top_p": 0.9
//	  }
//	}
//
// Response:
//
//	{
//	  "output": {"message": {"role": "assistant", "content": [{"text": "..."}]}},
//	  "stopReason": "end_turn",
//	  "usage": {"inputTokens": N, "outputTokens": N, "totalTokens": N}
//	}

// buildNovaRequest builds a request for Amazon Nova models on Bedrock.
// Nova natively supports text + image (and video, not yet wired). Image
// attachments on user turns are emitted as {image: {format, source: {bytes}}}
// content blocks.
func (g *Bedrock) buildNovaRequest(conv *attempt.Conversation) ([]byte, error) {
	messages := make([]map[string]any, 0, len(conv.Turns)*2)
	for _, turn := range conv.Turns {
		content, err := buildNovaContent(&turn.Prompt)
		if err != nil {
			return nil, err
		}
		messages = append(messages, map[string]any{
			"role":    "user",
			"content": content,
		})
		if turn.Response != nil {
			messages = append(messages, map[string]any{
				"role":    "assistant",
				"content": []any{map[string]any{"text": turn.Response.Content}},
			})
		}
	}

	inference := map[string]any{
		"max_new_tokens": g.maxTokens,
		"temperature":    g.temperature,
	}
	if g.topP > 0 {
		inference["top_p"] = g.topP
	}

	req := map[string]any{
		"schemaVersion":   "messages-v1",
		"messages":        messages,
		"inferenceConfig": inference,
	}

	if conv.System != nil && conv.System.Content != "" {
		req["system"] = []any{map[string]any{"text": conv.System.Content}}
	}

	return json.Marshal(req)
}

// buildNovaContent assembles a Nova content array from a Message: one
// {text: ...} block (if non-empty), followed by one {image: {...}} block per
// attached image. Images with unsupported MIME types are skipped rather than
// misrepresented to the API (see novaImageFormat). Documents and audio are
// not yet wired through Nova.
func buildNovaContent(msg *attempt.Message) ([]any, error) {
	blocks := make([]any, 0, 1+len(msg.Images))
	if msg.Content != "" {
		blocks = append(blocks, map[string]any{"text": msg.Content})
	}
	for _, img := range msg.Images {
		format := novaImageFormat(img.MimeType)
		if format == "" {
			// Skip rather than mislabel the bytes — Nova will decode
			// based on the declared format and would error on mismatch.
			continue
		}
		data, err := img.ToBase64()
		if err != nil {
			return nil, fmt.Errorf("bedrock nova: encode image: %w", err)
		}
		blocks = append(blocks, map[string]any{
			"image": map[string]any{
				"format": format,
				"source": map[string]any{
					"bytes": data,
				},
			},
		})
	}
	return blocks, nil
}

// novaImageFormat maps a standard image MIME type to Nova's "format" string.
// Nova accepts: "png", "jpeg", "gif", "webp". Returns "" for unrecognized
// types so callers can skip the image rather than misrepresent its format
// (Nova decodes based on the declared format — a wrong label corrupts data).
func novaImageFormat(mime string) string {
	switch strings.ToLower(strings.TrimSpace(mime)) {
	case "image/png":
		return "png"
	case "image/jpeg", "image/jpg":
		return "jpeg"
	case "image/gif":
		return "gif"
	case "image/webp":
		return "webp"
	default:
		return ""
	}
}

// parseNovaResponse parses a response from Amazon Nova models on Bedrock.
func (g *Bedrock) parseNovaResponse(body []byte) (string, error) {
	var resp struct {
		Output struct {
			Message struct {
				Role    string `json:"role"`
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
		StopReason string `json:"stopReason"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}

	var text string
	for _, block := range resp.Output.Message.Content {
		text += block.Text
	}
	return text, nil
}
