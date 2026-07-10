package openaicompat

import (
	"encoding/json"
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// AudioChatParams carries the tunable knobs for an audio chat request.
type AudioChatParams struct {
	Voice       string
	Format      string
	Temperature float32
	TopP        float32
	MaxTokens   int
}

type audioChatBody struct {
	Model       string             `json:"model"`
	Messages    []audioChatMessage `json:"messages"`
	Modalities  []string           `json:"modalities"`
	Audio       audioOutputConfig  `json:"audio"`
	Temperature float32            `json:"temperature,omitempty"`
	TopP        float32            `json:"top_p,omitempty"`
	MaxTokens   int                `json:"max_tokens,omitempty"`
}

type audioOutputConfig struct {
	Voice  string `json:"voice"`
	Format string `json:"format"`
}

type audioChatMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // string, or []content part
}

type textContentPart struct {
	Type string `json:"type"` // "text"
	Text string `json:"text"`
}

// BuildAudioChatBody serializes conv to the OpenAI Chat Completions request body
// for gpt-4o-audio-preview, emitting input_audio content parts. It requests both
// text and audio modalities so the response carries a transcript and audio bytes.
func BuildAudioChatBody(model string, conv *attempt.Conversation, p AudioChatParams) ([]byte, error) {
	voice := p.Voice
	if voice == "" {
		voice = "alloy"
	}
	format := p.Format
	if format == "" {
		format = "wav"
	}

	body := audioChatBody{
		Model:       model,
		Modalities:  []string{"text", "audio"},
		Audio:       audioOutputConfig{Voice: voice, Format: format},
		Temperature: p.Temperature,
		TopP:        p.TopP,
		MaxTokens:   p.MaxTokens,
	}

	if conv.System != nil {
		body.Messages = append(body.Messages, audioChatMessage{Role: "system", Content: conv.System.Content})
	}

	for _, turn := range conv.Turns {
		if len(turn.Prompt.Audio) == 0 {
			body.Messages = append(body.Messages, audioChatMessage{Role: "user", Content: turn.Prompt.Content})
		} else {
			parts := []any{textContentPart{Type: "text", Text: turn.Prompt.Content}}
			for _, au := range turn.Prompt.Audio {
				f := AudioFormatFromMime(au.MimeType)
				if f == "" {
					return nil, fmt.Errorf("openaicompat: unsupported audio MIME %q (want wav or mp3)", au.MimeType)
				}
				encoded, err := au.ToBase64()
				if err != nil {
					return nil, fmt.Errorf("openaicompat: encode audio: %w", err)
				}
				parts = append(parts, AudioContentPart{
					Type:       "input_audio",
					InputAudio: InputAudioPayload{Data: encoded, Format: f},
				})
			}
			body.Messages = append(body.Messages, audioChatMessage{Role: "user", Content: parts})
		}
		if turn.Response != nil {
			body.Messages = append(body.Messages, audioChatMessage{Role: "assistant", Content: turn.Response.Content})
		}
	}

	return json.Marshal(body)
}

type audioChatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
			Audio   *struct {
				Data       string `json:"data"`
				Transcript string `json:"transcript"`
			} `json:"audio"`
		} `json:"message"`
	} `json:"choices"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// mimeForAudioFormat maps a requested audio output format (as passed to
// BuildAudioChatBody) to the MIME type used to label captured response audio.
// Unknown or empty formats default to "audio/wav".
func mimeForAudioFormat(format string) string {
	switch format {
	case "mp3":
		return "audio/mpeg"
	case "wav":
		return "audio/wav"
	default:
		return "audio/wav"
	}
}

// ParseAudioChatResponse parses an OpenAI audio chat response into attempt
// messages. Returned audio bytes populate Message.Audio, labeled with the MIME
// type corresponding to format (the same format requested via
// AudioChatParams.Format when building the request); when the text content is
// empty the audio transcript is used as the message content.
func ParseAudioChatResponse(body []byte, format string) ([]attempt.Message, int, error) {
	var resp audioChatResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("openaicompat: decode audio response: %w", err)
	}
	if resp.Error != nil {
		return nil, 0, fmt.Errorf("openaicompat: api error: %s", resp.Error.Message)
	}

	mime := mimeForAudioFormat(format)
	messages := make([]attempt.Message, 0, len(resp.Choices))
	for _, c := range resp.Choices {
		content := c.Message.Content
		msg := attempt.NewAssistantMessage(content)
		if c.Message.Audio != nil && c.Message.Audio.Data != "" {
			msg.Audio = []attempt.Audio{{MimeType: mime, Base64: c.Message.Audio.Data}}
			if content == "" {
				msg.Content = c.Message.Audio.Transcript
			}
		}
		messages = append(messages, msg)
	}
	return messages, resp.Usage.TotalTokens, nil
}
