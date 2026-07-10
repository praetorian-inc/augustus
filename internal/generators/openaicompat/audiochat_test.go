package openaicompat

import (
	"encoding/json"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestBuildAudioChatBody_EmitsInputAudio(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPromptMessage(attempt.NewUserMessageWithAudio("listen", []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}))

	body, err := BuildAudioChatBody("gpt-4o-audio-preview", conv, AudioChatParams{Voice: "alloy", Format: "wav"})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	mods, _ := got["modalities"].([]any)
	if len(mods) != 2 {
		t.Fatalf("modalities = %v, want [text audio]", got["modalities"])
	}
	msgs := got["messages"].([]any)
	parts := msgs[0].(map[string]any)["content"].([]any)
	foundAudio := false
	for _, p := range parts {
		if p.(map[string]any)["type"] == "input_audio" {
			foundAudio = true
		}
	}
	if !foundAudio {
		t.Fatalf("no input_audio part in %s", body)
	}
}

func TestParseAudioChatResponse_CapturesAudio(t *testing.T) {
	raw := `{"choices":[{"message":{"content":"","audio":{"data":"QUJD","transcript":"hello"}}}],"usage":{"total_tokens":42}}`
	msgs, tokens, err := ParseAudioChatResponse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 42 {
		t.Fatalf("tokens = %d, want 42", tokens)
	}
	if len(msgs) != 1 || len(msgs[0].Audio) != 1 || msgs[0].Audio[0].Base64 != "QUJD" {
		t.Fatalf("audio not captured: %#v", msgs)
	}
	if msgs[0].Content != "hello" {
		t.Fatalf("transcript not used as content: %q", msgs[0].Content)
	}
}
