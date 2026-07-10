package openaicompat

import (
	"encoding/json"
	"strings"
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
	if len(mods) != 2 || mods[0] != "text" || mods[1] != "audio" {
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
	msgs, tokens, err := ParseAudioChatResponse([]byte(raw), "wav")
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 42 {
		t.Fatalf("tokens = %d, want 42", tokens)
	}
	if len(msgs) != 1 || len(msgs[0].Audio) != 1 || msgs[0].Audio[0].Base64 != "QUJD" {
		t.Fatalf("audio not captured: %#v", msgs)
	}
	if msgs[0].Audio[0].MimeType != "audio/wav" {
		t.Fatalf("MimeType = %q, want audio/wav", msgs[0].Audio[0].MimeType)
	}
	if msgs[0].Content != "hello" {
		t.Fatalf("transcript not used as content: %q", msgs[0].Content)
	}
}

func TestParseAudioChatResponse_MP3MimeType(t *testing.T) {
	raw := `{"choices":[{"message":{"content":"","audio":{"data":"QUJD","transcript":"hello"}}}],"usage":{"total_tokens":7}}`
	msgs, _, err := ParseAudioChatResponse([]byte(raw), "mp3")
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || len(msgs[0].Audio) != 1 {
		t.Fatalf("audio not captured: %#v", msgs)
	}
	if msgs[0].Audio[0].MimeType != "audio/mpeg" {
		t.Fatalf("MimeType = %q, want audio/mpeg", msgs[0].Audio[0].MimeType)
	}
}

func TestParseAudioChatResponse_APIError(t *testing.T) {
	raw := `{"error":{"message":"boom"}}`
	_, _, err := ParseAudioChatResponse([]byte(raw), "wav")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("error = %q, want it to contain %q", err.Error(), "boom")
	}
}

func TestBuildAudioChatBody_UnsupportedMime(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPromptMessage(attempt.NewUserMessageWithAudio("listen", []attempt.Audio{{MimeType: "audio/flac", Base64: "UklGRg=="}}))

	_, err := BuildAudioChatBody("gpt-4o-audio-preview", conv, AudioChatParams{Voice: "alloy", Format: "wav"})
	if err == nil {
		t.Fatal("expected error for unsupported MIME type, got nil")
	}
}

func TestBuildAudioChatBody_DefaultsVoiceAndFormat(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPromptMessage(attempt.NewUserMessage("hello"))

	body, err := BuildAudioChatBody("gpt-4o-audio-preview", conv, AudioChatParams{})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	audio, _ := got["audio"].(map[string]any)
	if audio["voice"] != "alloy" {
		t.Fatalf("audio.voice = %v, want alloy", audio["voice"])
	}
	if audio["format"] != "wav" {
		t.Fatalf("audio.format = %v, want wav", audio["format"])
	}
}
