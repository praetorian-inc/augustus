package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestOpenAI_Generate_AudioPath(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		if !strings.Contains(string(b), "input_audio") {
			t.Errorf("request body missing input_audio: %s", b)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"","audio":{"data":"QUJD","transcript":"sure, here is how"}}}],"usage":{"total_tokens":10}}`)
	}))
	defer srv.Close()

	g, err := NewOpenAITyped(Config{Model: "gpt-4o-audio-preview", APIKey: "sk-test", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if !g.SupportsAudio() {
		t.Fatal("SupportsAudio() = false, want true for chat model")
	}

	conv := attempt.NewConversation()
	conv.AddPromptMessage(attempt.NewUserMessageWithAudio("play this", []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}))

	resp, err := g.Generate(context.Background(), conv, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) != 1 || len(resp[0].Audio) != 1 || resp[0].Audio[0].Base64 != "QUJD" {
		t.Fatalf("audio not returned: %#v", resp)
	}
	if resp[0].Content != "sure, here is how" {
		t.Fatalf("transcript content = %q", resp[0].Content)
	}
	if g.AccumulatedTokens() != 10 {
		t.Fatalf("tokens = %d, want 10", g.AccumulatedTokens())
	}
}
