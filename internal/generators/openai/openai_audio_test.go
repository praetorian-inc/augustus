package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

// TestOpenAI_Generate_AudioFanOut verifies that n>1 on the audio path issues n
// separate requests (gpt-4o-audio-preview can't return n>1 in one call) and
// aggregates the responses, honoring Generate's contract instead of silently
// returning a single message.
func TestOpenAI_Generate_AudioFanOut(t *testing.T) {
	// atomic even though generateChatAudio fans out sequentially today: the
	// counter is written from server goroutines and read from the test
	// goroutine, so this stays race-free if the fan-out is ever parallelized.
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"choices":[{"message":{"content":"ok"}}],"usage":{"total_tokens":3}}`)
	}))
	defer srv.Close()

	g, err := NewOpenAITyped(Config{Model: "gpt-4o-audio-preview", APIKey: "sk-test", BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	conv := attempt.NewConversation()
	conv.AddPromptMessage(attempt.NewUserMessageWithAudio("play this", []attempt.Audio{{MimeType: "audio/wav", Base64: "UklGRg=="}}))

	resp, err := g.Generate(context.Background(), conv, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests = %d, want 3 (one per requested completion)", got)
	}
	if len(resp) != 3 {
		t.Fatalf("len(resp) = %d, want 3", len(resp))
	}
	if g.AccumulatedTokens() != 9 {
		t.Fatalf("tokens = %d, want 9 (3 requests x 3)", g.AccumulatedTokens())
	}
}

// TestOpenAI_AudioHTTPClientHasTimeout verifies the custom audio HTTP client
// carries a finite request timeout so a hung upstream can't block indefinitely.
func TestOpenAI_AudioHTTPClientHasTimeout(t *testing.T) {
	g, err := NewOpenAITyped(Config{Model: "gpt-4o-audio-preview", APIKey: "sk-test"})
	if err != nil {
		t.Fatal(err)
	}
	if g.httpClient.Timeout <= 0 {
		t.Fatalf("httpClient.Timeout = %v, want > 0", g.httpClient.Timeout)
	}
}
