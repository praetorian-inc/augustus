// Package openaicompat provides shared functions for OpenAI-compatible API generators.
package openaicompat

import (
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	goopenai "github.com/sashabaranov/go-openai"
)

func TestConversationToMessages_TextOnly(t *testing.T) {
	conv := attempt.NewConversation()
	conv.AddPrompt("hello world")

	msgs, err := ConversationToMessages(conv)
	if err != nil {
		t.Fatalf("ConversationToMessages returned error: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	msg := msgs[0]
	if msg.Role != goopenai.ChatMessageRoleUser {
		t.Errorf("Expected role %q, got %q", goopenai.ChatMessageRoleUser, msg.Role)
	}
	if msg.Content != "hello world" {
		t.Errorf("Expected content %q, got %q", "hello world", msg.Content)
	}
	if msg.MultiContent != nil {
		t.Error("Expected MultiContent to be nil for text-only message")
	}
}

func TestConversationToMessages_WithImages(t *testing.T) {
	conv := attempt.NewConversation()
	msg := attempt.NewUserMessageWithImages("describe this image", []attempt.Image{
		{MimeType: "image/png", Base64: "dGVzdA=="},
	})
	conv.AddPromptMessage(msg)

	msgs, err := ConversationToMessages(conv)
	if err != nil {
		t.Fatalf("ConversationToMessages returned error: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	out := msgs[0]
	if out.Role != goopenai.ChatMessageRoleUser {
		t.Errorf("Expected role %q, got %q", goopenai.ChatMessageRoleUser, out.Role)
	}
	// Must use MultiContent, not Content
	if out.Content != "" {
		t.Errorf("Expected Content to be empty for multimodal message, got %q", out.Content)
	}
	if len(out.MultiContent) != 2 {
		t.Fatalf("Expected 2 parts (text + image), got %d", len(out.MultiContent))
	}

	textPart := out.MultiContent[0]
	if textPart.Type != goopenai.ChatMessagePartTypeText {
		t.Errorf("Expected first part type %q, got %q", goopenai.ChatMessagePartTypeText, textPart.Type)
	}
	if textPart.Text != "describe this image" {
		t.Errorf("Expected text part %q, got %q", "describe this image", textPart.Text)
	}

	imgPart := out.MultiContent[1]
	if imgPart.Type != goopenai.ChatMessagePartTypeImageURL {
		t.Errorf("Expected second part type %q, got %q", goopenai.ChatMessagePartTypeImageURL, imgPart.Type)
	}
	if imgPart.ImageURL == nil {
		t.Fatal("Expected ImageURL to be set")
	}
	if !strings.HasPrefix(imgPart.ImageURL.URL, "data:image/png;base64,") {
		t.Errorf("Expected data URL prefix, got %q", imgPart.ImageURL.URL)
	}
	if imgPart.ImageURL.Detail != goopenai.ImageURLDetailAuto {
		t.Errorf("Expected detail %q, got %q", goopenai.ImageURLDetailAuto, imgPart.ImageURL.Detail)
	}
}

func TestConversationToMessages_WithMultipleImages(t *testing.T) {
	conv := attempt.NewConversation()
	msg := attempt.NewUserMessageWithImages("compare these", []attempt.Image{
		{MimeType: "image/png", Base64: "aW1nMQ=="},
		{MimeType: "image/jpeg", Base64: "aW1nMg=="},
	})
	conv.AddPromptMessage(msg)

	msgs, err := ConversationToMessages(conv)
	if err != nil {
		t.Fatalf("ConversationToMessages returned error: %v", err)
	}

	if len(msgs) != 1 {
		t.Fatalf("Expected 1 message, got %d", len(msgs))
	}
	// 1 text + 2 images = 3 parts
	if len(msgs[0].MultiContent) != 3 {
		t.Errorf("Expected 3 parts, got %d", len(msgs[0].MultiContent))
	}
}

func TestConversationToMessages_WithSystemAndImages(t *testing.T) {
	conv := attempt.NewConversation()
	conv.WithSystem("You are a vision model.")
	msg := attempt.NewUserMessageWithImages("look at this", []attempt.Image{
		{MimeType: "image/png", Base64: "dGVzdA=="},
	})
	conv.AddPromptMessage(msg)

	msgs, err := ConversationToMessages(conv)
	if err != nil {
		t.Fatalf("ConversationToMessages returned error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("Expected 2 messages (system + user), got %d", len(msgs))
	}
	if msgs[0].Role != goopenai.ChatMessageRoleSystem {
		t.Errorf("Expected first message to be system, got %q", msgs[0].Role)
	}
	if msgs[1].MultiContent == nil {
		t.Error("Expected second message to have MultiContent")
	}
}

func TestConversationToMessages_MixedTurns(t *testing.T) {
	conv := attempt.NewConversation()
	// First turn: text only
	conv.AddPrompt("text only turn")
	// Second turn: with image
	conv.AddPromptMessage(attempt.NewUserMessageWithImages("image turn", []attempt.Image{
		{MimeType: "image/png", Base64: "dGVzdA=="},
	}))

	msgs, err := ConversationToMessages(conv)
	if err != nil {
		t.Fatalf("ConversationToMessages returned error: %v", err)
	}

	if len(msgs) != 2 {
		t.Fatalf("Expected 2 messages, got %d", len(msgs))
	}
	// First message: text-only path
	if msgs[0].Content != "text only turn" {
		t.Errorf("Expected text-only content, got %q", msgs[0].Content)
	}
	if msgs[0].MultiContent != nil {
		t.Error("Text-only turn should not have MultiContent")
	}
	// Second message: multipart path
	if msgs[1].Content != "" {
		t.Errorf("Image turn should not set Content, got %q", msgs[1].Content)
	}
	if len(msgs[1].MultiContent) != 2 {
		t.Errorf("Expected 2 parts in image turn, got %d", len(msgs[1].MultiContent))
	}
}
