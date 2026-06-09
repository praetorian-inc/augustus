package anthropic

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

func TestBuildMessages_TextOnly_PreservesStringShape(t *testing.T) {
	// When no attachments are present, Content must marshal to a plain JSON
	// string. This preserves byte-for-byte wire compatibility with the
	// pre-multimodal Anthropic generator.
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessage("hello")},
		},
	}

	msgs, system, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	if system != "" {
		t.Errorf("expected empty system, got %q", system)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	if string(msgs[0].Content) != `"hello"` {
		t.Errorf("expected plain string content, got %s", string(msgs[0].Content))
	}
}

func TestBuildMessages_WithSystem(t *testing.T) {
	sys := attempt.NewSystemMessage("be helpful")
	conv := &attempt.Conversation{
		System: &sys,
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessage("hi")},
		},
	}

	msgs, system, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	if system != "be helpful" {
		t.Errorf("expected system to be extracted, got %q", system)
	}
	// System must NOT appear in messages array (Anthropic carries it as top-level field).
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
}

func TestBuildMessages_WithImage(t *testing.T) {
	img := attempt.Image{
		Data:     []byte{0xDE, 0xAD, 0xBE, 0xEF},
		MimeType: "image/png",
	}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessageWithImages("describe this", []attempt.Image{img})},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	// Decode the content array
	var blocks []map[string]any
	if err := json.Unmarshal(msgs[0].Content, &blocks); err != nil {
		t.Fatalf("expected content array, got %s: %v", string(msgs[0].Content), err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks (text + image), got %d", len(blocks))
	}
	if blocks[0]["type"] != "text" || blocks[0]["text"] != "describe this" {
		t.Errorf("expected text block first, got %+v", blocks[0])
	}
	if blocks[1]["type"] != "image" {
		t.Errorf("expected image block second, got %+v", blocks[1])
	}
	source, ok := blocks[1]["source"].(map[string]any)
	if !ok {
		t.Fatalf("expected image.source object, got %T", blocks[1]["source"])
	}
	if source["type"] != "base64" {
		t.Errorf("expected source.type=base64, got %v", source["type"])
	}
	if source["media_type"] != "image/png" {
		t.Errorf("expected source.media_type=image/png, got %v", source["media_type"])
	}
	expectedB64 := base64.StdEncoding.EncodeToString(img.Data)
	if source["data"] != expectedB64 {
		t.Errorf("expected base64 image bytes, got %v", source["data"])
	}
}

func TestBuildMessages_WithMultipleImages(t *testing.T) {
	images := []attempt.Image{
		{Data: []byte{0x01}, MimeType: "image/png"},
		{Data: []byte{0x02}, MimeType: "image/jpeg"},
		{Data: []byte{0x03}, MimeType: "image/webp"},
	}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessageWithImages("compare", images)},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	var blocks []map[string]any
	if err := json.Unmarshal(msgs[0].Content, &blocks); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	// 1 text + 3 image blocks
	if len(blocks) != 4 {
		t.Fatalf("expected 4 blocks, got %d", len(blocks))
	}
	gotMimes := []string{}
	for _, b := range blocks[1:] {
		src := b["source"].(map[string]any)
		gotMimes = append(gotMimes, src["media_type"].(string))
	}
	want := []string{"image/png", "image/jpeg", "image/webp"}
	for i, mt := range want {
		if gotMimes[i] != mt {
			t.Errorf("image block %d: expected media_type %q, got %q", i, mt, gotMimes[i])
		}
	}
}

func TestBuildMessages_WithSystemAndImage(t *testing.T) {
	sys := attempt.NewSystemMessage("you are a vision model")
	img := attempt.Image{Data: []byte{0xFF}, MimeType: "image/png"}
	conv := &attempt.Conversation{
		System: &sys,
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessageWithImages("ocr this", []attempt.Image{img})},
		},
	}

	msgs, system, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	if system != "you are a vision model" {
		t.Errorf("system not extracted; got %q", system)
	}
	// System still doesn't appear in messages; image still emitted as content blocks.
	if len(msgs) != 1 {
		t.Fatalf("expected 1 user message, got %d", len(msgs))
	}
	if !strings.Contains(string(msgs[0].Content), `"type":"image"`) {
		t.Errorf("expected image block in content: %s", string(msgs[0].Content))
	}
}

func TestBuildMessages_MixedTurns(t *testing.T) {
	// Turn 1: image, Turn 2: text-only follow-up.
	img := attempt.Image{Data: []byte{0xAA}, MimeType: "image/png"}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{
				Prompt:   attempt.NewUserMessageWithImages("look", []attempt.Image{img}),
				Response: ptrMsg(attempt.NewAssistantMessage("ok i see it")),
			},
			{Prompt: attempt.NewUserMessage("what color?")},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 messages (user+image, assistant, user), got %d", len(msgs))
	}
	// Turn 1 user: content blocks array
	if !strings.HasPrefix(string(msgs[0].Content), "[") {
		t.Errorf("turn 1 user should be array; got %s", string(msgs[0].Content))
	}
	// Assistant: plain string
	if string(msgs[1].Content) != `"ok i see it"` {
		t.Errorf("assistant should be plain string; got %s", string(msgs[1].Content))
	}
	// Turn 2 user: plain string (no images)
	if string(msgs[2].Content) != `"what color?"` {
		t.Errorf("turn 2 user should be plain string; got %s", string(msgs[2].Content))
	}
}

func TestBuildMessages_EmptyTextWithImage(t *testing.T) {
	// When text is empty but image is present, text block should be omitted.
	img := attempt.Image{Data: []byte{0xBE, 0xEF}, MimeType: "image/png"}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessageWithImages("", []attempt.Image{img})},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	var blocks []map[string]any
	if err := json.Unmarshal(msgs[0].Content, &blocks); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if len(blocks) != 1 {
		t.Fatalf("expected 1 block (image only), got %d", len(blocks))
	}
	if blocks[0]["type"] != "image" {
		t.Errorf("expected image block, got %v", blocks[0]["type"])
	}
}

func TestBuildMessages_WithDocument(t *testing.T) {
	doc := attempt.Document{
		Data:     []byte("%PDF-1.4 fake"),
		MimeType: "application/pdf",
	}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.NewUserMessageWithDocuments("summarize this", []attempt.Document{doc})},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}

	var blocks []map[string]any
	if err := json.Unmarshal(msgs[0].Content, &blocks); err != nil {
		t.Fatalf("expected content array, got %s: %v", string(msgs[0].Content), err)
	}
	if len(blocks) != 2 {
		t.Fatalf("expected 2 blocks (text + document), got %d", len(blocks))
	}
	if blocks[0]["type"] != "text" || blocks[0]["text"] != "summarize this" {
		t.Errorf("expected text block first, got %+v", blocks[0])
	}
	if blocks[1]["type"] != "document" {
		t.Errorf("expected document block second, got %+v", blocks[1])
	}
	source, ok := blocks[1]["source"].(map[string]any)
	if !ok {
		t.Fatalf("expected document.source object, got %T", blocks[1]["source"])
	}
	if source["type"] != "base64" || source["media_type"] != "application/pdf" {
		t.Errorf("unexpected document source: %+v", source)
	}
	expectedB64 := base64.StdEncoding.EncodeToString(doc.Data)
	if source["data"] != expectedB64 {
		t.Errorf("expected base64 doc bytes, got %v", source["data"])
	}
}

func TestBuildMessages_WithImageAndDocument(t *testing.T) {
	img := attempt.Image{Data: []byte{0x01}, MimeType: "image/png"}
	doc := attempt.Document{Data: []byte("%PDF"), MimeType: "application/pdf"}
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{Prompt: attempt.Message{
				Role:      attempt.RoleUser,
				Content:   "both",
				Images:    []attempt.Image{img},
				Documents: []attempt.Document{doc},
			}},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}

	var blocks []map[string]any
	if err := json.Unmarshal(msgs[0].Content, &blocks); err != nil {
		t.Fatalf("decode content: %v", err)
	}
	if len(blocks) != 3 {
		t.Fatalf("expected 3 blocks (text + image + document), got %d", len(blocks))
	}
	wantTypes := []string{"text", "image", "document"}
	for i, w := range wantTypes {
		if blocks[i]["type"] != w {
			t.Errorf("block %d: want type %q, got %v", i, w, blocks[i]["type"])
		}
	}
}

func TestBuildMessages_NilConversation(t *testing.T) {
	msgs, system, err := BuildMessages(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 0 || system != "" {
		t.Errorf("expected empty results for nil conv, got %d msgs / system=%q", len(msgs), system)
	}
}

func ptrMsg(m attempt.Message) *attempt.Message { return &m }

// TestBuildMessages_AssistantResponseOnly verifies that turns containing only
// an assistant response (with empty/default user Prompt) still serialize
// cleanly. This shouldn't happen in normal Augustus flow, but BuildMessages
// is exported and may be called from less constrained contexts.
func TestBuildMessages_AssistantResponseOnly(t *testing.T) {
	conv := &attempt.Conversation{
		Turns: []attempt.Turn{
			{
				Prompt:   attempt.NewUserMessage(""),
				Response: ptrMsg(attempt.NewAssistantMessage("hello back")),
			},
		},
	}

	msgs, _, err := BuildMessages(conv)
	if err != nil {
		t.Fatalf("BuildMessages: %v", err)
	}
	// Two messages — user (empty string content) + assistant.
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	if string(msgs[0].Content) != `""` {
		t.Errorf("expected empty user content as JSON empty string, got %s", string(msgs[0].Content))
	}
	if string(msgs[1].Content) != `"hello back"` {
		t.Errorf("expected assistant content as plain string, got %s", string(msgs[1].Content))
	}
}
