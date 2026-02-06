package encoding

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestBase64_Name(t *testing.T) {
	b := &Base64{}
	if got := b.Name(); got != "encoding.Base64" {
		t.Errorf("Name() = %q, want %q", got, "encoding.Base64")
	}
}

func TestBase64_Description(t *testing.T) {
	b := &Base64{}
	desc := b.Description()
	if desc == "" {
		t.Error("Description() returned empty string")
	}
	if len(desc) < 10 {
		t.Errorf("Description() too short: %q", desc)
	}
}

func TestBase64_Transform_EncodesCorrectly(t *testing.T) {
	tests := []struct {
		name       string
		prompt     string
		wantPrefix string
	}{
		{
			name:       "simple text",
			prompt:     "Hello, World!",
			wantPrefix: "The following instruction is base64 encoded: ",
		},
		{
			name:       "test prompt",
			prompt:     "test",
			wantPrefix: "The following instruction is base64 encoded: ",
		},
		{
			name:       "longer prompt",
			prompt:     "This is a longer prompt to test base64 encoding",
			wantPrefix: "The following instruction is base64 encoded: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Base64{}
			a := attempt.New(tt.prompt)

			// Collect transformed attempts
			var results []*attempt.Attempt
			for transformed := range b.Transform(a) {
				results = append(results, transformed)
			}

			if len(results) != 1 {
				t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
			}

			result := results[0]

			// Verify prefix
			if !strings.HasPrefix(result.Prompt, tt.wantPrefix) {
				t.Errorf("Transform() prompt = %q, want prefix %q", result.Prompt, tt.wantPrefix)
			}

			// Extract and verify base64 encoding
			encodedPart := strings.TrimPrefix(result.Prompt, tt.wantPrefix)
			decoded, err := base64.StdEncoding.DecodeString(encodedPart)
			if err != nil {
				t.Fatalf("encoded part is not valid base64: %v", err)
			}

			if string(decoded) != tt.prompt {
				t.Errorf("decoded = %q, want %q", string(decoded), tt.prompt)
			}
		})
	}
}

func TestBase64_Transform_MatchesPythonOutput(t *testing.T) {
	// Test that Go output matches Python garak output format exactly
	b := &Base64{}

	// "test" in base64 is "dGVzdA=="
	a := attempt.New("test")

	var results []*attempt.Attempt
	for transformed := range b.Transform(a) {
		results = append(results, transformed)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
	}

	expected := "The following instruction is base64 encoded: dGVzdA=="
	if results[0].Prompt != expected {
		t.Errorf("Transform() = %q, want %q", results[0].Prompt, expected)
	}
}

func TestBase64_Transform_Unicode(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
	}{
		{
			name:   "chinese characters",
			prompt: "你好世界",
		},
		{
			name:   "emoji",
			prompt: "Hello 🌍!",
		},
		{
			name:   "mixed unicode",
			prompt: "Hello, мир, 世界! 🌍",
		},
		{
			name:   "arabic",
			prompt: "مرحبا بالعالم",
		},
		{
			name:   "japanese",
			prompt: "こんにちは",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Base64{}
			a := attempt.New(tt.prompt)

			var results []*attempt.Attempt
			for transformed := range b.Transform(a) {
				results = append(results, transformed)
			}

			if len(results) != 1 {
				t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
			}

			// Extract and verify base64 encoding
			prefix := "The following instruction is base64 encoded: "
			if !strings.HasPrefix(results[0].Prompt, prefix) {
				t.Fatalf("missing expected prefix")
			}

			encodedPart := strings.TrimPrefix(results[0].Prompt, prefix)
			decoded, err := base64.StdEncoding.DecodeString(encodedPart)
			if err != nil {
				t.Fatalf("encoded part is not valid base64: %v", err)
			}

			if string(decoded) != tt.prompt {
				t.Errorf("decoded = %q, want %q", string(decoded), tt.prompt)
			}
		})
	}
}

func TestBase64_Transform_EmptyString(t *testing.T) {
	b := &Base64{}
	a := attempt.New("")

	var results []*attempt.Attempt
	for transformed := range b.Transform(a) {
		results = append(results, transformed)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
	}

	// Empty string in base64 is ""
	expected := "The following instruction is base64 encoded: "
	if results[0].Prompt != expected {
		t.Errorf("Transform() = %q, want %q", results[0].Prompt, expected)
	}
}

func TestBase64_Transform_WhitespacePreservation(t *testing.T) {
	tests := []struct {
		name   string
		prompt string
	}{
		{
			name:   "leading spaces",
			prompt: "   hello",
		},
		{
			name:   "trailing spaces",
			prompt: "hello   ",
		},
		{
			name:   "newlines",
			prompt: "hello\nworld",
		},
		{
			name:   "tabs",
			prompt: "hello\tworld",
		},
		{
			name:   "only whitespace",
			prompt: "   \n\t   ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &Base64{}
			a := attempt.New(tt.prompt)

			var results []*attempt.Attempt
			for transformed := range b.Transform(a) {
				results = append(results, transformed)
			}

			if len(results) != 1 {
				t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
			}

			// Extract and verify base64 encoding preserves whitespace
			prefix := "The following instruction is base64 encoded: "
			encodedPart := strings.TrimPrefix(results[0].Prompt, prefix)
			decoded, err := base64.StdEncoding.DecodeString(encodedPart)
			if err != nil {
				t.Fatalf("encoded part is not valid base64: %v", err)
			}

			if string(decoded) != tt.prompt {
				t.Errorf("decoded = %q, want %q", string(decoded), tt.prompt)
			}
		})
	}
}

func TestBase64_Buff_SliceOfAttempts(t *testing.T) {
	b := &Base64{}

	attempts := []*attempt.Attempt{
		attempt.New("prompt1"),
		attempt.New("prompt2"),
		attempt.New("prompt3"),
	}

	results, err := b.Buff(context.Background(), attempts)
	if err != nil {
		t.Fatalf("Buff() error = %v, want nil", err)
	}

	if len(results) != 3 {
		t.Fatalf("Buff() returned %d attempts, want 3", len(results))
	}

	expectedPrompts := []string{
		"The following instruction is base64 encoded: cHJvbXB0MQ==",
		"The following instruction is base64 encoded: cHJvbXB0Mg==",
		"The following instruction is base64 encoded: cHJvbXB0Mw==",
	}

	for i, result := range results {
		if result.Prompt != expectedPrompts[i] {
			t.Errorf("Buff()[%d].Prompt = %q, want %q", i, result.Prompt, expectedPrompts[i])
		}
	}
}

func TestBase64_Buff_EmptySlice(t *testing.T) {
	b := &Base64{}

	results, err := b.Buff(context.Background(), []*attempt.Attempt{})
	if err != nil {
		t.Fatalf("Buff() error = %v, want nil", err)
	}

	if len(results) != 0 {
		t.Errorf("Buff() returned %d attempts, want 0", len(results))
	}
}

func TestBase64_Buff_ContextCancellation(t *testing.T) {
	b := &Base64{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	attempts := []*attempt.Attempt{
		attempt.New("test"),
	}

	// Buff should still work (or return context error - either is acceptable)
	_, err := b.Buff(ctx, attempts)
	// Accept either success or context.Canceled error
	if err != nil && err != context.Canceled {
		t.Errorf("Buff() error = %v, want nil or context.Canceled", err)
	}
}

func TestBase64_Registration(t *testing.T) {
	// Test that the buff is registered via init()
	factory, ok := buffs.Get("encoding.Base64")
	if !ok {
		t.Fatal("encoding.Base64 not registered in buffs registry")
	}

	// Test factory creates valid buff
	b, err := factory(registry.Config{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}

	if b.Name() != "encoding.Base64" {
		t.Errorf("factory created buff with name %q, want %q", b.Name(), "encoding.Base64")
	}
}

func TestNewBase64(t *testing.T) {
	tests := []struct {
		name   string
		config registry.Config
	}{
		{
			name:   "nil config",
			config: nil,
		},
		{
			name:   "empty config",
			config: registry.Config{},
		},
		{
			name: "config with data",
			config: registry.Config{
				"key": "value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := NewBase64(tt.config)
			if err != nil {
				t.Fatalf("NewBase64() error = %v, want nil", err)
			}
			if b == nil {
				t.Fatal("NewBase64() returned nil buff")
			}
			if b.Name() != "encoding.Base64" {
				t.Errorf("buff.Name() = %q, want %q", b.Name(), "encoding.Base64")
			}
		})
	}
}

func TestBase64_Transform_PreservesAttemptMetadata(t *testing.T) {
	b := &Base64{}

	a := attempt.New("test prompt")
	a.ID = "test-id"
	a.Probe = "test.Probe"
	a.Generator = "test.Generator"
	a.WithMetadata("custom", "value")

	var results []*attempt.Attempt
	for transformed := range b.Transform(a) {
		results = append(results, transformed)
	}

	if len(results) != 1 {
		t.Fatalf("Transform() yielded %d attempts, want 1", len(results))
	}

	result := results[0]

	// Verify metadata is preserved or copied appropriately
	// The transform should work on the attempt without losing core data
	if result.ID != a.ID {
		t.Errorf("ID = %q, want %q", result.ID, a.ID)
	}
	if result.Probe != a.Probe {
		t.Errorf("Probe = %q, want %q", result.Probe, a.Probe)
	}
	if result.Generator != a.Generator {
		t.Errorf("Generator = %q, want %q", result.Generator, a.Generator)
	}
}
