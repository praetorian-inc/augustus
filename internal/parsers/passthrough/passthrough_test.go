package passthrough

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewPassthrough(t *testing.T) {
	p, err := NewPassthrough(registry.Config{})
	if err != nil {
		t.Fatalf("NewPassthrough failed: %v", err)
	}
	if p == nil {
		t.Fatal("NewPassthrough returned nil")
	}
}

func TestPassthrough_Parse(t *testing.T) {
	p := &Passthrough{}
	ctx := context.Background()

	tests := []struct {
		name        string
		input       []byte
		contentType string
		want        string
	}{
		{
			name:        "empty input",
			input:       []byte(""),
			contentType: "text/plain",
			want:        "",
		},
		{
			name:        "plain text",
			input:       []byte("Hello, world!"),
			contentType: "text/plain",
			want:        "Hello, world!",
		},
		{
			name:        "json input",
			input:       []byte(`{"key": "value"}`),
			contentType: "application/json",
			want:        `{"key": "value"}`,
		},
		{
			name:        "sse input unchanged",
			input:       []byte("data: {\"content\": \"test\"}\n"),
			contentType: "text/event-stream",
			want:        "data: {\"content\": \"test\"}\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Parse(ctx, tt.input, tt.contentType)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPassthrough_Name(t *testing.T) {
	p := &Passthrough{}
	if got := p.Name(); got != "passthrough.Passthrough" {
		t.Errorf("Name() = %q, want %q", got, "passthrough.Passthrough")
	}
}

func TestPassthrough_Description(t *testing.T) {
	p := &Passthrough{}
	if got := p.Description(); got == "" {
		t.Error("Description() returned empty string")
	}
}
