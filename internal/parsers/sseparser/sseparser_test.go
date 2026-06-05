package sseparser

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewAggregate(t *testing.T) {
	tests := []struct {
		name string
		cfg  registry.Config
	}{
		{
			name: "empty config uses defaults",
			cfg:  registry.Config{},
		},
		{
			name: "custom text field",
			cfg: registry.Config{
				"text_field": "$.choices[0].delta.content",
				"mode":       "delta",
			},
		},
		{
			name: "last mode with filter",
			cfg: registry.Config{
				"text_field":   "$.content.text",
				"mode":         "last",
				"filter_field": "$.content.type",
				"filter_value": "CHAT_TEXT",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewAggregate(tt.cfg)
			if err != nil {
				t.Fatalf("NewAggregate() error = %v", err)
			}
			if p == nil {
				t.Fatal("NewAggregate() returned nil")
			}
		})
	}
}

func TestAggregate_Parse(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		cfg  registry.Config
		body string
		want string
	}{
		{
			name: "default heuristic delta.text",
			cfg:  registry.Config{},
			body: "data: {\"delta\":{\"text\":\"Hello\"}}\n\ndata: {\"delta\":{\"text\":\" world\"}}\n\n",
			want: "Hello world",
		},
		{
			name: "configurable text field",
			cfg: registry.Config{
				"text_field": "$.choices[0].delta.content",
				"mode":       "delta",
			},
			body: "data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n",
			want: "Hi there",
		},
		{
			name: "last mode",
			cfg: registry.Config{
				"text_field": "$.text",
				"mode":       "last",
			},
			body: "data: {\"text\":\"partial\"}\n\ndata: {\"text\":\"final answer\"}\n\n",
			want: "final answer",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewAggregate(tt.cfg)
			if err != nil {
				t.Fatalf("NewAggregate() error = %v", err)
			}
			got, err := p.Parse(ctx, []byte(tt.body), "text/event-stream")
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAggregate_Name(t *testing.T) {
	a := &Aggregate{}
	if got := a.Name(); got != "sse.Aggregate" {
		t.Errorf("Name() = %q, want %q", got, "sse.Aggregate")
	}
}

func TestAggregate_Description(t *testing.T) {
	a := &Aggregate{}
	if got := a.Description(); got == "" {
		t.Error("Description() returned empty string")
	}
}
