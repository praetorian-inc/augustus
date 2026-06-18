package sse

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseDefault(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "delta text format",
			body: "data: {\"delta\":{\"text\":\"Hello \"}}\ndata: {\"delta\":{\"text\":\"World\"}}",
			want: "Hello World",
		},
		{
			name: "message parts format",
			body: "data: {\"message\":{\"parts\":[{\"text\":\"SSE text\"}]}}",
			want: "SSE text",
		},
		{
			name: "direct text field",
			body: "data: {\"text\":\"Direct text\"}",
			want: "Direct text",
		},
		{
			name: "content field",
			body: "data: {\"content\":\"Content field text\"}",
			want: "Content field text",
		},
		{
			name: "invalid json fallback",
			body: "data: Plain text response",
			want: "data: Plain text response",
		},
		{
			name: "mixed valid and invalid lines",
			body: "data: {\"delta\":{\"text\":\"ok\"}}\ndata: [DONE]\nevent: ping",
			want: "ok",
		},
		{
			name: "empty body",
			body: "",
			want: "",
		},
		{
			name: "no data lines",
			body: "event: ping\n: comment",
			want: "event: ping\n: comment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseDefault([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParseConfigurable(t *testing.T) {
	tests := []struct {
		name string
		body string
		opts Options
		want string
	}{
		{
			name: "delta mode concatenation",
			body: "data: {\"response\":{\"chunk\":\"Hello \"}}\ndata: {\"response\":{\"chunk\":\"World\"}}",
			opts: Options{
				TextField: "$.response.chunk",
				Mode:      "delta",
			},
			want: "Hello World",
		},
		{
			name: "last mode keeps final value",
			body: "data: {\"content\":{\"text\":\"partial\"}}\ndata: {\"content\":{\"text\":\"complete answer\"}}",
			opts: Options{
				TextField: "$.content.text",
				Mode:      "last",
			},
			want: "complete answer",
		},
		{
			name: "filter by field value",
			body: "data: {\"content\":{\"type\":\"metadata\",\"text\":\"skip\"}}\ndata: {\"content\":{\"type\":\"CHAT_TEXT\",\"text\":\"keep\"}}",
			opts: Options{
				TextField:   "$.content.text",
				Mode:        "delta",
				FilterField: "$.content.type",
				FilterValue: "CHAT_TEXT",
			},
			want: "keep",
		},
		{
			name: "last mode no match falls back to raw",
			body: "data: {\"type\":\"metadata\",\"text\":\"skip\"}",
			opts: Options{
				TextField:   "$.text",
				Mode:        "last",
				FilterField: "$.type",
				FilterValue: "CHAT_TEXT",
			},
			want: "data: {\"type\":\"metadata\",\"text\":\"skip\"}",
		},
		{
			name: "delta mode no match falls back to raw",
			body: "data: {\"type\":\"other\"}",
			opts: Options{
				TextField:   "$.text",
				Mode:        "delta",
				FilterField: "$.type",
				FilterValue: "CHAT_TEXT",
			},
			want: "data: {\"type\":\"other\"}",
		},
		{
			name: "non-JSON sentinels skipped",
			body: "data: [DONE]\ndata: \ndata: {\"text\":\"ok\"}",
			opts: Options{
				TextField: "$.text",
				Mode:      "delta",
			},
			want: "ok",
		},
		{
			name: "empty text values skipped in last mode",
			body: "data: {\"text\":\"real\"}\ndata: {\"text\":\"\"}",
			opts: Options{
				TextField: "$.text",
				Mode:      "last",
			},
			want: "real",
		},
		{
			name: "missing text field skipped",
			body: "data: {\"other\":\"value\"}\ndata: {\"text\":\"found\"}",
			opts: Options{
				TextField: "$.text",
				Mode:      "delta",
			},
			want: "found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseConfigurable([]byte(tt.body), tt.opts)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParse(t *testing.T) {
	t.Run("routes to configurable when TextField set", func(t *testing.T) {
		body := []byte("data: {\"text\":\"hello\"}")
		opts := Options{TextField: "$.text", Mode: "delta"}
		got := Parse(body, opts)
		assert.Equal(t, "hello", got)
	})

	t.Run("routes to default when TextField empty", func(t *testing.T) {
		body := []byte("data: {\"delta\":{\"text\":\"hello\"}}")
		got := Parse(body, Options{})
		assert.Equal(t, "hello", got)
	})
}
