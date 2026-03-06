package sse

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewAggregate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name:    "default config",
			cfg:     registry.Config{},
			wantErr: false,
		},
		{
			name: "with text_field",
			cfg: registry.Config{
				"text_field": "$.content",
			},
			wantErr: false,
		},
		{
			name: "with mode delta",
			cfg: registry.Config{
				"mode": "delta",
			},
			wantErr: false,
		},
		{
			name: "with mode last",
			cfg: registry.Config{
				"mode": "last",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewAggregate(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAggregate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && p == nil {
				t.Error("NewAggregate() returned nil without error")
			}
		})
	}
}

func TestAggregate_ParseDefault(t *testing.T) {
	p := &Aggregate{Mode: "delta"}
	ctx := context.Background()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "non-sse input returns unchanged",
			input: "Hello, world!",
			want:  "Hello, world!",
		},
		{
			name: "openai delta style",
			input: `data: {"delta": {"text": "Hello"}}
data: {"delta": {"text": " world"}}
`,
			want: "Hello world",
		},
		{
			name: "openai chat completions style",
			input: `data: {"choices": [{"delta": {"content": "Hello"}}]}
data: {"choices": [{"delta": {"content": " world"}}]}
data: [DONE]
`,
			want: "Hello world",
		},
		{
			name: "direct content field",
			input: `data: {"content": "Hello"}
data: {"content": " world"}
`,
			want: "Hello world",
		},
		{
			name: "direct text field",
			input: `data: {"text": "Hello"}
data: {"text": " world"}
`,
			want: "Hello world",
		},
		{
			name: "claude message style",
			input: `data: {"message": {"parts": [{"text": "Hello"}]}}
data: {"message": {"parts": [{"text": " world"}]}}
`,
			want: "Hello world",
		},
		{
			name: "mixed with invalid json",
			input: `data: {"content": "Hello"}
data: invalid json
data: {"content": " world"}
`,
			want: "Hello world",
		},
		{
			name: "with empty data lines",
			input: `data: {"content": "Hello"}
data:
data: {"content": " world"}
`,
			want: "Hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.Parse(ctx, []byte(tt.input), "text/event-stream")
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAggregate_ParseConfigurable(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		parser      *Aggregate
		input       string
		want        string
	}{
		{
			name: "custom text field",
			parser: &Aggregate{
				TextField: "$.data.text",
				Mode:      "delta",
			},
			input: `data: {"data": {"text": "Hello"}}
data: {"data": {"text": " world"}}
`,
			want: "Hello world",
		},
		{
			name: "mode last",
			parser: &Aggregate{
				TextField: "$.content",
				Mode:      "last",
			},
			input: `data: {"content": "First"}
data: {"content": "Second"}
data: {"content": "Third"}
`,
			want: "Third",
		},
		{
			name: "with filter",
			parser: &Aggregate{
				TextField:   "$.content",
				Mode:        "delta",
				FilterField: "$.type",
				FilterValue: "text",
			},
			input: `data: {"type": "text", "content": "Hello"}
data: {"type": "meta", "content": "ignored"}
data: {"type": "text", "content": " world"}
`,
			want: "Hello world",
		},
		{
			name: "array access",
			parser: &Aggregate{
				TextField: "$.choices[0].delta.content",
				Mode:      "delta",
			},
			input: `data: {"choices": [{"delta": {"content": "Hello"}}]}
data: {"choices": [{"delta": {"content": " world"}}]}
`,
			want: "Hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.parser.Parse(ctx, []byte(tt.input), "text/event-stream")
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			if got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAggregate_Name(t *testing.T) {
	p := &Aggregate{}
	if got := p.Name(); got != "sse.Aggregate" {
		t.Errorf("Name() = %q, want %q", got, "sse.Aggregate")
	}
}

func TestEvaluateJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		path    string
		want    string
		wantErr bool
	}{
		{
			name:    "simple field",
			data:    map[string]any{"name": "test"},
			path:    "$.name",
			want:    "test",
			wantErr: false,
		},
		{
			name:    "nested field",
			data:    map[string]any{"outer": map[string]any{"inner": "value"}},
			path:    "$.outer.inner",
			want:    "value",
			wantErr: false,
		},
		{
			name:    "array index",
			data:    map[string]any{"items": []any{"a", "b", "c"}},
			path:    "$.items[1]",
			want:    "b",
			wantErr: false,
		},
		{
			name:    "missing field",
			data:    map[string]any{"name": "test"},
			path:    "$.missing",
			want:    "",
			wantErr: true,
		},
		{
			name:    "array out of bounds",
			data:    map[string]any{"items": []any{"a"}},
			path:    "$.items[5]",
			want:    "",
			wantErr: true,
		},
		{
			name:    "number value",
			data:    map[string]any{"count": float64(42)},
			path:    "$.count",
			want:    "42",
			wantErr: false,
		},
		{
			name:    "bool value",
			data:    map[string]any{"active": true},
			path:    "$.active",
			want:    "true",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateJSONPath(tt.data, tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateJSONPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("evaluateJSONPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
