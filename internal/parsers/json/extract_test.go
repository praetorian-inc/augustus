package json

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewExtract(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name:    "missing field config",
			cfg:     registry.Config{},
			wantErr: true,
		},
		{
			name: "empty field config",
			cfg: registry.Config{
				"field": "",
			},
			wantErr: true,
		},
		{
			name: "valid field config",
			cfg: registry.Config{
				"field": "$.content",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewExtract(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewExtract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && p == nil {
				t.Error("NewExtract() returned nil without error")
			}
		})
	}
}

func TestExtract_Parse(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		field   string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "simple field",
			field:   "$.content",
			input:   `{"content": "Hello, world!"}`,
			want:    "Hello, world!",
			wantErr: false,
		},
		{
			name:    "nested field",
			field:   "$.message.text",
			input:   `{"message": {"text": "nested value"}}`,
			want:    "nested value",
			wantErr: false,
		},
		{
			name:    "array access",
			field:   "$.choices[0].message.content",
			input:   `{"choices": [{"message": {"content": "first choice"}}]}`,
			want:    "first choice",
			wantErr: false,
		},
		{
			name:    "number value",
			field:   "$.count",
			input:   `{"count": 42}`,
			want:    "42",
			wantErr: false,
		},
		{
			name:    "bool value",
			field:   "$.active",
			input:   `{"active": true}`,
			want:    "true",
			wantErr: false,
		},
		{
			name:    "null value",
			field:   "$.nullable",
			input:   `{"nullable": null}`,
			want:    "",
			wantErr: false,
		},
		{
			name:    "invalid json",
			field:   "$.content",
			input:   `not json`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "missing field",
			field:   "$.missing",
			input:   `{"content": "value"}`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "array out of bounds",
			field:   "$.items[10]",
			input:   `{"items": ["a", "b"]}`,
			want:    "",
			wantErr: true,
		},
		{
			name:    "object as result",
			field:   "$.data",
			input:   `{"data": {"key": "value"}}`,
			want:    `{"key":"value"}`,
			wantErr: false,
		},
		{
			name:    "array as result",
			field:   "$.items",
			input:   `{"items": [1, 2, 3]}`,
			want:    `[1,2,3]`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Extract{Field: tt.field}
			got, err := p.Parse(ctx, []byte(tt.input), "application/json")
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("Parse() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtract_Name(t *testing.T) {
	p := &Extract{}
	if got := p.Name(); got != "json.Extract" {
		t.Errorf("Name() = %q, want %q", got, "json.Extract")
	}
}

func TestExtract_Description(t *testing.T) {
	p := &Extract{}
	if got := p.Description(); got == "" {
		t.Error("Description() returned empty string")
	}
}
