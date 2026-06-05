package jsonparser

import (
	"context"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewExtract(t *testing.T) {
	tests := []struct {
		name string
		cfg  registry.Config
	}{
		{
			name: "empty config",
			cfg:  registry.Config{},
		},
		{
			name: "with field",
			cfg: registry.Config{
				"field": "$.choices[0].message.content",
			},
		},
		{
			name: "with response_json_field alias",
			cfg: registry.Config{
				"response_json_field": "$.data.text",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewExtract(tt.cfg)
			if err != nil {
				t.Fatalf("NewExtract() error = %v", err)
			}
			if p == nil {
				t.Fatal("NewExtract() returned nil")
			}
		})
	}
}

func TestExtract_Parse(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name    string
		field   string
		body    string
		want    string
		wantErr bool
	}{
		{
			name:  "no field returns raw",
			field: "",
			body:  `{"message": "hello"}`,
			want:  `{"message": "hello"}`,
		},
		{
			name:  "simple field",
			field: "message",
			body:  `{"message": "hello world"}`,
			want:  "hello world",
		},
		{
			name:  "jsonpath field",
			field: "$.choices[0].message.content",
			body:  `{"choices": [{"message": {"content": "the answer"}}]}`,
			want:  "the answer",
		},
		{
			name:    "missing field",
			field:   "$.nonexistent",
			body:    `{"data": "test"}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Extract{field: tt.field}
			got, err := p.Parse(ctx, []byte(tt.body), "application/json")
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
	e := &Extract{}
	if got := e.Name(); got != "json.Extract" {
		t.Errorf("Name() = %q, want %q", got, "json.Extract")
	}
}

func TestExtract_Description(t *testing.T) {
	e := &Extract{}
	if got := e.Description(); got == "" {
		t.Error("Description() returned empty string")
	}
}
