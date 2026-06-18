package jsonpath

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "simple dot notation",
			path:     ".field.nested",
			expected: []string{"field", "nested"},
		},
		{
			name:     "array index",
			path:     ".field[0].value",
			expected: []string{"field", "[0]", "value"},
		},
		{
			name:     "multiple indices",
			path:     "[0][1]",
			expected: []string{"[0]", "[1]"},
		},
		{
			name:     "empty path",
			path:     "",
			expected: nil,
		},
		{
			name:     "leading dot only",
			path:     ".",
			expected: nil,
		},
		{
			name:     "deep nesting",
			path:     ".a.b.c.d",
			expected: []string{"a", "b", "c", "d"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParsePath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNavigateSegment(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		seg     string
		want    any
		wantErr string
	}{
		{
			name: "object field",
			data: map[string]any{"key": "value"},
			seg:  "key",
			want: "value",
		},
		{
			name: "array index 0",
			data: []any{"a", "b", "c"},
			seg:  "[0]",
			want: "a",
		},
		{
			name: "array index 2",
			data: []any{"a", "b", "c"},
			seg:  "[2]",
			want: "c",
		},
		{
			name:    "missing field",
			data:    map[string]any{"key": "value"},
			seg:     "missing",
			wantErr: `field "missing" not found`,
		},
		{
			name:    "index out of bounds",
			data:    []any{"a"},
			seg:     "[5]",
			wantErr: "array index 5 out of bounds",
		},
		{
			name:    "index on non-array",
			data:    map[string]any{"key": "value"},
			seg:     "[0]",
			wantErr: "expected array",
		},
		{
			name:    "field on non-object",
			data:    []any{"a"},
			seg:     "key",
			wantErr: "expected object",
		},
		{
			name:    "negative index",
			data:    []any{"a", "b"},
			seg:     "[-1]",
			wantErr: "invalid array index",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NavigateSegment(tt.data, tt.seg)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestValueToString(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want string
	}{
		{name: "string", val: "hello", want: "hello"},
		{name: "float", val: 3.14, want: "3.14"},
		{name: "integer float", val: float64(42), want: "42"},
		{name: "bool true", val: true, want: "true"},
		{name: "bool false", val: false, want: "false"},
		{name: "nil", val: nil, want: ""},
		{name: "map", val: map[string]any{"k": "v"}, want: `{"k":"v"}`},
		{name: "slice", val: []any{1, 2}, want: "[1,2]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ValueToString(tt.val))
		})
	}
}

func TestEvaluate(t *testing.T) {
	data := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{
					"content": "hello world",
				},
			},
		},
		"text": "direct",
	}

	tests := []struct {
		name    string
		data    any
		path    string
		want    string
		wantErr string
	}{
		{
			name: "simple field",
			data: data,
			path: "$.text",
			want: "direct",
		},
		{
			name: "nested with array",
			data: data,
			path: "$.choices[0].message.content",
			want: "hello world",
		},
		{
			name: "root only",
			data: "raw string",
			path: "$",
			want: "raw string",
		},
		{
			name:    "missing field",
			data:    data,
			path:    "$.nonexistent",
			wantErr: `field "nonexistent" not found`,
		},
		{
			name:    "index out of bounds",
			data:    data,
			path:    "$.choices[5]",
			wantErr: "out of bounds",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Evaluate(tt.data, tt.path)
			if tt.wantErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
