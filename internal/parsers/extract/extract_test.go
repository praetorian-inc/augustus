package extract

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestField(t *testing.T) {
	tests := []struct {
		name    string
		data    any
		field   string
		want    string
		wantErr string
	}{
		{
			name:  "simple field from object",
			data:  map[string]any{"text": "hello"},
			field: "text",
			want:  "hello",
		},
		{
			name:  "jsonpath field",
			data:  map[string]any{"choices": []any{map[string]any{"text": "hello"}}},
			field: "$.choices[0].text",
			want:  "hello",
		},
		{
			name:  "simple field from array first element",
			data:  []any{map[string]any{"text": "first"}, map[string]any{"text": "second"}},
			field: "text",
			want:  "first",
		},
		{
			name:    "missing field",
			data:    map[string]any{"other": "value"},
			field:   "text",
			wantErr: `field "text" not found`,
		},
		{
			name:    "empty array",
			data:    []any{},
			field:   "text",
			wantErr: "empty array",
		},
		{
			name:    "unexpected type",
			data:    "plain string",
			field:   "text",
			wantErr: "unexpected response type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Field(tt.data, tt.field)
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

func TestResponse(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		responseJSON bool
		field        string
		want         string
		wantErr      string
	}{
		{
			name:         "plain text when responseJSON false",
			body:         "raw response body",
			responseJSON: false,
			want:         "raw response body",
		},
		{
			name:         "extract json field",
			body:         `{"text":"extracted"}`,
			responseJSON: true,
			field:        "text",
			want:         "extracted",
		},
		{
			name:         "extract jsonpath field",
			body:         `{"data":{"content":"deep"}}`,
			responseJSON: true,
			field:        "$.data.content",
			want:         "deep",
		},
		{
			name:         "invalid json",
			body:         "not json",
			responseJSON: true,
			field:        "text",
			wantErr:      "failed to parse JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Response([]byte(tt.body), tt.responseJSON, tt.field)
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
