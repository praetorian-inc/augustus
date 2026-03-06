package external

import (
	"context"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestNewScript(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantErr bool
	}{
		{
			name:    "missing command",
			cfg:     registry.Config{},
			wantErr: true,
		},
		{
			name: "empty command",
			cfg: registry.Config{
				"command": "",
			},
			wantErr: true,
		},
		{
			name: "valid command docker mode",
			cfg: registry.Config{
				"command": "python3 parser.py",
				"mode":    "docker",
			},
			wantErr: false,
		},
		{
			name: "unsafe mode without allow flag",
			cfg: registry.Config{
				"command":      "python3 parser.py",
				"mode":         "unsafe",
				"allow_unsafe": false,
			},
			wantErr: true,
		},
		{
			name: "unsafe mode with allow flag",
			cfg: registry.Config{
				"command":      "python3 parser.py",
				"mode":         "unsafe",
				"allow_unsafe": true,
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			cfg: registry.Config{
				"command": "python3 parser.py",
				"mode":    "invalid",
			},
			wantErr: true,
		},
		{
			name: "custom timeout",
			cfg: registry.Config{
				"command": "python3 parser.py",
				"timeout": float64(60),
			},
			wantErr: false,
		},
		{
			name: "custom memory",
			cfg: registry.Config{
				"command":    "python3 parser.py",
				"max_memory": "256m",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewScript(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewScript() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && p == nil {
				t.Error("NewScript() returned nil without error")
			}
		})
	}
}

func TestScript_Name(t *testing.T) {
	s := &Script{}
	if got := s.Name(); got != "external.Script" {
		t.Errorf("Name() = %q, want %q", got, "external.Script")
	}
}

func TestScript_Description(t *testing.T) {
	s := &Script{}
	if got := s.Description(); got == "" {
		t.Error("Description() returned empty string")
	}
}

func TestScript_ParseOutput(t *testing.T) {
	s := &Script{}

	tests := []struct {
		name    string
		stdout  []byte
		want    string
		wantErr bool
	}{
		{
			name:    "valid output",
			stdout:  []byte(`{"content": "parsed text"}`),
			want:    "parsed text",
			wantErr: false,
		},
		{
			name:    "empty content",
			stdout:  []byte(`{"content": ""}`),
			want:    "",
			wantErr: false,
		},
		{
			name:    "script error",
			stdout:  []byte(`{"content": "", "error": "parsing failed"}`),
			want:    "",
			wantErr: true,
		},
		{
			name:    "invalid json",
			stdout:  []byte(`not json`),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := s.parseOutput(tt.stdout)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseOutput() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseOutput() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestScript_ParseUnsafe(t *testing.T) {
	// Test with a simple echo command that outputs valid JSON
	s := &Script{
		command: `echo '{"content": "test output"}'`,
		mode:    ModeUnsafe,
		timeout: 30 * time.Second,
	}

	ctx := context.Background()
	got, err := s.parseUnsafe(ctx, []byte("test input"), "text/plain")
	if err != nil {
		t.Fatalf("parseUnsafe() error = %v", err)
	}
	if got != "test output" {
		t.Errorf("parseUnsafe() = %q, want %q", got, "test output")
	}
}

func TestScriptInput_JSON(t *testing.T) {
	input := ScriptInput{
		RawResponse: "test data",
		ContentType: "text/plain",
		Metadata:    map[string]string{"key": "value"},
	}

	// Verify it's a valid struct (no JSON marshaling test needed, just verify fields exist)
	if input.RawResponse != "test data" {
		t.Error("RawResponse not set correctly")
	}
	if input.ContentType != "text/plain" {
		t.Error("ContentType not set correctly")
	}
	if input.Metadata["key"] != "value" {
		t.Error("Metadata not set correctly")
	}
}

func TestScriptOutput_JSON(t *testing.T) {
	output := ScriptOutput{
		Content: "parsed content",
		Error:   "",
	}

	// Verify it's a valid struct
	if output.Content != "parsed content" {
		t.Error("Content not set correctly")
	}
	if output.Error != "" {
		t.Error("Error should be empty")
	}
}
