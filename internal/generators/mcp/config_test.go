package mcp

import (
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestConfigFromMap_InfersTransport(t *testing.T) {
	tests := []struct {
		name string
		cfg  registry.Config
		want string
	}{
		{
			name: "endpoint infers http",
			cfg:  registry.Config{"endpoint": "http://x/mcp", "tool_name": "t", "arg_name": "q"},
			want: TransportHTTP,
		},
		{
			name: "command infers stdio",
			cfg:  registry.Config{"command": "npx", "tool_name": "t", "arg_name": "q"},
			want: TransportStdio,
		},
		{
			name: "explicit http",
			cfg:  registry.Config{"transport": "http", "endpoint": "http://x/mcp", "tool_name": "t", "arg_name": "q"},
			want: TransportHTTP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ConfigFromMap(tt.cfg)
			if err != nil {
				t.Fatalf("ConfigFromMap() error = %v", err)
			}
			if got.Transport != tt.want {
				t.Errorf("Transport = %q, want %q", got.Transport, tt.want)
			}
		})
	}
}

func TestConfigFromMap_Errors(t *testing.T) {
	tests := []struct {
		name    string
		cfg     registry.Config
		wantSub string
	}{
		{
			name:    "no transport at all",
			cfg:     registry.Config{"tool_name": "t", "arg_name": "q"},
			wantSub: "no transport configured",
		},
		{
			name:    "ambiguous transport",
			cfg:     registry.Config{"endpoint": "http://x", "command": "npx", "tool_name": "t", "arg_name": "q"},
			wantSub: "specify 'transport'",
		},
		{
			name:    "http without endpoint",
			cfg:     registry.Config{"transport": "http", "tool_name": "t", "arg_name": "q"},
			wantSub: "requires 'endpoint'",
		},
		{
			name:    "stdio without command",
			cfg:     registry.Config{"transport": "stdio", "tool_name": "t", "arg_name": "q"},
			wantSub: "requires 'command'",
		},
		{
			name:    "bad transport",
			cfg:     registry.Config{"transport": "carrier-pigeon", "endpoint": "http://x"},
			wantSub: "transport must be",
		},
		{
			name:    "sse without endpoint",
			cfg:     registry.Config{"transport": "sse", "tool_name": "t", "arg_name": "q"},
			wantSub: "requires 'endpoint'",
		},
		{
			name:    "bad mode",
			cfg:     registry.Config{"endpoint": "http://x", "mode": "telepathy"},
			wantSub: "mode must be",
		},
		{
			name:    "tool_call without tool_name",
			cfg:     registry.Config{"endpoint": "http://x", "mode": "tool_call"},
			wantSub: "requires 'tool_name'",
		},
		{
			name:    "tool_call without arg placement",
			cfg:     registry.Config{"endpoint": "http://x", "mode": "tool_call", "tool_name": "t"},
			wantSub: "requires 'arg_name'",
		},
		{
			name:    "negative rate limit",
			cfg:     registry.Config{"endpoint": "http://x", "tool_name": "t", "arg_name": "q", "rate_limit": -1},
			wantSub: "non-negative",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConfigFromMap(tt.cfg)
			if err == nil {
				t.Fatalf("ConfigFromMap() expected error containing %q, got nil", tt.wantSub)
			}
			if !strings.Contains(err.Error(), tt.wantSub) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantSub)
			}
		})
	}
}

func TestConfigFromMap_Defaults(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"endpoint": "http://x/mcp", "tool_name": "t", "arg_name": "q"})
	if err != nil {
		t.Fatalf("ConfigFromMap() error = %v", err)
	}
	if cfg.Mode != ModeToolCall {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModeToolCall)
	}
	if !cfg.Persistent {
		t.Error("Persistent should default to true")
	}
	if cfg.RequestTimeout != 60*time.Second {
		t.Errorf("RequestTimeout = %v, want 60s", cfg.RequestTimeout)
	}
	if cfg.ClientName != "augustus" {
		t.Errorf("ClientName = %q, want augustus", cfg.ClientName)
	}
}

func TestConfigFromMap_ListToolsNeedsNoTool(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"endpoint": "http://x/mcp", "mode": "list_tools"})
	if err != nil {
		t.Fatalf("ConfigFromMap() error = %v", err)
	}
	if cfg.Mode != ModeListTools {
		t.Errorf("Mode = %q, want %q", cfg.Mode, ModeListTools)
	}
}

func TestConfigFromMap_Proxy(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"endpoint":  "https://x/mcp",
		"tool_name": "t",
		"arg_name":  "q",
		"proxy":     "http://127.0.0.1:8080",
	})
	if err != nil {
		t.Fatalf("ConfigFromMap() error = %v", err)
	}
	if cfg.ProxyURL == nil || cfg.ProxyURL.Host != "127.0.0.1:8080" {
		t.Errorf("ProxyURL = %v, want host 127.0.0.1:8080", cfg.ProxyURL)
	}
}

func TestConfigFromMap_ProxyDefaultsNil(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"endpoint": "https://x/mcp", "tool_name": "t", "arg_name": "q"})
	if err != nil {
		t.Fatalf("ConfigFromMap() error = %v", err)
	}
	if cfg.ProxyURL != nil {
		t.Errorf("ProxyURL = %v, want nil (falls back to env)", cfg.ProxyURL)
	}
}

func TestConfigFromMap_InvalidProxy(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{
		"endpoint":  "https://x/mcp",
		"tool_name": "t",
		"arg_name":  "q",
		"proxy":     "://not a url",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid proxy URL") {
		t.Fatalf("expected invalid proxy URL error, got %v", err)
	}
}

func TestConfigFromMap_ArgumentsTemplateFromObject(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"endpoint":           "http://x/mcp",
		"tool_name":          "t",
		"arguments_template": map[string]any{"query": "$INPUT", "limit": float64(5)},
	})
	if err != nil {
		t.Fatalf("ConfigFromMap() error = %v", err)
	}
	if !strings.Contains(cfg.ArgumentsTemplate, "$INPUT") {
		t.Errorf("ArgumentsTemplate = %q, want it to contain $INPUT", cfg.ArgumentsTemplate)
	}
}
