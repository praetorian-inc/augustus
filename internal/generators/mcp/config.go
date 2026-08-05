package mcp

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Transport selects how the generator reaches the MCP server.
const (
	// TransportHTTP speaks JSON-RPC over the Streamable HTTP transport (HTTP
	// POST with optional SSE responses) against a remote/hosted MCP server.
	TransportHTTP = "http"
	// TransportSSE speaks the legacy HTTP+SSE transport (a GET /sse event stream
	// plus POST /messages), which older FastMCP-based servers still expose. The
	// endpoint is the SSE URL (e.g. http://host:9001/sse). Must be set
	// explicitly — it cannot be inferred, since it shares the endpoint key with
	// the streamable HTTP transport.
	TransportSSE = "sse"
	// TransportAuto probes an HTTP(S) endpoint at connect time and picks the
	// transport that successfully initializes: it attempts Streamable HTTP first
	// and falls back to legacy HTTP+SSE (or the reverse when the endpoint path
	// ends in /sse, a strong SSE hint). It lets an operator point at an HTTP MCP
	// endpoint without pre-knowing which HTTP transport the server speaks; it
	// requires 'endpoint' and never launches a subprocess.
	TransportAuto = "auto"
)

// Mode selects what a Generate call does against the connected server.
const (
	// ModeToolCall issues a tools/call for the configured tool on every
	// Generate, injecting the probe's prompt into the configured argument and
	// returning the tool result's text. This is the transport-style mode that
	// lets prompt-injection / BOLA / tool-coercion / SSRF probes target a
	// specific MCP tool.
	ModeToolCall = "tool_call"
	// ModeListTools ignores the prompt and returns the server's advertised tool
	// names, descriptions, and input schemas (tools/list). This exposes the
	// metadata an MCP client would feed its model, for tool-poisoning /
	// rug-pull probes that inspect descriptions for injected instructions.
	ModeListTools = "list_tools"
)

// Config holds typed configuration for the MCP generator.
//
// The configuration vocabulary intentionally overlaps the REST and WebSocket
// generators where it can (endpoint, headers, api_key, request_timeout,
// rate_limit, insecure_skip_verify) so operators can reason about all three the
// same way. MCP-specific keys (transport, mode, tool_name, arg_name) cover the
// parts that have no REST analog.
//
// Only network transports are supported (http, sse, auto). The MCP stdio
// transport is intentionally NOT implemented: it works by launching the server
// as a local subprocess, which is (a) irrelevant to scanning remote MCP targets
// and (b) an arbitrary-code-execution surface if the config is ever driven by
// untrusted input (e.g. augustus running as a hosted capability). Remote targets
// are reached over http/sse, which execute nothing.
type Config struct {
	Transport string // "http", "sse", or "auto"
	Mode      string // "tool_call" or "list_tools"

	// Client identity announced to the server during initialize.
	ClientName    string
	ClientVersion string

	// HTTP transport.
	Endpoint             string            // MCP server URL (http/https).
	Headers              map[string]string // Extra request headers; values support $KEY / hook-var substitution.
	InsecureSkipVerify   bool              // Skip TLS verification (http transport only).
	DisableStandaloneSSE bool              // Do not open the standalone server->client SSE stream.
	ProxyURL             *url.URL          // Explicit HTTP(S) proxy (e.g. Burp); nil falls back to the *_PROXY env vars.

	// tool_call mode.
	ToolName          string         // Name of the MCP tool to invoke.
	ArgName           string         // Argument that receives the prompt ($INPUT).
	Arguments         map[string]any // Static arguments merged into every call; string values support substitution.
	ArgumentsTemplate string         // JSON-object template rendered per call; overrides ArgName/Arguments when set.

	// Common.
	APIKey         string        // Substituted for $KEY in headers and argument templates.
	RequestTimeout time.Duration // Deadline for connect+handshake and for each tool call.
	RateLimit      float64       // Requests per second (0 = unlimited).
	Persistent     bool          // Reuse one initialized session across Generate calls (closed by ClearHistory).
}

// DefaultConfig returns a Config with sensible defaults. Persistent defaults to
// true because the MCP initialize handshake is per-session overhead that a
// scanner should pay once, not on every prompt.
func DefaultConfig() Config {
	return Config{
		Mode:           ModeToolCall,
		ClientName:     "augustus",
		ClientVersion:  "dev",
		Headers:        make(map[string]string),
		Arguments:      make(map[string]any),
		RequestTimeout: 60 * time.Second,
		Persistent:     true,
	}
}

// ConfigFromMap parses a registry.Config into a typed Config, validating
// constraints. It fails loudly on a missing required key or a contradictory
// combination rather than degrading silently: a misconfigured target that is
// never actually reached must not be reported clean by the scanner.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Client identity.
	cfg.ClientName = registry.GetString(m, "client_name", cfg.ClientName)
	cfg.ClientVersion = registry.GetString(m, "client_version", cfg.ClientVersion)

	// Common: api_key, timeouts, rate limit, persistence.
	cfg.APIKey = registry.GetString(m, "api_key", "")
	if timeout, ok := durationSeconds(m, "request_timeout"); ok {
		// A non-positive value must not be taken literally. Elsewhere in Augustus
		// 0 means "no timeout", but here it would be applied as an already-expired
		// deadline: every request and every catalog page would fail instantly and the
		// scan would report an empty tool surface rather than an error. Clamp to the
		// default and say so, matching how a below-floor rate limit is clamped.
		if timeout <= 0 {
			slog.Warn("mcp: request_timeout must be positive; using the default",
				"requested", timeout, "using", cfg.RequestTimeout)
		} else {
			cfg.RequestTimeout = timeout
		}
	}
	cfg.Persistent = registry.GetBool(m, "persistent", cfg.Persistent)
	if rl, err := parseRateLimit(m); err != nil {
		return cfg, err
	} else {
		cfg.RateLimit = rl
	}

	// Transport connection details.
	cfg.Endpoint = firstString(m, "endpoint", "uri", "url")
	cfg.Headers = stringMap(m, "headers")
	cfg.InsecureSkipVerify = registry.GetBool(m, "insecure_skip_verify", false)
	cfg.DisableStandaloneSSE = registry.GetBool(m, "disable_standalone_sse", false)
	if proxy := registry.GetString(m, "proxy", ""); proxy != "" {
		parsed, err := url.Parse(proxy)
		if err != nil {
			return cfg, fmt.Errorf("mcp: invalid proxy URL %q: %w", proxy, err)
		}
		cfg.ProxyURL = parsed
	}

	// Transport: explicit if given, otherwise inferred from which connection
	// details are present. Inference keeps simple configs terse while still
	// erroring on an ambiguous or empty setup.
	cfg.Transport = registry.GetString(m, "transport", "")
	if err := resolveTransport(&cfg); err != nil {
		return cfg, err
	}

	// Mode.
	cfg.Mode = registry.GetString(m, "mode", cfg.Mode)
	switch cfg.Mode {
	case ModeToolCall, ModeListTools:
	default:
		return cfg, fmt.Errorf("mcp: mode must be %q or %q, got %q", ModeToolCall, ModeListTools, cfg.Mode)
	}

	// tool_call parameters. These are validated lazily (in callTool) rather than
	// here, because the generator is also usable purely as a types.ToolInvoker
	// (ListTools/CallTool), for which tool_name/arg_name are irrelevant — a
	// mcptool probe drives the generator without ever touching the tool_call
	// Generate path, so requiring them at construction would break that use.
	if cfg.Mode == ModeToolCall {
		cfg.ToolName = registry.GetString(m, "tool_name", "")
		cfg.ArgName = registry.GetString(m, "arg_name", "")
		cfg.Arguments = anyMap(m, "arguments")
		if tmpl, ok := m["arguments_template"]; ok {
			s, err := templateString(tmpl)
			if err != nil {
				return cfg, err
			}
			cfg.ArgumentsTemplate = s
		}
	}

	return cfg, nil
}

// resolveTransport validates an explicit transport or, when none is given,
// infers the streamable HTTP transport from the presence of 'endpoint'. All
// supported transports are network transports; none launches a subprocess.
func resolveTransport(cfg *Config) error {
	switch cfg.Transport {
	case TransportHTTP:
		if cfg.Endpoint == "" {
			return fmt.Errorf("mcp: transport %q requires 'endpoint'", TransportHTTP)
		}
	case TransportSSE:
		if cfg.Endpoint == "" {
			return fmt.Errorf("mcp: transport %q requires 'endpoint' (the /sse URL)", TransportSSE)
		}
	case TransportAuto:
		if cfg.Endpoint == "" {
			return fmt.Errorf("mcp: transport %q requires 'endpoint' (an http/https URL)", TransportAuto)
		}
	case "":
		if cfg.Endpoint == "" {
			return fmt.Errorf("mcp: no transport configured; set 'endpoint' (http/https URL)")
		}
		cfg.Transport = TransportHTTP
	default:
		return fmt.Errorf("mcp: transport must be %q, %q, or %q, got %q", TransportHTTP, TransportSSE, TransportAuto, cfg.Transport)
	}
	return nil
}

// parseRateLimit reads a non-negative rate_limit accepting int or float.
func parseRateLimit(m registry.Config) (float64, error) {
	switch v := m["rate_limit"].(type) {
	case nil:
		return 0, nil
	case float64:
		if v < 0 {
			return 0, fmt.Errorf("mcp: rate_limit must be non-negative, got %f", v)
		}
		return v, nil
	case int:
		if v < 0 {
			return 0, fmt.Errorf("mcp: rate_limit must be non-negative, got %d", v)
		}
		return float64(v), nil
	default:
		return 0, fmt.Errorf("mcp: rate_limit must be a number, got %T", v)
	}
}

// firstString returns the first non-empty string value among the given keys,
// warning if more than one is set to a different value.
func firstString(m registry.Config, keys ...string) string {
	var chosen, chosenKey string
	for _, k := range keys {
		v := registry.GetString(m, k, "")
		if v == "" {
			continue
		}
		if chosen == "" {
			chosen, chosenKey = v, k
		} else if v != chosen {
			slog.Warn("mcp: multiple aliases set; using first", "using", chosenKey, "ignored", k)
		}
	}
	return chosen
}

// stringMap extracts a map[string]string from a config key, keeping only
// string-valued entries.
func stringMap(m registry.Config, key string) map[string]string {
	out := make(map[string]string)
	raw, ok := m[key].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// anyMap extracts a map[string]any from a config key.
func anyMap(m registry.Config, key string) map[string]any {
	if raw, ok := m[key].(map[string]any); ok {
		return raw
	}
	return make(map[string]any)
}

// templateString renders a config value as a JSON-object template string. It
// accepts either a raw string (used verbatim) or a map (marshaled to JSON).
func templateString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case map[string]any:
		data, err := json.Marshal(t)
		if err != nil {
			return "", fmt.Errorf("mcp: failed to marshal arguments_template: %w", err)
		}
		return string(data), nil
	default:
		return "", fmt.Errorf("mcp: arguments_template must be a string or object, got %T", v)
	}
}

// durationSeconds reads a numeric config value as a duration in seconds,
// accepting int or float. The bool reports whether the key was present and
// valid.
func durationSeconds(m registry.Config, key string) (time.Duration, bool) {
	switch v := m[key].(type) {
	case float64:
		return time.Duration(v * float64(time.Second)), true
	case int:
		return time.Duration(v) * time.Second, true
	default:
		return 0, false
	}
}
