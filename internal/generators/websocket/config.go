package websocket

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/wsutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Read modes control how many frames the generator consumes per request before
// it considers the response complete.
const (
	// ReadModeSingle reads exactly one frame and returns it. This suits
	// request/response endpoints that answer with a single message.
	ReadModeSingle = "single"
	// ReadModeUntilClose accumulates frames until the server closes the
	// connection or no frame arrives within idle_timeout. This suits streamed
	// responses that terminate by closing the socket.
	ReadModeUntilClose = "until_close"
	// ReadModeUntilMarker accumulates frames until one matches a configured
	// terminator (done_marker substring or done_field/done_value), or until
	// idle_timeout elapses. The terminator frame is not included in the output.
	ReadModeUntilMarker = "until_marker"
)

// Config holds typed configuration for the WebSocket generator.
//
// The configuration deliberately mirrors the REST generator's vocabulary
// (uri/endpoint, headers, req_template, response_json/response_json_field,
// api_key, rate_limit, insecure_skip_verify) so operators can move a target
// between the two transports with minimal edits.
type Config struct {
	// Required: ws:// or wss:// endpoint URL.
	URI string

	// Handshake
	Headers      map[string]string
	Origin       string   // Origin header; auto-derived from URI when empty.
	Subprotocols []string // Sec-WebSocket-Protocol values offered in the handshake.

	// Request
	ReqTemplate string // Outgoing message template; supports $INPUT, $KEY, $MESSAGES, hook vars.
	APIKey      string // Substituted for $KEY in templates and headers.

	// Response framing
	ReadMode          string
	ResponseJSON      bool
	ResponseJSONField string // Field/JSONPath extracted from each frame when ResponseJSON.
	DoneMarker        string // until_marker: stop when a frame contains this substring.
	DoneField         string // until_marker: JSONPath whose value is compared to DoneValue.
	DoneValue         string // until_marker: value of DoneField that terminates reading.

	// Connection lifecycle
	Persistent     bool          // Reuse one connection across Generate calls (closed by ClearHistory).
	RequestTimeout time.Duration // Overall deadline for connect + send + read of one request.
	IdleTimeout    time.Duration // Per-frame read deadline in multi-frame read modes.

	// Transport
	InsecureSkipVerify bool
	RateLimit          float64 // Requests per second (0 = unlimited).
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Headers:        make(map[string]string),
		ReqTemplate:    "$INPUT",
		ReadMode:       ReadModeSingle,
		RequestTimeout: 30 * time.Second,
		IdleTimeout:    10 * time.Second,
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config, validating
// constraints. It returns an error for missing required keys or contradictory
// option combinations rather than silently degrading — a misconfigured target
// must fail loudly so a scan is never reported clean against an endpoint that
// was never actually reached.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: URI (accept "endpoint" as alias for parity with REST/GeneratorConfig).
	uri, err := registry.RequireString(m, "uri")
	if err != nil {
		endpoint, endpointErr := registry.RequireString(m, "endpoint")
		if endpointErr != nil {
			return cfg, fmt.Errorf("websocket generator requires 'uri' or 'endpoint' configuration")
		}
		uri = endpoint
	} else if endpoint, _ := registry.RequireString(m, "endpoint"); endpoint != "" && endpoint != uri {
		slog.Warn("both 'uri' and 'endpoint' specified; using 'uri'", "uri", uri, "endpoint", endpoint)
	}
	cfg.URI = uri

	// Optional: headers.
	if headers, ok := m["headers"].(map[string]any); ok {
		cfg.Headers = make(map[string]string)
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				cfg.Headers[k] = vs
			}
		}
	}

	// Optional: origin and subprotocols.
	cfg.Origin = registry.GetString(m, "origin", "")
	cfg.Subprotocols = registry.GetStringSlice(m, "subprotocols", nil)

	// Optional: request template (accept "body" as alias).
	cfg.ReqTemplate = registry.GetString(m, "req_template", cfg.ReqTemplate)
	if _, hasReqTemplate := m["req_template"]; !hasReqTemplate {
		if body := registry.GetString(m, "body", ""); body != "" {
			cfg.ReqTemplate = body
		}
	} else if body := registry.GetString(m, "body", ""); body != "" && body != cfg.ReqTemplate {
		slog.Warn("both 'req_template' and 'body' specified; using 'req_template'",
			"req_template", cfg.ReqTemplate, "body", body)
	}

	// Optional: JSON request template object (serialized to the template string).
	if tmplObj, ok := m["req_template_json_object"].(map[string]any); ok {
		data, err := json.Marshal(tmplObj)
		if err != nil {
			return cfg, fmt.Errorf("websocket: failed to marshal req_template_json_object: %w", err)
		}
		cfg.ReqTemplate = string(data)
	}

	// Optional: API key.
	cfg.APIKey = registry.GetString(m, "api_key", "")

	// Optional: response JSON parsing (accept "response_path" as alias).
	_, responseJSONExplicit := m["response_json"].(bool)
	cfg.ResponseJSON = registry.GetBool(m, "response_json", false)
	cfg.ResponseJSONField = registry.GetString(m, "response_json_field", "")
	if cfg.ResponseJSONField == "" {
		if responsePath := registry.GetString(m, "response_path", ""); responsePath != "" {
			cfg.ResponseJSONField = responsePath
			if responseJSONExplicit && !cfg.ResponseJSON {
				slog.Warn("'response_path' would enable JSON parsing, but 'response_json' is explicitly false; respecting 'response_json: false'",
					"response_path", responsePath)
			} else {
				cfg.ResponseJSON = true
			}
		}
	} else if responsePath := registry.GetString(m, "response_path", ""); responsePath != "" && responsePath != cfg.ResponseJSONField {
		slog.Warn("both 'response_json_field' and 'response_path' specified; using 'response_json_field'",
			"response_json_field", cfg.ResponseJSONField, "response_path", responsePath)
	}
	if cfg.ResponseJSON && cfg.ResponseJSONField == "" {
		return cfg, fmt.Errorf("websocket generator: response_json is true but response_json_field is not set")
	}

	// Optional: read mode.
	cfg.ReadMode = registry.GetString(m, "read_mode", cfg.ReadMode)
	switch cfg.ReadMode {
	case ReadModeSingle, ReadModeUntilClose, ReadModeUntilMarker:
	default:
		return cfg, fmt.Errorf("websocket: read_mode must be %q, %q, or %q, got %q",
			ReadModeSingle, ReadModeUntilClose, ReadModeUntilMarker, cfg.ReadMode)
	}

	// Optional: terminator configuration (only meaningful for until_marker).
	cfg.DoneMarker = registry.GetString(m, "done_marker", "")
	cfg.DoneField = registry.GetString(m, "done_field", "")
	cfg.DoneValue = registry.GetString(m, "done_value", "")
	if (cfg.DoneField != "") != (cfg.DoneValue != "") {
		return cfg, fmt.Errorf("websocket: done_field and done_value must both be set or both be empty")
	}
	if cfg.ReadMode == ReadModeUntilMarker && cfg.DoneMarker == "" && cfg.DoneField == "" {
		return cfg, fmt.Errorf("websocket: read_mode %q requires done_marker or done_field/done_value", ReadModeUntilMarker)
	}

	// Optional: lifecycle.
	cfg.Persistent = registry.GetBool(m, "persistent", false)

	// Optional: timeouts (seconds; accept int or float).
	if timeout, ok := wsutil.DurationSeconds(m, "request_timeout"); ok {
		cfg.RequestTimeout = timeout
	}
	if timeout, ok := wsutil.DurationSeconds(m, "idle_timeout"); ok {
		cfg.IdleTimeout = timeout
	}

	// Optional: transport.
	cfg.InsecureSkipVerify = registry.GetBool(m, "insecure_skip_verify", false)
	if rateLimit, ok := m["rate_limit"].(float64); ok {
		if rateLimit < 0 {
			return cfg, fmt.Errorf("rate_limit must be non-negative, got %f", rateLimit)
		}
		cfg.RateLimit = rateLimit
	} else if rateLimit, ok := m["rate_limit"].(int); ok {
		if rateLimit < 0 {
			return cfg, fmt.Errorf("rate_limit must be non-negative, got %d", rateLimit)
		}
		cfg.RateLimit = float64(rateLimit)
	}

	return cfg, nil
}
