package hybrid

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/praetorian-inc/augustus/internal/generators/wsutil"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Step types for the hybrid choreography engine.
const (
	stepHTTP      = "http"       // a templated HTTP request (may carry $INPUT and/or produce the answer)
	stepHTTPPoll  = "http_poll"  // re-request an endpoint until a readiness condition holds
	stepWSConnect = "ws_connect" // open a WebSocket and hold it for later ws_* steps
	stepWSSend    = "ws_send"    // send one templated frame on the open WebSocket
	stepWSAwait   = "ws_await"   // read frames until one matches a condition (e.g. connection_ack)
	stepWSStream  = "ws_stream"  // read frames, assemble the streamed answer
)

// Default polling cadence for http_poll steps.
const (
	defaultPollInterval    = 2 * time.Second
	defaultPollMaxAttempts = 30
)

// Assembly modes for reconstructing a streamed answer from frames.
const (
	// AssemblyFinal returns the response field of the terminal frame (the frame
	// satisfying the completion condition). Use when the endpoint emits a
	// cumulative final message — concatenating deltas as well would duplicate it.
	AssemblyFinal = "final"
	// AssemblyConcat concatenates the response field across every frame, skipping
	// empties. Use when the endpoint streams only deltas.
	AssemblyConcat = "concat"
)

const defaultSubprotocol = "graphql-transport-ws"

// httpForm is one attempt at an HTTP request. A step may hold several forms; the
// engine tries them in order until one succeeds (2xx and all captures resolve),
// which is how "alternative request/response schemas with fallback" is modeled.
type httpForm struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    string            // template; supports $INPUT/$INPUT_JSON/$KEY/$<VAR>
	Capture map[string]string // varName -> JSONPath into the response body
}

// step is one node in the choreography. Field relevance depends on Type; the
// parser validates the right fields are present per type.
type step struct {
	Name   string
	Type   string
	Once   bool // run only during conversation setup; skipped on reused persistent sessions
	Answer bool // this step produces the assistant message

	// http
	Forms []httpForm

	// ws_connect
	WSURL              string
	Subprotocol        string
	Origin             string
	Headers            map[string]string
	InsecureSkipVerify bool

	// ws_send
	Frame string

	// ws_await
	MatchField string
	MatchValue string

	// ws_stream (and http / http_poll answer): response extraction.
	ResponseFields []string // tried in order per frame/body; first non-empty wins (response fallback)
	CompleteField  string
	CompleteValue  string
	Assembly       string

	// http_poll: re-request until ready.
	Interval    time.Duration // wait between attempts
	MaxAttempts int           // give up after this many attempts
	UntilField  string        // JSONPath compared to UntilValue to decide readiness
	UntilValue  string        // readiness value of UntilField
}

// HybridConfig configures the Hybrid generator: an ordered list of steps that
// can mix HTTP requests and a WebSocket session in any arrangement, threading
// captured values (e.g. a conversation ID) between them. It expresses every
// request/response transport pairing — HTTP-in/WS-out (GraphQL subscription
// chat), WS-in/HTTP-out, pure HTTP, or pure WS — without target-specific code.
type HybridConfig struct {
	Steps []step

	APIKey             string            // bound to $KEY
	Vars               map[string]string // static $NAME substitutions
	RequestTimeout     time.Duration     // overall deadline for one Generate
	IdleTimeout        time.Duration     // per-frame read deadline while streaming/awaiting
	Persistent         bool              // reuse the WS session + setup captures across Generate calls
	ReuseConnection    bool              // when Persistent, also reuse the live WS connection (default true). Set false to reconnect the WS every Generate while still persisting HTTP captures (e.g. a conversationID), so no socket sits unread between turns and server keepalive pings are always answered within a turn.
	InsecureSkipVerify bool              // HTTP client TLS verification (WS uses per-connect setting)
	RateLimit          float64           // prompts per second (0 = unlimited)
	Proxy              string            // optional HTTP CONNECT proxy for both HTTP and WS legs (e.g. Burp)
}

// DefaultHybridConfig returns a HybridConfig with sensible defaults.
func DefaultHybridConfig() HybridConfig {
	return HybridConfig{
		RequestTimeout:  60 * time.Second,
		IdleTimeout:     30 * time.Second,
		Persistent:      true,
		ReuseConnection: true,
		Vars:            map[string]string{},
	}
}

// HybridConfigFromMap parses a registry.Config map into a typed HybridConfig,
// failing loudly on missing required keys or contradictory options so a
// misconfigured target never silently looks "safe".
func HybridConfigFromMap(m registry.Config) (HybridConfig, error) {
	cfg := DefaultHybridConfig()

	cfg.APIKey = registry.GetString(m, "api_key", "")
	cfg.Vars = stringMap(m, "vars")
	cfg.Persistent = registry.GetBool(m, "persistent", cfg.Persistent)
	cfg.ReuseConnection = registry.GetBool(m, "reuse_connection", cfg.ReuseConnection)
	cfg.InsecureSkipVerify = registry.GetBool(m, "insecure_skip_verify", false)
	cfg.Proxy = registry.GetString(m, "proxy", "")
	if timeout, ok := wsutil.DurationSeconds(m, "request_timeout"); ok {
		cfg.RequestTimeout = timeout
	}
	if timeout, ok := wsutil.DurationSeconds(m, "idle_timeout"); ok {
		cfg.IdleTimeout = timeout
	}
	if err := parseRateLimit(m, &cfg.RateLimit); err != nil {
		return cfg, err
	}

	rawSteps, ok := m["steps"].([]any)
	if !ok || len(rawSteps) == 0 {
		return cfg, fmt.Errorf("hybrid generator requires a non-empty 'steps' list")
	}
	for i, raw := range rawSteps {
		sm, ok := raw.(map[string]any)
		if !ok {
			return cfg, fmt.Errorf("hybrid generator: step %d is not an object", i)
		}
		st, err := parseStep(sm)
		if err != nil {
			return cfg, fmt.Errorf("hybrid generator: step %d (%s): %w", i, registry.GetString(sm, "name", "?"), err)
		}
		cfg.Steps = append(cfg.Steps, st)
	}

	if err := validateChoreography(cfg.Steps); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// parseStep parses and validates a single step.
func parseStep(sm registry.Config) (step, error) {
	st := step{
		Name:   registry.GetString(sm, "name", ""),
		Type:   registry.GetString(sm, "type", ""),
		Once:   registry.GetBool(sm, "once", false),
		Answer: registry.GetBool(sm, "answer", false),
	}

	switch st.Type {
	case stepHTTP:
		forms, err := parseForms(sm)
		if err != nil {
			return st, err
		}
		st.Forms = forms
		if st.Answer {
			st.ResponseFields = stringList(sm, "response_field")
			if len(st.ResponseFields) == 0 {
				return st, fmt.Errorf("http step with answer:true requires 'response_field'")
			}
		}

	case stepHTTPPoll:
		forms, err := parseForms(sm)
		if err != nil {
			return st, err
		}
		st.Forms = forms
		st.ResponseFields = stringList(sm, "response_field")
		st.UntilField = registry.GetString(sm, "until_field", "")
		st.UntilValue = registry.GetString(sm, "until_value", "")
		if (st.UntilField != "") != (st.UntilValue != "") {
			return st, fmt.Errorf("http_poll 'until_field' and 'until_value' must both be set or both be empty")
		}
		// A poll needs to know when to stop: either a status field flips to a
		// value, or the answer field appears. Without one it would spin forever.
		if st.UntilField == "" && len(st.ResponseFields) == 0 {
			return st, fmt.Errorf("http_poll requires a readiness condition: 'until_field'/'until_value' or 'response_field'")
		}
		if st.Answer && len(st.ResponseFields) == 0 {
			return st, fmt.Errorf("http_poll with answer:true requires 'response_field'")
		}
		st.Interval = defaultPollInterval
		if iv, ok := wsutil.DurationSeconds(sm, "interval"); ok {
			st.Interval = iv
		}
		st.MaxAttempts = registry.GetInt(sm, "max_attempts", defaultPollMaxAttempts)
		if st.MaxAttempts < 1 {
			return st, fmt.Errorf("http_poll 'max_attempts' must be >= 1")
		}

	case stepWSConnect:
		wsURL, err := registry.RequireString(sm, "url")
		if err != nil {
			return st, fmt.Errorf("ws_connect requires 'url'")
		}
		st.WSURL = wsURL
		st.Subprotocol = registry.GetString(sm, "subprotocol", defaultSubprotocol)
		st.Origin = registry.GetString(sm, "origin", "")
		st.Headers = stringMap(sm, "headers")
		st.InsecureSkipVerify = registry.GetBool(sm, "insecure_skip_verify", false)

	case stepWSSend:
		st.Frame = templateField(sm, "frame", "")
		if st.Frame == "" {
			return st, fmt.Errorf("ws_send requires 'frame'")
		}

	case stepWSAwait:
		st.MatchField = registry.GetString(sm, "match_field", "")
		st.MatchValue = registry.GetString(sm, "match_value", "")
		if st.MatchField == "" || st.MatchValue == "" {
			return st, fmt.Errorf("ws_await requires 'match_field' and 'match_value'")
		}

	case stepWSStream:
		if err := parseResponseExtraction(sm, &st); err != nil {
			return st, err
		}

	case "":
		return st, fmt.Errorf("missing 'type'")
	default:
		return st, fmt.Errorf("unknown step type %q", st.Type)
	}

	return st, nil
}

// parseForms reads one or more HTTP request forms. A single inline form (top
// level url/body/...) or an explicit "forms" list are both accepted.
func parseForms(sm registry.Config) ([]httpForm, error) {
	if rawForms, ok := sm["forms"].([]any); ok && len(rawForms) > 0 {
		var forms []httpForm
		for i, rf := range rawForms {
			fm, ok := rf.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("form %d is not an object", i)
			}
			f, err := parseForm(fm)
			if err != nil {
				return nil, fmt.Errorf("form %d: %w", i, err)
			}
			forms = append(forms, f)
		}
		return forms, nil
	}
	f, err := parseForm(sm)
	if err != nil {
		return nil, err
	}
	return []httpForm{f}, nil
}

func parseForm(fm registry.Config) (httpForm, error) {
	url, err := registry.RequireString(fm, "url")
	if err != nil {
		return httpForm{}, fmt.Errorf("http form requires 'url'")
	}
	// Body is optional: GET status/answer endpoints legitimately send none.
	return httpForm{
		URL:     url,
		Method:  strings.ToUpper(registry.GetString(fm, "method", "POST")),
		Headers: stringMap(fm, "headers"),
		Body:    templateField(fm, "body", ""),
		Capture: stringMap(fm, "capture"),
	}, nil
}

// parseResponseExtraction reads the response_field(s)/completion/assembly config
// shared by ws_stream and answer-producing http steps.
func parseResponseExtraction(sm registry.Config, st *step) error {
	st.ResponseFields = stringList(sm, "response_field")
	if len(st.ResponseFields) == 0 {
		return fmt.Errorf("requires 'response_field'")
	}
	st.CompleteField = registry.GetString(sm, "complete_field", "")
	st.CompleteValue = registry.GetString(sm, "complete_value", "")
	if (st.CompleteField != "") != (st.CompleteValue != "") {
		return fmt.Errorf("'complete_field' and 'complete_value' must both be set or both be empty")
	}
	st.Assembly = registry.GetString(sm, "assembly", AssemblyFinal)
	if st.Assembly != AssemblyFinal && st.Assembly != AssemblyConcat {
		return fmt.Errorf("'assembly' must be %q or %q, got %q", AssemblyFinal, AssemblyConcat, st.Assembly)
	}
	// Only ws_stream consumes completion/assembly. AssemblyFinal needs a way to
	// recognize the terminal data frame; a graphql-ws `complete` frame carries no
	// payload, so without a completion field the terminal value would be missed.
	if st.Type == stepWSStream && st.Assembly == AssemblyFinal && st.CompleteField == "" {
		return fmt.Errorf("ws_stream assembly %q requires 'complete_field'/'complete_value'", AssemblyFinal)
	}
	return nil
}

// validateChoreography enforces cross-step invariants.
func validateChoreography(steps []step) error {
	answers := 0
	wsOpened := false
	for _, st := range steps {
		switch st.Type {
		case stepWSConnect:
			wsOpened = true
		case stepWSSend, stepWSAwait, stepWSStream:
			if !wsOpened {
				return fmt.Errorf("step %q of type %s appears before any ws_connect", st.Name, st.Type)
			}
		}
		if st.Answer {
			answers++
		}
	}
	if answers != 1 {
		return fmt.Errorf("hybrid generator requires exactly one step with answer:true, found %d", answers)
	}
	return nil
}

func parseRateLimit(m registry.Config, dst *float64) error {
	if rl, ok := m["rate_limit"].(float64); ok {
		if rl < 0 {
			return fmt.Errorf("rate_limit must be non-negative, got %f", rl)
		}
		*dst = rl
	} else if rl, ok := m["rate_limit"].(int); ok {
		if rl < 0 {
			return fmt.Errorf("rate_limit must be non-negative, got %d", rl)
		}
		*dst = float64(rl)
	}
	return nil
}

// stringMap reads a config value as map[string]string, accepting the
// map[string]any shape YAML/JSON produces and dropping non-string values.
func stringMap(m registry.Config, key string) map[string]string {
	out := map[string]string{}
	if raw, ok := m[key].(map[string]any); ok {
		for k, v := range raw {
			if vs, ok := v.(string); ok {
				out[k] = vs
			}
		}
	}
	return out
}

// stringList reads a value that may be a single string or a list of strings.
func stringList(m registry.Config, key string) []string {
	switch v := m[key].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

// templateField reads a template supplied either as a raw string or a structured
// object (marshaled to JSON). The object form lets operators author multi-line
// GraphQL payloads in YAML without escaping.
func templateField(m registry.Config, key, def string) string {
	switch v := m[key].(type) {
	case string:
		return v
	case map[string]any:
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
	}
	return def
}
