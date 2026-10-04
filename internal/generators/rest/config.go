package rest

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// Config keys accepted by NewRest (the registered constructor) and
// ConfigFromMap. endpoint is an alias for uri, body for req_template, and
// response_path for response_json_field. multipart's sub-keys (file_field,
// filename, fields) are nested, not top-level.
const (
	keyURI                   = "uri"
	keyEndpoint              = "endpoint"
	keyMethod                = "method"
	keyHeaders               = "headers"
	keyReqTemplate           = "req_template"
	keyBody                  = "body"
	keyReqTemplateJSONObject = "req_template_json_object"
	keyResponseJSON          = "response_json"
	keyResponseJSONField     = "response_json_field"
	keyResponsePath          = "response_path"
	keyReasoningPath         = "reasoning_path"
	keyRequestTimeout        = "request_timeout"
	keyRateLimitCodes        = "ratelimit_codes"
	keySkipCodes             = "skip_codes"
	keyAPIKey                = "api_key"
	keyRateLimit             = "rate_limit"
	keyProxy                 = "proxy"
	keyInsecureSkipVerify    = "insecure_skip_verify"
	keySSETextField          = "sse_text_field"
	keySSEMode               = "sse_mode"
	keySSEFilterField        = "sse_filter_field"
	keySSEFilterValue        = "sse_filter_value"
	keyBodyMode              = "body_mode"
	keyMultipart             = "multipart"
)

// RequiredKeys returns the config keys NewRest requires. A required key may be
// satisfied by one of its KeyAliases() instead.
func RequiredKeys() []string {
	return []string{keyURI}
}

// KeyAliases maps a required key to the keys NewRest and ConfigFromMap accept in
// its place.
func KeyAliases() map[string][]string {
	return map[string][]string{keyURI: {keyEndpoint}}
}

// OptionalKeys returns the config keys NewRest accepts but does not require.
func OptionalKeys() []string {
	return []string{
		keyEndpoint, keyMethod, keyHeaders, keyReqTemplate, keyBody,
		keyReqTemplateJSONObject, keyResponseJSON, keyResponseJSONField,
		keyResponsePath, keyReasoningPath, keyRequestTimeout, keyRateLimitCodes,
		keySkipCodes, keyAPIKey, keyRateLimit, keyProxy, keyInsecureSkipVerify,
		keySSETextField, keySSEMode, keySSEFilterField, keySSEFilterValue,
		keyBodyMode, keyMultipart,
	}
}

// Config holds typed configuration for the REST generator.
type Config struct {
	// Required
	URI string

	// Optional with defaults
	Method            string
	Headers           map[string]string
	ReqTemplate       string
	ResponseJSON      bool
	ResponseJSONField string
	RequestTimeout    time.Duration
	RateLimitCodes    map[int]bool
	SkipCodes         map[int]bool
	APIKey            string
	RateLimit         float64 // Requests per second (0 = unlimited)

	// SSE configuration (optional, enables configurable SSE parsing)
	SSETextField   string // JSONPath for text extraction from SSE events (e.g., "$.content.text")
	SSEMode        string // "delta" (concat all chunks) or "last" (take last non-empty value)
	SSEFilterField string // JSONPath for filtering SSE events (e.g., "$.content.type")
	SSEFilterValue string // Value to match for sse_filter_field (e.g., "CHAT_TEXT")
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		Method:         "POST",
		ReqTemplate:    "$INPUT",
		RequestTimeout: 20 * time.Second,
		Headers:        make(map[string]string),
		RateLimitCodes: map[int]bool{429: true},
		SkipCodes:      make(map[int]bool),
	}
}

// ConfigFromMap parses a registry.Config map into a typed Config.
func ConfigFromMap(m registry.Config) (Config, error) {
	cfg := DefaultConfig()

	// Required: URI (also accept "endpoint" as alias for compatibility with GeneratorConfig)
	uri, err := registry.RequireString(m, keyURI)
	if err != nil {
		endpoint, endpointErr := registry.RequireString(m, keyEndpoint)
		if endpointErr != nil {
			return cfg, fmt.Errorf("rest generator requires 'uri' or 'endpoint' configuration")
		}
		uri = endpoint
	} else if endpoint, _ := registry.RequireString(m, keyEndpoint); endpoint != "" && endpoint != uri {
		slog.Warn("both 'uri' and 'endpoint' specified; using 'uri'")
	}
	cfg.URI = uri

	// Optional: method
	cfg.Method = registry.GetString(m, keyMethod, cfg.Method)

	// Optional: headers
	if headers, ok := m[keyHeaders].(map[string]any); ok {
		cfg.Headers = make(map[string]string)
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				cfg.Headers[k] = vs
			}
		}
	}

	// Optional: request template (also accept "body" as alias for compatibility with GeneratorConfig)
	cfg.ReqTemplate = registry.GetString(m, keyReqTemplate, cfg.ReqTemplate)
	if _, hasReqTemplate := m[keyReqTemplate]; !hasReqTemplate {
		if body := registry.GetString(m, keyBody, ""); body != "" {
			cfg.ReqTemplate = body
		}
	} else if body := registry.GetString(m, keyBody, ""); body != "" && body != cfg.ReqTemplate {
		slog.Warn("both 'req_template' and 'body' specified; using 'req_template'",
			"req_template", cfg.ReqTemplate, "body", body)
	}

	// Optional: response JSON parsing
	_, responseJSONExplicit := m[keyResponseJSON].(bool)
	if responseJSON, ok := m[keyResponseJSON].(bool); ok {
		cfg.ResponseJSON = responseJSON
	}
	cfg.ResponseJSONField = registry.GetString(m, keyResponseJSONField, "")
	// Also accept "response_path" as alias for compatibility with GeneratorConfig
	if cfg.ResponseJSONField == "" {
		if responsePath := registry.GetString(m, keyResponsePath, ""); responsePath != "" {
			cfg.ResponseJSONField = responsePath
			if responseJSONExplicit && !cfg.ResponseJSON {
				slog.Warn("'response_path' would enable JSON parsing, but 'response_json' is explicitly false; respecting 'response_json: false'",
					"response_path", responsePath)
			} else {
				cfg.ResponseJSON = true
			}
		}
	} else if responsePath := registry.GetString(m, keyResponsePath, ""); responsePath != "" && responsePath != cfg.ResponseJSONField {
		slog.Warn("both 'response_json_field' and 'response_path' specified; using 'response_json_field'",
			"response_json_field", cfg.ResponseJSONField, "response_path", responsePath)
	}

	// Validate JSON response configuration
	if cfg.ResponseJSON && cfg.ResponseJSONField == "" {
		return cfg, fmt.Errorf("rest generator: response_json is true but response_json_field is not set")
	}

	// Optional: timeout
	if timeout, ok := m[keyRequestTimeout].(float64); ok {
		cfg.RequestTimeout = time.Duration(timeout * float64(time.Second))
	} else if timeout, ok := m[keyRequestTimeout].(int); ok {
		cfg.RequestTimeout = time.Duration(timeout) * time.Second
	}

	// Optional: rate limit codes
	if codes, ok := m[keyRateLimitCodes].([]any); ok {
		cfg.RateLimitCodes = make(map[int]bool)
		for _, c := range codes {
			if code, ok := c.(int); ok {
				cfg.RateLimitCodes[code] = true
			} else if code, ok := c.(float64); ok {
				cfg.RateLimitCodes[int(code)] = true
			}
		}
	}

	// Optional: skip codes
	if codes, ok := m[keySkipCodes].([]any); ok {
		cfg.SkipCodes = make(map[int]bool)
		for _, c := range codes {
			if code, ok := c.(int); ok {
				cfg.SkipCodes[code] = true
			} else if code, ok := c.(float64); ok {
				cfg.SkipCodes[int(code)] = true
			}
		}
	}

	// Optional: API key
	cfg.APIKey = registry.GetString(m, keyAPIKey, "")

	// Optional: Rate limit (requests per second)
	if rateLimit, ok := m[keyRateLimit].(float64); ok {
		if rateLimit < 0 {
			return cfg, fmt.Errorf("rate_limit must be non-negative, got %f", rateLimit)
		}
		cfg.RateLimit = rateLimit
	} else if rateLimit, ok := m[keyRateLimit].(int); ok {
		if rateLimit < 0 {
			return cfg, fmt.Errorf("rate_limit must be non-negative, got %d", rateLimit)
		}
		cfg.RateLimit = float64(rateLimit)
	}

	// Optional: SSE configuration
	cfg.SSETextField = registry.GetString(m, keySSETextField, "")
	cfg.SSEMode = registry.GetString(m, keySSEMode, "delta")
	cfg.SSEFilterField = registry.GetString(m, keySSEFilterField, "")
	cfg.SSEFilterValue = registry.GetString(m, keySSEFilterValue, "")

	// Validate SSE mode
	if cfg.SSEMode != "delta" && cfg.SSEMode != "last" {
		return cfg, fmt.Errorf("sse_mode must be \"delta\" or \"last\", got %q", cfg.SSEMode)
	}

	// Validate SSE filter: both field and value must be set together
	if (cfg.SSEFilterField != "") != (cfg.SSEFilterValue != "") {
		return cfg, fmt.Errorf("sse_filter_field and sse_filter_value must both be set or both be empty")
	}

	return cfg, nil
}

// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
	return registry.ApplyOptions(cfg, opts...)
}

// WithURI sets the API URI.
func WithURI(uri string) Option {
	return func(c *Config) {
		c.URI = uri
	}
}

// WithMethod sets the HTTP method.
func WithMethod(method string) Option {
	return func(c *Config) {
		c.Method = method
	}
}

// WithHeaders sets the HTTP headers.
func WithHeaders(headers map[string]string) Option {
	return func(c *Config) {
		c.Headers = headers
	}
}

// WithReqTemplate sets the request template.
func WithReqTemplate(template string) Option {
	return func(c *Config) {
		c.ReqTemplate = template
	}
}

// WithResponseJSON sets whether to parse JSON responses.
func WithResponseJSON(parseJSON bool) Option {
	return func(c *Config) {
		c.ResponseJSON = parseJSON
	}
}

// WithResponseJSONField sets the JSON field to extract.
func WithResponseJSONField(field string) Option {
	return func(c *Config) {
		c.ResponseJSONField = field
	}
}

// WithRequestTimeout sets the request timeout.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(c *Config) {
		c.RequestTimeout = timeout
	}
}

// WithRateLimitCodes sets the rate limit HTTP status codes.
func WithRateLimitCodes(codes map[int]bool) Option {
	return func(c *Config) {
		c.RateLimitCodes = codes
	}
}

// WithSkipCodes sets the HTTP status codes to skip (return empty response).
func WithSkipCodes(codes map[int]bool) Option {
	return func(c *Config) {
		c.SkipCodes = codes
	}
}

// WithAPIKey sets the API key.
func WithAPIKey(key string) Option {
	return func(c *Config) {
		c.APIKey = key
	}
}

// WithRateLimit sets the rate limit in requests per second.
func WithRateLimit(rps float64) Option {
	return func(c *Config) {
		c.RateLimit = rps
	}
}

// WithSSETextField sets the JSONPath for text extraction from SSE events.
func WithSSETextField(field string) Option {
	return func(c *Config) {
		c.SSETextField = field
	}
}

// WithSSEMode sets the SSE accumulation mode ("delta" or "last").
func WithSSEMode(mode string) Option {
	return func(c *Config) {
		c.SSEMode = mode
	}
}

// WithSSEFilterField sets the JSONPath for filtering SSE events.
func WithSSEFilterField(field string) Option {
	return func(c *Config) {
		c.SSEFilterField = field
	}
}

// WithSSEFilterValue sets the value to match for the SSE filter field.
func WithSSEFilterValue(value string) Option {
	return func(c *Config) {
		c.SSEFilterValue = value
	}
}
