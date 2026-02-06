package rest

import (
	"fmt"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

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

	// Required: URI
	uri, err := registry.RequireString(m, "uri")
	if err != nil {
		return cfg, fmt.Errorf("rest generator requires 'uri' configuration")
	}
	cfg.URI = uri

	// Optional: method
	cfg.Method = registry.GetString(m, "method", cfg.Method)

	// Optional: headers
	if headers, ok := m["headers"].(map[string]any); ok {
		cfg.Headers = make(map[string]string)
		for k, v := range headers {
			if vs, ok := v.(string); ok {
				cfg.Headers[k] = vs
			}
		}
	}

	// Optional: request template
	cfg.ReqTemplate = registry.GetString(m, "req_template", cfg.ReqTemplate)

	// Optional: response JSON parsing
	if responseJSON, ok := m["response_json"].(bool); ok {
		cfg.ResponseJSON = responseJSON
	}
	cfg.ResponseJSONField = registry.GetString(m, "response_json_field", "")

	// Validate JSON response configuration
	if cfg.ResponseJSON && cfg.ResponseJSONField == "" {
		return cfg, fmt.Errorf("rest generator: response_json is true but response_json_field is not set")
	}

	// Optional: timeout
	if timeout, ok := m["request_timeout"].(float64); ok {
		cfg.RequestTimeout = time.Duration(timeout * float64(time.Second))
	} else if timeout, ok := m["request_timeout"].(int); ok {
		cfg.RequestTimeout = time.Duration(timeout) * time.Second
	}

	// Optional: rate limit codes
	if codes, ok := m["ratelimit_codes"].([]any); ok {
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
	if codes, ok := m["skip_codes"].([]any); ok {
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
	cfg.APIKey = registry.GetString(m, "api_key", "")

	// Optional: Rate limit (requests per second)
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
