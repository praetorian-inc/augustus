package rest

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "POST", cfg.Method)
	assert.Equal(t, "$INPUT", cfg.ReqTemplate)
	assert.Equal(t, 20*time.Second, cfg.RequestTimeout)
	assert.Equal(t, map[int]bool{429: true}, cfg.RateLimitCodes)
}

func TestConfigFromMap_RequiresURI(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri")
}

func TestConfigFromMap_Success(t *testing.T) {
	m := registry.Config{
		"uri":                 "https://api.example.com/generate",
		"method":              "PUT",
		"headers":             map[string]any{"Authorization": "Bearer token"},
		"req_template":        "{\"prompt\": \"$INPUT\"}",
		"response_json":       true,
		"response_json_field": "text",
		"request_timeout":     30.0,
		"ratelimit_codes":     []any{429, 503},
		"skip_codes":          []any{404},
		"api_key":             "test-key",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "https://api.example.com/generate", cfg.URI)
	assert.Equal(t, "PUT", cfg.Method)
	assert.Equal(t, map[string]string{"Authorization": "Bearer token"}, cfg.Headers)
	assert.Equal(t, "{\"prompt\": \"$INPUT\"}", cfg.ReqTemplate)
	assert.True(t, cfg.ResponseJSON)
	assert.Equal(t, "text", cfg.ResponseJSONField)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
	assert.Equal(t, map[int]bool{429: true, 503: true}, cfg.RateLimitCodes)
	assert.Equal(t, map[int]bool{404: true}, cfg.SkipCodes)
	assert.Equal(t, "test-key", cfg.APIKey)
}

func TestConfigFromMap_ResponseJSONRequiresField(t *testing.T) {
	m := registry.Config{
		"uri":           "https://api.example.com",
		"response_json": true,
		// Missing response_json_field
	}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response_json_field")
}

func TestFunctionalOptions(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithURI("https://test.com/api"),
		WithMethod("PATCH"),
		WithHeaders(map[string]string{"X-API-Key": "key"}),
		WithReqTemplate("{\"input\": \"$INPUT\"}"),
		WithResponseJSON(true),
		WithResponseJSONField("output"),
		WithRequestTimeout(45*time.Second),
		WithRateLimitCodes(map[int]bool{429: true}),
		WithSkipCodes(map[int]bool{400: true}),
		WithAPIKey("secret"),
		WithRateLimit(10.0),
	)

	assert.Equal(t, "https://test.com/api", cfg.URI)
	assert.Equal(t, "PATCH", cfg.Method)
	assert.Equal(t, map[string]string{"X-API-Key": "key"}, cfg.Headers)
	assert.Equal(t, "{\"input\": \"$INPUT\"}", cfg.ReqTemplate)
	assert.True(t, cfg.ResponseJSON)
	assert.Equal(t, "output", cfg.ResponseJSONField)
	assert.Equal(t, 45*time.Second, cfg.RequestTimeout)
	assert.Equal(t, map[int]bool{429: true}, cfg.RateLimitCodes)
	assert.Equal(t, map[int]bool{400: true}, cfg.SkipCodes)
	assert.Equal(t, "secret", cfg.APIKey)
	assert.Equal(t, 10.0, cfg.RateLimit)
}

func TestConfigFromMap_RateLimit(t *testing.T) {
	tests := []struct {
		name     string
		config   registry.Config
		expected float64
	}{
		{
			name: "rate_limit as float64",
			config: registry.Config{
				"uri":        "https://api.example.com",
				"rate_limit": 5.5,
			},
			expected: 5.5,
		},
		{
			name: "rate_limit as int",
			config: registry.Config{
				"uri":        "https://api.example.com",
				"rate_limit": 10,
			},
			expected: 10.0,
		},
		{
			name: "rate_limit not set",
			config: registry.Config{
				"uri": "https://api.example.com",
			},
			expected: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ConfigFromMap(tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, cfg.RateLimit)
		})
	}
}

func TestConfigFromMap_RateLimitNegative(t *testing.T) {
	tests := []struct {
		name   string
		config registry.Config
	}{
		{
			name: "negative float64",
			config: registry.Config{
				"uri":        "https://api.example.com",
				"rate_limit": -5.0,
			},
		},
		{
			name: "negative int",
			config: registry.Config{
				"uri":        "https://api.example.com",
				"rate_limit": -10,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ConfigFromMap(tt.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "rate_limit must be non-negative")
		})
	}
}

func TestConfigFromMap_SSEFields(t *testing.T) {
	m := registry.Config{
		"uri":              "https://api.example.com",
		"sse_text_field":   "$.content.text",
		"sse_mode":         "last",
		"sse_filter_field": "$.content.type",
		"sse_filter_value": "CHAT_TEXT",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "$.content.text", cfg.SSETextField)
	assert.Equal(t, "last", cfg.SSEMode)
	assert.Equal(t, "$.content.type", cfg.SSEFilterField)
	assert.Equal(t, "CHAT_TEXT", cfg.SSEFilterValue)
}

func TestConfigFromMap_SSEDefaultMode(t *testing.T) {
	m := registry.Config{
		"uri":            "https://api.example.com",
		"sse_text_field": "$.text",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)

	assert.Equal(t, "delta", cfg.SSEMode)
}

func TestConfigFromMap_SSEInvalidMode(t *testing.T) {
	m := registry.Config{
		"uri":      "https://api.example.com",
		"sse_mode": "invalid",
	}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sse_mode")
}

func TestConfigFromMap_SSEFilterFieldWithoutValue(t *testing.T) {
	m := registry.Config{
		"uri":              "https://api.example.com",
		"sse_filter_field": "$.type",
		// Missing sse_filter_value
	}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sse_filter_field and sse_filter_value must both be set")
}

func TestConfigFromMap_SSEFilterValueWithoutField(t *testing.T) {
	m := registry.Config{
		"uri":              "https://api.example.com",
		"sse_filter_value": "CHAT_TEXT",
		// Missing sse_filter_field
	}

	_, err := ConfigFromMap(m)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sse_filter_field and sse_filter_value must both be set")
}

// TestConfigFromMap_EndpointAlias verifies that "endpoint" works as an alias for "uri".
func TestConfigFromMap_EndpointAlias(t *testing.T) {
	m := registry.Config{
		"endpoint": "https://api.example.com/chat",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err, "ConfigFromMap with 'endpoint' key should succeed")
	assert.Equal(t, "https://api.example.com/chat", cfg.URI)
}

// TestConfigFromMap_BodyAlias verifies that "body" works as an alias for "req_template".
func TestConfigFromMap_BodyAlias(t *testing.T) {
	m := registry.Config{
		"uri":  "https://api.example.com",
		"body": `{"prompt":"$INPUT"}`,
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err, "ConfigFromMap with 'body' key should succeed")
	assert.Equal(t, `{"prompt":"$INPUT"}`, cfg.ReqTemplate)
}

// TestConfigFromMap_ResponsePathAlias verifies that "response_path" works as an
// alias for "response_json_field" and implicitly enables ResponseJSON.
func TestConfigFromMap_ResponsePathAlias(t *testing.T) {
	m := registry.Config{
		"uri":           "https://api.example.com",
		"response_path": "choices[0].text",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err, "ConfigFromMap with 'response_path' key should succeed")
	assert.Equal(t, "choices[0].text", cfg.ResponseJSONField)
	assert.True(t, cfg.ResponseJSON, "response_path alias should enable ResponseJSON")
}

// TestConfigFromMap_URITakesPrecedenceOverEndpoint verifies that when both "uri"
// and "endpoint" keys are present, "uri" wins.
func TestConfigFromMap_URITakesPrecedenceOverEndpoint(t *testing.T) {
	m := registry.Config{
		"uri":      "https://canonical.example.com",
		"endpoint": "https://alias.example.com",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "https://canonical.example.com", cfg.URI, "uri should take precedence over endpoint")
}

// TestConfigFromMap_ReqTemplateTakesPrecedenceOverBody verifies that when both
// "req_template" and "body" are present, "req_template" wins.
func TestConfigFromMap_ReqTemplateTakesPrecedenceOverBody(t *testing.T) {
	m := registry.Config{
		"uri":          "https://api.example.com",
		"req_template": `{"from":"req_template"}`,
		"body":         `{"from":"body"}`,
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, `{"from":"req_template"}`, cfg.ReqTemplate, "req_template should take precedence over body")
}

// TestConfigFromMap_ResponseJSONFieldTakesPrecedenceOverResponsePath verifies
// that when both "response_json_field" and "response_path" are present,
// "response_json_field" wins.
func TestConfigFromMap_ResponseJSONFieldTakesPrecedenceOverResponsePath(t *testing.T) {
	m := registry.Config{
		"uri":                 "https://api.example.com",
		"response_json":       true,
		"response_json_field": "canonical_field",
		"response_path":       "alias_field",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, "canonical_field", cfg.ResponseJSONField, "response_json_field should take precedence over response_path")
}

// TestConfigFromMap_ResponsePathRespectsExplicitResponseJSONFalse verifies that
// when "response_path" is used alongside an explicit "response_json": false,
// the explicit false is respected (ResponseJSON stays false).
func TestConfigFromMap_ResponsePathRespectsExplicitResponseJSONFalse(t *testing.T) {
	m := registry.Config{
		"uri":           "https://api.example.com",
		"response_json": false,
		"response_path": "choices[0].text",
	}

	cfg, err := ConfigFromMap(m)
	require.NoError(t, err, "ConfigFromMap should succeed")
	assert.Equal(t, "choices[0].text", cfg.ResponseJSONField, "response_path should still set the field")
	assert.False(t, cfg.ResponseJSON, "explicit response_json: false should be respected despite response_path alias")
}

func TestFunctionalOptions_SSE(t *testing.T) {
	cfg := ApplyOptions(DefaultConfig(),
		WithURI("https://test.com/api"),
		WithSSETextField("$.content.text"),
		WithSSEMode("last"),
		WithSSEFilterField("$.content.type"),
		WithSSEFilterValue("CHAT_TEXT"),
	)

	assert.Equal(t, "$.content.text", cfg.SSETextField)
	assert.Equal(t, "last", cfg.SSEMode)
	assert.Equal(t, "$.content.type", cfg.SSEFilterField)
	assert.Equal(t, "CHAT_TEXT", cfg.SSEFilterValue)
}
