package rest

import (
	"testing"
	"time"

	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		"uri":                  "https://api.example.com/generate",
		"method":               "PUT",
		"headers":              map[string]any{"Authorization": "Bearer token"},
		"req_template":         "{\"prompt\": \"$INPUT\"}",
		"response_json":        true,
		"response_json_field":  "text",
		"request_timeout":      30.0,
		"ratelimit_codes":      []any{429, 503},
		"skip_codes":           []any{404},
		"api_key":              "test-key",
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
