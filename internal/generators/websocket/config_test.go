package websocket

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

func TestConfigFromMap_RequiresURI(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "uri")
}

func TestConfigFromMap_EndpointAlias(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"endpoint": "ws://example/ws"})
	require.NoError(t, err)
	assert.Equal(t, "ws://example/ws", cfg.URI)
}

func TestConfigFromMap_Defaults(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"uri": "ws://x/ws"})
	require.NoError(t, err)
	assert.Equal(t, "$INPUT", cfg.ReqTemplate)
	assert.Equal(t, ReadModeSingle, cfg.ReadMode)
	assert.Equal(t, 30*time.Second, cfg.RequestTimeout)
	assert.Equal(t, 10*time.Second, cfg.IdleTimeout)
	assert.False(t, cfg.Persistent)
}

func TestConfigFromMap_BodyAliasAndJSONObject(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"uri": "ws://x", "body": "hello $INPUT"})
	require.NoError(t, err)
	assert.Equal(t, "hello $INPUT", cfg.ReqTemplate)

	cfg, err = ConfigFromMap(registry.Config{
		"uri":                      "ws://x",
		"req_template_json_object": map[string]any{"message": "$INPUT_JSON"},
	})
	require.NoError(t, err)
	assert.JSONEq(t, `{"message":"$INPUT_JSON"}`, cfg.ReqTemplate)
}

func TestConfigFromMap_ReadModeValidation(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{"uri": "ws://x", "read_mode": "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read_mode")
}

func TestConfigFromMap_UntilMarkerRequiresTerminator(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{"uri": "ws://x", "read_mode": ReadModeUntilMarker})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "done_marker")
}

func TestConfigFromMap_DoneFieldValuePairing(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{"uri": "ws://x", "read_mode": ReadModeUntilMarker, "done_field": "type"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "done_value")

	cfg, err := ConfigFromMap(registry.Config{
		"uri":        "ws://x",
		"read_mode":  ReadModeUntilMarker,
		"done_field": "type",
		"done_value": "end",
	})
	require.NoError(t, err)
	assert.Equal(t, "type", cfg.DoneField)
	assert.Equal(t, "end", cfg.DoneValue)
}

func TestConfigFromMap_ResponseJSONRequiresField(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{"uri": "ws://x", "response_json": true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "response_json_field")
}

func TestConfigFromMap_ResponsePathAliasEnablesJSON(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{"uri": "ws://x", "response_path": "$.data.text"})
	require.NoError(t, err)
	assert.True(t, cfg.ResponseJSON)
	assert.Equal(t, "$.data.text", cfg.ResponseJSONField)
}

func TestConfigFromMap_Timeouts(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"uri":             "ws://x",
		"request_timeout": 5,
		"idle_timeout":    2.5,
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Second, cfg.RequestTimeout)
	assert.Equal(t, 2500*time.Millisecond, cfg.IdleTimeout)
}

func TestConfigFromMap_NegativeRateLimit(t *testing.T) {
	_, err := ConfigFromMap(registry.Config{"uri": "ws://x", "rate_limit": -1})
	require.Error(t, err)
}

func TestConfigFromMap_HeadersAndSubprotocols(t *testing.T) {
	cfg, err := ConfigFromMap(registry.Config{
		"uri":          "ws://x",
		"headers":      map[string]any{"Authorization": "Bearer t"},
		"subprotocols": []any{"chat", "v1"},
	})
	require.NoError(t, err)
	assert.Equal(t, "Bearer t", cfg.Headers["Authorization"])
	assert.Equal(t, []string{"chat", "v1"}, cfg.Subprotocols)
}
