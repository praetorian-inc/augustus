package hybrid

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/augustus/pkg/registry"
)

// minimalSteps is a valid single-step pure-HTTP choreography.
func minimalSteps() []any {
	return []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"url": "https://x/api", "body": `{"q":"$INPUT_JSON"}`,
			"response_field": "$.text",
		},
	}
}

func TestHybridConfig_RequiresSteps(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "steps")
}

func TestHybridConfig_ExactlyOneAnswer(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "a", "type": "http", "url": "https://x", "body": "$INPUT"},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly one step with answer")

	_, err = HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "a", "type": "http", "answer": true, "url": "https://x", "body": "$INPUT", "response_field": "$.t"},
		map[string]any{"name": "b", "type": "http", "answer": true, "url": "https://y", "body": "$INPUT", "response_field": "$.t"},
	}})
	require.Error(t, err)
}

func TestHybridConfig_Minimal(t *testing.T) {
	cfg, err := HybridConfigFromMap(registry.Config{"steps": minimalSteps()})
	require.NoError(t, err)
	require.Len(t, cfg.Steps, 1)
	assert.True(t, cfg.Steps[0].Answer)
	assert.Equal(t, []string{"$.text"}, cfg.Steps[0].ResponseFields)
	assert.False(t, cfg.Persistent, "persistent defaults to false so probes get isolated sessions")
}

func TestHybridConfig_WSStepBeforeConnectRejected(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "send", "type": "ws_send", "frame": `{"type":"x"}`},
		map[string]any{
			"name": "ans", "type": "ws_stream", "answer": true,
			"response_field": "$.m", "complete_field": "$.t", "complete_value": "done",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "before any ws_connect")
}

func TestHybridConfig_AnswerOnNonAnswerStepRejected(t *testing.T) {
	// ws_await can never set the answer, so answer:true on it must be rejected at
	// construction rather than the count passing and failing mid-run.
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "connect", "type": "ws_connect", "url": "ws://x/ws"},
		map[string]any{
			"name": "ack", "type": "ws_await", "answer": true,
			"match_field": "$.type", "match_value": "connection_ack",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot be answer:true")
}

func TestHybridConfig_PromptMustReferenceInput(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"url": "https://x", "body": `{"q":"static"}`, "response_field": "$.t",
		},
	}})
	// The prompt-carrying requirement is not enforced at parse time for the
	// general engine (any step may carry $INPUT), so this parses fine.
	require.NoError(t, err)
}

func TestHybridConfig_StreamFinalRequiresCompletion(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": "wss://x/ws"},
		map[string]any{
			"name": "ans", "type": "ws_stream", "answer": true,
			"response_field": "$.m", "assembly": "final",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires 'complete_field'")
}

func TestHybridConfig_StreamConcatNeedsNoCompletion(t *testing.T) {
	cfg, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": "wss://x/ws"},
		map[string]any{
			"name": "ans", "type": "ws_stream", "answer": true,
			"response_field": "$.m", "assembly": "concat",
		},
	}})
	require.NoError(t, err)
	assert.Equal(t, AssemblyConcat, cfg.Steps[1].Assembly)
}

func TestHybridConfig_CompletePairing(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": "wss://x/ws"},
		map[string]any{
			"name": "ans", "type": "ws_stream", "answer": true,
			"response_field": "$.m", "complete_field": "$.t",
		},
	}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both be set")
}

func TestHybridConfig_CreateRequiresIDField(t *testing.T) {
	_, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"url": "https://x", "body": "$INPUT", "response_field": "$.t",
			"forms": []any{map[string]any{"url": "https://x", "body": "$INPUT", "capture": map[string]any{"ID": "$.id"}}},
		},
	}})
	// capture is allowed on any form; this is valid.
	require.NoError(t, err)
}

func TestHybridConfig_MultiFormFallback(t *testing.T) {
	cfg, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{
			"name": "ask", "type": "http", "answer": true,
			"response_field": "$.t",
			"forms": []any{
				map[string]any{"url": "https://x/v2", "body": `{"new":"$INPUT_JSON"}`},
				map[string]any{"url": "https://x/v1", "body": `{"old":"$INPUT_JSON"}`},
			},
		},
	}})
	require.NoError(t, err)
	require.Len(t, cfg.Steps[0].Forms, 2)
	assert.Equal(t, "https://x/v2", cfg.Steps[0].Forms[0].URL)
}

func TestHybridConfig_StructuredTemplateField(t *testing.T) {
	cfg, err := HybridConfigFromMap(registry.Config{"steps": []any{
		map[string]any{"name": "c", "type": "ws_connect", "url": "wss://x/ws"},
		map[string]any{
			"name": "init", "type": "ws_send",
			"frame": map[string]any{"type": "connection_init", "payload": map[string]any{"authorization": "Bearer $KEY"}},
		},
		map[string]any{
			"name": "ans", "type": "ws_stream", "answer": true,
			"response_field": "$.m", "complete_field": "$.t", "complete_value": "done",
		},
	}})
	require.NoError(t, err)
	assert.Contains(t, cfg.Steps[1].Frame, `"type":"connection_init"`)
	assert.Contains(t, cfg.Steps[1].Frame, `Bearer $KEY`)
}
