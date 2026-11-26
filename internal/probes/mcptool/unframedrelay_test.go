package mcptool

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/internal/mcpprobe"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newUnframedRelayProbe(t *testing.T) *UnframedRelay {
	t.Helper()
	p, err := NewUnframedRelay(registry.Config{})
	if err != nil {
		t.Fatalf("NewUnframedRelay: %v", err)
	}
	return p.(*UnframedRelay)
}

// relayDetectorStub re-implements the framing check locally so the probe test
// does not import the detector package (avoids a probe→detector dependency).
func scoreRelay(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, ok := a.GetMetadata(attempt.MetadataKeyRelayCanary)
	if !ok {
		return scores
	}
	canary, _ := raw.(string)
	if canary == "" {
		return scores
	}
	for i, out := range a.Outputs {
		result := mcpprobe.AnalyzeFraming(out, canary, a.Prompt)
		if result.IsUnframed() {
			scores[i] = 1.0
		}
	}
	return scores
}

func TestUnframedRelay_DetectsUnframedResponse(t *testing.T) {
	p := newUnframedRelayProbe(t)
	marker := p.canary.Marker

	target := &mockTarget{
		tools: []map[string]any{stringTool("process_document", "document_text")},
		call: func(_ string, args map[string]any) types.ToolResult {
			text, _ := args["document_text"].(string)
			return types.ToolResult{
				Text: "Document Analysis Report\n\nThe submitted document contains the following content:\n\n" +
					text + "\n\nBased on our analysis, the document appears to be a standard business communication.",
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}

	fired := false
	for _, a := range attempts {
		for _, s := range scoreRelay(a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Errorf("expected the unframed relay to be flagged (marker %q not found unframed in any output)", marker)
	}
}

func TestUnframedRelay_NoFalsePositiveOnFramedJSON(t *testing.T) {
	p := newUnframedRelayProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("process", "input")},
		call: func(_ string, args map[string]any) types.ToolResult {
			input, _ := args["input"].(string)
			resp := map[string]string{"result": input, "source": "user_input"}
			b, _ := json.Marshal(resp)
			return types.ToolResult{Text: string(b)}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, a := range attempts {
		for _, s := range scoreRelay(a) {
			if s != 0.0 {
				t.Errorf("JSON-framed tool falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

func TestUnframedRelay_NoFalsePositiveOnBareEcho(t *testing.T) {
	p := newUnframedRelayProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("echo", "message")},
		call: func(_ string, args map[string]any) types.ToolResult {
			msg, _ := args["message"].(string)
			return types.ToolResult{Text: msg}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, a := range attempts {
		for _, s := range scoreRelay(a) {
			if s != 0.0 {
				t.Errorf("bare echo tool falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

func TestUnframedRelay_NoFalsePositiveOnCodeFence(t *testing.T) {
	p := newUnframedRelayProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("process", "content")},
		call: func(_ string, args map[string]any) types.ToolResult {
			content, _ := args["content"].(string)
			return types.ToolResult{
				Text: "Here is the processed document:\n\n```\n" + content + "\n```\n\nProcessing complete with detailed results.",
			}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	for _, a := range attempts {
		for _, s := range scoreRelay(a) {
			if s != 0.0 {
				t.Errorf("code-fenced tool falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

func TestUnframedRelay_FailsLoudOnNonToolInvoker(t *testing.T) {
	p := newUnframedRelayProbe(t)
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err == nil {
		t.Fatalf("expected an error for non-ToolInvoker target, got nil (attempts=%d)", len(attempts))
	}
	if !strings.Contains(err.Error(), "direct tool invocation") {
		t.Errorf("error = %q, want it to explain the target is not tool-invokable", err)
	}
}

func TestUnframedRelay_EmptyToolList(t *testing.T) {
	p := newUnframedRelayProbe(t)
	target := &mockTarget{
		tools: []map[string]any{},
		call:  func(_ string, _ map[string]any) types.ToolResult { return types.ToolResult{} },
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("expected no attempts for empty tool list, got %d", len(attempts))
	}
}

func TestUnframedRelay_MetadataPopulated(t *testing.T) {
	p := newUnframedRelayProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("test_tool", "text")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "ok"}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}

	a := attempts[0]
	if _, ok := a.GetMetadata(attempt.MetadataKeyRelayCanary); !ok {
		t.Error("missing metadata key: mcptool.relay_canary")
	}
	if _, ok := a.GetMetadata("mcptool.tool"); !ok {
		t.Error("missing metadata key: mcptool.tool")
	}
	if _, ok := a.GetMetadata("mcptool.param"); !ok {
		t.Error("missing metadata key: mcptool.param")
	}
}
