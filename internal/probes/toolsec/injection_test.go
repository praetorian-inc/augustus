package toolsec

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// mockTarget implements types.Generator + types.ToolInvoker for tests.
type mockTarget struct {
	tools    []map[string]any
	call     func(name string, args map[string]any) types.ToolResult
	listHook func() // optional: invoked whenever ListTools is called
}

func (m *mockTarget) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (m *mockTarget) ClearHistory()       {}
func (m *mockTarget) Name() string        { return "mock" }
func (m *mockTarget) Description() string { return "mock" }

func (m *mockTarget) ListTools(context.Context) ([]map[string]any, error) {
	if m.listHook != nil {
		m.listHook()
	}
	return m.tools, nil
}

func (m *mockTarget) CallTool(_ context.Context, name string, args map[string]any) (types.ToolResult, error) {
	return m.call(name, args), nil
}

func stringTool(name, param string) map[string]any {
	return map[string]any{
		"name":        name,
		"description": name,
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{param: map[string]any{"type": "string"}},
			"required":   []any{param},
		},
	}
}

// evalMul mimics an eval()/expression sink: it multiplies "<int>*<int>".
func evalMul(expr string) (string, bool) {
	parts := strings.Split(expr, "*")
	if len(parts) != 2 {
		return "", false
	}
	a, e1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	b, e2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if e1 != nil || e2 != nil {
		return "", false
	}
	return strconv.Itoa(a * b), true
}

func newInjectionProbe(t *testing.T) *Injection {
	t.Helper()
	p, err := NewInjection(registry.Config{})
	if err != nil {
		t.Fatalf("NewInjection: %v", err)
	}
	return p.(*Injection)
}

// TestInjection_DetectsEvalSink: a tool that evaluates the payload returns the
// canary marker, and the detector flags it.
func TestInjection_DetectsEvalSink(t *testing.T) {
	p := newInjectionProbe(t)
	marker := p.canary.marker

	target := &mockTarget{
		tools: []map[string]any{stringTool("calc", "expression")},
		call: func(_ string, args map[string]any) types.ToolResult {
			expr, _ := args["expression"].(string)
			if product, ok := evalMul(expr); ok {
				return types.ToolResult{Text: "Result: " + product}
			}
			return types.ToolResult{Text: "syntax error", IsError: true}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}

	det := &injectionDetectorStub{}
	fired := false
	for _, a := range attempts {
		scores := det.detect(a)
		for _, s := range scores {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Errorf("expected the eval sink to be flagged (marker %q not found in any output)", marker)
	}
}

// TestInjection_NoFalsePositiveOnEcho: a tool that echoes its input back must NOT
// be flagged — the marker (a product) never appears in the payload text.
func TestInjection_NoFalsePositiveOnEcho(t *testing.T) {
	p := newInjectionProbe(t)

	target := &mockTarget{
		tools: []map[string]any{stringTool("echo", "message")},
		call: func(_ string, args map[string]any) types.ToolResult {
			msg, _ := args["message"].(string)
			return types.ToolResult{Text: "you said: " + msg} // reflects the payload verbatim
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	det := &injectionDetectorStub{}
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s != 0.0 {
				t.Errorf("echo tool falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

// TestInjection_SkipsNonToolInvoker: a plain generator yields no attempts.
func TestInjection_SkipsNonToolInvoker(t *testing.T) {
	p := newInjectionProbe(t)
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected nil attempts for non-ToolInvoker target, got %d", len(attempts))
	}
}

type plainGen struct{}

func (plainGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainGen) ClearHistory()       {}
func (plainGen) Name() string        { return "plain" }
func (plainGen) Description() string { return "plain" }

func TestToolParams(t *testing.T) {
	params := toolParams(stringTool("t", "q"))
	if len(params) != 1 || params[0].name != "q" || params[0].typ != "string" || !params[0].required {
		t.Fatalf("toolParams = %+v, want one required string param q", params)
	}
}

// injectionDetectorStub re-implements the marker check locally so the probe test
// does not import the detector package (avoids a probe→detector dependency).
type injectionDetectorStub struct{}

func (injectionDetectorStub) detect(a *attempt.Attempt) []float64 {
	scores := make([]float64, len(a.Outputs))
	raw, ok := a.GetMetadata(attempt.MetadataKeyInjectionCanaries)
	if !ok {
		return scores
	}
	markers, _ := raw.([]string)
	for i, out := range a.Outputs {
		for _, m := range markers {
			if m != "" && strings.Contains(out, m) {
				scores[i] = 1.0
			}
		}
	}
	return scores
}
