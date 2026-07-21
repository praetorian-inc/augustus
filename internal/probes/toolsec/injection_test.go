package toolsec

import (
	"context"
	"io"
	"net/http"
	"regexp"
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

// TestInjection_FailsLoudOnNonToolInvoker: a target that cannot be tool-invoked
// must produce a loud error, not a clean-looking empty result. Silently
// returning no attempts would read as "no injection sinks" — a false negative,
// the worst outcome for a scanner.
func TestInjection_FailsLoudOnNonToolInvoker(t *testing.T) {
	p := newInjectionProbe(t)
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err == nil {
		t.Fatalf("expected an error for non-ToolInvoker target, got nil (attempts=%d)", len(attempts))
	}
	if !strings.Contains(err.Error(), "direct tool invocation") {
		t.Errorf("error = %q, want it to explain the target is not tool-invokable", err)
	}
}

type plainGen struct{}

func (plainGen) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (plainGen) ClearHistory()       {}
func (plainGen) Name() string        { return "plain" }
func (plainGen) Description() string { return "plain" }

// testURLRE extracts the canary URL a shell-command payload would hand to curl.
var testURLRE = regexp.MustCompile("https?://[^\\s`)\"']+")

func newInjectionProbeCfg(t *testing.T, cfg registry.Config) *Injection {
	t.Helper()
	p, err := NewInjection(cfg)
	if err != nil {
		t.Fatalf("NewInjection: %v", err)
	}
	return p.(*Injection)
}

// shellFetchTool simulates a tool whose string argument is passed to a shell: any
// URL embedded in a command-injection payload gets fetched (as `curl` would). When
// blind is true the fetched body is discarded (the sink executed but returns
// nothing to the client); otherwise the body is returned (non-blind). Arithmetic
// canary payloads carry no URL and return a benign "ok".
func shellFetchTool(blind bool) *mockTarget {
	return &mockTarget{
		tools: []map[string]any{stringTool("run", "cmd")},
		call: func(_ string, args map[string]any) types.ToolResult {
			cmd, _ := args["cmd"].(string)
			u := testURLRE.FindString(cmd)
			if u == "" {
				return types.ToolResult{Text: "ok"}
			}
			resp, err := http.Get(u) //nolint:gosec,noctx // localhost test collector
			if err != nil {
				return types.ToolResult{Text: "fetch error", IsError: true}
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if blind {
				return types.ToolResult{Text: ""}
			}
			return types.ToolResult{Text: string(body)}
		},
	}
}

func sawOOBCallback(attempts []*attempt.Attempt) bool {
	for _, a := range attempts {
		if v, ok := a.GetMetadata(attempt.MetadataKeyInjectionOOBCallback); ok {
			if b, _ := v.(bool); b {
				return true
			}
		}
	}
	return false
}

// TestInjection_DetectsBlindCommandInjection: a tool that shells out and returns
// nothing still gets caught — the injected payload fetches the OOB collector, so a
// callback is recorded even with no in-band signal.
func TestInjection_DetectsBlindCommandInjection(t *testing.T) {
	p := newInjectionProbeCfg(t, registry.Config{"oob_wait_seconds": 0})
	attempts, err := p.Probe(context.Background(), shellFetchTool(true))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !sawOOBCallback(attempts) {
		t.Fatal("expected an OOB callback (blind command injection) to be recorded")
	}
}

// TestInjection_DetectsReflectedCommandInjection: a non-blind sink returns the
// fetched body (the collector marker), caught by the marker-reflection path.
func TestInjection_DetectsReflectedCommandInjection(t *testing.T) {
	p := newInjectionProbeCfg(t, registry.Config{"oob_wait_seconds": 0})
	attempts, err := p.Probe(context.Background(), shellFetchTool(false))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	det := &injectionDetectorStub{}
	fired := false
	for _, a := range attempts {
		for _, s := range det.detect(a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Error("expected reflected command injection (collector marker in output) to be flagged")
	}
}

// TestInjection_NoOOBCallbackOnEcho: a tool that echoes its argument without
// shelling out must not trigger any callback — no false command-injection finding.
func TestInjection_NoOOBCallbackOnEcho(t *testing.T) {
	p := newInjectionProbeCfg(t, registry.Config{"oob_wait_seconds": 0})
	target := &mockTarget{
		tools: []map[string]any{stringTool("echo", "message")},
		call: func(_ string, args map[string]any) types.ToolResult {
			msg, _ := args["message"].(string)
			return types.ToolResult{Text: "you said: " + msg}
		},
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if sawOOBCallback(attempts) {
		t.Error("echo tool triggered a false OOB callback")
	}
}

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
