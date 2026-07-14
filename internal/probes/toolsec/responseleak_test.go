package toolsec

import (
	"context"
	"errors"
	"strings"
	"testing"

	_ "github.com/praetorian-inc/augustus/internal/detectors/mcpsecrets"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newResponseLeak(t *testing.T, cfg registry.Config) *ResponseLeak {
	t.Helper()
	p, err := NewResponseLeak(cfg)
	if err != nil {
		t.Fatalf("NewResponseLeak: %v", err)
	}
	return p.(*ResponseLeak)
}

// scoreConfigLeak scores an attempt's outputs with the real mcpsecrets.ConfigLeak
// detector, resolved via the registry (blank-imported above).
func scoreConfigLeak(t *testing.T, a *attempt.Attempt) []float64 {
	t.Helper()
	det, err := detectors.Create("mcpsecrets.ConfigLeak", registry.Config{})
	if err != nil {
		t.Fatalf("detectors.Create: %v", err)
	}
	scores, err := det.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	return scores
}

// TestResponseLeak_FlagsLeakedSecret: a tool whose response embeds a real-format
// credential is flagged by the primary detector.
func TestResponseLeak_FlagsLeakedSecret(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})
	secret := "ghp_016c7f8a9b2d3e4f5061728394a5b6c7d8e9"

	target := &mockTarget{
		tools: []map[string]any{stringTool("lookup", "id")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "Error: auth failed. debug env: GITHUB_TOKEN=" + secret}
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
		for _, s := range scoreConfigLeak(t, a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Errorf("expected the leaked secret %q to be flagged by mcpsecrets.ConfigLeak", secret)
	}
}

// TestResponseLeak_FlagsSecretInRawOnly: a credential present only in the
// structured/raw result (ToolResult.Raw), not in Text, is still scored.
func TestResponseLeak_FlagsSecretInRawOnly(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})

	target := &mockTarget{
		tools: []map[string]any{stringTool("lookup", "id")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{
				Text: "ok",
				Raw:  []byte(`{"session":{"github_token":"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}}`),
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
		for _, s := range scoreConfigLeak(t, a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Error("expected the secret present only in ToolResult.Raw to be flagged by mcpsecrets.ConfigLeak")
	}
}

// TestResponseLeak_BenignResponsesScoreZero: tools that only return benign text
// produce no credential findings.
func TestResponseLeak_BenignResponsesScoreZero(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})

	target := &mockTarget{
		tools: []map[string]any{stringTool("weather", "city")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "It is 72F and sunny."}
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	for _, a := range attempts {
		for _, s := range scoreConfigLeak(t, a) {
			if s != 0.0 {
				t.Errorf("benign response falsely flagged (score %v) for output %q", s, a.Outputs)
			}
		}
	}
}

// TestResponseLeak_FailsLoudOnNonToolInvoker: a non-tool-invokable target must
// error rather than return a clean-looking empty result.
func TestResponseLeak_FailsLoudOnNonToolInvoker(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), plainGen{})
	if err == nil {
		t.Fatalf("expected an error for non-ToolInvoker target, got nil (attempts=%d)", len(attempts))
	}
	if !strings.Contains(err.Error(), "direct tool invocation") {
		t.Errorf("error = %q, want it to explain the target is not tool-invokable", err)
	}
}

// TestResponseLeak_SkipsDestructiveTool: a tool the server annotates destructive
// is skipped unless allow_destructive=true.
func TestResponseLeak_SkipsDestructiveTool(t *testing.T) {
	tru := true
	destructive := stringTool("delete_account", "id")
	destructive["annotations"] = types.MCPToolAnnotations{Destructive: &tru}

	target := &mockTarget{
		tools: []map[string]any{destructive},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "deleted"}
		},
	}

	// Default policy: destructive tool skipped. The tool is never invoked, but
	// because the target DID advertise a tool the probe emits one informational
	// (non-vulnerable) attempt noting all tools were gated (see FIX D).
	var called bool
	target.call = func(_ string, _ map[string]any) types.ToolResult {
		called = true
		return types.ToolResult{Text: "deleted"}
	}
	def := newResponseLeak(t, registry.Config{})
	attempts, err := def.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe (default): %v", err)
	}
	if called {
		t.Error("destructive tool was invoked under default policy")
	}
	if len(attempts) != 1 {
		t.Fatalf("want one informational attempt when all tools gated, got %d", len(attempts))
	}
	for _, s := range scoreConfigLeak(t, attempts[0]) {
		if s != 0.0 {
			t.Errorf("informational gated attempt scored vulnerable (%v)", s)
		}
	}

	// Opt-in: destructive tool is tested.
	opt := newResponseLeak(t, registry.Config{cfgAllowDestructive: true})
	attempts, err = opt.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe (allow_destructive): %v", err)
	}
	if len(attempts) == 0 {
		t.Error("destructive tool skipped even with allow_destructive=true")
	}
}

// TestResponseLeak_EmptyToolList: no tools -> no attempts, no error.
func TestResponseLeak_EmptyToolList(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})
	target := &mockTarget{
		tools: nil,
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{}
		},
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 0 {
		t.Errorf("expected no attempts for empty tool list, got %d", len(attempts))
	}
}

// TestResponseLeak_DebugParamVariant: a debug/verbose/trace-named param yields an
// extra case that sets it true.
func TestResponseLeak_DebugParamVariant(t *testing.T) {
	p := newResponseLeak(t, registry.Config{})
	tool := map[string]any{
		"name":        "query",
		"description": "query",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"q":     map[string]any{"type": "string"},
				"debug": map[string]any{"type": "boolean"},
			},
			"required": []any{"q"},
		},
	}
	var sawDebug bool
	target := &mockTarget{
		tools: []map[string]any{tool},
		call: func(_ string, args map[string]any) types.ToolResult {
			if d, ok := args["debug"].(bool); ok && d {
				sawDebug = true
			}
			return types.ToolResult{Text: "ok"}
		},
	}
	if _, err := p.Probe(context.Background(), target); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !sawDebug {
		t.Error("expected a case that sets the debug param true")
	}
}

// TestResponseLeak_CredentialVendingToolFlagged documents the intended
// true-positive (OWASP MCP01): a tool whose legitimate purpose is to vend a
// credential is still reported as vulnerable. Operators suppress a known
// secret-vending tool with tool_denylist, which stops the probe invoking it.
func TestResponseLeak_CredentialVendingToolFlagged(t *testing.T) {
	secret := "ghp_016c7f8a9b2d3e4f5061728394a5b6c7d8e9"
	newTarget := func(called *bool) *mockTarget {
		return &mockTarget{
			tools: []map[string]any{stringTool("get_token", "scope")},
			call: func(_ string, _ map[string]any) types.ToolResult {
				if called != nil {
					*called = true
				}
				return types.ToolResult{Text: "your token: GITHUB_TOKEN=" + secret}
			},
		}
	}

	// No denylist: the credential-vending tool IS invoked and flagged 1.0.
	p := newResponseLeak(t, registry.Config{})
	attempts, err := p.Probe(context.Background(), newTarget(nil))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	fired := false
	for _, a := range attempts {
		for _, s := range scoreConfigLeak(t, a) {
			if s == 1.0 {
				fired = true
			}
		}
	}
	if !fired {
		t.Fatalf("expected credential-vending tool to be flagged 1.0")
	}

	// Denylisted: the tool is never invoked (no attempt for it, no VULN).
	var called bool
	denied := newResponseLeak(t, registry.Config{cfgToolDenylist: []string{"get_token"}})
	attempts, err = denied.Probe(context.Background(), newTarget(&called))
	if err != nil {
		t.Fatalf("Probe (denylist): %v", err)
	}
	if called {
		t.Error("denylisted tool get_token was invoked")
	}
	for _, a := range attempts {
		if a.Metadata["toolsec.tool"] == "get_token" {
			t.Errorf("denylisted tool produced an attempt: %+v", a.Metadata)
		}
		for _, s := range scoreConfigLeak(t, a) {
			if s != 0.0 {
				t.Errorf("denylisted tool scored vulnerable (%v)", s)
			}
		}
	}
}

// TestResponseLeak_DedupesIdenticalArgCases: a tool with no required params makes
// the "empty" and "required" cases identical ({}), so it must be invoked exactly
// once, not twice (FIX C).
func TestResponseLeak_DedupesIdenticalArgCases(t *testing.T) {
	noReq := map[string]any{
		"name":        "ping",
		"description": "ping",
		"parameters": map[string]any{
			"type":       "object",
			"properties": map[string]any{},
		},
	}
	var calls int
	target := &mockTarget{
		tools: []map[string]any{noReq},
		call: func(_ string, _ map[string]any) types.ToolResult {
			calls++
			return types.ToolResult{Text: "pong"}
		},
	}
	attempts, err := newResponseLeak(t, registry.Config{}).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if calls != 1 {
		t.Errorf("tool with no required params invoked %d times, want 1", calls)
	}
	pingAttempts := 0
	for _, a := range attempts {
		if a.Metadata["toolsec.tool"] == "ping" {
			pingAttempts++
		}
	}
	if pingAttempts != 1 {
		t.Errorf("got %d attempts for ping, want 1", pingAttempts)
	}
}

// TestResponseLeak_AllToolsGated: when the target DID advertise tools but every
// one is excluded by policy, the probe emits one informational (non-vulnerable)
// attempt so the scan doesn't read as a clean pass (FIX D).
func TestResponseLeak_AllToolsGated(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{stringTool("secret_read", "key")},
		call: func(_ string, _ map[string]any) types.ToolResult {
			return types.ToolResult{Text: "should not be called"}
		},
	}
	// Deny the only advertised tool -> all filtered out.
	p := newResponseLeak(t, registry.Config{cfgToolDenylist: []string{"secret_read"}})
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) != 1 {
		t.Fatalf("want one informational attempt, got %d", len(attempts))
	}
	a := attempts[0]
	if a.Status != attempt.StatusComplete {
		t.Errorf("informational attempt status = %q, want complete", a.Status)
	}
	if a.Metadata["toolsec.gated"] == nil {
		t.Errorf("informational attempt missing toolsec.gated metadata: %+v", a.Metadata)
	}
	for _, s := range scoreConfigLeak(t, a) {
		if s != 0.0 {
			t.Errorf("informational gated attempt scored vulnerable (%v)", s)
		}
	}
}

// TestResponseLeak_TransportError: a transport-level CallTool error yields an
// attempt with StatusError and no outputs (FIX E).
func TestResponseLeak_TransportError(t *testing.T) {
	target := &erroringInvoker{tools: []map[string]any{stringTool("lookup", "id")}}
	attempts, err := newResponseLeak(t, registry.Config{}).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	for _, a := range attempts {
		if a.Status != attempt.StatusError {
			t.Errorf("attempt status = %q, want error", a.Status)
		}
		if len(a.Outputs) != 0 {
			t.Errorf("errored attempt has outputs %v, want none", a.Outputs)
		}
	}
}

// TestResponseLeak_ListToolsError: a transport-level ListTools failure must
// surface as a Probe error, not a clean empty result.
func TestResponseLeak_ListToolsError(t *testing.T) {
	attempts, err := newResponseLeak(t, registry.Config{}).Probe(context.Background(), listErrInvoker{})
	if err == nil {
		t.Fatalf("expected an error when ListTools fails, got nil (attempts=%d)", len(attempts))
	}
	if !errors.Is(err, errListTools) {
		t.Errorf("error = %v, want it to wrap errListTools", err)
	}
}

// TestResponseLeak_ContextCancellationReturnsPartial: cancelling the context
// mid-scan (after the first tool call) makes Probe stop early, returning the
// attempts gathered so far plus ctx.Err().
func TestResponseLeak_ContextCancellationReturnsPartial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	target := &mockTarget{
		tools: []map[string]any{stringTool("alpha", "x"), stringTool("beta", "y")},
		call: func(string, map[string]any) types.ToolResult {
			calls++
			cancel() // cancel after the first invocation
			return types.ToolResult{Text: "ok"}
		},
	}

	attempts, err := newResponseLeak(t, registry.Config{}).Probe(ctx, target)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(attempts) == 0 {
		t.Error("expected partial attempts gathered before cancellation, got none")
	}
	if calls >= 4 {
		t.Errorf("all cases ran (%d calls); cancellation did not stop the scan early", calls)
	}
}

// TestResponseLeak_TruncatesOversizeResponse: a tool returning a response larger
// than maxResponseBytes has its stored output capped (FIX 3) so a hostile or
// buggy target cannot force unbounded memory into the report.
func TestResponseLeak_TruncatesOversizeResponse(t *testing.T) {
	big := strings.Repeat("a", maxResponseBytes+5000)
	target := &mockTarget{
		tools: []map[string]any{stringTool("lookup", "id")},
		call: func(string, map[string]any) types.ToolResult {
			return types.ToolResult{Text: big}
		},
	}
	attempts, err := newResponseLeak(t, registry.Config{}).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("Probe produced no attempts")
	}
	const marker = 64 // generous allowance for the "...[truncated]" suffix
	for _, a := range attempts {
		for _, o := range a.Outputs {
			if len(o) > maxResponseBytes+marker {
				t.Errorf("stored output length %d exceeds cap %d (+marker)", len(o), maxResponseBytes)
			}
		}
	}
}

// listErrInvoker is a tool-surface target whose ListTools always fails with a
// transport error, exercising the list-tools error path.
type listErrInvoker struct{}

func (listErrInvoker) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (listErrInvoker) ClearHistory()       {}
func (listErrInvoker) Name() string        { return "listerr" }
func (listErrInvoker) Description() string { return "listerr" }

func (listErrInvoker) ListTools(context.Context) ([]map[string]any, error) {
	return nil, errListTools
}

func (listErrInvoker) CallTool(context.Context, string, map[string]any) (types.ToolResult, error) {
	return types.ToolResult{}, nil
}

var errListTools = errors.New("list tools transport failure")

// erroringInvoker is a tool-surface target whose CallTool always fails with a
// transport error, exercising the SetError path in responseleak.go.
type erroringInvoker struct {
	tools []map[string]any
}

func (e *erroringInvoker) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (e *erroringInvoker) ClearHistory()       {}
func (e *erroringInvoker) Name() string        { return "erroring" }
func (e *erroringInvoker) Description() string { return "erroring" }

func (e *erroringInvoker) ListTools(context.Context) ([]map[string]any, error) {
	return e.tools, nil
}

func (e *erroringInvoker) CallTool(context.Context, string, map[string]any) (types.ToolResult, error) {
	return types.ToolResult{}, errTransport
}

var errTransport = errors.New("connection reset by peer")
