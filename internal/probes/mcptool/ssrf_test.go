package mcptool

import (
	"context"
	"io"
	"net/http"
	"testing"

	_ "github.com/praetorian-inc/augustus/internal/detectors/mcptool"
	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/results"
	"github.com/praetorian-inc/augustus/pkg/types"
)

func newSSRFProbe(t *testing.T) *SSRF {
	t.Helper()
	// oob_wait_seconds:0 — the mock fetches synchronously, so the callback is
	// already recorded by the time CallTool returns; no need to wait.
	p, err := NewSSRF(registry.Config{"oob_wait_seconds": 0})
	if err != nil {
		t.Fatalf("NewSSRF: %v", err)
	}
	return p.(*SSRF)
}

// fetchGet performs a real HTTP GET of the injected url, returning the body when
// returnBody is set (non-blind) or a fixed string (blind).
func fetchTool(returnBody bool) func(string, map[string]any) types.ToolResult {
	return func(_ string, args map[string]any) types.ToolResult {
		u, _ := args["url"].(string)
		resp, err := http.Get(u) //nolint:noctx,gosec // test helper hitting the local OOB collector
		if err != nil {
			return types.ToolResult{Text: "error", IsError: true}
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		if returnBody {
			return types.ToolResult{Text: string(body)}
		}
		return types.ToolResult{Text: "fetched ok"}
	}
}

func attemptFor(attempts []*attempt.Attempt, tool string) *attempt.Attempt {
	for _, a := range attempts {
		if v, _ := a.GetMetadata("mcptool.tool"); v == tool {
			return a
		}
	}
	return nil
}

// TestSSRF_FailsLoudOnNonToolInvoker: like Injection, SSRF must error rather than
// return a clean-looking empty result when the target cannot be tool-invoked.
func TestSSRF_FailsLoudOnNonToolInvoker(t *testing.T) {
	p := newSSRFProbe(t)
	if _, err := p.Probe(context.Background(), plainGen{}); err == nil {
		t.Fatal("expected an error for a non-ToolInvoker target, got nil")
	}
}

// TestSSRF_BlindCallback: a tool that fetches the URL but returns no content is
// still caught via the out-of-band callback.
func TestSSRF_BlindCallback(t *testing.T) {
	p := newSSRFProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("fetch", "url")},
		call:  fetchTool(false),
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	a := attemptFor(attempts, "fetch")
	if a == nil {
		t.Fatal("no attempt for fetch tool")
	}
	if cb, _ := a.GetMetadata(attempt.MetadataKeySSRFCallback); cb != true {
		t.Errorf("expected OOB callback recorded, got %v", cb)
	}
	if scores := (&stub{}).detect(a); len(scores) == 0 || scores[0] != 1.0 {
		t.Errorf("expected blind SSRF to score 1.0, got %v", scores)
	}
}

// TestSSRF_ReflectedContent: a tool that returns the fetched body is caught via
// the reflected collector marker (and also the callback).
func TestSSRF_ReflectedContent(t *testing.T) {
	p := newSSRFProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("fetch", "url")},
		call:  fetchTool(true),
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	a := attemptFor(attempts, "fetch")
	if refl, _ := a.GetMetadata(attempt.MetadataKeySSRFReflected); refl != true {
		t.Errorf("expected reflected marker recorded, got %v", refl)
	}
}

// TestSSRF_NoFalsePositiveOnEcho: a tool that echoes the URL without fetching it
// must not be flagged (no callback, and the marker is never in the echoed URL).
func TestSSRF_NoFalsePositiveOnEcho(t *testing.T) {
	p := newSSRFProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("lookup", "url")},
		call: func(_ string, args map[string]any) types.ToolResult {
			u, _ := args["url"].(string)
			return types.ToolResult{Text: "you asked about " + u} // never fetches
		},
	}

	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	a := attemptFor(attempts, "lookup")
	if cb, _ := a.GetMetadata(attempt.MetadataKeySSRFCallback); cb == true {
		t.Error("echo tool falsely recorded a callback")
	}
	if refl, _ := a.GetMetadata(attempt.MetadataKeySSRFReflected); refl == true {
		t.Error("echo tool falsely recorded a reflection")
	}
	if scores := (&stub{}).detect(a); len(scores) > 0 && scores[0] != 0.0 {
		t.Errorf("echo tool falsely flagged: %v", scores)
	}
}

// TestSSRF_SkipsNonURLParams: tools with no URL-like param produce no attempts.
func TestSSRF_SkipsNonURLParams(t *testing.T) {
	p := newSSRFProbe(t)
	target := &mockTarget{
		tools: []map[string]any{stringTool("note", "text")},
		call:  fetchTool(false),
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if attempts != nil {
		t.Errorf("expected no attempts for non-URL params, got %d", len(attempts))
	}
}

// stub mirrors the SSRF detector's scoring locally so the probe test avoids a
// probe->detector import.
type stub struct{}

func (stub) detect(a *attempt.Attempt) []float64 {
	cb, _ := a.GetMetadata(attempt.MetadataKeySSRFCallback)
	refl, _ := a.GetMetadata(attempt.MetadataKeySSRFReflected)
	confirmed := cb == true || refl == true
	scores := make([]float64, len(a.Outputs))
	if !confirmed {
		return scores
	}
	if len(scores) == 0 {
		return []float64{1.0}
	}
	for i := range scores {
		scores[i] = 1.0
	}
	return scores
}

// fetchThenFailInvoker fetches the injected URL — firing the collector callback —
// and only then fails the call. This models the most common blind-SSRF shape: the
// tool reaches a slow or unresponsive internal host, the outbound request has
// already gone, and the call times out afterwards.
type fetchThenFailInvoker struct{ tools []map[string]any }

func (f *fetchThenFailInvoker) Generate(context.Context, *attempt.Conversation, int) ([]attempt.Message, error) {
	return nil, nil
}
func (f *fetchThenFailInvoker) ClearHistory()       {}
func (f *fetchThenFailInvoker) Name() string        { return "fetch-then-fail" }
func (f *fetchThenFailInvoker) Description() string { return "fetch-then-fail" }

func (f *fetchThenFailInvoker) ListTools(context.Context) ([]map[string]any, error) {
	return f.tools, nil
}

func (f *fetchThenFailInvoker) CallTool(_ context.Context, _ string, args map[string]any) (types.ToolResult, error) {
	if u, ok := args["url"].(string); ok {
		if resp, err := http.Get(u); err == nil { //nolint:noctx,gosec // test helper hitting the local OOB collector
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}
	return types.ToolResult{}, context.DeadlineExceeded
}

// TestSSRF_CallbackPromotesErroredAttempt: a confirmed callback must not be
// reported as an error. results.Verdict returns "error" on an errored status
// without ever consulting the score, so an attempt left in StatusError would file a
// proven SSRF as a failed request — the finding would be invisible in the report.
func TestSSRF_CallbackPromotesErroredAttempt(t *testing.T) {
	target := &fetchThenFailInvoker{tools: []map[string]any{stringTool("fetch", "url")}}

	attempts, err := newSSRFProbe(t).Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	a := attemptFor(attempts, "fetch")
	if a == nil {
		t.Fatal("no attempt recorded for the fetch tool")
	}

	if hit, _ := a.GetMetadata(attempt.MetadataKeySSRFCallback); hit != true {
		t.Fatalf("callback metadata = %v, want true (the mock fetched the canary)", hit)
	}
	if a.Status == attempt.StatusError {
		t.Error("attempt left in error status despite a confirmed callback")
	}
	// Score it with the SHIPPING detector and replay what the report would render,
	// so the assertion covers the whole path rather than the status flag alone.
	det, err := detectors.Create("mcptool.SSRF", registry.Config{})
	if err != nil {
		t.Fatalf("detectors.Create: %v", err)
	}
	scores, err := det.Detect(context.Background(), a)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	for _, sc := range scores {
		a.AddScore(sc)
	}
	if got := results.Verdict(a); got != "vuln" {
		t.Errorf("verdict = %q, want \"vuln\" — a confirmed SSRF must not report as an error", got)
	}
	if reason, ok := a.GetMetadata("mcptool.ssrf_oob_call_error"); !ok || reason == "" {
		t.Error("original call error was not preserved for the reviewer")
	}
}
