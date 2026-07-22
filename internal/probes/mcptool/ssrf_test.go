package mcptool

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
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
