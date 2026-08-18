package mcptool

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/registry"
	"github.com/praetorian-inc/augustus/pkg/results"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// refusedErr is what the MCP generator produces when the SERVER answers a call
// with a JSON-RPC error: the request arrived, was parsed, and was rejected.
func refusedErr(msg string) error {
	return fmt.Errorf("%w (JSON-RPC -32602): %s", types.ErrCallRefused, msg)
}

// echoTool's only REQUIRED parameter carries values the target itself documents,
// so every argument of a call into it can be filled from what the target said —
// nothing is invented. A refusal of such a call is therefore about the payload
// and nothing else.
func echoTool() map[string]any {
	return map[string]any{
		"name": "echo_tool",
		"description": "Echo a value.\n" +
			"            Args:\n" +
			"                mode: The mode to use (read, write)\n",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"mode": map[string]any{"type": "string"},
				"text": map[string]any{"type": "string"},
			},
			"required": []any{"mode"},
		},
	}
}

// opaqueTool requires an identifier the schema says nothing about — no enum, no
// documented values, no pattern. Nothing but a guess can fill it.
func opaqueTool() map[string]any {
	return map[string]any{
		"name":        "opaque_read",
		"description": "Read a record.",
		"parameters": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"tenant_id": map[string]any{"type": "string"},
				"path":      map[string]any{"type": "string"},
			},
			"required": []any{"tenant_id", "path"},
		},
	}
}

// TestRefusalIsATestedResult: a payload the server rejects at schema validation
// was submitted, considered, and refused. That is a completed test with a
// negative result, not a broken probe.
//
// Recording it as an error is not a harmless over-report. On a server that
// validates strictly most attempts are refusals, so most of the scan reads as
// broken and the operator learns to ignore the error count — at which point a
// genuine "we never tested this" becomes invisible.
func TestRefusalIsATestedResult(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{echoTool()},
		callErr: func(_ string, _ map[string]any) error {
			return refusedErr("arguments failed schema validation")
		},
	}
	p, err := NewInjection(registry.Config{})
	if err != nil {
		t.Fatalf("NewInjection: %v", err)
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts recorded")
	}
	for _, a := range attempts {
		if !results.RefusedByTarget(a) {
			t.Errorf("attempt %q was not recorded as refused by the target", a.Prompt)
		}
		if results.NotTested(a) {
			t.Errorf("attempt %q was recorded as NOT TESTED, but every required argument came from the target's own documentation, so the refusal is about the payload", a.Prompt)
		}
		if a.Status == attempt.StatusError {
			t.Errorf("attempt %q errored; a refusal is a result, not a failure to obtain one", a.Prompt)
		}
	}
}

// TestRefusalOfAGuessedCallIsNotATestedResult is the other half, and the one
// that keeps the change above from manufacturing a false clean.
//
// When another required argument held an INVENTED placeholder, the refusal may
// be about that placeholder rather than about the payload — which never reached
// anything. Reporting "tested, and the target held" would be exactly the false
// clean this whole branch exists to remove, arriving through the fix for the
// opposite error.
func TestRefusalOfAGuessedCallIsNotATestedResult(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{opaqueTool()},
		callErr: func(_ string, _ map[string]any) error {
			return refusedErr("unknown tenant")
		},
	}
	p, err := NewPathTraversal(registry.Config{})
	if err != nil {
		t.Fatalf("NewPathTraversal: %v", err)
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts recorded")
	}
	for _, a := range attempts {
		if !results.NotTested(a) {
			t.Fatalf("attempt %q reads as tested, but tenant_id was a guess so the refusal cannot be attributed to the payload", a.Prompt)
		}
		reason, _ := a.Metadata[attempt.MetadataKeyNotTestedReason].(string)
		if reason == "" {
			t.Error("an attempt was marked NOT TESTED with no reason; the gap has to be answerable from the output")
		}
		if a.Status != attempt.StatusError {
			t.Errorf("attempt %q did not error; an untested attempt must not read as a pass", a.Prompt)
		}
	}
}

// TestTransportFailureIsNotATestedResult: nothing reached the target, so nothing
// is known. This must never read as a pass.
func TestTransportFailureIsNotATestedResult(t *testing.T) {
	target := &mockTarget{
		tools: []map[string]any{echoTool()},
		callErr: func(_ string, _ map[string]any) error {
			return errors.New("dial tcp 127.0.0.1:9999: connect: connection refused")
		},
	}
	p, err := NewInjection(registry.Config{})
	if err != nil {
		t.Fatalf("NewInjection: %v", err)
	}
	attempts, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if len(attempts) == 0 {
		t.Fatal("no attempts recorded")
	}
	for _, a := range attempts {
		if results.RefusedByTarget(a) {
			t.Errorf("attempt %q was recorded as refused, but the target never answered", a.Prompt)
		}
		if !results.NotTested(a) {
			t.Errorf("attempt %q was not recorded as NOT TESTED, though nothing reached the target", a.Prompt)
		}
		if a.Status != attempt.StatusError {
			t.Errorf("attempt %q did not error; a call that never arrived must not read as a pass", a.Prompt)
		}
	}
}

// TestSummarySeparatesRefusedFromNotTested: the counts have to be readable off
// the summary, because that is where an operator decides whether a clean-looking
// scan actually covered anything.
func TestSummarySeparatesRefusedFromNotTested(t *testing.T) {
	tested := attempt.New("refused")
	tested.Metadata[attempt.MetadataKeyTargetRefused] = true
	tested.AddOutput("the target refused the call")
	tested.Complete()

	gap := attempt.New("untested")
	gap.Metadata[attempt.MetadataKeyNotTested] = true
	gap.Metadata[attempt.MetadataKeyNotTestedReason] = "tenant_id was a guess"
	gap.SetError(errors.New("boom"))

	s := results.ComputeSummary([]*attempt.Attempt{tested, gap})
	if s.Refused != 1 {
		t.Errorf("Refused = %d, want 1", s.Refused)
	}
	if s.NotTested != 1 {
		t.Errorf("NotTested = %d, want 1", s.NotTested)
	}
	if s.Errored != 1 {
		t.Errorf("Errored = %d, want 1 — the refusal is a result and must not be counted as a broken attempt", s.Errored)
	}
}
